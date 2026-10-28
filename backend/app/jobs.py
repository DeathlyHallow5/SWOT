"""Persistent jobs, bounded concurrency and resumable live event streams."""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, TYPE_CHECKING

from .config import settings
from .storage import JobStore

if TYPE_CHECKING:
    from .scanners.base import ScannerRunner


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    error = "error"
    cancelled = "cancelled"


@dataclass
class Event:
    seq: int
    kind: str
    data: dict[str, Any]
    at: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        return {"seq": self.seq, "kind": self.kind, "data": self.data, "at": self.at}


@dataclass
class Job:
    id: str
    scanner: str
    target: str
    status: JobStatus = JobStatus.queued
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    error: str | None = None
    events: list[Event] = field(default_factory=list)
    finding_count: int = 0
    _subscribers: set[asyncio.Queue] = field(default_factory=set)
    _task: asyncio.Task | None = None
    _seq: int = 0
    _store: JobStore | None = None

    def emit(self, kind: str, **data: Any) -> Event:
        self._seq += 1
        event = Event(self._seq, kind, data)
        self.events.append(event)
        if kind == "finding":
            self.finding_count += 1
        if self._store:
            self._store.save(self, event)
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # A slow client reconnects and replays from SQLite / history.
                while not queue.empty():
                    queue.get_nowait()
                queue.put_nowait(None)
                self._subscribers.discard(queue)
        return event

    def is_terminal(self) -> bool:
        return self.status in (JobStatus.done, JobStatus.error, JobStatus.cancelled)

    def summary(self) -> dict:
        return {"job_id": self.id, "scanner": self.scanner, "target": self.target,
                "status": self.status.value, "created_at": self.created_at,
                "finished_at": self.finished_at, "error": self.error,
                "finding_count": self.finding_count}

    def detail(self) -> dict:
        return {**self.summary(), "events": [e.as_dict() for e in self.events]}


class JobManager:
    def __init__(self, store: JobStore | None = None, concurrency: int | None = None) -> None:
        self._jobs: dict[str, Job] = {}
        self._semaphore = asyncio.Semaphore(concurrency or settings.max_concurrent_jobs)
        self._cleanup_tasks: set[asyncio.Task] = set()
        self.store = store

    def start_store(self, path: str) -> None:
        self.store = JobStore(path)
        for job_id in self.store.interrupted_ids():
            job = self.get(job_id)
            if job:
                job.error = "Server restarted before the scan completed. Start a new scan to retry."
                self._finish(job, JobStatus.error)

    def get(self, job_id: str) -> Job | None:
        if job_id in self._jobs:
            return self._jobs[job_id]
        data = self.store.get(job_id) if self.store else None
        if data is None:
            return None
        events = [Event(**event) for event in data.pop("events")]
        return Job(id=data.pop("job_id"), **{**data, "status": JobStatus(data["status"])},
                   events=events, _seq=events[-1].seq if events else 0, _store=self.store)

    def list(self, limit: int = 100, offset: int = 0) -> list[dict]:
        if self.store:
            return self.store.list(limit, offset)
        return [j.summary() for j in sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)][offset:offset + limit]

    async def submit(self, scanner: str, target: str, runner: ScannerRunner) -> Job:
        if sum(not j.is_terminal() for j in self._jobs.values()) >= settings.max_queued_jobs:
            raise RuntimeError("Scan queue is full. Wait for a running scan to finish.")
        job = Job(uuid.uuid4().hex, scanner, target, _store=self.store)
        self._jobs[job.id] = job
        job.emit("status", status="queued")
        job._task = asyncio.create_task(self._run(job, runner))
        return job

    def _finish(self, job: Job, status: JobStatus) -> None:
        if job.is_terminal():
            return
        job.status = status
        job.finished_at = time.time()
        job.emit("status", status=status.value)
        for queue in list(job._subscribers):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(None)

    async def cancel(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job or job.is_terminal() or not job._task:
            return False
        # Finalize even if cancellation happens before the task first executes.
        job._task.cancel()
        job.emit("log", level="warn", message="Scan cancelled")
        self._finish(job, JobStatus.cancelled)
        await asyncio.gather(job._task, return_exceptions=True)
        self._schedule_cleanup(job.id)
        return True

    async def _run(self, job: Job, runner: ScannerRunner) -> None:
        result = JobStatus.done
        try:
            async with self._semaphore:
                if job.is_terminal():
                    return
                job.status = JobStatus.running
                job.emit("status", status="running")
                async with asyncio.timeout(settings.scan_timeout_seconds):
                    await runner(job)
        except asyncio.CancelledError:
            result = JobStatus.cancelled
        except TimeoutError:
            result = JobStatus.error
            job.error = f"Scan exceeded the {settings.scan_timeout_seconds}s time limit; partial results are saved."
            job.emit("log", level="error", message=job.error)
        except Exception as exc:
            result = JobStatus.error
            job.error = str(exc)
            job.emit("log", level="error", message=job.error)
        finally:
            self._finish(job, result)
            self._schedule_cleanup(job.id)

    def _schedule_cleanup(self, job_id: str) -> None:
        async def cleanup():
            await asyncio.sleep(settings.job_ttl_seconds)
            self._jobs.pop(job_id, None)
        task = asyncio.create_task(cleanup())
        self._cleanup_tasks.add(task)
        task.add_done_callback(self._cleanup_tasks.discard)

    async def stream(self, job: Job, after: int = 0) -> AsyncIterator[Event | None]:
        queue: asyncio.Queue = asyncio.Queue(maxsize=512)
        job._subscribers.add(queue)
        last_seq = after
        try:
            for event in list(job.events):
                if event.seq > last_seq:
                    last_seq = event.seq
                    yield event
            if job.is_terminal():
                # The consumer may have paused during the initial replay while
                # the producer completed. Include events added in that gap.
                for pending in job.events:
                    if pending.seq > last_seq:
                        last_seq = pending.seq
                        yield pending
                return
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    yield None  # heartbeat, not an end-of-stream signal
                    continue
                if event is None:
                    # Flush any events dropped from a slow subscriber's queue.
                    for pending in job.events:
                        if pending.seq > last_seq:
                            last_seq = pending.seq
                            yield pending
                    return
                if event.seq > last_seq:
                    last_seq = event.seq
                    yield event
        finally:
            job._subscribers.discard(queue)

    async def shutdown(self) -> None:
        for job in list(self._jobs.values()):
            if not job.is_terminal():
                await self.cancel(job.id)
        for task in list(self._cleanup_tasks):
            task.cancel()
        await asyncio.gather(*self._cleanup_tasks, return_exceptions=True)
        if self.store:
            self.store.close()
            self.store = None
        self._jobs.clear()


manager = JobManager()
