"""In-memory job queue with live event streaming over asyncio queues.

A job runs one scanner against one target. While it runs, the scanner emits
events (log lines, findings, progress). Each event is appended to the job's
history and pushed to every live subscriber, so the SSE endpoint can replay
what already happened and then follow along in real time.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator

from .config import settings


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    error = "error"
    cancelled = "cancelled"


@dataclass
class Event:
    """A single message produced while a scan runs."""

    seq: int
    kind: str  # "log" | "finding" | "progress" | "status"
    data: dict[str, Any]
    at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
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
    _subscribers: set[asyncio.Queue[Event | None]] = field(default_factory=set)
    _task: asyncio.Task[None] | None = None
    _seq: int = 0

    def emit(self, kind: str, **data: Any) -> Event:
        self._seq += 1
        event = Event(seq=self._seq, kind=kind, data=data)
        self.events.append(event)
        for queue in self._subscribers:
            queue.put_nowait(event)
        return event

    def _close_subscribers(self) -> None:
        for queue in self._subscribers:
            queue.put_nowait(None)  # sentinel: stream complete

    def is_terminal(self) -> bool:
        return self.status in (JobStatus.done, JobStatus.error, JobStatus.cancelled)


class JobManager:
    """Owns all jobs and enforces the concurrency limit."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_jobs)
        # Hold references so background cleanup tasks are not GC'd mid-flight.
        self._cleanup_tasks: set[asyncio.Task[None]] = set()

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    async def submit(self, scanner: str, target: str, runner: "ScannerRunner") -> Job:
        job = Job(id=uuid.uuid4().hex, scanner=scanner, target=target)
        self._jobs[job.id] = job
        job._task = asyncio.create_task(self._run(job, runner))
        return job

    async def cancel(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job is None or job.is_terminal() or job._task is None:
            return False
        job._task.cancel()
        return True

    async def _run(self, job: Job, runner: "ScannerRunner") -> None:
        async with self._semaphore:
            job.status = JobStatus.running
            job.emit("status", status=job.status.value)
            try:
                async with asyncio.timeout(settings.scan_timeout_seconds):
                    await runner(job)
                job.status = JobStatus.done
            except asyncio.CancelledError:
                job.status = JobStatus.cancelled
                job.emit("log", level="warn", message="scan cancelled")
            except asyncio.TimeoutError:
                job.status = JobStatus.error
                job.error = "scan timed out"
                job.emit("log", level="error", message=job.error)
            except Exception as exc:  # noqa: BLE001 - surfaced to the client
                job.status = JobStatus.error
                job.error = str(exc)
                job.emit("log", level="error", message=job.error)
            finally:
                job.finished_at = time.time()
                job.emit("status", status=job.status.value)
                job._close_subscribers()
                self._schedule_cleanup(job.id)

    def _schedule_cleanup(self, job_id: str) -> None:
        async def _cleanup() -> None:
            await asyncio.sleep(settings.job_ttl_seconds)
            self._jobs.pop(job_id, None)

        task = asyncio.create_task(_cleanup())
        self._cleanup_tasks.add(task)
        task.add_done_callback(self._cleanup_tasks.discard)

    async def stream(self, job: Job) -> AsyncIterator[Event]:
        """Yield the job's past events, then live ones until it finishes."""
        queue: asyncio.Queue[Event | None] = asyncio.Queue()
        # Subscribe before snapshotting history so no event slips through the
        # gap between replay and live follow.
        job._subscribers.add(queue)
        backlog = list(job.events)
        last_seq = 0
        try:
            for event in backlog:
                last_seq = event.seq
                yield event
            if job.is_terminal():
                return
            while True:
                event = await queue.get()
                if event is None:  # sentinel: stream complete
                    return
                if event.seq <= last_seq:
                    continue  # already replayed from backlog
                last_seq = event.seq
                yield event
        finally:
            job._subscribers.discard(queue)


# Imported lazily to avoid a cycle; defined in scanners/base.py.
from .scanners.base import ScannerRunner  # noqa: E402

manager = JobManager()
