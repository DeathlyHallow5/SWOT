"""Exercise the job lifecycle and the SSE replay-then-follow contract."""
import asyncio

import pytest

from app.jobs import JobStatus, manager

pytestmark = pytest.mark.asyncio


async def _ok_runner(job) -> None:
    job.emit("log", level="info", message="start")
    job.emit("finding", host="www.example.com")


async def _boom_runner(job) -> None:
    raise RuntimeError("deliberate failure")


async def test_job_runs_and_reports_events() -> None:
    job = await manager.submit("demo", "example.com", _ok_runner)
    events = [e async for e in manager.stream(job)]
    assert job.status is JobStatus.done
    kinds = [e.kind for e in events]
    assert "finding" in kinds
    assert kinds[-1] == "status"  # terminal status is the last event


async def test_job_captures_errors() -> None:
    job = await manager.submit("demo", "example.com", _boom_runner)
    async for _ in manager.stream(job):
        pass
    assert job.status is JobStatus.error
    assert "deliberate failure" in (job.error or "")


async def test_stream_has_no_duplicates_with_live_follow() -> None:
    async def slow(job) -> None:
        for i in range(5):
            job.emit("log", message=f"line {i}")
            await asyncio.sleep(0.01)

    job = await manager.submit("demo", "example.com", slow)
    seqs = [e.seq async for e in manager.stream(job)]
    assert seqs == sorted(set(seqs))  # strictly increasing, no repeats
