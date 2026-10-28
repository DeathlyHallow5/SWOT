"""Storage, cancellation and restart regression tests; no external scans."""
import asyncio
import pytest
from app.jobs import JobManager, JobStatus
from app.storage import JobStore

pytestmark = pytest.mark.asyncio


async def test_history_survives_restart_and_replays_after_cursor(tmp_path):
    path = str(tmp_path / 'history.db')
    first = JobManager(JobStore(path))
    async def run(job):
        job.emit('finding', host='www.example.com')
        job.emit('finding', host='api.example.com')
    job = await first.submit('demo', 'example.com', run)
    await job._task
    expected = job.detail()
    await first.shutdown()
    second = JobManager(JobStore(path))
    restored = second.get(job.id)
    assert restored.detail() == expected
    assert second.list()[0]['finding_count'] == 2
    remaining = [e.seq async for e in second.stream(restored, after=2)]
    assert remaining == [3, 4, 5]
    await second.shutdown()


async def test_cancel_before_task_starts():
    manager = JobManager()
    async def never(job):
        pytest.fail('cancelled runner must not execute')
    job = await manager.submit('demo', 'example.com', never)
    assert await manager.cancel(job.id)
    assert job.status == JobStatus.cancelled
    assert job.finished_at
    assert [e.kind async for e in manager.stream(job)][-1] == 'status'
    await manager.shutdown()


async def test_cancel_while_waiting_for_worker():
    manager = JobManager(concurrency=1)
    gate = asyncio.Event()
    async def wait(job):
        await gate.wait()
    first = await manager.submit('demo', 'one.example.com', wait)
    second = await manager.submit('demo', 'two.example.com', wait)
    await asyncio.sleep(0)
    assert first.status == JobStatus.running
    assert second.status == JobStatus.queued
    assert await manager.cancel(second.id)
    assert second.status == JobStatus.cancelled
    gate.set()
    await first._task
    assert first.status == JobStatus.done
    await manager.shutdown()


async def test_abrupt_restart_marks_unfinished_job_failed(tmp_path):
    from app.jobs import Job
    path = str(tmp_path / 'history.db')
    store = JobStore(path)
    job = Job('a' * 32, 'demo', 'example.com', _store=store)
    job.emit('status', status='queued')
    store.close()
    manager = JobManager()
    manager.start_store(path)
    recovered = manager.get(job.id)
    assert recovered.status == JobStatus.error
    assert 'restarted' in recovered.error
    assert recovered.events[-1].data['status'] == 'error'
    await manager.shutdown()


async def test_slow_subscriber_does_not_lose_final_findings():
    manager = JobManager()
    gate = asyncio.Event()
    async def run(job):
        await gate.wait()
        for n in range(700):
            job.emit('finding', index=n)
    job = await manager.submit('demo', 'example.com', run)
    stream = manager.stream(job)
    first = await anext(stream)
    gate.set()
    await job._task
    remaining = [e async for e in stream]
    all_events = [first, *remaining]
    assert len([e for e in all_events if e.kind == 'finding']) == 700
    assert len({e.seq for e in all_events}) == len(all_events)
    await manager.shutdown()
