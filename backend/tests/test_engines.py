"""Exercise real child-process IO and mocked discovery stages."""
import asyncio
from dataclasses import replace
import json
import sys
import pytest
from app import tools
from app.jobs import Job
from app.scanners import external
from app.scanners.base import TargetError
from app.scanners._scope import in_scope, public_target


def test_scope_does_not_accept_suffix_lookalikes():
    assert in_scope('api.example.com', 'example.com')
    assert not in_scope('notexample.com', 'example.com')
    assert not in_scope('example.com.evil.test', 'example.com')


@pytest.mark.asyncio
async def test_dns_resolved_private_addresses_are_rejected(monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args: [(2, 1, 6, '', ('127.0.0.1', 0))])
    with pytest.raises(TargetError, match='private'):
        await public_target('example.com')


@pytest.mark.asyncio
async def test_jsonl_runner_preserves_results_and_checks_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(tools, 'executable', lambda _: sys.executable)
    monkeypatch.setattr(tools, 'settings', replace(tools.settings, database_path=str(tmp_path / 'db.sqlite')))
    job = Job('a' * 32, 'httpx', 'example.com')
    code = "import json; print(json.dumps({'url':'https://example.com','status_code':200,'tech':['nginx']}))"
    await tools.run_jsonl(job, 'httpx', ['-c', code])
    finding = next(e.data for e in job.events if e.kind == 'finding')
    assert finding['host'] == 'example.com'
    assert finding['status'] == 200
    assert finding['technologies'] == ['nginx']
    with pytest.raises(RuntimeError, match='code 7'):
        await tools.run_jsonl(job, 'httpx', ['-c', "import sys; print('test failure',file=sys.stderr); sys.exit(7)"])


@pytest.mark.asyncio
async def test_invalid_json_is_not_reported_as_clean_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(tools, 'executable', lambda _: sys.executable)
    monkeypatch.setattr(tools, 'settings', replace(tools.settings, database_path=str(tmp_path / 'db.sqlite')))
    with pytest.raises(RuntimeError, match='unparseable'):
        await tools.run_jsonl(Job('b' * 32, 'httpx', 'example.com'), 'httpx', ['-c', "print('invalid output')"])


@pytest.mark.asyncio
async def test_cancellation_reaps_child_process(monkeypatch, tmp_path):
    monkeypatch.setattr(tools, 'executable', lambda _: sys.executable)
    monkeypatch.setattr(tools, 'settings', replace(tools.settings, database_path=str(tmp_path / 'db.sqlite')))
    original = asyncio.create_subprocess_exec
    children = []
    async def spawn(*args, **kwargs):
        proc = await original(*args, **kwargs)
        children.append(proc)
        return proc
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', spawn)
    task = asyncio.create_task(tools.run_jsonl(Job('c' * 32, 'httpx', 'example.com'), 'httpx', ['-c', 'import time; time.sleep(60)']))
    async with asyncio.timeout(5):
        while not children:
            await asyncio.sleep(.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert children[0].returncode is not None


@pytest.mark.asyncio
async def test_discovery_excludes_out_of_scope_and_merges_dns(monkeypatch):
    calls = []
    async def public(target):
        if target == 'private.example.com':
            raise TargetError('private')
        return target
    async def run(job, name, args, targets=None, emit=True):
        calls.append((name, targets))
        return {
            'subfinder': [{'host': 'app.example.com'}, {'host': 'outside.test'}, {'host': 'private.example.com'}],
            'dnsx': [{'host': 'app.example.com', 'a': ['8.8.8.8']}, {'host': 'private.example.com', 'a': ['127.0.0.1']}],
            'httpx': [{'url': 'https://app.example.com', 'status_code': 200, 'title': 'Application'}],
        }[name]
    monkeypatch.setattr(external, 'public_target', public)
    monkeypatch.setattr(external, 'run_jsonl', run)
    job = Job('d' * 32, 'discovery', 'example.com')
    await external.discovery(job)
    assert 'outside.test' not in calls[1][1]
    assert calls[2][1] == ['app.example.com']
    finding = next(e.data for e in job.events if e.kind == 'finding')
    assert finding['addresses'] == ['8.8.8.8']
    assert finding['status'] == 200
    assert finding['source'] == 'discovery'


def test_httpx_binary_does_not_fall_back_to_python_cli(monkeypatch, tmp_path):
    monkeypatch.setattr(tools, 'settings', replace(tools.settings, tools_dir=str(tmp_path)))
    seen = []
    monkeypatch.setattr(tools.shutil, 'which', lambda name: seen.append(name))
    assert tools.executable('httpx') is None
    assert seen == ['pd-httpx']


@pytest.mark.asyncio
async def test_version_probe_is_shared_and_disables_updates(monkeypatch):
    tools._cache.clear()
    monkeypatch.setattr(tools, 'executable', lambda _: 'test-nuclei')
    calls = []
    class Process:
        returncode = 0
        async def communicate(self):
            await asyncio.sleep(.02)
            return b'Current Version: v3.11.1', None
    async def spawn(*args, **kwargs):
        calls.append(args)
        return Process()
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', spawn)
    results = await asyncio.gather(*(tools.inspect_tool('nuclei') for _ in range(5)))
    assert calls == [('test-nuclei', '-version', '-duc')]
    assert all(row['available'] and row['version'] == '3.11.1' for row in results)
    await tools.inspect_tool('nuclei')
    assert len(calls) == 1
    tools._cache.clear()


@pytest.mark.asyncio
async def test_duplicate_observations_emit_once(monkeypatch, tmp_path):
    monkeypatch.setattr(tools, 'executable', lambda _: sys.executable)
    monkeypatch.setattr(tools, 'settings', replace(tools.settings, database_path=str(tmp_path / 'db.sqlite')))
    job = Job('e' * 32, 'naabu', 'example.com')
    code = "import json; [print(json.dumps({'ip':'127.0.0.1','port':8080,'timestamp':i})) for i in range(2)]"
    records = await tools.run_jsonl(job, 'naabu', ['-c', code])
    assert len(records) == 1
    assert len([e for e in job.events if e.kind == 'finding']) == 1
