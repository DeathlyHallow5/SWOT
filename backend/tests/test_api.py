from dataclasses import replace
import pytest
from fastapi.testclient import TestClient
from app import main, scanners
from app.jobs import JobManager
from app.scanners.base import Scanner, validate_hostname


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'settings', replace(main.settings, database_path=str(tmp_path / 'test.db')))
    monkeypatch.setattr(main, 'manager', JobManager())
    async def engines():
        return [{'name': 'subfinder', 'available': False}]
    monkeypatch.setattr(main.tools, 'catalog', engines)
    async def run(job):
        job.emit('finding', host='www.example.com')
    monkeypatch.setitem(scanners.REGISTRY, 'fixture', Scanner('fixture', 'Fixture', 'test', validate_hostname, run, 'workflow'))
    with TestClient(main.app) as api:
        yield api


def test_api_history_details_and_resumable_events(client):
    accepted = client.post('/api/scans', json={'scanner': 'fixture', 'target': 'example.com'})
    assert accepted.status_code == 202
    job_id = accepted.json()['job_id']
    stream = client.get(f'/api/scans/{job_id}/events')
    assert 'event: end' in stream.text
    assert 'id: 1' in stream.text
    history = client.get('/api/scans').json()
    assert history[0]['finding_count'] == 1
    assert history[0]['status'] == 'done'
    detail = client.get(f'/api/scans/{job_id}').json()
    assert detail['created_at'] and detail['finished_at']
    resumed = client.get(f'/api/scans/{job_id}/events', headers={'Last-Event-ID': '2'})
    assert 'id: 1\n' not in resumed.text and 'id: 2\n' not in resumed.text
    assert 'id: 3\n' in resumed.text
    assert client.post(f'/api/scans/{job_id}/cancel').status_code == 409


def test_missing_engine_and_invalid_targets_are_clear_errors(client):
    assert client.post('/api/scans', json={'scanner': 'subfinder', 'target': 'example.com'}).status_code == 503
    assert client.post('/api/scans', json={'scanner': 'missing', 'target': 'example.com'}).status_code == 404
    assert client.post('/api/scans', json={'scanner': 'fixture', 'target': 'example.com; whoami'}).status_code == 422
    assert client.get('/api/scans?limit=9999').status_code == 422
    assert client.get('/api/scans/' + '0' * 32).status_code == 404
