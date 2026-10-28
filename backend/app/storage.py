"""Small SQLite store for scan metadata and ordered events."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path


class JobStore:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                job_id TEXT PRIMARY KEY, scanner TEXT NOT NULL, target TEXT NOT NULL,
                status TEXT NOT NULL, created_at REAL NOT NULL, finished_at REAL,
                error TEXT, finding_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS events (
                job_id TEXT NOT NULL REFERENCES scans(job_id), seq INTEGER NOT NULL,
                kind TEXT NOT NULL, data TEXT NOT NULL, at REAL NOT NULL,
                PRIMARY KEY(job_id, seq)
            );
            CREATE INDEX IF NOT EXISTS scans_created ON scans(created_at DESC);
        """)

    def save(self, job, event=None) -> None:
        with self.db:
            self.db.execute("""INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET status=excluded.status,
                finished_at=excluded.finished_at, error=excluded.error,
                finding_count=excluded.finding_count""",
                (job.id, job.scanner, job.target, job.status.value, job.created_at,
                 job.finished_at, job.error, job.finding_count))
            if event:
                self.db.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?)",
                                (job.id, event.seq, event.kind, json.dumps(event.data), event.at))

    def get(self, job_id: str) -> dict | None:
        row = self.db.execute("SELECT * FROM scans WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["events"] = [dict(r, data=json.loads(r["data"])) for r in self.db.execute(
            "SELECT seq, kind, data, at FROM events WHERE job_id=? ORDER BY seq", (job_id,))]
        return result

    def list(self, limit: int = 100, offset: int = 0) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))]

    def interrupted_ids(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT job_id FROM scans WHERE status IN ('queued','running')")]

    def close(self) -> None:
        self.db.close()
