"""Shared logic for path-discovery scanners (directories, API endpoints).

Requests each path from a wordlist against a validated base URL and reports
every path whose status is "interesting" (not a plain 404/connection error).
Redirects are not followed, so 301/302/401/403 are reported as findings too,
which the legacy 200-only check missed.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from ._http import client, probe

_DATA = Path(__file__).resolve().parent.parent / "data"
_CONCURRENCY = 24
# Statuses worth surfacing: found, redirected, or access-controlled.
_INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}


def load_wordlist(filename: str) -> list[str]:
    path = _DATA / filename
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


async def sweep(job, wordlist: str) -> None:  # noqa: ANN001 - Job
    base = job.target.rstrip("/")
    paths = load_wordlist(wordlist)
    total = len(paths)
    job.emit("log", level="info", message=f"checking {total} paths on {base}")

    semaphore = asyncio.Semaphore(_CONCURRENCY)
    done = 0
    hits = 0

    async with client(follow_redirects=False) as http:

        async def check(path: str) -> None:
            nonlocal done, hits
            status = await probe(http, base + path, semaphore)
            done += 1
            if status in _INTERESTING:
                hits += 1
                job.emit("finding", path=path, status=status)
            if done % 10 == 0 or done == total:
                job.emit("progress", done=done, total=total)

        await asyncio.gather(*(check(p) for p in paths))

    job.emit("log", level="info", message=f"done — {hits} interesting path(s)")
