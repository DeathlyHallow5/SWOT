"""Shared async HTTP helpers for the HTTP-based scanners.

One place to configure timeouts, redirect policy and a bounded concurrency
gate, so every scanner behaves consistently and politely.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx

# A neutral UA; scanners announce themselves rather than spoofing a browser.
USER_AGENT = "SWOT/2.0 (+https://github.com/DeathlyHallow5/SWOT)"

DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


@asynccontextmanager
async def client(follow_redirects: bool = True) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=follow_redirects,
        headers={"User-Agent": USER_AGENT},
        verify=True,
    ) as c:
        yield c


async def probe(
    http: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
) -> int | None:
    """HEAD a URL, falling back to GET; return the status code or None."""
    async with semaphore:
        try:
            resp = await http.head(url)
            if resp.status_code == 405:  # method not allowed -> try GET
                resp = await http.get(url)
            return resp.status_code
        except httpx.HTTPError:
            return None
