"""Resolve a wordlist of candidate subdomains against a domain via DNS.

Pure Python using the resolver in the standard library, run concurrently in a
thread pool. Replaces the original per-host `nslookup` shell loop. Each name
that resolves is reported as a finding as soon as it is confirmed, so the UI
fills in live.
"""
from __future__ import annotations

import asyncio
import socket
from pathlib import Path

from .base import validate_hostname

name = "dns_subdomains"
title = "Subdomain Discovery"
description = "Resolve common subdomain names against a domain over DNS."
validate = validate_hostname

_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "subdomains.txt"
# Cap concurrent resolver threads so a scan does not exhaust the pool.
_CONCURRENCY = 32


def _load_words() -> list[str]:
    try:
        lines = _WORDLIST.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return ["www", "mail", "api", "dev", "admin", "shop"]
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def _resolve(fqdn: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(fqdn, None)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    domain = job.target
    words = _load_words()
    total = len(words)
    job.emit("log", level="info", message=f"resolving {total} candidate subdomains")

    semaphore = asyncio.Semaphore(_CONCURRENCY)
    done = 0

    async def check(word: str) -> None:
        nonlocal done
        fqdn = f"{word}.{domain}"
        async with semaphore:
            addresses = await asyncio.to_thread(_resolve, fqdn)
        done += 1
        if addresses:
            job.emit("finding", host=fqdn, addresses=addresses)
        if done % 25 == 0 or done == total:
            job.emit("progress", done=done, total=total)

    await asyncio.gather(*(check(word) for word in words))
    job.emit("log", level="info", message="subdomain sweep complete")
