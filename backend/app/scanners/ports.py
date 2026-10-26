"""TCP connect scan over a curated list of common ports, in pure Python.

Replaces the legacy `nmap -sV -A -Pn` shell call. A plain connect check needs
no external binary, no root and no shell, so it runs the same on any OS. Open
ports are reported live as they are confirmed.

Service-version detection (the `-sV` part of the original) is intentionally
left out of this pure-Python scanner; a separate nmap-backed scanner can be
added where nmap is installed, on this same job contract.
"""
from __future__ import annotations

import asyncio

from .base import validate_host_or_ip

name = "ports"
title = "Port Scan"
description = "Check a host for open TCP ports from a common-services list."
validate = validate_host_or_ip

# Well-known services worth checking first; keeps scans quick and non-abusive.
_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3000: "dev-http", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5672: "amqp", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
_CONCURRENCY = 64
_CONNECT_TIMEOUT = 3.0


async def _is_open(host: str, port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), _CONNECT_TIMEOUT
        )
    except (asyncio.TimeoutError, OSError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001 - close best-effort
        pass
    return True


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    host = job.target
    ports = sorted(_PORTS)
    total = len(ports)
    job.emit("log", level="info", message=f"scanning {total} common ports on {host}")

    semaphore = asyncio.Semaphore(_CONCURRENCY)
    done = 0
    open_count = 0

    async def check(port: int) -> None:
        nonlocal done, open_count
        async with semaphore:
            is_open = await _is_open(host, port)
        done += 1
        if is_open:
            open_count += 1
            job.emit("finding", port=port, service=_PORTS[port], state="open")
        if done == total:
            job.emit("progress", done=done, total=total)

    await asyncio.gather(*(check(p) for p in ports))
    job.emit("log", level="info", message=f"done — {open_count} open port(s)")
