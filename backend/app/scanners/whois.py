"""WHOIS lookup over TCP port 43, in pure Python.

Replaces the original `shell_exec("whois $domain")` — the biggest hole in the
legacy tool, since the domain went into a shell unescaped. Here the target is
a validated hostname and never touches a shell: we query IANA, follow the
referral to the authoritative WHOIS server, and return the raw record.
"""
from __future__ import annotations

import asyncio
import re

from .base import validate_hostname

name = "whois"
title = "WHOIS"
description = "Look up domain registration details over WHOIS (port 43)."
validate = validate_hostname

_IANA = "whois.iana.org"
_PORT = 43
_REFERRAL_RE = re.compile(r"refer:\s*(\S+)", re.IGNORECASE)
_WHOIS_SERVER_RE = re.compile(r"whois server:\s*(\S+)", re.IGNORECASE)


async def _query(server: str, domain: str, timeout: float = 10.0) -> str:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(server, _PORT), timeout
    )
    try:
        writer.write(f"{domain}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(-1), timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - close best-effort
            pass
    return data.decode("utf-8", errors="replace")


def _find_referral(text: str) -> str | None:
    for pattern in (_REFERRAL_RE, _WHOIS_SERVER_RE):
        match = pattern.search(text)
        if match:
            return match.group(1).strip().rstrip(".")
    return None


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    domain = job.target
    job.emit("log", level="info", message=f"querying {_IANA} for {domain}")
    root = await _query(_IANA, domain)

    referral = _find_referral(root)
    record = root
    if referral and referral != _IANA:
        job.emit("log", level="info", message=f"referred to {referral}")
        try:
            record = await _query(referral, domain)
        except (asyncio.TimeoutError, OSError) as exc:
            job.emit("log", level="warn", message=f"referral failed: {exc}")

    # Pull a few well-known fields out for a structured finding. Registry
    # records indent their fields, and some keys repeat (name servers, status),
    # so allow leading whitespace and collect every value per key.
    fields: dict[str, str | list[str]] = {}
    for key in ("Registrar", "Creation Date", "Registry Expiry Date",
                "Updated Date", "Domain Status", "Name Server"):
        matches = re.findall(
            rf"^[ \t]*{re.escape(key)}:\s*(.+?)\s*$",
            record,
            re.IGNORECASE | re.MULTILINE,
        )
        if not matches:
            continue
        unique = list(dict.fromkeys(m.strip() for m in matches))
        fields[key] = unique if len(unique) > 1 else unique[0]

    job.emit("finding", domain=domain, fields=fields, raw=record.strip()[:4000])
    job.emit("log", level="info", message="whois complete")
