"""Check whether a domain appears in infostealer-log / leak corpora.

Defensive exposure check (like a breach monitor): queries a threat-intel
provider for accounts tied to the domain that surfaced in stealer logs. Needs a
provider key; without one it returns a clear, non-failing "token required"
result. Counts and sources are reported; raw credentials are never displayed.
"""
from __future__ import annotations

from ._intel import configured, get_json, key_for, needs_key
from .base import validate_hostname

name = "stealer_check"
title = "Stealer-Log Exposure"
description = "Check if a domain's accounts appear in infostealer-log leaks."
validate = validate_hostname


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    domain = job.target
    if not configured("leakcheck") and not configured("intelx"):
        needs_key(job, "leakcheck", "Intelligence X is also supported.")
        job.emit("log", level="info", message="no stealer-intel provider configured")
        return

    total = 0
    if configured("leakcheck"):
        job.emit("log", level="info", message="querying LeakCheck")
        status, data = await get_json(
            "https://leakcheck.io/api/v2/query/" + domain,
            headers={"X-API-Key": key_for("leakcheck"), "Accept": "application/json"},
            params={"type": "domain"},
        )
        if status == 200 and isinstance(data, dict):
            for row in (data.get("result") or [])[:100]:
                total += 1
                # Report metadata only — not the leaked values themselves.
                job.emit("finding", provider="LeakCheck", username=row.get("username") or row.get("email"),
                         sources=row.get("sources") or row.get("source"), fields=row.get("fields"),
                         last_seen=row.get("last_breach") or row.get("date"))
        elif status in (401, 403):
            job.emit("log", level="error", message="LeakCheck rejected the API key")
        elif status == 404:
            job.emit("log", level="info", message="LeakCheck: no records for this domain")

    if configured("intelx"):
        job.emit("log", level="info", message="querying Intelligence X")
        status, data = await get_json(
            "https://2.intelx.io/intelligent/search",
            headers={"x-key": key_for("intelx")}, params={"term": domain},
        )
        if status == 200 and isinstance(data, dict) and data.get("id"):
            job.emit("finding", provider="Intelligence X", search_id=data["id"],
                     note="Search submitted; retrieve records in the Intelligence X console.")

    job.emit("log", level="info", message=f"done — {total} stealer-log record group(s)")
