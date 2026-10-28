"""Check a domain against known database-breach corpora.

Free path: Have I Been Pwned's public breach catalogue, filtered to breaches of
the target site itself (no key needed). Optional path: with an HIBP key, list
the breached accounts under a domain you control. Account values are never
shown — only breach names, dates and sizes.
"""
from __future__ import annotations

from ._http import USER_AGENT
from ._intel import configured, get_json, key_for, needs_key
from .base import validate_hostname

name = "db_leak"
title = "Database Leak Check"
description = "Check a domain against known breach databases (HIBP)."
validate = validate_hostname


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    domain = job.target
    job.emit("log", level="info", message="querying Have I Been Pwned breach catalogue")

    # Public: breaches of this site/domain itself. No key required.
    status, data = await get_json(
        "https://haveibeenpwned.com/api/v3/breaches",
        headers={"User-Agent": USER_AGENT}, params={"domain": domain},
    )
    found = 0
    if status == 200 and isinstance(data, list):
        for breach in data:
            found += 1
            job.emit("finding", breach=breach.get("Name"), title=breach.get("Title"),
                     breach_date=breach.get("BreachDate"), pwned_accounts=breach.get("PwnCount"),
                     data_classes=breach.get("DataClasses", []), verified=breach.get("IsVerified"))
    elif status != 200:
        job.emit("log", level="warn", message=f"HIBP breach catalogue returned HTTP {status}")

    if found == 0:
        job.emit("finding", status="clean", message=f"No catalogued breach is attributed to {domain}.")

    # Authenticated: accounts under a domain you control (requires HIBP key).
    if configured("hibp"):
        job.emit("log", level="info", message="querying breached accounts for the domain")
        status, data = await get_json(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            headers={"hibp-api-key": key_for("hibp"), "User-Agent": USER_AGENT},
        )
        if status == 200 and isinstance(data, dict):
            for alias, breaches in list(data.items())[:200]:
                job.emit("finding", account=f"{alias}@{domain}", breaches=breaches, source="hibp-domain")
        elif status in (401, 403):
            job.emit("log", level="error", message="HIBP rejected the API key or domain is unverified")
    else:
        needs_key(job, "hibp", "The public breach catalogue above needs no key.")

    job.emit("log", level="info", message=f"done — {found} known breach(es) for {domain}")
