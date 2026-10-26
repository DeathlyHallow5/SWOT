"""List URLs the Wayback Machine has archived for a domain.

Queries the Internet Archive CDX API (not the target itself), so the target
is a validated hostname used only as a query parameter.
"""
from __future__ import annotations

from ._http import client
from .base import validate_hostname

name = "wayback"
title = "Wayback URLs"
description = "List archived URLs for a domain from the Internet Archive."
validate = validate_hostname

_CDX = "https://web.archive.org/cdx/search/cdx"
_LIMIT = 500


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    domain = job.target
    job.emit("log", level="info", message=f"querying Wayback CDX for {domain}")

    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(_LIMIT),
    }
    async with client() as http:
        resp = await http.get(_CDX, params=params)
        resp.raise_for_status()
        rows = resp.json()

    # First row is the header (["original"]); the rest are URL tuples.
    urls = [row[0] for row in rows[1:]] if isinstance(rows, list) and rows else []
    job.emit("finding", domain=domain, count=len(urls), urls=urls)
    job.emit(
        "log",
        level="info",
        message=f"found {len(urls)} archived URL(s)"
        + (f" (capped at {_LIMIT})" if len(urls) >= _LIMIT else ""),
    )
