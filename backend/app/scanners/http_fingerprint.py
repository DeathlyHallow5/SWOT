"""Fingerprint a web host from its response, replacing the `whatweb` call.

Fetches the URL once and reports the server, framework hints, security
headers and page title. Pure Python via httpx; no external tool or shell.
"""
from __future__ import annotations

import re

from ._http import client
from .base import validate_http_url

name = "http_fingerprint"
title = "HTTP Fingerprint"
description = "Identify server, framework and security headers of a web host."
validate = validate_http_url

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]
# Simple header/cookie signatures -> technology name.
_SIGNATURES = {
    "x-powered-by": "declared via X-Powered-By",
    "x-aspnet-version": "ASP.NET",
    "x-drupal-cache": "Drupal",
    "x-generator": "declared via X-Generator",
}


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    url = job.target
    job.emit("log", level="info", message=f"fetching {url}")

    async with client(follow_redirects=True) as http:
        resp = await http.get(url)

    headers = {k.lower(): v for k, v in resp.headers.items()}
    title_match = _TITLE_RE.search(resp.text[:20000]) if resp.text else None
    title = title_match.group(1).strip() if title_match else None

    tech: list[str] = []
    for header, label in _SIGNATURES.items():
        if header in headers:
            tech.append(f"{label}: {headers[header]}")

    present_sec = [h for h in _SECURITY_HEADERS if h in headers]
    missing_sec = [h for h in _SECURITY_HEADERS if h not in headers]

    job.emit(
        "finding",
        final_url=str(resp.url),
        status=resp.status_code,
        server=headers.get("server"),
        powered_by=headers.get("x-powered-by"),
        title=title[:200] if title else None,
        technologies=tech,
        security_headers_present=present_sec,
        security_headers_missing=missing_sec,
    )
    job.emit("log", level="info", message="fingerprint complete")
