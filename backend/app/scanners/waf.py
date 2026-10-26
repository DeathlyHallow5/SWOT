"""Lightweight WAF/CDN detection, replacing the `wafw00f` call.

Sends one ordinary request and inspects response headers, cookies and server
banner for well-known WAF/CDN signatures. Pure Python; no external tool. This
is a heuristic fingerprint, not a bypass, and only reads public responses.
"""
from __future__ import annotations

from ._http import client
from .base import validate_http_url

name = "waf"
title = "WAF Detection"
description = "Fingerprint a common WAF or CDN in front of a web host."
validate = validate_http_url

# signature name -> (header or cookie substring to look for, matched against keys/values)
_HEADER_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cf-mitigated"],
    "AWS CloudFront / WAF": ["x-amz-cf-id", "x-amzn-requestid", "awselb"],
    "Akamai": ["akamai", "x-akamai-transformed", "akamaighost"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "sucuri"],
    "Imperva / Incapsula": ["incap_ses", "visid_incap", "x-iinfo", "x-cdn"],
    "F5 BIG-IP": ["bigipserver", "x-wa-info", "ts01"],
    "Fastly": ["x-served-by", "fastly"],
    "Barracuda": ["barra_counter_session", "barracuda"],
    "Wordfence": ["wordfence", "wfvt_"],
}


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    url = job.target
    job.emit("log", level="info", message=f"probing {url} for WAF/CDN signatures")

    async with client(follow_redirects=True) as http:
        resp = await http.get(url)

    haystack = " ".join(
        [str(resp.headers).lower(), resp.headers.get("set-cookie", "").lower()]
    )
    server = resp.headers.get("server", "").lower()
    haystack += " " + server

    detected: list[str] = []
    for waf, needles in _HEADER_SIGNATURES.items():
        if any(needle in haystack for needle in needles):
            detected.append(waf)

    job.emit(
        "finding",
        status=resp.status_code,
        server=resp.headers.get("server"),
        detected=detected or None,
        note="no known WAF/CDN signature matched" if not detected else None,
    )
    job.emit(
        "log",
        level="info",
        message=(
            f"detected: {', '.join(detected)}" if detected else "no signature matched"
        ),
    )
