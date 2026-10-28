"""Search for exposed secrets related to a target.

Two sources:
  1. The site's own inline and linked JavaScript, scanned for secret-shaped
     patterns (pure Python, only the target is fetched).
  2. GitHub public code search for the domain (optional token raises limits).
Secrets are redacted in findings — only a short prefix is shown as evidence.
For authorized review of your own exposure.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

from ._http import client
from ._intel import configured, get_json, key_for, needs_key, redact
from ._scope import public_target
from ..config import settings
from .base import validate_hostname

name = "secret_search"
title = "Secret Exposure"
description = "Scan a site's JavaScript and public code for leaked secrets."
validate = validate_hostname

# name -> compiled pattern. Kept conservative to limit false positives.
_PATTERNS = {
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    "GitHub token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"),
    "Stripe key": re.compile(r"sk_live_[0-9A-Za-z]{24}"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Generic API key assignment": re.compile(r"""(?i)(?:api[_-]?key|secret|token|passwd|password)["'\s:=]{1,4}["']([A-Za-z0-9\-_]{16,64})["']"""),
}
_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
_INLINE_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)


def _scan(text: str, location: str) -> list[dict]:
    out = []
    for label, pattern in _PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            out.append({"type": label, "location": location, "evidence": redact(value), "source": "site-js"})
            if len(out) >= 25:
                return out
    return out


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    domain = job.target
    await public_target(domain)  # SSRF guard: the site is fetched directly
    url = f"https://{domain}"
    job.emit("log", level="info", message=f"scanning JavaScript on {url}")
    findings = 0

    async with client(follow_redirects=True) as http:
        try:
            page = await http.get(url)
            html = page.text or ""
        except Exception as exc:  # noqa: BLE001
            job.emit("log", level="warn", message=f"could not fetch {url}: {exc}")
            html = ""

        for hit in _scan(html, url):
            findings += 1
            job.emit("finding", **hit)

        scripts = [urljoin(str(page.url), s) for s in _SRC_RE.findall(html)][: settings.max_intel_lookups] if html else []
        sem = asyncio.Semaphore(8)

        async def scan_script(src: str) -> None:
            nonlocal findings
            async with sem:
                try:
                    resp = await http.get(src)
                except Exception:  # noqa: BLE001
                    return
            for hit in _scan(resp.text or "", src[:140]):
                findings += 1
                job.emit("finding", **hit)

        await asyncio.gather(*(scan_script(s) for s in scripts))

    await _github(job, domain)
    job.emit("log", level="info", message=f"done — {findings} potential secret(s) in site assets")


async def _github(job, domain: str) -> None:  # noqa: ANN001
    headers = {"Accept": "application/vnd.github.text-match+json"}
    if configured("github"):
        headers["Authorization"] = f"Bearer {key_for('github')}"
    else:
        needs_key(job, "github", "Unauthenticated GitHub search is heavily rate-limited.")
    query = f'"{domain}" (password OR secret OR api_key OR token)'
    status, data = await get_json("https://api.github.com/search/code",
                                  headers=headers, params={"q": query, "per_page": 10})
    if status == 200 and isinstance(data, dict):
        for item in data.get("items", [])[:10]:
            repo = (item.get("repository") or {}).get("full_name")
            job.emit("finding", type="GitHub code match", location=item.get("html_url"),
                     evidence=f"{repo}/{item.get('path')}", source="github")
    elif status == 403:
        job.emit("log", level="warn", message="GitHub search rate-limited (configure SWOT_GITHUB_TOKEN)")
