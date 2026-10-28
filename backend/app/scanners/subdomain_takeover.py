"""Detect subdomains at risk of takeover (dangling CNAMEs).

For each candidate subdomain it reads the CNAME chain; when the target points
at a takeover-prone third-party service it fetches the host and matches the
service's "unclaimed resource" signature. Detection only — nothing is ever
claimed. Pure Python (minimal DNS + HTTP).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from ._dns import cname_chain, resolve
from ._http import client
from .base import validate_hostname

name = "subdomain_takeover"
title = "Subdomain Takeover"
description = "Find dangling CNAMEs pointing at unclaimed third-party services."
validate = validate_hostname

_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "subdomains.txt"
_CONCURRENCY = 16

# service -> (cname substrings, unclaimed-response signatures)
_FINGERPRINTS: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = [
    ("GitHub Pages", ("github.io",), ("There isn't a GitHub Pages site here",)),
    ("AWS S3", ("s3.amazonaws.com", "s3-website", "s3.", ".s3-"), ("NoSuchBucket", "The specified bucket does not exist")),
    ("Heroku", ("herokuapp.com", "herokudns.com"), ("No such app", "herokucdn.com/error-pages/no-such-app.html")),
    ("Microsoft Azure", ("azurewebsites.net", "cloudapp.net", "trafficmanager.net", "azureedge.net"), ("404 Web Site not found",)),
    ("Fastly", ("fastly.net",), ("Fastly error: unknown domain",)),
    ("Shopify", ("myshopify.com",), ("Sorry, this shop is currently unavailable",)),
    ("Surge.sh", ("surge.sh",), ("project not found",)),
    ("Bitbucket", ("bitbucket.io",), ("Repository not found",)),
    ("Read the Docs", ("readthedocs.io",), ("unknown to Read the Docs",)),
    ("Pantheon", ("pantheonsite.io",), ("The gods are wise",)),
    ("Tumblr", ("domains.tumblr.com",), ("Whatever you were looking for doesn't currently exist",)),
    ("Zendesk", ("zendesk.com",), ("Help Center Closed",)),
    ("Unbounce", ("unbouncepages.com",), ("The requested URL was not found on this server",)),
    ("Cargo", ("cargocollective.com",), ("404 Not Found",)),
]


def _load_words() -> list[str]:
    try:
        lines = _WORDLIST.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return ["www", "mail", "dev", "test", "staging", "api", "blog", "cdn", "assets"]
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


def _service_for(cname: str) -> tuple[str, tuple[str, ...]] | None:
    low = cname.lower()
    for service, patterns, signatures in _FINGERPRINTS:
        if any(p in low for p in patterns):
            return service, signatures
    return None


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    domain = job.target
    words = _load_words()
    candidates = [domain, *[f"{w}.{domain}" for w in words]]
    total = len(candidates)
    job.emit("log", level="info", message=f"checking {total} hosts for dangling CNAMEs")

    semaphore = asyncio.Semaphore(_CONCURRENCY)
    done = 0
    flagged = 0

    async def check(host: str) -> None:
        nonlocal done, flagged
        async with semaphore:
            cnames = await cname_chain(host)
            match = next((m for c in cnames if (m := _service_for(c))), None)
            if match:
                service, signatures = match
                resolves = bool(await resolve(host, "A"))
                vulnerable, evidence = await _confirm(host, signatures)
                if vulnerable or not resolves:
                    flagged += 1
                    job.emit(
                        "finding",
                        host=host,
                        service=service,
                        cname=cnames,
                        risk="high" if vulnerable else "medium",
                        status="vulnerable" if vulnerable else "dangling",
                        detail=evidence or ("CNAME target does not resolve (A record missing)"),
                    )
        done += 1
        if done % 10 == 0 or done == total:
            job.emit("progress", done=done, total=total)

    await asyncio.gather(*(check(h) for h in candidates))
    job.emit("log", level="info", message=f"done — {flagged} host(s) need review")


async def _confirm(host: str, signatures: tuple[str, ...]) -> tuple[bool, str | None]:
    async with client(follow_redirects=True) as http:
        for scheme in ("https", "http"):
            try:
                resp = await http.get(f"{scheme}://{host}")
            except Exception:  # noqa: BLE001 - connection errors are expected here
                continue
            text = resp.text or ""
            for sig in signatures:
                if sig.lower() in text.lower():
                    return True, f"matched signature: {sig[:60]}"
            return False, None
    return False, None
