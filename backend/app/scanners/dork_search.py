"""Generate search-engine dork queries for a target, and optionally run them.

Produces ready-to-open dork URLs across Google, GitHub, Shodan and paste sites
for exposed files, panels and leaks. When a Google Programmable Search key is
configured, a subset is executed through the official API — no HTML scraping
and no CAPTCHA handling.
"""
from __future__ import annotations

from urllib.parse import quote_plus

from ._intel import configured, get_json, needs_key
from ..config import settings
from .base import validate_hostname

name = "dork_search"
title = "Dork Search"
description = "Build (and optionally run) search-engine dorks for exposed assets."
validate = validate_hostname

# (category, query template). {d} is replaced with the domain.
_DORKS = [
    ("Exposed files", 'site:{d} (ext:sql OR ext:env OR ext:log OR ext:bak OR ext:old OR ext:config)'),
    ("Directory listing", 'site:{d} intitle:"index of"'),
    ("Login / admin", 'site:{d} inurl:(login OR admin OR dashboard OR signin OR portal)'),
    ("Config & secrets", 'site:{d} (inurl:config OR inurl:.git OR inurl:credentials OR "api_key")'),
    ("Documents", 'site:{d} (ext:pdf OR ext:docx OR ext:xlsx) (confidential OR internal OR private)'),
    ("Open redirects / params", 'site:{d} inurl:(redirect OR url= OR return=)'),
    ("Paste sites", '("{d}") (site:pastebin.com OR site:ghostbin.com OR site:rentry.co)'),
    ("Code hosting", '"{d}" (site:github.com OR site:gitlab.com OR site:bitbucket.org)'),
]


def _links(domain: str, query: str) -> dict:
    enc = quote_plus(query)
    return {
        "google": f"https://www.google.com/search?q={enc}",
        "bing": f"https://www.bing.com/search?q={enc}",
        "duckduckgo": f"https://duckduckgo.com/?q={enc}",
    }


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    domain = job.target
    job.emit("log", level="info", message="generating dork queries")

    for category, template in _DORKS:
        query = template.format(d=domain)
        job.emit("finding", category=category, query=query, links=_links(domain, query), results=None)

    # Direct platform searches that need no engine operators.
    for label, url in (
        ("GitHub code", f"https://github.com/search?q=%22{quote_plus(domain)}%22&type=code"),
        ("Shodan hosts", f"https://www.shodan.io/search?query=hostname%3A{quote_plus(domain)}"),
        ("Censys hosts", f"https://search.censys.io/search?resource=hosts&q={quote_plus(domain)}"),
    ):
        job.emit("finding", category=label, query=domain, links={"open": url}, results=None)

    if configured("google_cse"):
        await _run_cse(job, domain)
    else:
        needs_key(job, "google_cse", "Without it, dorks are generated as links to open manually.")

    job.emit("log", level="info", message="dork generation complete")


async def _run_cse(job, domain: str) -> None:  # noqa: ANN001
    ran = 0
    for category, template in _DORKS:
        if ran >= min(5, settings.max_intel_lookups):
            break
        query = template.format(d=domain)
        status, data = await get_json(
            "https://www.googleapis.com/customsearch/v1",
            params={"key": settings.google_api_key, "cx": settings.google_cse_id, "q": query, "num": 5},
        )
        ran += 1
        if status == 200 and isinstance(data, dict):
            hits = [{"title": it.get("title"), "url": it.get("link")} for it in data.get("items", [])]
            if hits:
                job.emit("finding", category=f"{category} (results)", query=query, links={}, results=hits)
        elif status != 200:
            job.emit("log", level="warn", message=f"Google CSE returned HTTP {status}")
            break
