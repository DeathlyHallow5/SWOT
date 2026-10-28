"""Identify the technologies, libraries and versions a site is built from.

Fetches the page once and inspects response headers, cookies, the generator
meta tag, inline framework markers and the versions embedded in script/style
URLs. Pure Python; reports each detection with the evidence it came from.
"""
from __future__ import annotations

import re

from ._http import client
from .base import validate_http_url

name = "tech_stack"
title = "Technology Stack"
description = "Detect server software, frameworks, JS libraries and versions."
validate = validate_http_url

# Signatures matched against a response header's value. key -> (tech, category)
_HEADER_TECH = {
    "x-powered-by": ("{value}", "runtime"),
    "x-aspnet-version": ("ASP.NET {value}", "framework"),
    "x-drupal-dynamic-cache": ("Drupal", "cms"),
    "x-generator": ("{value}", "generator"),
    "x-shopify-stage": ("Shopify", "platform"),
    "x-wix-request-id": ("Wix", "platform"),
}
# Cookie name substrings -> technology.
_COOKIE_TECH = {
    "phpsessid": ("PHP", "runtime"),
    "wordpress_": ("WordPress", "cms"),
    "wp-settings": ("WordPress", "cms"),
    "laravel_session": ("Laravel", "framework"),
    "ci_session": ("CodeIgniter", "framework"),
    "jsessionid": ("Java (Servlet)", "runtime"),
    "csrftoken": ("Django", "framework"),
    "django": ("Django", "framework"),
    "_shopify": ("Shopify", "platform"),
    "ASP.NET_SessionId".lower(): ("ASP.NET", "framework"),
}
# Inline HTML markers -> technology (value captured as version when a group).
_HTML_MARKERS = [
    (re.compile(r"__NEXT_DATA__"), "Next.js", "framework", None),
    (re.compile(r'id="__nuxt"|window\.__NUXT__'), "Nuxt.js", "framework", None),
    (re.compile(r"data-reactroot|__REACT_DEVTOOLS"), "React", "library", None),
    (re.compile(r'ng-version="([\d.]+)"'), "Angular", "framework", 1),
    (re.compile(r'<meta[^>]+name="generator"[^>]+content="([^"]+)"', re.I), "{group}", "generator", 1),
    (re.compile(r"/wp-content/|/wp-includes/"), "WordPress", "cms", None),
    (re.compile(r"Drupal\.settings|/sites/default/files/"), "Drupal", "cms", None),
    (re.compile(r"cdn\.shopify\.com|Shopify\.theme"), "Shopify", "platform", None),
    (re.compile(r"window\.Vue|__VUE__"), "Vue.js", "library", None),
]
# Library name + version pulled from script/style URLs.
_ASSET_LIB = re.compile(
    r"(?P<lib>jquery|bootstrap|react|react-dom|vue|angular|angularjs|lodash|"
    r"d3|moment|axios|three|gsap|swiper|alpine|htmx|tailwind|font-?awesome|"
    r"popper|underscore|backbone|ember|preact|svelte)"
    r"[-@/](?P<ver>\d+\.\d+(?:\.\d+)?)",
    re.I,
)
_SRC_RE = re.compile(r"""<(?:script|link)[^>]+(?:src|href)=["']([^"']+)["']""", re.I)


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    url = job.target
    job.emit("log", level="info", message=f"fetching {url}")
    async with client(follow_redirects=True) as http:
        resp = await http.get(url)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text[:200_000] if resp.text else ""

    found: dict[str, dict] = {}

    def add(tech: str, category: str, version: str | None, evidence: str) -> None:
        if not tech:
            return
        key = tech.lower()
        prev = found.get(key)
        if prev is None or (version and not prev.get("version")):
            found[key] = {"technology": tech, "category": category,
                          "version": version, "evidence": evidence}

    if server := headers.get("server"):
        # Server banners often carry a version, e.g. "nginx/1.25.3".
        m = re.search(r"([A-Za-z][\w\- ]*?)(?:/([\d.]+))?$", server.strip())
        add(server.split("/")[0], "server", (m.group(2) if m else None), f"Server: {server}")
    for header, (tpl, cat) in _HEADER_TECH.items():
        if header in headers:
            add(tpl.replace("{value}", headers[header]), cat, None, f"{header}: {headers[header]}")
    cookies = headers.get("set-cookie", "").lower()
    for needle, (tech, cat) in _COOKIE_TECH.items():
        if needle.lower() in cookies:
            add(tech, cat, None, "Set-Cookie signature")
    for pattern, tech, cat, grp in _HTML_MARKERS:
        if match := pattern.search(body):
            version = match.group(grp) if grp else None
            label = tech.replace("{group}", match.group(1)) if "{group}" in tech else tech
            add(label, cat, version, "inline page marker")
    for asset in _SRC_RE.findall(body):
        if m := _ASSET_LIB.search(asset):
            lib = m.group("lib").lower().replace("fontawesome", "font-awesome")
            add(lib, "library", m.group("ver"), f"asset: {asset[:120]}")

    for item in sorted(found.values(), key=lambda d: d["technology"].lower()):
        job.emit("finding", **item)
    job.emit("log", level="info", message=f"detected {len(found)} technologies")
