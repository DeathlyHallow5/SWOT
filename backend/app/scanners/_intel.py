"""Shared helpers for the key-ready intelligence scanners.

Each intel scanner may use a third-party provider. Providers are optional:
when a key is absent the scanner still runs and returns a clear, actionable
"token required" finding instead of failing. Keys live only in settings and
are never emitted or logged.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from ..config import settings
from ._http import USER_AGENT


@dataclass(frozen=True)
class Provider:
    name: str  # stable id, also the Tools inventory entry
    title: str
    setting: str  # attribute on settings holding the key
    signup: str  # where to obtain a key
    purpose: str


# Catalogue of providers the intel scanners can use. All optional.
PROVIDERS: dict[str, Provider] = {
    p.name: p
    for p in [
        Provider("github", "GitHub code search", "github_token",
                 "https://github.com/settings/tokens", "Exposed secrets in public code."),
        Provider("shodan", "Shodan", "shodan_key",
                 "https://account.shodan.io", "Origin IPs and exposed services."),
        Provider("securitytrails", "SecurityTrails", "securitytrails_key",
                 "https://securitytrails.com/app/account", "Historical DNS for origin discovery."),
        Provider("hibp", "Have I Been Pwned", "hibp_key",
                 "https://haveibeenpwned.com/API/Key", "Breached accounts for a domain."),
        Provider("leakcheck", "LeakCheck", "leakcheck_key",
                 "https://leakcheck.io/", "Infostealer-log and leak exposure."),
        Provider("intelx", "Intelligence X", "intelx_key",
                 "https://intelx.io/account?tab=developer", "Leak and stealer-log corpora."),
        Provider("google_cse", "Google Programmable Search", "google_api_key",
                 "https://programmablesearchengine.google.com/", "Run dork queries via the official API."),
    ]
}


def key_for(provider: str) -> str:
    prov = PROVIDERS.get(provider)
    return getattr(settings, prov.setting, "") if prov else ""


def configured(provider: str) -> bool:
    if provider == "google_cse":
        return bool(settings.google_api_key and settings.google_cse_id)
    return bool(key_for(provider))


def provider_catalog() -> list[dict]:
    """Entries for the Tools & engines inventory; availability = key present."""
    return [
        {
            "name": f"provider:{p.name}",
            "title": p.title,
            "description": f"{p.purpose} Optional API key.",
            "docs": p.signup,
            "available": configured(p.name),
            "version": "configured" if configured(p.name) else None,
        }
        for p in PROVIDERS.values()
    ]


def needs_key(job, provider: str, extra: str = "") -> None:
    """Emit a clear, non-failing finding when a provider key is missing."""
    prov = PROVIDERS[provider]
    job.emit(
        "finding",
        status="token_required",
        provider=prov.title,
        message=f"Set {_env_name(prov.setting)} to enable {prov.title}."
        + (f" {extra}" if extra else ""),
        signup=prov.signup,
    )
    job.emit("log", level="warn", message=f"{prov.title} API key not configured — skipped")


def _env_name(setting: str) -> str:
    # settings attribute -> the SWOT_* environment variable that feeds it
    special = {"google_api_key": "SWOT_GOOGLE_API_KEY"}
    return special.get(setting, "SWOT_" + setting.upper())


async def get_json(url: str, *, headers: dict | None = None, params: dict | None = None,
                   timeout: float = 15.0):
    """GET and parse JSON, returning (status_code, data|None)."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                 headers={"User-Agent": USER_AGENT, **(headers or {})}) as client:
        resp = await client.get(url, params=params)
        data = None
        try:
            data = resp.json()
        except ValueError:
            data = None
        return resp.status_code, data


def redact(secret: str, keep: int = 4) -> str:
    """Show only the first few characters of a sensitive string."""
    secret = str(secret)
    if len(secret) <= keep:
        return "•" * len(secret)
    return secret[:keep] + "•" * min(8, len(secret) - keep)
