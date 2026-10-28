"""Optional ZAP worker adapter (no Docker socket is exposed to the API)."""
from __future__ import annotations
import asyncio
import httpx
from ..config import settings
from .base import validate_http_url
from ._scope import public_target

name = "zap"
title = "OWASP ZAP Baseline"
description = "Crawl a website and run passive response checks with the optional ZAP worker."
validate = validate_http_url


async def run(job):
    if not settings.zap_url:
        raise RuntimeError("ZAP is not configured. Start Docker Compose with --profile zap.")
    await public_target(job.target)
    base = settings.zap_url.rstrip("/")
    job.emit("log", level="info", message="Starting ZAP baseline crawl and passive checks")
    async with httpx.AsyncClient(timeout=settings.scan_timeout_seconds) as client:
        try:
            response = await client.post(base + "/scan", json={"id": job.id, "target": job.target})
            if response.status_code != 200:
                raise RuntimeError(f"ZAP worker failed: {response.text[:500]}")
            report = response.json()
            for site in report.get("site", []):
                for alert in site.get("alerts", []):
                    job.emit("finding", source="zap", title=alert.get("name") or alert.get("alert"),
                             severity={"0": "info", "1": "low", "2": "medium", "3": "high"}.get(str(alert.get("riskcode")), "info"),
                             url=site.get("@name"), description=alert.get("desc"), evidence=alert)
            job.emit("log", level="info", message="ZAP baseline completed")
        except asyncio.CancelledError:
            try:
                await asyncio.shield(client.post(base + "/cancel/" + job.id, timeout=5))
            except httpx.HTTPError:
                pass
            raise
