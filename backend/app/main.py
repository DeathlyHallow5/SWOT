"""SWOT API: persistent scans, engine inventory and resumable SSE."""
from __future__ import annotations
import json
from contextlib import asynccontextmanager
from typing import AsyncIterator
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import scanners, tools
from .config import settings
from .jobs import manager
from .scanners._scope import in_scope, public_target


@asynccontextmanager
async def lifespan(app):
    manager.start_store(settings.database_path)
    yield
    await manager.shutdown()


app = FastAPI(title="SWOT API", version="2.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type", "Last-Event-ID"])


class ScanRequest(BaseModel):
    scanner: str = Field(..., min_length=1, max_length=64)
    target: str = Field(..., min_length=1, max_length=255)


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "version": "2.1.0"}


@app.get("/api/tools")
async def list_tools() -> list[dict]:
    return await tools.catalog()


@app.get("/api/scanners")
async def list_scanners() -> list[dict]:
    engines = await tools.catalog()
    return scanners.catalog({engine["name"]: engine["available"] for engine in engines})


@app.get("/api/scans")
async def list_scans(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)) -> list[dict]:
    return manager.list(limit, offset)


@app.post("/api/scans", status_code=202)
async def start_scan(req: ScanRequest) -> dict:
    scanner = scanners.get(req.scanner)
    if scanner is None:
        raise HTTPException(404, f"Unknown scanner: {req.scanner}")
    try:
        target = scanner.validate(req.target)
    except scanners.TargetError as exc:
        raise HTTPException(422, str(exc)) from exc
    hostname = urlparse(target).hostname if "://" in target else target
    if settings.allowed_domains and not any(in_scope(hostname, d) for d in settings.allowed_domains):
        raise HTTPException(422, "Target is outside SWOT_ALLOWED_DOMAINS")
    if scanner.requires:
        engines = {tool["name"]: tool["available"] for tool in await tools.catalog()}
        missing = [name for name in scanner.requires if not engines.get(name)]
        if missing:
            raise HTTPException(503, "Unavailable engines: " + ", ".join(missing) + ". Check Tools & engines or start Docker Compose.")

    async def guarded_runner(job):
        if scanner.category == "builtin" and scanner.name not in ("dns_subdomains", "whois", "wayback"):
            await public_target(target)
        await scanner.run(job)

    try:
        job = await manager.submit(scanner.name, target, guarded_runner)
    except RuntimeError as exc:
        raise HTTPException(429, str(exc)) from exc
    return {"job_id": job.id, "scanner": job.scanner, "target": job.target}


def _sse(event: str, payload: dict, seq: int | None = None) -> str:
    prefix = f"id: {seq}\n" if seq is not None else ""
    return prefix + f"event: {event}\ndata: {json.dumps(payload)}\n\n"


@app.get("/api/scans/{job_id}/events")
async def scan_events(job_id: str, last_event_id: str | None = Header(None)) -> StreamingResponse:
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(404, "Scan not found")
    try:
        after = max(0, int(last_event_id or "0"))
    except ValueError:
        raise HTTPException(422, "Invalid Last-Event-ID")

    async def generator() -> AsyncIterator[str]:
        yield _sse("hello", {"job_id": job.id, "status": job.status.value})
        async for event in manager.stream(job, after=after):
            yield _sse("event", event.as_dict(), event.seq) if event else ": heartbeat\n\n"
        if job.is_terminal():
            yield _sse("end", {"job_id": job.id, "status": job.status.value, "error": job.error})

    return StreamingResponse(generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"})


@app.get("/api/scans/{job_id}")
async def scan_status(job_id: str) -> dict:
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(404, "Scan not found")
    return job.detail()


@app.post("/api/scans/{job_id}/cancel", status_code=202)
async def cancel_scan(job_id: str) -> dict:
    if not await manager.cancel(job_id):
        raise HTTPException(409, "Scan is not cancellable")
    return {"cancelled": True}
