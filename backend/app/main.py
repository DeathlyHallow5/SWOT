"""SWOT API: start scans as jobs and stream their results over SSE."""
from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import scanners
from .config import settings
from .jobs import Job, manager

app = FastAPI(title="SWOT API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    scanner: str = Field(..., description="registered scanner name")
    target: str = Field(..., min_length=1, max_length=255)


class ScanAccepted(BaseModel):
    job_id: str
    scanner: str
    target: str


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/scanners")
async def list_scanners() -> list[dict[str, str]]:
    return scanners.catalog()


@app.post("/api/scans", status_code=202, response_model=ScanAccepted)
async def start_scan(req: ScanRequest) -> ScanAccepted:
    scanner = scanners.get(req.scanner)
    if scanner is None:
        raise HTTPException(404, f"unknown scanner: {req.scanner}")
    try:
        target = scanner.validate(req.target)
    except scanners.TargetError as exc:
        raise HTTPException(422, str(exc)) from exc

    job = await manager.submit(scanner.name, target, scanner.run)
    return ScanAccepted(job_id=job.id, scanner=job.scanner, target=job.target)


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


@app.get("/api/scans/{job_id}/events")
async def scan_events(job_id: str) -> StreamingResponse:
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(404, "job not found")

    async def generator() -> AsyncIterator[str]:
        yield _sse("hello", {"job_id": job.id, "status": job.status.value})
        async for event in manager.stream(job):
            yield _sse("event", event.as_dict())
        yield _sse(
            "end",
            {"job_id": job.id, "status": job.status.value, "error": job.error},
        )

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/scans/{job_id}")
async def scan_status(job_id: str) -> dict:
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    return {
        "job_id": job.id,
        "scanner": job.scanner,
        "target": job.target,
        "status": job.status.value,
        "error": job.error,
        "events": [e.as_dict() for e in job.events],
    }


@app.post("/api/scans/{job_id}/cancel", status_code=202)
async def cancel_scan(job_id: str) -> dict[str, bool]:
    ok = await manager.cancel(job_id)
    if not ok:
        raise HTTPException(409, "job is not cancellable")
    return {"cancelled": True}
