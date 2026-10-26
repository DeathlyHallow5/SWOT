"""Runtime configuration, read from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _csv(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    # CORS origins allowed to call the API (the Next.js dev server by default).
    cors_origins: list[str] = field(
        default_factory=lambda: _csv("SWOT_CORS_ORIGINS", "http://localhost:3000")
    )
    # How long a finished job is kept in memory before cleanup, in seconds.
    job_ttl_seconds: int = int(os.getenv("SWOT_JOB_TTL", "900"))
    # Hard cap on concurrent running jobs, to bound resource use.
    max_concurrent_jobs: int = int(os.getenv("SWOT_MAX_JOBS", "4"))
    # Per-scan wall-clock limit, in seconds.
    scan_timeout_seconds: int = int(os.getenv("SWOT_SCAN_TIMEOUT", "120"))


settings = Settings()
