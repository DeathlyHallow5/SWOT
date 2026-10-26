"""Discover exposed API endpoints on a web host."""
from __future__ import annotations

from ._pathsweep import sweep
from .base import validate_http_url

name = "api_endpoints"
title = "API Endpoint Finder"
description = "Probe a web host for common API and framework endpoints."
validate = validate_http_url


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    await sweep(job, "api_endpoints.txt")
