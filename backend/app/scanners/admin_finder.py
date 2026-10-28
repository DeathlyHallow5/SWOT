"""Locate administrative / login panels on a web host.

Reuses the shared path sweep with an admin-focused wordlist. Reports every
path whose response is interesting (200/301/302/401/403), so access-controlled
panels are surfaced, not only openly reachable ones.
"""
from __future__ import annotations

from ._pathsweep import sweep
from .base import validate_http_url

name = "admin_finder"
title = "Admin Panel Finder"
description = "Probe a web host for administrative and login panels."
validate = validate_http_url


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    await sweep(job, "admin_paths.txt")
