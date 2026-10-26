"""Discover interesting directories/files on a web host."""
from __future__ import annotations

from ._pathsweep import sweep
from .base import validate_http_url

name = "directories"
title = "Directory Check"
description = "Probe a web host for common sensitive directories and files."
validate = validate_http_url


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    await sweep(job, "directories.txt")
