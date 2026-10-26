"""Read a TLS certificate from a host and report its key fields.

Pure Python, no external tools, works on any OS. Replaces the original
stream_socket_client/openssl_x509_parse block.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from .base import validate_http_url

name = "ssl_cert"
title = "SSL Certificate"
description = "Fetch and summarise the TLS certificate served by a host."
validate = validate_http_url


def _name_tuples_to_dict(pairs: tuple) -> dict[str, str]:
    out: dict[str, str] = {}
    for rdn in pairs:
        for key, value in rdn:
            out[key] = value
    return out


def _fetch(host: str, port: int, timeout: float) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert()


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    parsed = urlparse(job.target)
    host = parsed.hostname or ""
    port = parsed.port or 443
    job.emit("log", level="info", message=f"connecting to {host}:{port}")

    cert = await asyncio.to_thread(_fetch, host, port, 15.0)

    subject = _name_tuples_to_dict(cert.get("subject", ()))
    issuer = _name_tuples_to_dict(cert.get("issuer", ()))
    not_after = cert.get("notAfter")
    expires = None
    days_left = None
    if not_after:
        expires_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        expires = expires_dt.isoformat()
        days_left = (expires_dt - datetime.now(timezone.utc)).days

    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]

    job.emit(
        "finding",
        common_name=subject.get("commonName"),
        issuer=issuer.get("organizationName") or issuer.get("commonName"),
        valid_from=cert.get("notBefore"),
        valid_until=expires,
        days_until_expiry=days_left,
        subject_alt_names=sans,
    )
    job.emit("log", level="info", message="certificate read")
