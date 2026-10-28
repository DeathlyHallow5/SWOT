"""Scanner contract plus shared helpers for safe target handling.

A scanner is an async callable that receives a Job and emits events on it.
The registry maps a public name to a scanner and declares how its target is
validated, so every entry point normalises input the same way.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Awaitable, Callable, Protocol
from urllib.parse import urlparse

# A runner drives one job to completion, emitting events as it goes.
ScannerRunner = Callable[["Job"], Awaitable[None]]

# Hostname per RFC 1123: labels of letters/digits/hyphen, dot-separated.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


class TargetError(ValueError):
    """Raised when a target fails validation for a scanner."""


def _is_public_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_hostname(target: str) -> str:
    """Return a bare hostname, rejecting anything shell- or SSRF-unsafe."""
    host = target.strip().lower()
    if not host:
        raise TargetError("target is empty")
    if _HOSTNAME_RE.match(host):
        return host.rstrip(".")
    raise TargetError("target is not a valid hostname")


def _parses_as_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def validate_host_or_ip(target: str) -> str:
    """Return a hostname or a public IP; private/loopback IPs are rejected."""
    host = target.strip().lower()
    if _is_public_ip(host):
        return host
    if _parses_as_ip(host):
        # A valid IP that is not public -> block it (SSRF guard).
        raise TargetError("private or reserved IP addresses are not allowed")
    return validate_hostname(host)


def validate_http_url(target: str) -> str:
    """Return a normalised http(s) URL with a non-private host."""
    raw = target.strip()
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        parsed.port
    except ValueError as exc:
        raise TargetError("invalid URL or port") from exc
    if parsed.scheme not in ("http", "https"):
        raise TargetError("only http and https URLs are allowed")
    host = parsed.hostname or ""
    if parsed.username is not None or parsed.password is not None:
        raise TargetError("URLs containing credentials are not allowed")
    validate_host_or_ip(host)  # reuse the SSRF/hostname guard
    return parsed.geturl()


@dataclass(frozen=True)
class Scanner:
    name: str
    title: str
    description: str
    validate: Callable[[str], str]
    run: ScannerRunner
    category: str = "builtin"
    requires: tuple[str, ...] = ()


class ScannerSpec(Protocol):
    name: str
    title: str
    description: str

    def validate(self, target: str) -> str: ...

    async def run(self, job: "Job") -> None: ...


# Avoids a circular import at module load; Job is only needed for typing.
from ..jobs import Job  # noqa: E402,F401
