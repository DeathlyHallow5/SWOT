"""Shared target scope checks before external engines are started."""
from __future__ import annotations
import asyncio
import socket
from urllib.parse import urlparse
from .base import TargetError, _is_public_ip, validate_host_or_ip
from ..config import settings


def in_scope(host: str, domain: str) -> bool:
    host, domain = host.rstrip('.').lower(), domain.rstrip('.').lower()
    return host == domain or host.endswith('.' + domain)


async def public_target(target: str) -> str:
    host = urlparse(target).hostname if '://' in target else target
    host = validate_host_or_ip(host or '')
    if settings.allowed_domains and not any(in_scope(host, domain) for domain in settings.allowed_domains):
        raise TargetError('Target is outside SWOT_ALLOWED_DOMAINS')
    try:
        records = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, host, None), timeout=10)
    except (socket.gaierror, TimeoutError) as exc:
        raise TargetError(f'Could not resolve {host}') from exc
    if not records or any(not _is_public_ip(row[4][0]) for row in records):
        raise TargetError('Target resolves to a private or reserved IP address')
    return host
