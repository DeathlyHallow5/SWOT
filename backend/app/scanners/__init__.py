"""Scanner registry.

Register each scanner module here. The API exposes the registry so the
frontend can render the available scans and validate targets consistently.
"""
from __future__ import annotations

from .base import Scanner, TargetError
from . import dns_subdomains, ssl_cert

_MODULES = [ssl_cert, dns_subdomains]

REGISTRY: dict[str, Scanner] = {
    module.name: Scanner(
        name=module.name,
        title=module.title,
        description=module.description,
        validate=module.validate,
        run=module.run,
    )
    for module in _MODULES
}


def get(name: str) -> Scanner | None:
    return REGISTRY.get(name)


def catalog() -> list[dict[str, str]]:
    return [
        {"name": s.name, "title": s.title, "description": s.description}
        for s in REGISTRY.values()
    ]


__all__ = ["REGISTRY", "get", "catalog", "Scanner", "TargetError"]
