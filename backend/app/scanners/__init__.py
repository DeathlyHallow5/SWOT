"""Scanner catalog shared by the API, dashboard and Docker installation."""
from __future__ import annotations
from .base import Scanner, TargetError
from . import api_endpoints, directories, dns_subdomains, http_fingerprint, ports, ssl_cert, waf, wayback, whois, zap
from .external import EXTERNAL, WORKFLOW
from ..tools import executable

_MODULES = [dns_subdomains, ports, http_fingerprint, ssl_cert, whois, wayback, directories, api_endpoints, waf]
REGISTRY: dict[str, Scanner] = {module.name: Scanner(module.name, module.title, module.description, module.validate, module.run) for module in _MODULES}
REGISTRY.update({scanner.name: scanner for scanner in [WORKFLOW, *EXTERNAL]})
REGISTRY["zap"] = Scanner(zap.name, zap.title, zap.description, zap.validate, zap.run, "external", ("zap",))


def get(name: str) -> Scanner | None:
    return REGISTRY.get(name)


def catalog(availability: dict[str, bool] | None = None) -> list[dict]:
    availability = availability if availability is not None else {name: executable(name) is not None for s in REGISTRY.values() for name in s.requires}
    return [{"name": s.name, "title": s.title, "description": s.description, "category": s.category,
             "requires": list(s.requires), "available": all(availability.get(name, False) for name in s.requires)} for s in REGISTRY.values()]


__all__ = ["REGISTRY", "get", "catalog", "Scanner", "TargetError"]
