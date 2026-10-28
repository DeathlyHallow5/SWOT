"""Scanner catalog shared by the API, dashboard and Docker installation."""
from __future__ import annotations
from .base import Scanner, TargetError
from . import (api_endpoints, directories, dns_subdomains, http_fingerprint, ports, ssl_cert, waf, wayback, whois, zap,
               tech_stack, admin_finder, subdomain_takeover, real_ip, dork_search, secret_search, stealer_check, db_leak)
from .external import EXTERNAL, WORKFLOW
from ..tools import executable

# Pure-Python scanners that connect to the target (or its subdomains).
_BUILTIN = [dns_subdomains, ports, http_fingerprint, ssl_cert, whois, wayback,
            directories, api_endpoints, waf, tech_stack, admin_finder, subdomain_takeover]
# Intelligence scanners: query third-party sources, optionally with API keys.
_INTEL = [real_ip, dork_search, secret_search, stealer_check, db_leak]

REGISTRY: dict[str, Scanner] = {m.name: Scanner(m.name, m.title, m.description, m.validate, m.run) for m in _BUILTIN}
REGISTRY.update({m.name: Scanner(m.name, m.title, m.description, m.validate, m.run, "intel") for m in _INTEL})
REGISTRY.update({scanner.name: scanner for scanner in [WORKFLOW, *EXTERNAL]})
REGISTRY["zap"] = Scanner(zap.name, zap.title, zap.description, zap.validate, zap.run, "external", ("zap",))


def get(name: str) -> Scanner | None:
    return REGISTRY.get(name)


def catalog(availability: dict[str, bool] | None = None) -> list[dict]:
    availability = availability if availability is not None else {name: executable(name) is not None for s in REGISTRY.values() for name in s.requires}
    return [{"name": s.name, "title": s.title, "description": s.description, "category": s.category,
             "requires": list(s.requires), "available": all(availability.get(name, False) for name in s.requires)} for s in REGISTRY.values()]


__all__ = ["REGISTRY", "get", "catalog", "Scanner", "TargetError"]
