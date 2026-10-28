"""Find candidate origin IPs behind a CDN / reverse proxy.

Free path: enumerate subdomains from Certificate Transparency (crt.sh), resolve
them, and separate addresses that are not in common CDN ranges — origins often
leak through a side host (origin., direct., mail.). Optional providers add
historical DNS (SecurityTrails) and host data (Shodan) when keys are present.
"""
from __future__ import annotations

import asyncio
import ipaddress

from ._dns import resolve
from ._intel import configured, get_json, key_for, needs_key
from .base import validate_hostname

name = "real_ip"
title = "Real IP Discovery"
description = "Reveal likely origin IPs hidden behind a CDN or proxy."
validate = validate_hostname

# Best-effort labelling only: a few major CDN ranges.
_CDN_RANGES = {
    "Cloudflare": ["104.16.0.0/13", "172.64.0.0/13", "131.0.72.0/22", "108.162.192.0/18", "141.101.64.0/18", "190.93.240.0/20", "162.158.0.0/15", "173.245.48.0/20"],
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16"],
    "Akamai": ["23.0.0.0/12", "104.64.0.0/10"],
    "Amazon CloudFront": ["13.32.0.0/15", "13.224.0.0/14", "99.84.0.0/16"],
}
_NETS = [(name_, ipaddress.ip_network(cidr)) for name_, cidrs in _CDN_RANGES.items() for cidr in cidrs]
_MAX_HOSTS = 80


def _cdn_label(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for label, net in _NETS:
        if addr.version == net.version and addr in net:
            return label
    return None


async def _crtsh_hosts(domain: str) -> set[str]:
    status, data = await get_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=25)
    hosts: set[str] = set()
    if status == 200 and isinstance(data, list):
        for row in data:
            for item in str(row.get("name_value", "")).splitlines():
                item = item.strip().lstrip("*.").lower()
                if item.endswith(domain) and "@" not in item:
                    hosts.add(item)
    return hosts


async def run(job) -> None:  # noqa: ANN001 - Job, typed via registry
    domain = job.target
    job.emit("log", level="info", message="collecting hosts from Certificate Transparency")
    hosts = await _crtsh_hosts(domain)
    hosts.add(domain)
    ordered = [domain, *sorted(hosts - {domain})][:_MAX_HOSTS]
    job.emit("log", level="info", message=f"resolving {len(ordered)} hosts")

    apex_ips: set[str] = set()
    semaphore = asyncio.Semaphore(16)
    origins: dict[str, dict] = {}

    async def check(host: str) -> None:
        async with semaphore:
            records = await resolve(host, "A")
        ips = [v for t, v in records if t == "A"]
        if host == domain:
            apex_ips.update(ips)
        for ip in ips:
            label = _cdn_label(ip)
            if label is None:  # not a recognised CDN range -> candidate origin
                origins.setdefault(ip, {"ip": ip, "hosts": [], "classification": "candidate origin"})
                origins[ip]["hosts"].append(host)

    await asyncio.gather(*(check(h) for h in ordered))

    front = {ip: _cdn_label(ip) for ip in apex_ips}
    for ip, label in front.items():
        job.emit("finding", ip=ip, hosts=[domain], classification=f"edge / {label}" if label else "edge (direct)")
    for info in list(origins.values())[: _MAX_HOSTS]:
        info["hosts"] = sorted(set(info["hosts"]))[:10]
        job.emit("finding", **info)

    await _providers(job, domain, origins)
    job.emit("log", level="info", message=f"done — {len(origins)} candidate origin IP(s)")


async def _providers(job, domain: str, origins: dict) -> None:  # noqa: ANN001
    if configured("securitytrails"):
        status, data = await get_json(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": key_for("securitytrails")},
        )
        if status == 200 and isinstance(data, dict):
            seen = set()
            for record in data.get("records", [])[:50]:
                for value in record.get("values", []):
                    ip = value.get("ip")
                    if ip and ip not in seen:
                        seen.add(ip)
                        job.emit("finding", ip=ip, hosts=[domain], classification="historical A (SecurityTrails)")
    if configured("shodan"):
        status, data = await get_json(
            f"https://api.shodan.io/dns/domain/{domain}", params={"key": key_for("shodan")}
        )
        if status == 200 and isinstance(data, dict):
            for record in data.get("data", [])[:100]:
                if record.get("type") == "A" and record.get("value"):
                    job.emit("finding", ip=record["value"], hosts=[f"{record.get('subdomain') or '@'}.{domain}".lstrip(".")],
                             classification="Shodan DNS record")
    if not configured("securitytrails") and not configured("shodan"):
        needs_key(job, "securitytrails", "Shodan is also supported for historical IPs.")
