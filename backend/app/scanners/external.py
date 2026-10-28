"""Adapters for ProjectDiscovery engines and the discovery workflow."""
from __future__ import annotations
import re
from pathlib import Path
from urllib.parse import urlparse

from ..config import settings
from ..tools import TOOLS, normalize, run_jsonl
from .base import Scanner, TargetError, validate_host_or_ip, validate_http_url
from ._scope import in_scope, public_target

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"


def arguments(name: str, target: str) -> list[str]:
    rate = str(settings.tool_rate)
    common = ["-silent", "-duc"]
    if name == "subfinder":
        return common + ["-d", target, "-json", "-cs", "-rl", rate, "-timeout", "10", "-max-time", "1"]
    if name == "dnsx":
        return common + ["-json", "-a", "-aaaa", "-cname", "-rl", rate, "-t", "5", "-retry", "1"]
    if name == "httpx":
        return common + ["-json", "-sc", "-title", "-tech-detect", "-ip", "-server", "-rl", rate, "-threads", "5", "-timeout", "10", "-exclude", "private-ips"]
    if name == "katana":
        host = urlparse(target).hostname or target
        scope = r"^https?://" + re.escape(host) + r"(?::\d+)?(?:/|$)"
        return common + ["-u", target, "-jsonl", "-d", "2", "-jc", "-fx", "-ct", "60s", "-rl", rate,
                         "-c", "3", "-timeout", "10", "-cs", scope, "-fs", "fqdn", "-dr", "-or", "-ob"]
    if name == "nuclei":
        return common + ["-u", target, "-jsonl", "-t", str(TEMPLATES), "-rl", rate, "-c", "3", "-timeout", "10", "-retries", "1", "-ni", "-dr", "-or", "-ot"]
    if name == "naabu":
        return common + ["-host", target, "-json", "-s", "c", "-top-ports", "100", "-rate", rate, "-c", "5", "-timeout", "2000"]
    if name == "tlsx":
        return common + ["-u", target, "-json", "-san", "-cn", "-c", "2", "-timeout", "5"]
    raise ValueError(f"Unknown engine {name}")


def runner(name: str):
    async def run(job):
        await public_target(job.target)
        inputs = [job.target] if name in ("dnsx", "httpx") else None
        await run_jsonl(job, name, arguments(name, job.target), targets=inputs)
    return run


async def discovery(job) -> None:
    domain = job.target
    await public_target(domain)
    job.emit("progress", stage="Discovering subdomains", done=0, total=3)
    passive = await run_jsonl(job, "subfinder", arguments("subfinder", domain), emit=False)
    hosts = {domain}
    for row in passive:
        try:
            host = validate_host_or_ip(str(row.get("host", "")))
        except TargetError:
            continue
        if in_scope(host, domain):
            hosts.add(host)
    ordered = [domain, *sorted(hosts - {domain})]
    if len(ordered) > settings.max_discovery_hosts:
        job.emit("log", level="warn", message=f"Discovered {len(ordered)} hosts; this run checks the first {settings.max_discovery_hosts}.")
    ordered = ordered[:settings.max_discovery_hosts]
    job.emit("progress", stage="Resolving DNS records", done=1, total=3)
    resolved = await run_jsonl(job, "dnsx", arguments("dnsx", domain), targets=ordered, emit=False)
    allowed = []
    dns_records = {}
    for row in resolved:
        host = str(row.get("host", ""))
        if host not in ordered:
            continue
        try:
            await public_target(host)
        except TargetError as exc:
            job.emit("log", level="warn", message=f"Skipped {host}: {exc}")
            continue
        allowed.append(host)
        dns_records[host] = normalize("dnsx", row)
    job.emit("progress", stage="Inspecting web services", done=2, total=3)
    web = await run_jsonl(job, "httpx", arguments("httpx", domain), targets=allowed, emit=False) if allowed else []
    seen = set()
    for row in web:
        finding = normalize("httpx", row)
        host = finding.get("host")
        if host not in dns_records:
            continue
        seen.add(host)
        finding["addresses"] = dns_records[host]["addresses"]
        finding["source"] = "discovery"
        finding["dns_evidence"] = dns_records[host]["evidence"]
        job.emit("finding", **finding)
    for host in allowed:
        if host not in seen:
            job.emit("finding", **{**dns_records[host], "source": "discovery", "status": None, "title": "No web response", "technologies": []})
    job.emit("progress", stage="Discovery complete", done=3, total=3)


EXTERNAL = [Scanner(name=name, title=tool.title, description=tool.description,
                    validate=validate_http_url if name in ("httpx", "katana", "nuclei") else validate_host_or_ip,
                    run=runner(name), category="external", requires=(name,)) for name, tool in TOOLS.items()]
WORKFLOW = Scanner("discovery", "Domain discovery", "Subfinder → dnsx → httpx: map subdomains and inspect web services.",
                   validate_host_or_ip, discovery, "workflow", ("subfinder", "dnsx", "httpx"))
