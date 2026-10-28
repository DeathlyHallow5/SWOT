"""Pinned CLI engines: discovery, health checks and cancellable JSONL execution."""
from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

from .config import settings


@dataclass(frozen=True)
class Tool:
    name: str
    title: str
    description: str
    docs: str


TOOLS = {t.name: t for t in [
    Tool("subfinder", "Subfinder", "Find subdomains using passive intelligence sources.", "https://docs.projectdiscovery.io/opensource/subfinder/overview"),
    Tool("dnsx", "dnsx", "Resolve hosts and inspect A, AAAA and CNAME records.", "https://docs.projectdiscovery.io/opensource/dnsx/overview"),
    Tool("httpx", "httpx", "Inspect web responses, page titles and technology fingerprints.", "https://docs.projectdiscovery.io/opensource/httpx/overview"),
    Tool("katana", "Katana", "Discover endpoints and forms with a scoped website crawler.", "https://docs.projectdiscovery.io/opensource/katana/overview"),
    Tool("nuclei", "Nuclei", "Run bundled HTTP configuration checks and retain evidence.", "https://docs.projectdiscovery.io/opensource/nuclei/overview"),
    Tool("naabu", "Naabu", "Discover common TCP services using unprivileged connect scans.", "https://docs.projectdiscovery.io/opensource/naabu/overview"),
    Tool("tlsx", "tlsx", "Inspect TLS versions, certificate names, issuers and expiry.", "https://github.com/projectdiscovery/tlsx"),
]}
_cache: dict[str, tuple[float, dict]] = {}
_probes: dict[tuple[asyncio.AbstractEventLoop, str], asyncio.Task] = {}


def executable(name: str) -> str | None:
    if name not in TOOLS:
        return None
    # Never accidentally invoke the unrelated Python httpx entry point.
    binary = "pd-httpx" if name == "httpx" else name
    suffix = ".exe" if os.name == "nt" else ""
    local = Path(settings.tools_dir) / (binary + suffix)
    return str(local) if local.is_file() else shutil.which(binary)


def process_env() -> dict[str, str]:
    state = Path(settings.database_path).resolve().parent / "tool-state"
    config, cache = state / "config", state / "cache"
    config.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    # Per-child environment: keep engine caches and provider config in workspace.
    return {**os.environ, "APPDATA": str(config), "LOCALAPPDATA": str(cache), "XDG_CONFIG_HOME": str(config),
            "XDG_CACHE_HOME": str(cache), "USERPROFILE": str(state), "NO_COLOR": "1"}


def process_options() -> dict:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {"start_new_session": True}


async def stop_process(proc) -> None:
    if proc.returncode is not None:
        return
    try:
        if os.name == "nt":
            proc.kill()
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    await proc.wait()


async def inspect_tool(name: str) -> dict:
    path = executable(name)
    key = f"{name}:{path}"
    cached = _cache.get(key)
    if cached and time.monotonic() - cached[0] < (30 if cached[1]["available"] else 5):
        return cached[1]
    probe_key = (asyncio.get_running_loop(), key)
    task = _probes.get(probe_key)
    if task is None:
        task = asyncio.create_task(_probe_tool(name, path, key))
        _probes[probe_key] = task
        task.add_done_callback(lambda done: _probes.pop(probe_key, None))
    return await asyncio.shield(task)


async def _probe_tool(name: str, path: str | None, key: str) -> dict:
    tool = TOOLS[name]
    version = None
    available = False
    if path:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(path, "-version", "-duc", stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, env=process_env(), **process_options())
            output, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            text = re.sub(r"\x1b\[[0-9;]*m", "", output.decode(errors="replace"))
            match = re.search(r"(?:version[:\s]*|v)(\d+\.\d+\.\d+)", text, re.I)
            available = proc.returncode == 0 and match is not None
            version = match.group(1) if match else None
        except (OSError, TimeoutError):
            pass
        finally:
            if proc:
                await stop_process(proc)
    result = {"name": name, "title": tool.title, "description": tool.description,
              "docs": tool.docs, "available": available, "version": version}
    _cache[key] = (time.monotonic(), result)
    return result


async def catalog() -> list[dict]:
    results = await asyncio.gather(*(inspect_tool(name) for name in TOOLS))
    zap_available = False
    if settings.zap_url:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                response = await client.get(settings.zap_url.rstrip("/") + "/health")
                zap_available = response.status_code == 200
        except httpx.HTTPError:
            pass
    return [*results, {"name": "zap", "title": "OWASP ZAP", "description": "Baseline crawl and passive response analysis via the optional Docker worker.",
                       "docs": "https://www.zaproxy.org/docs/docker/baseline-scan/", "available": zap_available, "version": None}]


async def run_jsonl(job, name: str, args: list[str], targets: list[str] | None = None,
                    emit: bool = True) -> list[dict]:
    path = executable(name)
    if not path:
        raise RuntimeError(f"{name} is not installed. Run scripts/install_tools.py or use Docker Compose.")
    records: list[dict] = []
    errors: deque[str] = deque(maxlen=8)
    invalid_lines = 0
    seen: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="swot-") as scratch:
        command = [path, *args]
        if targets is not None:
            source = Path(scratch) / "targets.txt"
            source.write_text("\n".join(targets) + "\n", encoding="utf-8")
            command += ["-l", str(source)]
        job.emit("log", level="info", message=f"Starting {name}")
        proc = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, cwd=scratch, env=process_env(),
            limit=1024 * 1024, **process_options())

        async def read_errors():
            async for line in proc.stderr:
                errors.append(re.sub(r"\x1b\[[0-9;]*m", "", line.decode(errors="replace").strip())[:500])
        stderr_task = asyncio.create_task(read_errors())
        try:
            async for line in proc.stdout:
                text = line.decode(errors="replace").strip()
                if not text:
                    continue
                try:
                    record = json.loads(text)
                    if not isinstance(record, dict):
                        raise ValueError("expected object")
                except (ValueError, json.JSONDecodeError):
                    invalid_lines += 1
                    continue
                finding = normalize(name, record)
                identity = json.dumps({k: v for k, v in finding.items() if k != "evidence"}, sort_keys=True)
                if identity in seen:
                    continue
                seen.add(identity)
                records.append(record)
                if emit:
                    job.emit("finding", **finding)
                if len(records) >= settings.max_tool_results:
                    raise RuntimeError(f"{name} reached the {settings.max_tool_results}-result limit. Partial results are saved; narrow the target and retry.")
            await proc.wait()
            await stderr_task
            if proc.returncode != 0:
                raise RuntimeError(f"{name} exited with code {proc.returncode}: " + " | ".join(errors)[-1500:])
            if invalid_lines:
                raise RuntimeError(f"{name} returned {invalid_lines} unparseable output line(s); results may be incomplete.")
            job.emit("log", level="info", message=f"{name} completed · {len(records)} observations")
            return records
        finally:
            await stop_process(proc)
            stderr_task.cancel()
            await asyncio.gather(stderr_task, return_exceptions=True)


def normalize(name: str, row: dict) -> dict:
    from urllib.parse import urlparse
    data = {"source": name, "evidence": row}
    if name == "subfinder":
        data.update(host=row.get("host"), sources=row.get("sources") or [row.get("source", "passive")])
    elif name == "dnsx":
        data.update(host=row.get("host"), addresses=[*row.get("a", []), *row.get("aaaa", [])], cname=row.get("cname", []))
    elif name == "httpx":
        url = row.get("url", "")
        data.update(host=urlparse(url).hostname or row.get("input"), url=url, addresses=row.get("a") or ([row["host"]] if row.get("host") else []),
                    status=row.get("status_code"), title=row.get("title"), technologies=row.get("tech", []), server=row.get("webserver"))
    elif name == "katana":
        req, resp = row.get("request", {}), row.get("response", {})
        data.update(url=req.get("endpoint"), method=req.get("method", "GET"), status=resp.get("status_code"))
    elif name == "nuclei":
        info = row.get("info", {})
        data.update(title=info.get("name"), severity=info.get("severity", "info"), template_id=row.get("template-id"),
                    url=row.get("matched-at") or row.get("host"), description=info.get("description"), references=info.get("reference", []))
    elif name == "naabu":
        data.update(host=row.get("host") or row.get("ip"), addresses=[row.get("ip")], port=row.get("port"), protocol=row.get("protocol", "tcp"))
    elif name == "tlsx":
        data.update(host=row.get("host"), issuer=row.get("issuer_org") or row.get("issuer_cn"),
                    expires=row.get("not_after"), tls_version=row.get("tls_version"), names=row.get("subject_an", []))
    return data
