"""Nuclei template sources and scan profiles.

Lets a scan choose *which* templates run (bundled reviewed set, the official
nuclei-templates collection, or a user-supplied preset folder) and *how hard*
it looks (severity + tag profile). Intrusive and DoS tags are excluded from
every profile by default; the full profile is an explicit opt-in.
"""
from __future__ import annotations

from pathlib import Path

from ..config import settings
from ..tools import run_jsonl

BUNDLED_DIR = Path(__file__).resolve().parent.parent / "templates"
# Tags that can disrupt or brute-force a target; never run without opt-in.
_INTRUSIVE_TAGS = ["fuzzing", "brute-force", "intrusive"]
_DOS_TAG = ["dos"]

# id -> (title, severities | None, exclude_intrusive)
_PROFILES = {
    "safe": ("Safe — info & low, non-intrusive", "info,low", True),
    "standard": ("Standard — medium to critical, non-intrusive", "medium,high,critical", True),
    "full": ("Full — all severities (opt-in)", None, False),
}


def _has_templates(path: Path) -> bool:
    return path.is_dir() and any(path.rglob("*.yaml"))


def _preset_dir() -> Path:
    return Path(settings.nuclei_presets_dir)


def sources() -> list[dict]:
    """Available template sources, bundled first."""
    out = [{"id": "bundled", "title": "Bundled (reviewed)", "available": True,
            "description": "Curated HTTP configuration checks shipped with SWOT."}]
    official = Path(settings.nuclei_templates_dir)
    out.append({"id": "official", "title": "Official nuclei-templates",
                "available": _has_templates(official),
                "description": "The full ProjectDiscovery template collection. Install via scripts/install_nuclei_templates.py."})
    base = _preset_dir()
    if base.is_dir():
        for child in sorted(p for p in base.iterdir() if p.is_dir()):
            out.append({"id": f"preset:{child.name}", "title": f"Preset · {child.name}",
                        "available": _has_templates(child),
                        "description": f"User preset folder: {child.name}"})
    return out


def profiles() -> list[dict]:
    return [{"id": pid, "title": title} for pid, (title, _sev, _ex) in _PROFILES.items()]


def resolve_source(source_id: str) -> Path:
    if source_id == "bundled":
        return BUNDLED_DIR
    if source_id == "official":
        path = Path(settings.nuclei_templates_dir)
        if not _has_templates(path):
            raise ValueError("Official nuclei-templates are not installed. Run scripts/install_nuclei_templates.py.")
        return path
    if source_id.startswith("preset:"):
        path = _preset_dir() / source_id.split(":", 1)[1]
        if not _has_templates(path):
            raise ValueError(f"Preset '{source_id}' has no templates.")
        return path
    raise ValueError(f"Unknown template source: {source_id}")


def build_args(target: str, source_id: str, profile_id: str) -> list[str]:
    if profile_id not in _PROFILES:
        raise ValueError(f"Unknown scan profile: {profile_id}")
    source = resolve_source(source_id)
    _title, severities, exclude_intrusive = _PROFILES[profile_id]
    rate = str(settings.tool_rate)
    args = ["-silent", "-duc", "-u", target, "-jsonl", "-t", str(source),
            "-rl", rate, "-c", "3", "-timeout", "10", "-retries", "1",
            "-ni", "-dr", "-or", "-ot", "-mhe", "5"]
    excluded = list(_INTRUSIVE_TAGS) if exclude_intrusive else []
    if not settings.nuclei_allow_dos:
        excluded += _DOS_TAG
    if excluded:
        args += ["-etags", ",".join(sorted(set(excluded)))]
    if severities:
        args += ["-severity", severities]
    return args


def make_runner(source_id: str, profile_id: str):
    """Build a Job runner that executes nuclei with the chosen source/profile."""
    async def run(job):
        source = next((s for s in sources() if s["id"] == source_id), None)
        title = source["title"] if source else source_id
        profile = next((p for p in profiles() if p["id"] == profile_id), None)
        job.emit("log", level="info",
                 message=f"Nuclei source: {title} · profile: {profile['title'] if profile else profile_id}")
        try:
            await run_jsonl(job, "nuclei", build_args(job.target, source_id, profile_id))
        except RuntimeError as exc:
            # The profile's severity filter can legitimately select no templates
            # from a small source — that is a clean "nothing to run", not a fault.
            if "no templates provided for scan" in str(exc).lower():
                job.emit("log", level="info",
                         message="No templates in this source match the selected profile.")
                return
            raise
    return run
