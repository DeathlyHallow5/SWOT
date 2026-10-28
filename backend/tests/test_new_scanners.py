"""Offline unit tests for the new scanners and their helpers (no network)."""
import asyncio

import pytest

from app.scanners import _dns, _intel, dork_search, nuclei_config
from app.scanners.subdomain_takeover import _service_for
from app.scanners.tech_stack import _ASSET_LIB


class FakeJob:
    """Captures emitted events without a running JobManager."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.events: list[tuple[str, dict]] = []

    def emit(self, kind: str, **data) -> None:
        self.events.append((kind, data))

    def findings(self) -> list[dict]:
        return [d for k, d in self.events if k == "finding"]


def test_redact_hides_most_of_a_secret() -> None:
    assert _intel.redact("AKIA1234567890ABCD").startswith("AKIA")
    assert "1234567890" not in _intel.redact("AKIA1234567890ABCD")


def test_providers_unconfigured_by_default() -> None:
    catalog = _intel.provider_catalog()
    assert catalog, "expected provider entries"
    for entry in catalog:
        assert entry["name"].startswith("provider:")
        assert entry["available"] is False  # no keys set in the test env


def test_takeover_fingerprint_matches_known_service() -> None:
    service, signatures = _service_for("myapp.github.io")
    assert service == "GitHub Pages"
    assert any("GitHub Pages" in s for s in signatures)
    assert _service_for("example.com") is None


def test_asset_library_version_is_extracted() -> None:
    m = _ASSET_LIB.search("/static/jquery-3.6.0.min.js")
    assert m and m.group("lib").lower() == "jquery" and m.group("ver") == "3.6.0"
    assert _ASSET_LIB.search("https://cdn/bootstrap@5.3.1/dist/css/bootstrap.min.css")


def test_dns_name_roundtrip() -> None:
    encoded = _dns._encode("sub.example.com")
    name, end = _dns._read_name(encoded, 0)
    assert name == "sub.example.com" and end == len(encoded)


def test_nuclei_sources_and_profiles() -> None:
    ids = {s["id"] for s in nuclei_config.sources()}
    assert "bundled" in ids and "official" in ids
    assert [s for s in nuclei_config.sources() if s["id"] == "bundled"][0]["available"]
    profiles = {p["id"] for p in nuclei_config.profiles()}
    assert profiles == {"safe", "standard", "full"}


def test_nuclei_args_apply_profile_and_exclude_intrusive() -> None:
    safe = nuclei_config.build_args("https://example.com", "bundled", "safe")
    assert "-severity" in safe and safe[safe.index("-severity") + 1] == "info,low"
    tags = safe[safe.index("-etags") + 1]
    assert "fuzzing" in tags and "dos" in tags  # intrusive + dos excluded
    # Full profile has no severity restriction but still excludes dos by default.
    full = nuclei_config.build_args("https://example.com", "bundled", "full")
    assert "-severity" not in full
    assert "dos" in full[full.index("-etags") + 1]


def test_nuclei_rejects_unknown_profile_and_source() -> None:
    with pytest.raises(ValueError):
        nuclei_config.build_args("https://example.com", "bundled", "nope")
    with pytest.raises(ValueError):
        nuclei_config.resolve_source("preset:does-not-exist")


def test_dork_search_generates_queries_offline() -> None:
    job = FakeJob("example.com")
    asyncio.run(dork_search.run(job))
    findings = job.findings()
    # Templated dorks + platform searches, each referencing the domain.
    assert len(findings) >= 10
    categories = {f.get("category") for f in findings}
    assert "Login / admin" in categories
    assert any("example.com" in str(f.get("query", "")) for f in findings)
    # Without a Google key, a clear token-required notice is present.
    assert any(f.get("status") == "token_required" for f in findings)
