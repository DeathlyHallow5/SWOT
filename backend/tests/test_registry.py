"""The registry should expose every scanner with a working validator."""
from app import scanners


def test_all_scanners_registered() -> None:
    expected = {
        "dns_subdomains", "ports", "http_fingerprint", "ssl_cert",
        "whois", "wayback", "directories", "api_endpoints", "waf",
    }
    assert expected == set(scanners.REGISTRY)


def test_catalog_shape() -> None:
    for entry in scanners.catalog():
        assert {"name", "title", "description"} == set(entry)
        assert entry["title"] and entry["description"]


def test_every_scanner_validates_a_plain_domain() -> None:
    for scanner in scanners.REGISTRY.values():
        # Each validator accepts a bare domain (normalising URL scanners to a URL).
        assert scanner.validate("example.com")
