"""Target validation is the main security boundary, so test it directly."""
import pytest

from app.scanners.base import (
    TargetError,
    validate_host_or_ip,
    validate_hostname,
    validate_http_url,
)


@pytest.mark.parametrize("value", ["example.com", "sub.example.co.uk", "a.b.c"])
def test_valid_hostnames(value: str) -> None:
    assert validate_hostname(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "example.com; rm -rf /",
        "a b.com",
        "$(whoami).com",
        "`id`",
        "",
        "-leading.com",
    ],
)
def test_rejects_injection_hostnames(value: str) -> None:
    with pytest.raises(TargetError):
        validate_hostname(value)


@pytest.mark.parametrize("value", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "::1"])
def test_blocks_private_ips(value: str) -> None:
    with pytest.raises(TargetError):
        validate_host_or_ip(value)


def test_allows_public_ip() -> None:
    assert validate_host_or_ip("8.8.8.8") == "8.8.8.8"


def test_http_url_adds_scheme() -> None:
    assert validate_http_url("example.com").startswith("https://example.com")


@pytest.mark.parametrize("value", ["file:///etc/passwd", "ftp://example.com"])
def test_http_url_rejects_other_schemes(value: str) -> None:
    with pytest.raises(TargetError):
        validate_http_url(value)


def test_http_url_blocks_internal_host() -> None:
    with pytest.raises(TargetError):
        validate_http_url("http://127.0.0.1/admin")
