"""Tests for input parameter sanitization, injection defense, and cryptographic constraints."""

from __future__ import annotations

import re
from urllib.parse import urlparse

ALLOWED_DIGESTS = {"SHA256", "SHA384", "SHA512"}
ALLOWED_ENDPOINTS = {
    "https://eus.codesigning.azure.net/",
    "https://wus.codesigning.azure.net/",
    "https://wus2.codesigning.azure.net/",
    "https://weu.codesigning.azure.net/",
    "https://neu.codesigning.azure.net/",
}


def validate_digest(digest: str) -> bool:
    return digest.upper() in ALLOWED_DIGESTS


def validate_endpoint(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
    if not parsed.netloc.endswith("codesigning.azure.net"):
        return False
    return True


def validate_timestamp_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def test_allowed_digest_algorithms():
    for valid in ["SHA256", "SHA384", "SHA512", "sha256"]:
        assert validate_digest(valid)

    # Insecure or nonsensical digests must be rejected
    for invalid in ["MD5", "SHA1", "DES", "ROT13", "none", ""]:
        assert not validate_digest(invalid)


def test_endpoint_validation():
    assert validate_endpoint("https://eus.codesigning.azure.net/")
    assert validate_endpoint("https://weu.codesigning.azure.net/")

    # Insecure or spoofed endpoints must be rejected
    assert not validate_endpoint("http://eus.codesigning.azure.net/")
    assert not validate_endpoint("https://evil.azurewebsites.net/")
    assert not validate_endpoint("https://attacker.codesigning.azure.net.badsite.com/")


def test_timestamp_url_validation():
    assert validate_timestamp_url("http://timestamp.acs.microsoft.com")
    assert validate_timestamp_url("https://timestamp.acs.microsoft.com")
    assert not validate_timestamp_url("file:///etc/passwd")
    assert not validate_timestamp_url("ftp://test.com")


def test_command_injection_pattern_defense():
    """Verify that dangerous shell metacharacters in file inputs are detected."""
    injection_payloads = [
        "dist/app.exe; rm -rf /",
        "dist/app.exe && whoami",
        "dist/app.exe | cat /etc/passwd",
        "$(Invoke-Expression 'Get-Process')",
        "`Invoke-WebRequest evil.com`",
    ]

    dangerous_chars = re.compile(r"[`$()|;&><]")
    for payload in injection_payloads:
        assert dangerous_chars.search(payload) is not None, f"Payload should be recognized as containing shell operators: {payload}"


def test_boolean_conversion():
    def to_bool(val: str | bool) -> bool:
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("true", "1", "yes")

    assert to_bool("true") is True
    assert to_bool("True") is True
    assert to_bool(True) is True
    assert to_bool("false") is False
    assert to_bool("False") is False
    assert to_bool(False) is False
    assert to_bool("0") is False
    assert to_bool("") is False
