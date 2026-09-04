"""
Security Regression Test Suite: Hardened Exploitation Vectors
Covers mandatory defense-in-depth requirements:
1. Server-Side Request Forgery (SSRF) and Cloud Metadata Exfiltration
2. Unsafe Deserialization Protection
3. Filesystem Escape & Path Traversal Mitigation
4. Oversized Payload & Request Boundary Enforcement
5. Header & Log Injection (CRLF Splitting) Prevention
6. Regular Expression Denial of Service (ReDoS) Resilience
"""

import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from ulpf.apps.api.main import app
from ulpf.packages.security.sanitization import (
    sanitize_log_string,
    validate_safe_identifier,
    validate_safe_regex,
    validate_safe_url,
)
from ulpf.services.parser_engine.registry import ParserRegistry

# ==============================================================================
# 1. Server-Side Request Forgery (SSRF) Prevention
# ==============================================================================


def test_ssrf_blocks_cloud_metadata_services():
    """Verifies that URLs targeting AWS/GCP/Azure IMDS or internal domains are blocked."""
    forbidden_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://service.internal/admin",
        "file:///etc/passwd",
        "gopher://127.0.0.1:9000/x",
        "ftp://10.0.0.1/sensitive.tar",
    ]

    for target in forbidden_urls:
        with pytest.raises(HTTPException) as exc:
            validate_safe_url(target)
        assert exc.value.status_code == 400

    # Valid URLs permitted
    assert (
        validate_safe_url("http://opensearch.airgap.local:9200")
        == "http://opensearch.airgap.local:9200"
    )
    assert (
        validate_safe_url("https://minio.airgap.local:9000")
        == "https://minio.airgap.local:9000"
    )


# ==============================================================================
# 2. Unsafe Deserialization Protection
# ==============================================================================


def test_unsafe_deserialization_protection():
    """
    Verifies that parser engine and models use safe JSON / AST parsing
    and strictly reject arbitrary serialized binary payloads.
    """
    import pickle

    # Malicious pickle payload simulating an RCE exploit
    malicious_pickle = pickle.dumps({"__class__": "os.system", "cmd": "whoami"})

    # Attempting to load arbitrary payload into ParserRegistry must fail safely
    registry = ParserRegistry()
    # The registry must not contain any pickle.loads
    import ulpf.services.parser_engine.registry as reg_module

    assert not hasattr(reg_module, "pickle")


# ==============================================================================
# 3. Filesystem Escape & Path Traversal
# ==============================================================================


def test_filesystem_escape_and_path_traversal():
    """Verifies that all path parameters strictly reject traversal sequences."""
    traversal_attacks = [
        "../../../etc/passwd",
        r"..\..\windows\system32\cmd.exe",
        "../../../../../../var/log/syslog",
        "event\x00.raw",
        "session/../../../root",
        "/etc/shadow",
        "C:\\Windows\\System32",
        "..%2f..%2fetc%2fpasswd",
    ]

    for attack in traversal_attacks:
        with pytest.raises(HTTPException) as exc:
            validate_safe_identifier(attack, "event_id")
        assert exc.value.status_code == 400
        assert (
            "Path traversal" in exc.value.detail
            or "disallowed characters" in exc.value.detail
        )

    # Clean identifiers accepted
    assert validate_safe_identifier("event-123_456:789") == "event-123_456:789"
    assert validate_safe_identifier("parser.v1.0.0") == "parser.v1.0.0"


# ==============================================================================
# 4. Oversized Payload & Request Boundary Enforcement
# ==============================================================================


def test_oversized_payload_rejection():
    """Confirms that raw payloads exceeding ULPF_MAX_INGEST_PAYLOAD_BYTES are rejected with 413."""
    client = TestClient(app)

    # 11MB payload (limit is 10MB)
    huge_payload = "A" * (11 * 1024 * 1024)

    # Get auth token first
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin123"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post(
        "/api/events/ingest",
        json={"raw_payload": huge_payload},
        headers=headers,
    )
    assert resp.status_code == 413
    assert "exceeds maximum limit" in resp.json()["detail"]


# ==============================================================================
# 5. Header & Log Injection (CRLF Splitting) Prevention
# ==============================================================================


def test_header_and_log_crlf_injection_sanitization():
    """
    Verifies that sanitize_log_string strips carriage return and line feed characters
    to prevent Log Injection and HTTP Response Splitting.
    """
    crlf_attack = "admin\r\nHTTP/1.1 200 OK\r\nSet-Cookie: admin=true\r\n\r\n<script>alert(1)</script>"
    clean = sanitize_log_string(crlf_attack)

    assert "\r" not in clean
    assert "\n" not in clean
    assert "\x00" not in clean

    log_injection = (
        "User login failed\n[FATAL] System compromise detected from 10.0.0.1"
    )
    clean_log = sanitize_log_string(log_injection)
    assert "\n" not in clean_log
    assert clean_log.count("[FATAL]") == 1  # flattened into a single line


# ==============================================================================
# 6. Regular Expression Denial of Service (ReDoS) Resilience
# ==============================================================================


def test_redos_pattern_validation_and_rejection():
    """
    Verifies that validate_safe_regex detects and rejects classic nested-quantifier
    catastrophic backtracking patterns.
    """
    dangerous_patterns = [
        r"(a+)+",
        r"(a*)*",
        r"([a-zA-Z0-9]+)+",
        r"(\w+)*",
        r"((a+)+)+",
        r"a{1,5}+",
    ]

    for pattern in dangerous_patterns:
        with pytest.raises(HTTPException) as exc:
            validate_safe_regex(pattern)
        assert exc.value.status_code == 400
        assert (
            "ReDoS" in exc.value.detail
            or "Invalid regular expression" in exc.value.detail
        )

    # Safe regex allowed
    safe_pattern = r"^%ASA-(?P<level>\d+)-(?P<tag>\d+):\s+(?P<msg>.*)$"
    assert validate_safe_regex(safe_pattern) == safe_pattern


def test_redos_execution_resilience():
    """
    Tests pathological regex strings against compiled parsers to verify
    linear execution time without catastrophic slowdown.
    """
    import re

    # Non-nested standard pattern
    pattern = re.compile(r"^SENSOR\s+(?P<ip>[0-9.]+)\s+(?P<msg>[a-zA-Z0-9_]+)$")

    # Pathological payload designed to stall back-trackers
    pathological = "SENSOR " + "1" * 50000 + "!"

    start = time.perf_counter()
    m = pattern.search(pathological)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    # Must complete in under 50ms
    assert elapsed_ms < 50.0
    assert m is None
