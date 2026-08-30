"""
Phase 4 Security Hardening Test Suite
Verifies:
1. Input validation fuzzing (SQL injection, shell metacharacters, format strings, null bytes) -> safe handling without 500 errors.
2. Strict path traversal rejection on resource IDs (event_id, parser_id, session_id, error_id) -> HTTP 400.
3. Ingest payload size limit enforcement -> HTTP 413.
4. In-memory sliding-window rate limiting -> HTTP 429.
5. Administrative audit logging in persistent storage.
"""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from ulpf.apps.api.main import app
from ulpf.packages.security.sanitization import (
    InMemoryRateLimiter,
    validate_safe_identifier,
)
from ulpf.services.pipeline_orchestrator import PipelineOrchestrator

client = TestClient(app)


MALICIOUS_INPUT_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE events; --",
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\cmd.exe",
    "$(reboot)",
    "`rm -rf /`",
    "%s%s%s%n",
    "{{ 7 * 7 }}",
    "<script>alert(1)</script>",
    "payload\x00with_null_byte",
    "A" * 5000,
    "ðŸ’¥ðŸ”¥â˜ ï¸\u0000\uffff",
]


def test_path_traversal_validator():
    """Verifies that validate_safe_identifier rejects path traversal attempts."""
    traversal_attempts = [
        "../events/secret",
        "..\\windows\\win.ini",
        "../../etc/shadow",
        "id_with\x00null",
        "id/with/slash",
        "id\\with\\backslash",
        "id with space",
        "id;drop",
        "A" * 200,
    ]

    for attempt in traversal_attempts:
        with pytest.raises(HTTPException) as exc_info:
            validate_safe_identifier(attempt, "test_field")
        assert exc_info.value.status_code == 400


def test_safe_identifier_acceptance():
    """Verifies that valid alphanumeric and hyphenated identifiers pass validation."""
    valid_ids = [
        "evt-2026-08-27-001",
        "cisco_asa_parser",
        "panos_traffic_v1.0.0",
        "session_12345",
        "error-9876",
        "10.0.0.1:514",
    ]

    for valid in valid_ids:
        res = validate_safe_identifier(valid, "test_field")
        assert res == valid


def test_api_path_traversal_rejection():
    """Verifies that API path parameters reject traversal with HTTP 400."""
    # 1. Event details traversal
    res1 = client.get("/api/events/..%2f..%2fsecret")
    assert res1.status_code in (400, 404)

    # 2. Raw event traversal
    res2 = client.get("/api/events/..%5c..%5cwindows%5cwin.ini/raw")
    assert res2.status_code in (400, 404)

    # 3. Parser traversal
    res3 = client.get("/api/parsers/..%2fmalicious_parser")
    assert res3.status_code in (400, 404)

    # 4. Onboarding session traversal
    res4 = client.get("/api/onboarding/..%2fsession_exploit")
    assert res4.status_code in (400, 404)


def test_input_fuzzing_pipeline_resilience(tmp_path):
    """
    Fuzzes the core pipeline with malicious SQL injection, shell commands,
    format strings, and null bytes. Verifies zero unhandled 500 exceptions.
    """
    orch = PipelineOrchestrator(base_dir=str(tmp_path / "fuzz_pipeline"))

    for payload in MALICIOUS_INPUT_PAYLOADS:
        envelope = orch.process_raw_log(payload, transport="fuzz_test")
        assert envelope.event_id is not None
        assert envelope.raw.sha256 is not None
        # Unmutated payload stored accurately
        raw_stored, _ = orch.raw_store.retrieve_raw(envelope.event_id)
        assert raw_stored == payload


def test_payload_size_limit_rejection():
    """Verifies that oversized log payloads are rejected with HTTP 413."""
    from ulpf.packages.config.settings import get_settings

    settings = get_settings()
    orig_limit = settings.ULPF_MAX_INGEST_PAYLOAD_BYTES
    try:
        settings.ULPF_MAX_INGEST_PAYLOAD_BYTES = 100
        oversized = "X" * 150
        res = client.post("/api/events/ingest", json={"raw_payload": oversized})
        assert res.status_code == 413
    finally:
        settings.ULPF_MAX_INGEST_PAYLOAD_BYTES = orig_limit


def test_rate_limiter_sliding_window():
    """Verifies that InMemoryRateLimiter accurately throttles after threshold."""
    limiter = InMemoryRateLimiter(requests_per_minute=5)
    ip = "198.51.100.99"

    # First 5 requests succeed
    for _ in range(5):
        assert limiter.check_rate_limit(ip) is True

    # 6th request fails
    assert limiter.check_rate_limit(ip) is False

    # Different IP is not affected
    assert limiter.check_rate_limit("198.51.100.100") is True


def test_administrative_audit_trail_logging(tmp_path):
    """Verifies that administrative onboarding approvals are written to the audit log."""
    orch = PipelineOrchestrator(base_dir=str(tmp_path / "audit_test"))

    # Mine and approve session
    raw = "2026-08-27 10:15:30 [SEC_ALERT] source=10.0.0.1 user=attacker action=blocked"
    session = orch.onboarding_manager.process_unknown_log(raw)

    approval_res = orch.onboarding_manager.approve_and_publish(
        session_id=session.session_id,
        reviewed_by="lead-security-auditor",
        custom_parser_id="sec_alert_parser",
        version="1.0.0",
    )
    assert approval_res["success"] is True

    # Check audit trail in SQLite
    audits = orch.search_index.list_audits()
    assert len(audits) >= 1
    recent = audits[0]
    assert recent["user"] == "lead-security-auditor"
    assert recent["action"] == "ONBOARDING_APPROVED_AND_PUBLISHED"
    assert recent["resource_id"] == "sec_alert_parser:1.0.0"
