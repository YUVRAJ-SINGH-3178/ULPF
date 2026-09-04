"""
Unit & Integration Tests: Authentication, Configuration, and State Persistence
Tests Phase 2 production requirements: JWT tokens, password hashing, demo mode toggle,
fail-fast validation, refresh tokens, and state survival across restart.
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from ulpf.apps.api.auth import (
    LoginRequest,
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    verify_user,
)
from ulpf.apps.api.main import app
from ulpf.packages.config.settings import Settings, reset_settings
from ulpf.packages.schemas.models import FormatType, ParserDefinition
from ulpf.services.onboarding.session_manager import OnboardingSessionManager
from ulpf.services.parser_engine.registry import ParserRegistry


@pytest.fixture(autouse=True)
def restore_settings():
    yield
    reset_settings()


def test_settings_fail_fast_in_prod_mode():
    """Confirms that in non-demo mode, a missing secret key fails fast at startup."""
    with pytest.raises(ValidationError):
        Settings(ULPF_DEMO_MODE=False, ULPF_SECRET_KEY=None)

    with pytest.raises(ValidationError):
        Settings(ULPF_DEMO_MODE=False, ULPF_SECRET_KEY="short")

    # Valid secret in non-demo mode
    valid_settings = Settings(
        ULPF_DEMO_MODE=False, ULPF_SECRET_KEY="12345678901234567890"
    )
    assert valid_settings.ULPF_SECRET_KEY == "12345678901234567890"


def test_password_hashing_and_verification():
    """Verifies salted bcrypt password hashing and verification."""
    pwd = "SuperSecretPassword123!"
    h = hash_password(pwd)
    assert h.startswith("$2b$")
    assert verify_password(pwd, h) is True
    assert verify_password("WrongPassword", h) is False


def test_auth_login_and_refresh_flow():
    """Tests /api/auth/login and /api/auth/refresh endpoints."""
    client = TestClient(app)

    # 1. Successful Login
    resp = client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin123"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["username"] == "admin"
    assert data["role"] == "ADMIN"

    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    # 2. Authenticated /me check
    me_resp = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "admin"

    # 3. Refresh token exchange
    ref_resp = client.post("/api/auth/refresh", json={"refresh_token": refresh_token})
    assert ref_resp.status_code == 200
    ref_data = ref_resp.json()
    assert "access_token" in ref_data
    assert ref_data["username"] == "admin"

    # 4. Invalid refresh token rejected
    bad_ref_resp = client.post(
        "/api/auth/refresh", json={"refresh_token": "corrupt-token-xxx"}
    )
    assert bad_ref_resp.status_code == 401


def test_auth_prod_mode_enforcement(monkeypatch):
    """Tests that when ULPF_DEMO_MODE=False, unauthenticated requests return 401."""
    custom_settings = Settings(
        ULPF_DEMO_MODE=False,
        ULPF_SECRET_KEY="production-secret-key-at-least-32-chars-long",
    )
    reset_settings(custom_settings)

    client = TestClient(app)

    # Without auth header -> must return 401
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401

    # With bad token -> must return 401
    resp_bad = client.get(
        "/api/auth/me", headers={"Authorization": "Bearer invalid.token.payload"}
    )
    assert resp_bad.status_code == 401


def test_demo_credentials_blocked_when_non_demo_mode():
    """
    Regression test: Built-in demo accounts (admin, operator, analyst, reviewer)
    MUST NOT be usable for authentication when ULPF_DEMO_MODE=False (production).
    """
    prod_settings = Settings(
        ULPF_DEMO_MODE=False,
        ULPF_SECRET_KEY="production-secret-key-at-least-32-chars-long",
    )
    reset_settings(prod_settings)

    client = TestClient(app)

    # 1. Direct verify_user call must return None for demo credentials
    assert verify_user(LoginRequest(username="admin", password="admin123")) is None
    assert (
        verify_user(LoginRequest(username="operator", password="operator123")) is None
    )
    assert verify_user(LoginRequest(username="analyst", password="analyst123")) is None
    assert (
        verify_user(LoginRequest(username="reviewer", password="reviewer123")) is None
    )

    # 2. Login endpoint must reject all built-in demo credentials with 401
    demo_creds = [
        ("admin", "admin123"),
        ("operator", "operator123"),
        ("analyst", "analyst123"),
        ("reviewer", "reviewer123"),
    ]
    for username, password in demo_creds:
        resp = client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )
        assert resp.status_code == 401, (
            f"Expected 401 for demo user {username} in production mode, got {resp.status_code}"
        )
        assert "Invalid username or password" in resp.json().get("detail", "")

    # 3. Even if a JWT is crafted with a demo user name, get_current_user must reject it
    token = create_access_token(data={"sub": "admin", "role": "ADMIN"})
    me_resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 401
    assert (
        "Built-in demo accounts are disabled in production mode"
        in me_resp.json().get("detail", "")
    )

    # 4. Refresh token for demo user must also be rejected
    ref_token = create_refresh_token(data={"sub": "admin", "role": "ADMIN"})
    ref_resp = client.post(
        "/api/auth/refresh",
        json={"refresh_token": ref_token},
    )
    assert ref_resp.status_code == 401
    assert (
        "Built-in demo accounts are disabled in production mode"
        in ref_resp.json().get("detail", "")
    )


def test_state_persistence_across_restart(tmp_path):
    """
    Asserts that ParserRegistry and OnboardingSessionManager persist all state,
    dynamic rules, and audit trails across process restarts.
    """
    parsers_dir = tmp_path / "parsers"
    sessions_dir = tmp_path / "sessions"

    # Process 1: Create registry, register a dynamic parser, and start an onboarding session
    reg1 = ParserRegistry(persistence_dir=str(parsers_dir))
    session_mgr1 = OnboardingSessionManager(
        parser_registry=reg1, persistence_dir=str(sessions_dir)
    )

    # 1. Register a custom parser
    p_def = ParserDefinition(
        parser_id="custom-sensor-parser",
        vendor="CustomSensor",
        product="Sensor-V1",
        version="1.0.0",
        format=FormatType.PROPRIETARY,
        pattern=r"^SENSOR (?P<src_ip>\S+) (?P<msg>.*)$",
        rules=[],
    )
    reg1.register_parser_definition(p_def)

    # 2. Ingest unknown log to create onboarding session
    session = session_mgr1.process_unknown_log(
        raw_payload="SENSOR 10.0.0.1 SYSTEM_STATUS_OK",
        vendor_hint="CustomSensor",
        product_hint="Sensor-V1",
    )
    session_id = session.session_id
    assert session_id is not None

    # Simulate Process Restart (creating fresh instances pointing to the same directories)
    reg2 = ParserRegistry(persistence_dir=str(parsers_dir))
    session_mgr2 = OnboardingSessionManager(
        parser_registry=reg2, persistence_dir=str(sessions_dir)
    )

    # Verify parser survived restart
    loaded_parser = reg2.get_parser("custom-sensor-parser")
    assert loaded_parser is not None
    assert loaded_parser.vendor == "CustomSensor"

    # Verify onboarding session survived restart
    loaded_session = session_mgr2.get_session(session_id)
    assert loaded_session is not None
    assert loaded_session["session_id"] == session_id
    assert len(loaded_session["raw_sample_logs"]) == 1

    # Approve and publish on restarted process
    pub_res = session_mgr2.approve_and_publish(
        session_id=session_id, reviewed_by="admin-user", version="1.0.0"
    )
    assert pub_res["success"] is True

    # Check audit trail persistence across a 3rd restart
    session_mgr3 = OnboardingSessionManager(
        parser_registry=reg2, persistence_dir=str(sessions_dir)
    )
    audits = session_mgr3.get_audit_trail()
    assert len(audits) >= 1
    assert any(a["action"] == "ONBOARDING_APPROVED_AND_PUBLISHED" for a in audits)


def test_production_credentials_fail_fast():
    """Confirms production mode strictly rejects default/weak credentials."""
    # 1. Reject default minioadmin
    with pytest.raises(ValidationError) as exc:
        Settings(
            ULPF_DEMO_MODE=False,
            ULPF_SECRET_KEY="A" * 32,
            ULPF_STORAGE_BACKEND="minio",
            ULPF_MINIO_ENDPOINT="minio:9000",
            ULPF_MINIO_ACCESS_KEY="minioadmin",
            ULPF_MINIO_SECRET_KEY="valid-secret-key-12345",
        )
    assert "strictly forbidden in production" in str(exc.value)

    # 2. Reject plaintext OpenSearch URL in production
    with pytest.raises(ValidationError) as exc:
        Settings(
            ULPF_DEMO_MODE=False,
            ULPF_SECRET_KEY="A" * 32,
            ULPF_SEARCH_BACKEND="opensearch",
            ULPF_OPENSEARCH_URL="http://opensearch:9200",
            ULPF_OPENSEARCH_USERNAME="ulpf_writer",
            ULPF_OPENSEARCH_PASSWORD="StrongProductionPassword123!",
        )
    assert "strictly forbidden in production" in str(exc.value)

    # 3. Reject default OpenSearch password
    with pytest.raises(ValidationError) as exc:
        Settings(
            ULPF_DEMO_MODE=False,
            ULPF_SECRET_KEY="A" * 32,
            ULPF_SEARCH_BACKEND="opensearch",
            ULPF_OPENSEARCH_URL="https://opensearch:9200",
            ULPF_OPENSEARCH_USERNAME="ulpf_writer",
            ULPF_OPENSEARCH_PASSWORD="admin",
        )
    assert "strictly forbidden in production" in str(exc.value)

    # 3. Verify redaction masks secrets
    s = Settings(
        ULPF_DEMO_MODE=True,
        ULPF_SECRET_KEY="my-secret-key-123456789",
    )
    redacted = s.to_redacted_dict()
    assert redacted["ULPF_SECRET_KEY"] == "********"
    assert "********" in repr(s)
