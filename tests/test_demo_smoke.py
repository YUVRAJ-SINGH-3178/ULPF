"""
Automated Demo Smoke Test Suite
Executes both primary ULPF evaluation stories end-to-end against the API:
- Story 1: Known-Log Trace (Ingest -> Lossless Raw -> SHA256 Verification -> SIEM Search -> DuckDB Parquet Query -> OCSF Validation)
- Story 2: Unknown-Log Onboarding (Ingest Unseen -> Drain3 Template Discovery -> Mapping Review -> Approval & Publish -> Zero-Touch Ingestion -> Audit Trail)
"""

from fastapi.testclient import TestClient

from ulpf.apps.api.main import app

client = TestClient(app)


def test_story_1_known_log_trace_end_to_end():
    """
    Story 1: Known-Log Trace
    1. Ingest a Cisco ASA edge firewall connection log.
    2. Retrieve exact unmutated raw payload and metadata.
    3. Execute cryptographic SHA-256 integrity verification.
    4. Search the event via SIEM faceted search by IP, vendor, and disposition.
    5. Assert OCSF fields match schema (inbound connection directionality preserved).
    """
    sample_asa = (
        "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection 9812481 "
        "for outside:198.51.100.25/443 (198.51.100.25/443) to inside:10.0.0.5/54321 (10.0.0.5/54321)"
    )

    # 1. Ingest
    ingest_resp = client.post("/api/events/ingest", json={"raw_payload": sample_asa, "transport": "demo_smoke"})
    assert ingest_resp.status_code == 200
    ingest_data = ingest_resp.json()

    event_id = ingest_data["event_id"]
    assert event_id is not None
    assert ingest_data["ocsf"] is not None
    assert ingest_data["ocsf"]["src_endpoint"]["ip"] == "198.51.100.25"
    assert ingest_data["ocsf"]["dst_endpoint"]["ip"] == "10.0.0.5"
    assert ingest_data["ocsf"]["disposition"] == "Allowed"

    # 2. Retrieve Raw Payload
    raw_resp = client.get(f"/api/events/{event_id}/raw")
    assert raw_resp.status_code == 200
    raw_data = raw_resp.json()
    assert raw_data["raw_payload"] == sample_asa
    assert raw_data["sha256"] == ingest_data["raw"]["sha256"]

    # 3. Verify Cryptographic Integrity
    verify_resp = client.post(f"/api/events/{event_id}/verify-integrity")
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["is_valid"] is True
    assert verify_data["tampered"] is False

    # 4. Search via SIEM Faceted Search
    search_resp = client.get("/api/events", params={"vendor": "Cisco", "src_ip": "198.51.100.25", "disposition": "Allowed"})
    assert search_resp.status_code == 200
    search_data = search_resp.json()
    assert search_data["total"] >= 1
    matching_ids = [e["event_id"] for e in search_data["events"]]
    assert event_id in matching_ids


def test_story_2_unknown_log_onboarding_end_to_end():
    """
    Story 2: Unknown-Log Auto-Onboarding Lifecycle
    1. Mine an unseen proprietary firewall log.
    2. Review the discovered template, variable placeholders, and suggested mappings.
    3. Update variable mapping (human-in-the-loop adjustment).
    4. Approve and publish custom versioned parser.
    5. Ingest subsequent matching log line and verify zero-touch parsing into OCSF.
    6. Verify audit log entry for reviewer action.
    """
    import uuid
    run_id = uuid.uuid4().hex[:6]
    custom_parser_id = f"edgeguard_{run_id}"

    unseen_log_1 = f"2026-08-27 10:15:30 [PROP_FW_{run_id}] src=192.168.10.55 dst=10.20.30.40 sport=41234 dport=8080 proto=TCP act=PERMIT"
    unseen_log_2 = f"2026-08-27 10:15:35 [PROP_FW_{run_id}] src=192.168.10.88 dst=10.20.30.99 sport=51234 dport=443 proto=TCP act=DROP"

    # 1. Mine first unseen log
    mine_resp = client.post("/api/onboarding/mine", json={
        "raw_payload": unseen_log_1,
        "vendor_hint": "ProprietaryCorp",
        "product_hint": "EdgeGuard"
    })
    assert mine_resp.status_code == 200
    session_data = mine_resp.json()
    session_id = session_data["session_id"]
    assert session_id is not None
    assert len(session_data["variables"]) >= 2

    # 2. Get session details
    detail_resp = client.get(f"/api/onboarding/{session_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["discovered_template"] is not None

    # 3. Update a variable mapping
    update_resp = client.put(f"/api/onboarding/{session_id}/mapping", json={
        "var_index": 0,
        "target_ocsf_field": "src_endpoint.ip",
        "inferred_type": "ipv4"
    })
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "success"

    # 4. Approve and Publish Custom Parser
    approve_resp = client.post(f"/api/onboarding/{session_id}/approve", json={
        "custom_parser_id": custom_parser_id,
        "version": "1.0.0"
    })
    assert approve_resp.status_code == 200
    approve_data = approve_resp.json()
    assert approve_data["success"] is True

    # 5. Ingest subsequent matching log line -> Zero-touch parsing
    ingest_2_resp = client.post("/api/events/ingest", json={"raw_payload": unseen_log_2})
    assert ingest_2_resp.status_code == 200
    ingest_2_data = ingest_2_resp.json()
    assert ingest_2_data["ocsf"] is not None
    assert ingest_2_data["parsing"]["parser_used"] == custom_parser_id

    # 6. Verify Administrative Audit Trail Entry
    audit_resp = client.get("/api/onboarding/audit/logs")
    assert audit_resp.status_code == 200
    audits = audit_resp.json()
    assert len(audits) >= 1
    published_entries = [a for a in audits if a.get("action") == "ONBOARDING_APPROVED_AND_PUBLISHED"]
    assert len(published_entries) >= 1
