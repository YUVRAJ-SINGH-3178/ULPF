"""
Integration Tests: REST API Endpoints
"""

from fastapi.testclient import TestClient

from ulpf.apps.api.main import app

client = TestClient(app)


def test_api_health():
    resp = client.get("/api/pipeline/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"
    assert data["air_gapped"] is True


def test_api_pipeline_metrics():
    resp = client.get("/api/pipeline/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "realtime" in data
    assert "summary" in data


def test_api_ingest_single_and_verify():
    payload = "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection 9812481 for outside:198.51.100.25/443 to inside:10.0.0.5/54321"
    resp = client.post("/api/events/ingest", json={"raw_payload": payload})
    assert resp.status_code == 200
    data = resp.json()
    event_id = data["event_id"]
    assert event_id is not None
    assert data["raw"]["sha256"] is not None

    # Retrieve raw
    raw_resp = client.get(f"/api/events/{event_id}/raw")
    assert raw_resp.status_code == 200
    assert raw_resp.json()["raw_payload"] == payload

    # Verify integrity
    verify_resp = client.post(f"/api/events/{event_id}/verify-integrity")
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["is_valid"] is True
    assert verify_data["tampered"] is False


def test_api_list_parsers():
    resp = client.get("/api/parsers")
    assert resp.status_code == 200
    parsers = resp.json()
    assert len(parsers) >= 10


def test_api_benchmark_execution():
    resp = client.post(
        "/api/benchmark/run", json={"event_count": 500, "concurrency": 2}
    )
    assert resp.status_code == 200
    bench = resp.json()
    assert bench["throughput_eps"] > 0
    assert bench["total_events_processed"] == 500
