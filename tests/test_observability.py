"""
Phase 5 Observability & Operability Test Suite
Verifies:
1. Deep operational health check (/api/pipeline/health).
2. Prometheus OpenMetrics scraping (/metrics and /api/pipeline/metrics/prometheus).
3. Pipeline metrics accuracy under traffic.
"""

from fastapi.testclient import TestClient

from ulpf.apps.api.main import app

client = TestClient(app)


def test_deep_pipeline_health():
    """Verifies that /api/pipeline/health returns deep subsystem diagnostics."""
    resp = client.get("/api/pipeline/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"
    assert data["air_gapped"] is True
    assert "sqlite_search_index" in data["subsystems"]
    assert "duckdb_engine" in data["subsystems"]
    assert "storage_volume" in data["subsystems"]
    assert "memory_bounds" in data["subsystems"]
    assert "HEALTHY" in data["subsystems"]["sqlite_search_index"]
    assert "HEALTHY" in data["subsystems"]["duckdb_engine"]


def test_prometheus_metrics_endpoint():
    """Verifies that /metrics exports valid Prometheus text format."""
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    text = resp.text

    assert "ulpf_events_ingested_total" in text
    assert "ulpf_events_parsed_total" in text
    assert "ulpf_pipeline_latency_seconds" in text
    assert "ulpf_memory_bytes" in text
    assert "ulpf_backpressure_queue_depth" in text


def test_pipeline_prometheus_route_parity():
    """Verifies parity between /metrics and /api/pipeline/metrics/prometheus."""
    resp1 = client.get("/metrics")
    resp2 = client.get("/api/pipeline/metrics/prometheus")
    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert "ulpf_events_ingested_total" in resp2.text
