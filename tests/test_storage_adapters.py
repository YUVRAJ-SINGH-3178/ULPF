"""
Unit & Integration Tests for Storage Adapters
Verifies LocalRawStore, MinIORawStore, SQLiteSearchStore, and OpenSearchStore compliance with contracts.
"""

import hashlib
from unittest.mock import MagicMock

from ulpf.packages.config.settings import Settings
from ulpf.packages.schemas.models import (
    EventEnvelope,
    FormatType,
    ParsingMetadata,
    RawStorageRef,
    SourceMetadata,
)
from ulpf.services.storage.raw_store import (
    LocalRawStore,
    MinIORawStore,
    get_raw_store,
)
from ulpf.services.storage.search_index import (
    OpenSearchStore,
    SQLiteSearchStore,
    get_search_store,
)


def test_local_raw_store_byte_preservation_and_integrity(tmp_path):
    store = LocalRawStore(base_dir=str(tmp_path / "raw_store"))
    raw_payload = (
        "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection"
    )
    event_id = "test-uuid-001"

    # 1. Store
    ref = store.store_raw(raw_payload, event_id, source_meta={"vendor": "Cisco"})
    assert ref.byte_length == len(raw_payload.encode("utf-8"))
    assert ref.sha256 == hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

    # 2. Retrieve
    retrieved_text, ret_ref = store.retrieve_raw(event_id)
    assert retrieved_text == raw_payload
    assert ret_ref.sha256 == ref.sha256

    # 3. Verify integrity (untampered)
    res = store.verify_integrity(event_id)
    assert res.is_valid is True
    assert res.tampered is False
    assert res.computed_sha256 == ref.sha256

    # 4. Simulate tamper and verify detection
    store.tamper_for_test(event_id, " [UNAUTHORIZED_MODIFICATION]")
    tamper_res = store.verify_integrity(event_id)
    assert tamper_res.is_valid is False
    assert tamper_res.tampered is True


def test_minio_raw_store_contract(monkeypatch):
    # Mock Minio client to test MinIORawStore without live server
    mock_minio_cls = MagicMock()
    mock_client = MagicMock()
    mock_minio_cls.return_value = mock_client
    mock_client.bucket_exists.return_value = True

    monkeypatch.setattr("minio.Minio", mock_minio_cls)

    store = MinIORawStore(
        endpoint="localhost:9000",
        access_key="admin",
        secret_key="secret123",
        bucket="test-ulpf-raw",
    )

    raw_payload = "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|allow|1|src=10.0.0.1"
    event_id = "minio-event-101"

    # Store raw
    ref = store.store_raw(raw_payload, event_id)
    assert ref.bucket == "test-ulpf-raw"
    assert ref.sha256 == hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
    assert mock_client.put_object.call_count >= 2  # Raw bytes + companion metadata

    # Health check
    health = store.health_check()
    assert health["status"] == "HEALTHY"
    assert health["backend"] == "MinIORawStore"


def test_sqlite_search_store_indexing_and_search(tmp_path):
    db_file = tmp_path / "test_search.db"
    store = SQLiteSearchStore(db_path=str(db_file))

    raw_text = "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|allow|1|src=192.168.1.50 dst=10.0.0.1"
    env = EventEnvelope(
        event_id="env-uuid-123",
        source=SourceMetadata(
            vendor="Palo Alto", product="PAN-OS", detected_format=FormatType.CEF
        ),
        raw=RawStorageRef(
            bucket="ulpf-raw",
            object_key="2026-08-30/env-uuid-123.raw",
            sha256=hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
            byte_length=len(raw_text.encode("utf-8")),
            raw_payload=raw_text,
        ),
        parsing=ParsingMetadata(parser_used="palo-alto-parser", parser_version="1.0.0"),
        ocsf={
            "class_uid": 4001,
            "class_name": "Network Activity",
            "severity_id": 1,
            "severity": "Informational",
            "disposition": "Allowed",
            "src_endpoint": {"ip": "192.168.1.50", "port": 54321},
            "dst_endpoint": {"ip": "10.0.0.1", "port": 80},
        },
    )

    store.index_event(env)

    # Query event by ID
    event_dict = store.get_event_by_id("env-uuid-123")
    assert event_dict is not None
    assert event_dict["vendor"] == "Palo Alto"
    assert event_dict["src_ip"] == "192.168.1.50"

    # Faceted search
    search_res = store.search_events(vendor="Palo Alto", src_ip="192.168.1.50")
    assert search_res["total"] == 1
    assert search_res["events"][0]["event_id"] == "env-uuid-123"

    # Metrics summary
    summary = store.get_metrics_summary()
    assert summary["total_events"] == 1
    assert "Palo Alto" in summary["vendor_distribution"]


def test_opensearch_store_contract(monkeypatch):
    mock_opensearch_cls = MagicMock()
    mock_client = MagicMock()
    mock_opensearch_cls.return_value = mock_client
    mock_client.cluster.health.return_value = {"status": "green", "number_of_nodes": 1}

    monkeypatch.setattr("opensearchpy.OpenSearch", mock_opensearch_cls)

    store = OpenSearchStore(url="http://localhost:9200", index_prefix="test-events")

    health = store.health_check()
    assert health["status"] == "HEALTHY"
    assert health["backend"] == "OpenSearchStore"


def test_factories_with_settings(tmp_path):
    # Test local factory mode
    s_local = Settings(
        ULPF_STORAGE_BACKEND="local",
        ULPF_SEARCH_BACKEND="sqlite",
        ULPF_BASE_DATA_DIR=str(tmp_path),
        ULPF_DEMO_MODE=True,
    )
    raw_store = get_raw_store(s_local)
    search_store = get_search_store(s_local)
    assert isinstance(raw_store, LocalRawStore)
    assert isinstance(search_store, SQLiteSearchStore)
