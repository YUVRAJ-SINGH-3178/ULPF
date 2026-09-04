"""
Unit & Integration Tests: Traceability & Idempotent Ingestion
Verifies that duplicate ingestion of the same raw log or replaying an event
results in deterministic, idempotent indexing where _id = event_id and no uncontrolled
duplication occurs.
"""

from unittest.mock import MagicMock

from ulpf.packages.schemas.models import (
    EventEnvelope,
    FormatType,
    ParsingMetadata,
    RawStorageRef,
    SourceMetadata,
)
from ulpf.services.pipeline_orchestrator import PipelineOrchestrator
from ulpf.services.storage.search_index import OpenSearchStore, SQLiteSearchStore


def test_opensearch_idempotent_indexing_enforces_id_equality():
    """
    Verifies that multiple index_event calls with the same event_id target
    the identical document _id, ensuring update/upsert semantics rather than duplicate documents.
    """
    mock_opensearch_cls = MagicMock()
    mock_client = MagicMock()
    mock_opensearch_cls.return_value = mock_client

    store = OpenSearchStore.__new__(OpenSearchStore)
    store.client = mock_client
    store.index_prefix = "ulpf-events-v1"
    store.url = "http://localhost:9200"

    envelope = EventEnvelope(
        event_id="idempotent-event-001",
        source=SourceMetadata(
            vendor="Fortinet",
            product="FortiGate",
            detected_format=FormatType.LEEF,
        ),
        raw=RawStorageRef(
            bucket="ulpf-raw",
            object_key="2026/09/03/idempotent-event-001.raw",
            sha256="abc123hash",
            byte_length=100,
            raw_payload="LEEF:2.0|Fortinet|FortiGate|6.4.5|traffic|src=10.0.0.1",
        ),
        ocsf={"class_uid": 4001, "action": "allow"},
        parsing=ParsingMetadata(parser_used="fortinet-leef"),
    )

    # First index attempt
    store.index_event(envelope)
    assert mock_client.index.call_count == 1
    call1_kwargs = mock_client.index.call_args[1]
    assert call1_kwargs["id"] == "idempotent-event-001"

    # Second index attempt (simulating duplicate replay or re-delivery)
    store.index_event(envelope)
    assert mock_client.index.call_count == 2
    call2_kwargs = mock_client.index.call_args[1]
    assert call2_kwargs["id"] == "idempotent-event-001"
    assert call1_kwargs["id"] == call2_kwargs["id"]


def test_sqlite_search_store_idempotency(tmp_path):
    """
    Verifies that SQLiteSearchStore handles duplicate indexing of the same event_id
    idempotently without creating duplicate rows or integrity errors.
    """
    db_file = str(tmp_path / "idempotent_test.db")
    store = SQLiteSearchStore(db_path=db_file)

    envelope = EventEnvelope(
        event_id="sqlite-dedup-001",
        source=SourceMetadata(
            vendor="Checkpoint",
            product="Firewall-1",
            detected_format=FormatType.PROPRIETARY,
        ),
        raw=RawStorageRef(
            bucket="ulpf-raw",
            object_key="2026/09/03/sqlite-dedup-001.raw",
            sha256="checkpoint-hash-123",
            byte_length=80,
            raw_payload="FW-1: accept in eth0 proto tcp",
        ),
        ocsf={"class_uid": 4001, "action": "allow"},
        parsing=ParsingMetadata(parser_used="checkpoint-parser"),
    )

    # 1. Index first time
    store.index_event(envelope)
    event1 = store.get_event_by_id("sqlite-dedup-001")
    assert event1 is not None
    assert event1["event_id"] == "sqlite-dedup-001"

    # 2. Index identical event a second time
    store.index_event(envelope)
    search_results = store.search_events(vendor="Checkpoint")
    assert search_results["total"] == 1, "Expected exactly 1 document, no duplicates"


def test_pipeline_end_to_end_forensic_traceability(tmp_path):
    """
    Verifies that an event ingested through PipelineOrchestrator contains
    full forensic lineage linking the normalized event directly to raw bytes in storage.
    """
    orch = PipelineOrchestrator(base_dir=str(tmp_path))

    raw_log = "<134>1 2026-08-27T10:15:30.123Z edge-firewall PaloAlto 10.1.0 TRAFFIC allow 1 src=192.168.1.10 dst=10.0.0.5"
    envelope = orch.process_raw_log(
        raw_log, transport="syslog_tcp", client_ip="10.0.0.1"
    )

    # Verify cryptographic integrity of the ingested event
    verif = orch.verify_event_integrity(envelope.event_id)
    assert verif.is_valid is True
    assert verif.tampered is False
    assert verif.stored_sha256 == envelope.raw.sha256

    # Verify search store contains forensic pointers
    indexed_doc = orch.search_index.get_event_by_id(envelope.event_id)
    assert indexed_doc is not None
    assert (
        indexed_doc["raw_storage_uri"]
        == f"{envelope.raw.bucket}/{envelope.raw.object_key}"
    )
    assert indexed_doc["raw_sha256"] == envelope.raw.sha256
    assert envelope.traceability.get("processing_status") in (
        "COMPLETED",
        "DELIVERY_COMPLETE",
    )
    assert "DELIVERY_COMPLETE_DUAL_ACK" in envelope.traceability.get(
        "provenance_chain", []
    )
    outbox_status = orch.outbox.get_outbox_status(envelope.event_id)
    assert outbox_status["state"] == "DELIVERY_COMPLETE"
    assert outbox_status["opensearch_ack"] is True
    assert outbox_status["parquet_ack"] is True
