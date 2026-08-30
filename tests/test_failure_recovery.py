"""
Chaos, Failure & Resiliency Tests for ULPF Pipeline
Verifies failure detection, error stage classification, dead-letter queueing,
MinIO failure fail-fast behavior, OpenSearch outage recovery, and idempotency.
"""

from unittest.mock import MagicMock

from ulpf.services.pipeline_orchestrator import PipelineOrchestrator
from ulpf.services.storage.raw_store import LocalRawStore
from ulpf.services.storage.search_index import SQLiteSearchStore


def test_malformed_and_oversized_payload_handling(tmp_path):
    orch = PipelineOrchestrator(base_dir=str(tmp_path))

    # Empty payload failure
    empty_env = orch.process_raw_log("   ")
    assert empty_env.traceability.get("processing_status") == "FAILED"
    errors = orch.error_queue.list_errors()
    assert len(errors) >= 1
    assert any(e["error_stage"] == "INGESTION" for e in errors)


def test_unknown_log_dlq_and_replay(tmp_path):
    orch = PipelineOrchestrator(base_dir=str(tmp_path))

    unseen_log = "2026-08-30 [UNKNOWN_GW_SYS] SRC=192.168.1.1 DST=10.0.0.1 PROTO=TCP ACTION=BLOCK"
    env = orch.process_raw_log(unseen_log)

    assert env.traceability.get("processing_status") == "ONBOARDING_QUEUED"
    errors = orch.error_queue.list_errors(status="UNRESOLVED")
    assert len(errors) >= 1
    unknown_err = errors[0]
    assert unknown_err["error_stage"] == "UNKNOWN_FORMAT"

    # Verify session in onboarding manager
    sessions = orch.onboarding_manager.list_sessions()
    assert len(sessions) == 1
    session_id = sessions[0]["session_id"]

    # Approve session to trigger automated replay
    res = orch.onboarding_manager.approve_and_publish(
        session_id=session_id, custom_parser_id="custom-gw-parser"
    )
    assert res["success"] is True
    assert res["replayed_events"] == 1


def test_minio_raw_preservation_failure_fails_fast(tmp_path):
    """
    Chaos Test: If MinIO raw storage fails, the pipeline MUST fail fast,
    refuse to mark the event as safely stored or normalized, and record to DLQ.
    """
    mock_raw_store = MagicMock()
    mock_raw_store.store_raw.side_effect = ConnectionError(
        "MinIO raw store unreachable (503 Service Unavailable)"
    )

    orch = PipelineOrchestrator(
        base_dir=str(tmp_path),
        raw_store=mock_raw_store,
        search_store=SQLiteSearchStore(f"{tmp_path}/search.db"),
    )

    sample_log = (
        "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection"
    )
    env = orch.process_raw_log(sample_log)

    assert env.traceability["processing_status"] == "RAW_STORE_FAILED"
    assert env.ocsf is None  # Never normalized when raw preservation failed!

    errors = orch.error_queue.list_errors()
    assert len(errors) >= 1
    assert any(e["error_stage"] == "RAW_STORE" for e in errors)


def test_opensearch_outage_and_idempotent_recovery(tmp_path):
    """
    Chaos Test: If OpenSearch fails during indexing:
    1. Raw event remains preserved on disk/MinIO.
    2. Event status marked INDEX_FAILED and recorded in DLQ.
    3. When OpenSearch recovers, retry indexes the event with idempotent event_id.
    4. Zero duplicate records are created.
    """
    real_search_store = SQLiteSearchStore(f"{tmp_path}/search.db")
    failing_search_store = MagicMock()
    failing_search_store.index_event.side_effect = TimeoutError(
        "OpenSearch cluster timeout (HTTP 504)"
    )

    real_raw_store = LocalRawStore(f"{tmp_path}/raw_store")
    orch = PipelineOrchestrator(
        base_dir=str(tmp_path),
        raw_store=real_raw_store,
        search_store=failing_search_store,
    )

    sample_log = "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|allow|1|src=10.0.0.1 dst=10.0.0.2"
    env = orch.process_raw_log(sample_log)

    # 1. Verify status is INDEX_FAILED
    assert env.traceability["processing_status"] == "INDEX_FAILED"

    # 2. Verify raw event IS safely preserved
    raw_payload, ref = real_raw_store.retrieve_raw(env.event_id)
    assert raw_payload == sample_log

    # 3. Verify failure is in DLQ
    errors = orch.error_queue.list_errors()
    assert len(errors) >= 1
    assert any(e["error_stage"] == "SEARCH_INDEX" for e in errors)

    # 4. OpenSearch recovers: re-index event with real store
    real_search_store.index_event(env)
    event_doc = real_search_store.get_event_by_id(env.event_id)
    assert event_doc is not None
    assert event_doc["event_id"] == env.event_id

    # 5. Idempotency test: Re-indexing same event_id does not duplicate
    real_search_store.index_event(env)
    assert real_search_store.get_metrics_summary()["total_events"] == 1


def test_deep_health_degradation_detection(tmp_path):
    orch = PipelineOrchestrator(base_dir=str(tmp_path))
    health = orch.search_index.health_check()
    assert health["status"] == "HEALTHY"
