"""
Unit & Integration Tests: Outbox Delivery State Machine & Dual-Sink Reliability
Verifies that DELIVERY_COMPLETE strictly requires BOTH OpenSearch ACK + Parquet ACK.
Tests that single-sink failures remain durable and retryable without data loss.
"""

from unittest.mock import MagicMock

import pytest

from ulpf.packages.schemas.models import (
    EventEnvelope,
    FormatType,
    ParsingMetadata,
    RawStorageRef,
    SourceMetadata,
)
from ulpf.services.storage.outbox import OutboxManager, OutboxState


@pytest.fixture
def sample_envelope():
    return EventEnvelope(
        event_id="outbox-evt-1001",
        source=SourceMetadata(
            vendor="Palo Alto",
            product="PAN-OS",
            detected_format=FormatType.CEF,
            collector_host="ulpf-collector-01",
        ),
        raw=RawStorageRef(
            bucket="ulpf-raw",
            object_key="2026/09/03/outbox-evt-1001.raw",
            sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
            byte_length=150,
            raw_payload="CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|allow|1|src=10.1.1.5 dst=10.2.2.8",
        ),
        ocsf={
            "class_uid": 4001,
            "class_name": "Network Activity",
            "action": "allow",
        },
        parsing=ParsingMetadata(
            parser_used="palo-alto-cef",
            parser_version="1.0.0",
        ),
        traceability={
            "trace_id": "trace-outbox-001",
            "processing_status": "VALIDATED",
        },
    )


def test_outbox_requires_both_opensearch_and_parquet_ack(tmp_path, sample_envelope):
    """
    Confirms that DELIVERY_COMPLETE is only achieved when BOTH sinks succeed.
    """
    db_file = str(tmp_path / "outbox.db")
    outbox = OutboxManager(db_path=db_file)

    # 1. Happy Path: Both sinks succeed
    mock_search = MagicMock()
    mock_data_lake = MagicMock()

    success = outbox.deliver_event(sample_envelope, mock_search, mock_data_lake)
    assert success is True

    status = outbox.get_outbox_status(sample_envelope.event_id)
    assert status["state"] == OutboxState.DELIVERY_COMPLETE
    assert status["opensearch_ack"] is True
    assert status["parquet_ack"] is True
    assert status["attempt_count"] == 1


def test_outbox_opensearch_failure_keeps_event_durable_and_retryable(
    tmp_path, sample_envelope
):
    """
    If OpenSearch fails but Parquet succeeds:
    - Event must NOT be marked DELIVERY_COMPLETE.
    - opensearch_ack = False, parquet_ack = True.
    - state = FAILED_RETRYABLE.
    """
    db_file = str(tmp_path / "outbox.db")
    outbox = OutboxManager(db_path=db_file)

    mock_search = MagicMock()
    mock_search.index_event.side_effect = ConnectionError(
        "OpenSearch cluster unreachable (503)"
    )
    mock_data_lake = MagicMock()

    success = outbox.deliver_event(sample_envelope, mock_search, mock_data_lake)
    assert success is False

    status = outbox.get_outbox_status(sample_envelope.event_id)
    assert status["state"] == OutboxState.FAILED_RETRYABLE
    assert status["opensearch_ack"] is False
    assert status["parquet_ack"] is True
    assert status["next_attempt_at"] is not None
    assert status["next_attempt_at"] > 0

    # Verify backoff prevents immediate tight-loop retry
    assert outbox.retry_pending_outbox(mock_search, mock_data_lake) == 0

    # Now simulate OpenSearch recovering: retry pending outbox once backoff elapsed
    mock_search.index_event.side_effect = None  # Recovered!
    repaired_count = outbox.retry_pending_outbox(
        mock_search, mock_data_lake, force=True
    )
    assert repaired_count == 1

    final_status = outbox.get_outbox_status(sample_envelope.event_id)
    assert final_status["state"] == OutboxState.DELIVERY_COMPLETE
    assert final_status["opensearch_ack"] is True
    assert final_status["parquet_ack"] is True


def test_outbox_parquet_failure_keeps_event_durable_and_retryable(
    tmp_path, sample_envelope
):
    """
    If Parquet data lake fails but OpenSearch succeeds:
    - Event must NOT be marked DELIVERY_COMPLETE.
    - opensearch_ack = True, parquet_ack = False.
    - state = FAILED_RETRYABLE.
    """
    db_file = str(tmp_path / "outbox.db")
    outbox = OutboxManager(db_path=db_file)

    mock_search = MagicMock()
    mock_data_lake = MagicMock()
    mock_data_lake.write_batch.side_effect = OSError("Disk full on parquet partition")

    success = outbox.deliver_event(sample_envelope, mock_search, mock_data_lake)
    assert success is False

    status = outbox.get_outbox_status(sample_envelope.event_id)
    assert status["state"] == OutboxState.FAILED_RETRYABLE
    assert status["opensearch_ack"] is True
    assert status["parquet_ack"] is False
    assert status["next_attempt_at"] is not None
    assert status["next_attempt_at"] > 0

    # Verify backoff prevents immediate tight-loop retry
    assert outbox.retry_pending_outbox(mock_search, mock_data_lake) == 0

    # Simulate disk freed: retry pending outbox once backoff elapsed
    mock_data_lake.write_batch.side_effect = None  # Recovered!
    repaired_count = outbox.retry_pending_outbox(
        mock_search, mock_data_lake, force=True
    )
    assert repaired_count == 1

    final_status = outbox.get_outbox_status(sample_envelope.event_id)
    assert final_status["state"] == OutboxState.DELIVERY_COMPLETE
    assert final_status["opensearch_ack"] is True
    assert final_status["parquet_ack"] is True
