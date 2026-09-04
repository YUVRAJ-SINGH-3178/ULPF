"""
Unit & Integration Tests: OpenSearch Production Path & Forensic Separation
Verifies that OpenSearch indexing enforces deterministic _id = event_id,
includes forensic pointers (raw_storage_uri, sha256_hash, trace_id), and
strictly EXCLUDES raw_payload from OpenSearch documents in production.
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
from ulpf.services.storage.search_index import OpenSearchStore


@pytest.fixture
def mock_opensearch():
    mock_opensearch_cls = MagicMock()
    mock_client = MagicMock()
    mock_opensearch_cls.return_value = mock_client
    mock_client.cluster.health.return_value = {"status": "green", "number_of_nodes": 1}
    return mock_opensearch_cls, mock_client


def test_opensearch_excludes_raw_payload_and_preserves_forensic_pointers(
    monkeypatch, mock_opensearch
):
    """
    Verifies that OpenSearch documents contain OCSF, trace_id, sha256_hash,
    raw_storage_uri, and STRICTLY EXCLUDE raw_payload.
    """
    mock_cls, mock_client = mock_opensearch
    monkeypatch.setattr("opensearchpy.OpenSearch", mock_cls)

    store = OpenSearchStore(
        url="http://opensearch.internal:9200",
        username="ulpf_writer",
        password="ProductionPassword123!",
        index_prefix="ulpf-events-v1",
    )

    envelope = EventEnvelope(
        event_id="opensearch-evt-001",
        source=SourceMetadata(
            vendor="Cisco",
            product="ASA",
            detected_format=FormatType.SYSLOG_RFC3164,
            collector_host="ulpf-gateway-node",
        ),
        raw=RawStorageRef(
            bucket="ulpf-raw",
            object_key="year=2026/month=09/day=03/source=cisco/opensearch-evt-001.raw",
            sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            byte_length=120,
            raw_payload="%ASA-6-302013: Built inbound TCP connection 1001 for outside:198.51.100.25/443 to inside:10.0.1.50/51234",
        ),
        ocsf={
            "class_uid": 4001,
            "class_name": "Network Activity",
            "category_uid": 4,
            "action": "allow",
            "src_endpoint": {"ip": "198.51.100.25", "port": 443},
            "dst_endpoint": {"ip": "10.0.1.50", "port": 51234},
        },
        parsing=ParsingMetadata(
            parser_used="cisco-asa-parser",
            parser_version="1.0.0",
            confidence=0.98,
        ),
        traceability={
            "trace_id": "trace-uuid-abc-123",
            "processing_status": "INDEX_PENDING",
        },
    )

    # 1. Test document generation
    doc = store._envelope_to_doc(envelope)

    # STRICT ASSERTIONS:
    assert "raw_payload" not in doc, (
        "Security Violation: raw_payload MUST NOT be stored in OpenSearch"
    )
    assert (
        doc["raw_storage_uri"]
        == "ulpf-raw/year=2026/month=09/day=03/source=cisco/opensearch-evt-001.raw"
    )
    assert (
        doc["raw_sha256"]
        == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    )
    assert (
        doc["sha256_hash"]
        == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    )
    assert doc["trace_id"] == "trace-uuid-abc-123"
    assert doc["event_id"] == "opensearch-evt-001"
    assert doc["src_ip"] == "198.51.100.25"
    assert doc["dst_ip"] == "10.0.1.50"

    # 2. Test single index operation enforces _id = event_id
    store.index_event(envelope)
    mock_client.index.assert_called_once()
    call_kwargs = mock_client.index.call_args[1]
    assert call_kwargs["id"] == "opensearch-evt-001"
    assert "raw_payload" not in call_kwargs["body"]

    # 3. Test bulk index operation enforces _id = event_id
    mock_bulk = MagicMock()
    monkeypatch.setattr("opensearchpy.helpers.bulk", mock_bulk)
    store.index_batch([envelope])
    mock_bulk.assert_called_once()
    actions = mock_bulk.call_args[0][1]
    assert len(actions) == 1
    assert actions[0]["_id"] == "opensearch-evt-001"
    assert "raw_payload" not in actions[0]["_source"]
