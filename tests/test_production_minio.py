"""
Unit & Integration Tests: MinIO Production Path & Deterministic Direct Object Lookup
Verifies that MinIORawStore uses direct deterministic key lookups and NEVER scans the bucket
with list_objects(recursive=True) during normal operations.
"""

import hashlib
from unittest.mock import MagicMock

import pytest

from ulpf.packages.schemas.models import VerificationResult
from ulpf.services.storage.raw_store import MinIORawStore


@pytest.fixture
def mock_minio():
    """Mock MinIO client simulating S3 storage."""
    mock_minio_cls = MagicMock()
    mock_client = MagicMock()
    mock_minio_cls.return_value = mock_client
    mock_client.bucket_exists.return_value = True

    # In-memory storage dictionary
    store_data: dict[str, bytes] = {}

    def fake_put_object(bucket_name, object_name, data, length, **kwargs):
        content = data.read()
        store_data[f"{bucket_name}/{object_name}"] = content
        return MagicMock()

    def fake_get_object(bucket_name, object_name):
        key = f"{bucket_name}/{object_name}"
        if key not in store_data:
            raise KeyError(f"NoSuchKey: {key}")
        content = store_data[key]
        mock_resp = MagicMock()
        mock_resp.read.return_value = content
        mock_resp.close.return_value = None
        mock_resp.release_conn.return_value = None
        return mock_resp

    mock_client.put_object.side_effect = fake_put_object
    mock_client.get_object.side_effect = fake_get_object

    return mock_client, store_data


def test_minio_deterministic_direct_lookup_without_scanning(monkeypatch, mock_minio):
    """
    Verifies that retrieving an event or verifying integrity performs direct
    deterministic key resolution and NEVER invokes list_objects.
    """
    mock_client, store_data = mock_minio
    monkeypatch.setattr("minio.Minio", lambda **kwargs: mock_client)

    store = MinIORawStore(
        endpoint="minio.internal:9000",
        access_key="valid-access-key-12345",
        secret_key="valid-secret-key-12345",
        bucket="ulpf-raw-production",
    )

    # Ingest 50 events to simulate a populated store
    event_payloads = {}
    for i in range(50):
        eid = f"event-uuid-{i:04d}"
        payload = f"CEF:0|VendorX|ProductY|1.0|LOGIN|auth_success|1|src=10.0.0.{i % 250} user=user_{i}"
        event_payloads[eid] = payload
        store.store_raw(
            payload, eid, source_meta={"vendor": "VendorX", "product": "ProductY"}
        )

    # Reset list_objects call counter
    mock_client.list_objects.reset_mock()

    # Flush in-memory meta cache to simulate cold-start / worker restart lookup
    store._meta_index.clear()

    # 1. Retrieve a specific event on cold cache
    target_id = "event-uuid-0027"
    retrieved_raw, storage_ref = store.retrieve_raw(target_id)
    assert retrieved_raw == event_payloads[target_id]
    assert (
        storage_ref.sha256
        == hashlib.sha256(event_payloads[target_id].encode("utf-8")).hexdigest()
    )

    # CRITICAL: Verify list_objects was NEVER called!
    mock_client.list_objects.assert_not_called()

    # 2. Verify Cryptographic Integrity on cold cache
    store._meta_index.clear()
    verif: VerificationResult = store.verify_integrity("event-uuid-0042")
    assert verif.is_valid is True
    assert verif.tampered is False
    assert (
        verif.computed_sha256
        == hashlib.sha256(event_payloads["event-uuid-0042"].encode("utf-8")).hexdigest()
    )

    # CRITICAL: list_objects must still NEVER be called!
    mock_client.list_objects.assert_not_called()


def test_minio_retrieve_by_storage_uri(monkeypatch, mock_minio):
    """Verifies direct O(1) retrieval using raw_storage_uri ('bucket/object_key')."""
    mock_client, store_data = mock_minio
    monkeypatch.setattr("minio.Minio", lambda **kwargs: mock_client)

    store = MinIORawStore(
        endpoint="minio.internal:9000",
        access_key="valid-access-key-12345",
        secret_key="valid-secret-key-12345",
        bucket="ulpf-raw-production",
    )

    raw_text = (
        "LEEF:2.0|Fortinet|FortiGate|6.4.5|traffic:101|src=172.16.1.10 dst=8.8.8.8"
    )
    ref = store.store_raw(raw_text, "leef-event-999")
    uri = f"{ref.bucket}/{ref.object_key}"

    # Clear cache and retrieve directly by URI
    store._meta_index.clear()
    mock_client.list_objects.reset_mock()

    retrieved_text, ret_ref = store.retrieve_by_storage_uri(uri)
    assert retrieved_text == raw_text
    assert ret_ref.sha256 == ref.sha256
    assert ret_ref.byte_length == len(raw_text.encode("utf-8"))
    mock_client.list_objects.assert_not_called()
