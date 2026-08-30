"""
Unit Tests: Lossless Raw Event Preservation & Cryptographic SHA-256 Verification
"""

import hashlib
import os
import shutil
import tempfile
import pytest

from ulpf.services.storage.raw_store import ImmutableRawStore


@pytest.fixture
def temp_raw_store():
    temp_dir = tempfile.mkdtemp()
    store = ImmutableRawStore(base_dir=temp_dir)
    yield store
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_lossless_round_trip_preservation(temp_raw_store):
    raw_payload = "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection 9812481 for outside:198.51.100.25/443 to inside:10.0.0.5/54321"
    event_id = "test-event-uuid-001"

    # Store raw
    raw_ref = temp_raw_store.store_raw(raw_payload=raw_payload, event_id=event_id)

    # Assert hash
    expected_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
    assert raw_ref.sha256 == expected_hash
    assert raw_ref.byte_length == len(raw_payload.encode("utf-8"))

    # Retrieve raw
    retrieved_payload, storage_ref = temp_raw_store.retrieve_raw(event_id)
    assert retrieved_payload == raw_payload
    assert storage_ref.sha256 == expected_hash


def test_cryptographic_integrity_verification_success(temp_raw_store):
    raw_payload = "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|allow|1|src=198.51.100.88 dst=10.0.1.50 spt=61234 dpt=80 proto=TCP"
    event_id = "test-event-uuid-002"

    temp_raw_store.store_raw(raw_payload=raw_payload, event_id=event_id)
    verify_res = temp_raw_store.verify_integrity(event_id)

    assert verify_res.is_valid is True
    assert verify_res.tampered is False
    assert verify_res.stored_sha256 == verify_res.computed_sha256


def test_tamper_detection(temp_raw_store):
    raw_payload = '{"event_type":"alert","src_ip":"185.220.101.5","alert":{"signature":"ET SCAN SSH"}}'
    event_id = "test-event-uuid-003"

    temp_raw_store.store_raw(raw_payload=raw_payload, event_id=event_id)
    
    # Tamper payload on disk
    tampered = temp_raw_store.tamper_for_test(event_id, " [UNAUTHORIZED_MODIFICATION]")
    assert tampered is True

    # Verify integrity must now fail and flag tampering
    verify_res = temp_raw_store.verify_integrity(event_id)
    assert verify_res.is_valid is False
    assert verify_res.tampered is True
    assert verify_res.stored_sha256 != verify_res.computed_sha256
