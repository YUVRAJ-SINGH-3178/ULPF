"""
Raw Envelope Generator & Lossless Capture Engine
Creates unmutated event envelopes, computes SHA-256, and ensures raw write-once storage BEFORE processing.
"""

import datetime
import uuid

from ulpf.packages.schemas.models import (
    EventEnvelope,
    FormatType,
    ParsingMetadata,
    SourceMetadata,
)
from ulpf.services.storage.raw_store import ImmutableRawStore


class EnvelopeFactory:
    """
    Constructs immutable event envelopes and immediately archives the raw payload into storage.
    """

    def __init__(self, raw_store: ImmutableRawStore | None = None):
        self.raw_store = raw_store or ImmutableRawStore()

    def create_envelope(
        self,
        raw_payload: str,
        transport: str = "api",
        client_ip: str | None = None,
        collector_host: str = "ulpf-node-01",
        vendor_hint: str | None = None,
        product_hint: str | None = None
    ) -> EventEnvelope:
        """
        1. Generates unique event_id (UUIDv4)
        2. Captures precise UTC timestamp
        3. Attaches source metadata
        4. Calculates SHA-256 and persists raw bytes into ImmutableRawStore
        5. Returns pre-transformation EventEnvelope
        """
        event_id = str(uuid.uuid4())
        ingest_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

        source_meta = SourceMetadata(
            vendor=vendor_hint or "unknown",
            product=product_hint or "unknown",
            detected_format=FormatType.UNKNOWN,
            collector_host=collector_host,
            client_ip=client_ip,
            transport=transport
        )

        # Store raw payload in immutable write-once store
        raw_ref = self.raw_store.store_raw(
            raw_payload=raw_payload,
            event_id=event_id,
            source_meta=source_meta.model_dump()
        )

        traceability = {
            "event_id": event_id,
            "raw_sha256": raw_ref.sha256,
            "raw_storage_uri": f"{raw_ref.bucket}/{raw_ref.object_key}",
            "ingest_timestamp": ingest_time,
            "byte_length": raw_ref.byte_length,
            "provenance_chain": ["INGESTION_RECEIVED", "RAW_ARCHIVED_SHA256"]
        }

        envelope = EventEnvelope(
            event_id=event_id,
            ingest_timestamp=ingest_time,
            source=source_meta,
            raw=raw_ref,
            parsing=ParsingMetadata(),
            ocsf=None,
            traceability=traceability
        )

        return envelope
