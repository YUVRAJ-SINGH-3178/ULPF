"""
Master Pipeline Orchestration Engine
Integrates Ingestion -> Lossless Storage -> Detection -> Parsing / Drain3 Onboarding -> OCSF Normalization -> Validation -> Enrichment -> Dual Sinks.
"""

import threading
import time
from collections import deque
from typing import Any

from ulpf.packages.schemas.models import (
    EventEnvelope,
    VerificationResult,
)
from ulpf.services.detection.format_detector import FormatDetector
from ulpf.services.enrichment.offline_enricher import OfflineEnricher
from ulpf.services.ingestion.raw_envelope import EnvelopeFactory
from ulpf.services.normalization.ocsf_mapper import OCSFNormalizer
from ulpf.services.onboarding.session_manager import OnboardingSessionManager
from ulpf.services.parser_engine.registry import ParserRegistry
from ulpf.services.replay.replay_engine import ErrorAndReplayQueue
from ulpf.services.storage.data_lake import ParquetDataLakeWriter
from ulpf.services.storage.raw_store import ImmutableRawStore
from ulpf.services.storage.search_index import SearchIndex
from ulpf.services.validation.validator import PipelineValidator


class PipelineOrchestrator:
    """
    The central coordinator executing the end-to-end ULPF lifecycle.
    """

    def __init__(
        self,
        base_dir: str = "data",
        enable_data_lake_auto_flush: bool = True
    ):
        self.base_dir = base_dir
        self.raw_store = ImmutableRawStore(f"{base_dir}/raw_store")
        self.search_index = SearchIndex(f"{base_dir}/search_index.db")
        self.data_lake = ParquetDataLakeWriter(f"{base_dir}/data_lake")
        self.format_detector = FormatDetector()
        self.parser_registry = ParserRegistry(f"{base_dir}/parsers")
        self.ocsf_normalizer = OCSFNormalizer()
        self.validator = PipelineValidator(self.raw_store)
        self.enricher = OfflineEnricher()
        self.error_queue = ErrorAndReplayQueue(f"{base_dir}/error_queue")
        self.envelope_factory = EnvelopeFactory(self.raw_store)

        # Onboarding manager with post-onboarding automated replay hook and audit persistence
        self.onboarding_manager = OnboardingSessionManager(
            parser_registry=self.parser_registry,
            persistence_dir=f"{base_dir}/onboarding_sessions",
            replay_callback=self._on_replay_requested,
            audit_sink=self.search_index.record_audit
        )

        self.enable_data_lake_auto_flush = enable_data_lake_auto_flush
        self._batch_buffer: list[EventEnvelope] = []
        self._buffer_lock = threading.Lock()

        # Telemetry metrics
        self._metrics_lock = threading.Lock()
        self.total_ingested = 0
        self.total_normalized = 0
        self.total_errors = 0
        self.total_unknowns = 0
        self._latencies_ms: deque = deque(maxlen=2000)
        self._throughput_timestamps: deque = deque(maxlen=5000)

    def process_raw_log(
        self,
        raw_payload: str,
        transport: str = "api",
        client_ip: str | None = "127.0.0.1",
        collector_host: str = "ulpf-node-01",
        vendor_hint: str | None = None,
        product_hint: str | None = None
    ) -> EventEnvelope:
        """
        Executes complete ULPF pipeline for a single raw event:
        1. Capture raw payload & compute SHA-256 (Write-Once Lossless Archive)
        2. Format & Vendor Detection
        3. Parser Registry match OR Drain3 Auto-Onboarding Queue
        4. OCSF 1.1.0 Normalization
        5. Multi-Stage Validation
        6. Offline Enrichment (GeoIP + Enterprise Assets)
        7. Dual Sink Ingestion (SIEM Search Index + Parquet Data Lake)
        8. Traceability Linking
        """
        start_time = time.perf_counter()

        # Stage 1: Lossless Raw Archive & Envelope Creation
        envelope = self.envelope_factory.create_envelope(
            raw_payload=raw_payload,
            transport=transport,
            client_ip=client_ip,
            collector_host=collector_host,
            vendor_hint=vendor_hint,
            product_hint=product_hint
        )

        with self._metrics_lock:
            self.total_ingested += 1
            now_ts = time.time()
            self._throughput_timestamps.append(now_ts)

        # Validate Ingestion Contract
        is_valid_ingest, ingest_errors = self.validator.validate_ingestion(envelope)
        if not is_valid_ingest:
            self.error_queue.record_failure(envelope, "INGESTION", ingest_errors)
            with self._metrics_lock:
                self.total_errors += 1
            return envelope

        # Stage 2: Format & Vendor Detection
        detected_fmt, det_vendor, det_product, det_conf = self.format_detector.detect(raw_payload)
        envelope.source.detected_format = detected_fmt
        if envelope.source.vendor == "unknown" and det_vendor != "unknown":
            envelope.source.vendor = det_vendor
        if envelope.source.product == "unknown" and det_product != "unknown":
            envelope.source.product = det_product

        # Stage 3: Parser Lookup
        parser = self.parser_registry.find_parser(raw_payload, envelope.source)

        if not parser:
            # Unseen / Unknown Format -> Route to Drain3 Auto-Onboarding Queue!
            with self._metrics_lock:
                self.total_unknowns += 1

            session = self.onboarding_manager.process_unknown_log(
                raw_payload=raw_payload,
                vendor_hint=envelope.source.vendor,
                product_hint=envelope.source.product
            )

            envelope.parsing.parser_used = "drain3-onboarding-queue"
            envelope.parsing.template_id = session.template_id
            envelope.parsing.confidence = session.confidence_score
            envelope.parsing.unparsed_fields = {"onboarding_session_id": session.session_id}

            # Record in error/onboarding queue
            self.error_queue.record_failure(
                envelope,
                "UNKNOWN_FORMAT",
                [f"Unrecognized log format routed to Drain3 Onboarding Studio (Template ID: {session.template_id})"]
            )
            return envelope

        # Stage 4: Parse Known Format
        parsed_fields, parsing_meta = parser.parse(raw_payload, envelope.source)
        envelope.parsing = parsing_meta

        # Stage 5: OCSF 1.1.0 Normalization
        ocsf_doc = self.ocsf_normalizer.normalize(
            parsed_fields=parsed_fields,
            source_meta=envelope.source,
            raw_payload=raw_payload,
            event_id=envelope.event_id
        )

        # Stage 6: Multi-Stage Schema Validation
        is_valid_ocsf, ocsf_errors = self.validator.validate_ocsf(ocsf_doc)
        if not is_valid_ocsf:
            envelope.parsing.errors.extend(ocsf_errors)
            self.error_queue.record_failure(envelope, "OCSF_VALIDATION", ocsf_errors)
            with self._metrics_lock:
                self.total_errors += 1

        # Stage 7: Offline Enrichment (Zero live network calls)
        ocsf_doc = self.enricher.enrich(ocsf_doc)
        envelope.ocsf = ocsf_doc

        # Stage 8: Traceability Metadata
        envelope.traceability = {
            "event_id": envelope.event_id,
            "raw_sha256": envelope.raw.sha256,
            "raw_storage_uri": f"{envelope.raw.bucket}/{envelope.raw.object_key}",
            "byte_length": envelope.raw.byte_length,
            "parser_id": parser.parser_id,
            "parser_version": parser.version,
            "mapping_version": "1.0.0",
            "ingest_timestamp": envelope.ingest_timestamp,
            "provenance_chain": [
                "INGESTION_RECEIVED",
                "RAW_ARCHIVED_SHA256",
                f"FORMAT_DETECTED:{detected_fmt.value}",
                f"PARSED:{parser.parser_id}:{parser.version}",
                "OCSF_NORMALIZED_1.1.0",
                "ENRICHED_OFFLINE",
                "INDEXED_DUAL_SINK"
            ]
        }

        # Stage 9: Ingest into SIEM Search Index & Buffer for Parquet Data Lake
        self.search_index.index_event(envelope)

        with self._buffer_lock:
            self._batch_buffer.append(envelope)
            if len(self._batch_buffer) >= 100 and self.enable_data_lake_auto_flush:
                to_flush = list(self._batch_buffer)
                self._batch_buffer.clear()
                self.data_lake.write_batch(to_flush)

        # Performance recording
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        with self._metrics_lock:
            self.total_normalized += 1
            self._latencies_ms.append(elapsed_ms)

        return envelope

    def process_batch(
        self,
        raw_payloads: list[str],
        transport: str = "batch",
        client_ip: str = "127.0.0.1"
    ) -> list[EventEnvelope]:
        """Processes a batch of raw log lines."""
        envelopes = []
        for raw in raw_payloads:
            if raw and raw.strip():
                env = self.process_raw_log(raw, transport=transport, client_ip=client_ip)
                envelopes.append(env)
        return envelopes

    def verify_event_integrity(self, event_id: str) -> VerificationResult:
        """Verifies cryptographic SHA-256 byte-level integrity for an event."""
        return self.validator.validate_integrity(event_id)

    def flush_data_lake(self) -> str | None:
        """Manually flushes pending envelopes to Parquet."""
        with self._buffer_lock:
            if not self._batch_buffer:
                return None
            to_flush = list(self._batch_buffer)
            self._batch_buffer.clear()
            return self.data_lake.write_batch(to_flush)

    def _on_replay_requested(self, raw_logs: list[str]):
        """Internal callback when an onboarding session is approved, replaying buffered logs."""
        for log in raw_logs:
            self.process_raw_log(log, transport="replay")

    def get_realtime_metrics(self) -> dict[str, Any]:
        """Calculates live EPS, latency percentiles, and counts."""
        with self._metrics_lock:
            now = time.time()
            # Clean timestamps older than 5 seconds
            recent_counts = sum(1 for t in self._throughput_timestamps if now - t <= 5.0)
            eps = round(recent_counts / 5.0, 1)

            latencies = sorted(list(self._latencies_ms))
            p50 = round(latencies[len(latencies) // 2], 2) if latencies else 0.0
            p95 = round(latencies[int(len(latencies) * 0.95)], 2) if latencies else 0.0
            p99 = round(latencies[int(len(latencies) * 0.99)], 2) if latencies else 0.0
            avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

            return {
                "total_ingested": self.total_ingested,
                "total_normalized": self.total_normalized,
                "total_errors": self.total_errors,
                "total_unknowns": self.total_unknowns,
                "current_eps": eps,
                "latency_p50_ms": p50,
                "latency_p95_ms": p95,
                "latency_p99_ms": p99,
                "latency_avg_ms": avg_lat
            }
