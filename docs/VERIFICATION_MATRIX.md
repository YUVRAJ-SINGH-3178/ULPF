# ULPF — Final Verification & Defensibility Matrix

**Project**: SIH26156 — Universal Log Pre-processing Framework  
**Organization**: National Technical Research Organisation (NTRO)  
**Standard**: 10/10 SIH Defensible Engineering & Verification  

---

## 1. Traceability & Defensibility Matrix

| # | System Requirement | Implementation Subsystem | Verification Test File | Status | Concrete Empirical Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Lossless Raw Preservation** | `MinIORawStore` & `LocalRawStore` (`ulpf/services/storage/raw_store.py`) | `tests/test_raw_storage_and_integrity.py` | **VERIFIED** | Original raw bytes preserved with SHA-256 integrity verification before parsing; retrieved byte-stream matches original 100%. |
| **2** | **Cryptographic Integrity Verification** | `PipelineValidator.validate_integrity` (`ulpf/services/validation/validator.py`) | `tests/test_raw_storage_and_integrity.py` | **VERIFIED** | Live endpoint `POST /events/{id}/verify-integrity` re-computes SHA-256 directly from MinIO object bytes. |
| **3** | **Tamper Detection** | SHA-256 hash comparison against disk payload | `tests/test_raw_storage_and_integrity.py` | **VERIFIED** | Unauthorized modification immediately flags `tampered: true` and `is_valid: false`. |
| **4** | **OCSF 1.1.0 Normalization** | `OCSFNormalizer` (`ulpf/services/normalization/ocsf_mapper.py`) | `tests/test_parsers_and_ocsf.py` | **VERIFIED** | Security telemetry normalized to OCSF 1.1.0 (Classes 4001 and 2001). |
| **5** | **Unmapped Attribute Preservation** | `ocsf_doc["unmapped"]` dictionary | `tests/test_parsers_and_ocsf.py` | **VERIFIED** | Non-standard vendor fields (e.g. Fortinet `policyid`, Checkpoint `rule_name`) preserved without data loss. |
| **6** | **Format & Vendor Detection** | `FormatDetector` (`ulpf/services/detection/format_detector.py`) | `tests/test_format_detection.py` | **VERIFIED** | Accurately classifies RFC 3164, RFC 5424, CEF, LEEF, JSON, and unknown proprietary formats. |
| **7** | **Unknown Source Auto-Onboarding** | `DrainMiner` & `FieldDiscoveryEngine` (`ulpf/services/onboarding/`) | `tests/test_drain3_onboarding.py` & `test_demo_smoke.py` | **VERIFIED** | Previously unseen log formats can be onboarded through template discovery and human-approved mapping. |
| **8** | **Human-in-the-Loop Approval & Replay** | `OnboardingSessionManager` (`ulpf/services/onboarding/session_manager.py`) | `tests/test_drain3_onboarding.py` | **VERIFIED** | Analyst reviews proposed mappings, dry-runs sample, approves parser v1.0.0, and triggers automated replay of buffered logs. |
| **9** | **Production Storage Tiering (MinIO)** | `MinIORawStore` (`ulpf/services/storage/raw_store.py`) | `tests/test_storage_adapters.py` | **VERIFIED** | Deterministic S3 URIs (`ulpf-raw/year=YYYY/month=MM/day=DD/source=<id>/<event_id>.raw`) with companion `.meta.json`. |
| **10** | **Production Search Engine (OpenSearch)** | `OpenSearchStore` (`ulpf/services/storage/search_index.py`) | `tests/test_storage_adapters.py` | **VERIFIED** | Index template `ulpf-events-v1-*` with strict explicit mappings, deterministic `_id = event_id`, and faceted aggregations. |
| **11** | **Outbox Delivery State & Idempotency** | `PipelineOrchestrator` (`ulpf/services/pipeline_orchestrator.py`) | `tests/test_failure_recovery.py` | **VERIFIED** | OpenSearch outage triggers `INDEX_FAILED` into DLQ; recovery retries index using deterministic `_id` with zero duplicates. |
| **12** | **MinIO Raw Preservation Fail-Fast** | `PipelineOrchestrator.process_raw_log` | `tests/test_failure_recovery.py` | **VERIFIED** | If MinIO fails during raw capture, event is flagged `RAW_STORE_FAILED`, recorded to DLQ, and never marked as processed. |
| **13** | **Durable Queue & Worker Crash Recovery** | `DurableEventQueue` (`ulpf/services/processing/event_queue.py`) | `tests/test_event_queue_and_workers.py` | **VERIFIED** | SQLite-backed durable queue recovers unacknowledged items into memory on process restart; handles backpressure gracefully. |
| **14** | **Verified Air-Gapped Operation** | Local font and JS bundling; Zero remote socket calls | `tests/test_observability.py` & `test_api_endpoints.py` | **VERIFIED** | Verified offline operation with no runtime external dependencies; `GET /api/pipeline/health` reports `air_gapped: true`. |
| **15** | **RBAC & Authentication Hardening** | BCrypt hashing + JWT Auth (`ulpf/apps/api/auth.py`) | `tests/test_auth_and_config.py` & `test_security_hardening.py` | **VERIFIED** | Role gates (`ADMIN`, `OPERATOR`, `ANALYST`, `REVIEWER`) enforce that only `REVIEWER`/`ADMIN` can publish parsers. |
| **16** | **Security & Path Traversal Rejection** | `validate_safe_identifier` & Rate Limiting | `tests/test_security_hardening.py` | **VERIFIED** | Directory traversal attempts (`../`) and malformed event IDs are rejected with HTTP 400. |
| **17** | **Parser Fuzzing & Mutation Resilience** | Property-based fuzzing with injection strings | `tests/test_parser_fuzzing.py` | **VERIFIED** | Corrupted payloads and malicious characters produce structured parser errors without crashing workers. |
| **18** | **Concurrent Load Durability** | Multi-threaded ingestion across 200 worker threads | `tests/test_concurrency_and_load.py` | **VERIFIED** | 100% Zero data loss, zero duplicate event IDs, 100% SHA-256 verification pass rate, and Parquet DuckDB consistency. |
| **19** | **Empirical Performance Benchmarks** | Benchmark Runner (`scripts/run_benchmarks.py`) | `docs/BENCHMARKS.md` | **MEASURED** | Measured at 3,450+ EPS (100 ev/batch, 245 B/ev, 4 workers) and 0.28 ms median latency on AMD Ryzen 5 / NVMe SSD. |
| **20** | **Observability & Prometheus OpenMetrics** | Metrics API (`ulpf/apps/api/routes/pipeline.py`) | `tests/test_observability.py` | **VERIFIED** | Exposes `/metrics` and `/api/pipeline/metrics/prometheus` with counters, latency quantiles, and subsystem health. |

---

## 2. Claim Classification Audit

- **VERIFIED**: Functionality fully implemented, covered by automated tests, and verified via end-to-end execution.
- **MEASURED**: Performance numbers gathered via automated benchmark harnesses on physical hardware under documented configurations.
- **DESIGNED / PLANNED**: Explicitly demarcated in documentation; never represented as implemented.
