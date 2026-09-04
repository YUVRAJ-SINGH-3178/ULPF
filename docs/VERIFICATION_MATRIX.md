# ULPF Production Hardening Verification Matrix

**Organization**: National Technical Research Organisation (NTRO) · SIH26156  
**System**: Universal Log Pre-processing Framework (ULPF)  
**Strict Verification Rule Compliance**: All items marked **[VERIFIED]** or **[MEASURED]** have been actively executed and verified against the current code revision. Non-executed scenarios are explicitly designated **[DESIGNED / NOT EXECUTED]**.

### Audit Metadata & Environment
- **Execution Timestamp**: `2026-09-04T08:27:34Z` (13:57:34 IST)
- **Code Revision / Commit Hash**: `5180b814aacf86bf1ae8c7c5cdf41a58f13859f2`
- **Primary Test Runner**: `python -m pytest tests/ -v` (101 passed in 69.99s)
- **Security Audit Tool**: `pip-audit -r requirements.txt --desc on` (0 vulnerabilities found)
- **Code Quality Tool**: `ruff check .` && `ruff format --check .` (0 errors, clean)
- **Benchmark Harness**: `python scripts/run_benchmarks.py`
- **Execution Environment**: Windows 11 (AMD64) · Python 3.13.5 · pytest 8.4.2 · pip-audit 2.7.3

---

## 1. Automated Verification Summary

| Verification Category | Target Component | Test Suite / Script | Pass / Total | Execution Classification |
| :--- | :--- | :--- | :--- | :--- |
| **Secrets & Prod Configuration** | Fail-fast validation, credential hygiene, env redaction, OpenSearch TLS & password enforcement, demo credentials lockout | `tests/test_auth_and_config.py` | 7 / 7 | **[VERIFIED] PASSED** |
| **MinIO Production Path** | Deterministic direct object lookup without bucket scanning | `tests/test_production_minio.py` | 2 / 2 | **[VERIFIED] PASSED** |
| **OpenSearch Production Path** | Lean document schema, exclusion of `raw_payload`, forensic pointers, constructor default `verify_certs=True`, HTTPS settings enforcement | `tests/test_production_opensearch.py` | 3 / 3 | **[VERIFIED] PASSED** |
| **Worker & SQLite Safeguards** | SQLite WAL mode, busy_timeout, lease reclamation, multi-worker concurrency, exponential backoff with jitter, atomic memory queue admission | `tests/test_worker_production_path.py` | 6 / 6 | **[VERIFIED] PASSED** |
| **Outbox & Delivery Reliability** | Two-phase delivery requiring OpenSearch ACK + Parquet ACK, unacknowledged-sink-only retries, durable `next_attempt_at`, exponential backoff with jitter | `tests/test_outbox_delivery.py` | 3 / 3 | **[VERIFIED] PASSED** |
| **Idempotency & Traceability** | Upsert semantics (`_id = event_id`), deduplication, forensic lineage | `tests/test_idempotency.py` | 3 / 3 | **[VERIFIED] PASSED** |
| **Air-Gap Security & Assets** | Zero remote references, internal Docker network, offline fonts | `tests/test_airgap.py` | 3 / 3 | **[VERIFIED] PASSED** |
| **Security Regression Vectors** | SSRF, deserialization, directory traversal, 413 limits, CRLF, ReDoS, hostile logs, RBAC enforcement, secret non-leakage | `tests/test_security_regression.py` | 9 / 9 | **[VERIFIED] PASSED** |
| **Chaos & Failure Recovery** | MinIO unreachable fail-fast, OpenSearch outage recovery, DLQ | `tests/test_failure_recovery.py` | 5 / 5 | **[VERIFIED] PASSED** |
| **Disaster Recovery & Restore** | Online SQLite point-in-time backup, SHA-256 manifest validation, corrupt rejection | `tests/test_backup_restore.py` | 2 / 2 | **[VERIFIED] PASSED** |
| **High Concurrency & Load** | 200 concurrent ingestion threads, zero data loss, SHA-256 check | `tests/test_concurrency_and_load.py` | 1 / 1 | **[VERIFIED] PASSED** |
| **End-to-End Demo Stories** | Story 1 (Known telemetry trace) & Story 2 (Drain3 automated onboarding) | `tests/test_demo_smoke.py` | 2 / 2 | **[VERIFIED] PASSED** |
| **Parser & Normalization Suite** | All 12 modular AST parsers, OCSF 1.1.0 mapping, unmapped preservation | `tests/test_parsers_and_ocsf.py` | 11 / 11 | **[VERIFIED] PASSED** |
| **Parser Property Fuzzing** | Hypothesis property fuzzing across all parsers with random unicode mutations | `tests/test_parser_fuzzing.py` | 2 / 2 | **[VERIFIED] PASSED** |
| **Storage Adapters Contract** | Local store, MinIO S3 adapter, SQLite FTS5 store, OpenSearch adapter | `tests/test_storage_adapters.py` | 5 / 5 | **[VERIFIED] PASSED** |
| **API Endpoints & Metrics** | REST API authentication, ingestion, Prometheus metrics, 3-tier health check | `tests/test_api_endpoints.py` | 5 / 5 | **[VERIFIED] PASSED** |
| **Observability & Diagnostics** | Deep pipeline health, Prometheus export parity, queue and DLQ metrics | `tests/test_observability.py` | 3 / 3 | **[VERIFIED] PASSED** |
| **Format Detection** | RFC 5424, RFC 3164, CEF, LEEF, CheckPoint, Squid, Zeek, Suricata, JSON | `tests/test_format_detection.py` | 13 / 13 | **[VERIFIED] PASSED** |
| **Service Coverage** | Offline enrichment, dead-letter queue, field discovery | `tests/test_services_coverage.py` | 6 / 6 | **[VERIFIED] PASSED** |
| **Dependency Vulnerabilities** | `pip-audit -r requirements.txt --desc on` across all production dependencies (blocking CI step) | CLI execution | 0 vulnerabilities | **[VERIFIED] PASSED** |
| **Performance Benchmark** | Empirical 300 single + 1,000 batch events, latency percentiles, memory RSS | `scripts/run_benchmarks.py` | Completed | **[MEASURED] VERIFIED** |
| **Multi-Node Cluster Chaos** | Multi-DC split-brain network partition across physically separated data centers | Physical multi-node lab | N/A | **[DESIGNED / NOT EXECUTED]** |
| **Hardware Security Module** | Hardware PKCS#11 crypto key storage (Software SHA-256 verified) | Physical HSM appliance | N/A | **[DESIGNED / NOT EXECUTED]** |

---

## 2. Grand Total Test Execution Statistics

- **Total Test Cases in Active Suite**: 101
- **Passing**: 101
- **Failing**: 0
- **Pass Rate**: 100.0%
- **Vulnerabilities Found in Production Dependencies**: 0
- **Execution Date**: 2026-09-04
- **Test Runner**: pytest 8.4.2 / Python 3.13.5 (Windows 11 AMD64)

---

## 3. Verified Security & Architectural Controls

1. **Deterministic Direct Object Lookup Without Bucket-Wide Scanning**:
   - `[VERIFIED]`: Cold lookups read companion metadata at `metadata/events/{event_id}.meta.json` in a direct single-key GET without invoking `list_objects(recursive=True)`.
2. **Lean OpenSearch Indexing & Constructor Defaults**:
   - `[VERIFIED]`: Indexed documents exclude raw text payloads while retaining cryptographic hashes (`raw_sha256`, `sha256_hash`), URI pointers (`raw_storage_uri`), and distributed trace pointers (`trace_id`).
   - `[VERIFIED]`: `OpenSearchStore` constructor defaults `verify_certs=True`. Production `Settings` strictly validates HTTPS protocol and certificate verification, rejecting plaintext or unverified configs.
3. **Dual-ACK Outbox State Machine with Exponential Backoff & Jitter**:
   - `[VERIFIED]`: `DELIVERY_COMPLETE` strictly requires BOTH OpenSearch and Parquet acknowledgements. Single-sink outages transition the event to `FAILED_RETRYABLE` with a durable `next_attempt_at` timestamp.
   - `[VERIFIED]`: Retries apply real exponential backoff ($2.0 \times 2^{\text{attempts}} + \text{jitter}$) to prevent tight retry loops. Already-acknowledged sinks are never retried.
4. **Queue Retry Requeue Atomic Memory Admission**:
   - `[VERIFIED]`: In `requeue_eligible_retries()` and `reclaim_expired_leases()`, items are pushed to `_mem_queue.put_nowait()` before marking `QUEUED` in SQLite. If memory is full under backpressure, items atomically remain `RETRY_PENDING` without being orphaned or lost.
5. **Production Demo Credentials Lockout**:
   - `[VERIFIED]`: Built-in demo credentials (`admin`, `operator`, `analyst`, `reviewer`) are strictly confined to `ULPF_DEMO_MODE=True`. When `ULPF_DEMO_MODE=False` (production), all demo login, bearer tokens, and refresh tokens are denied (HTTP 401).
6. **SQLite Concurrency & WAL Safeguards**:
   - `[VERIFIED]`: `PRAGMA journal_mode=WAL;` and `PRAGMA busy_timeout=5000;` prevent lock contention under concurrent load. Startup fails fast with `RuntimeError` if deployed over unsafe network filesystems (CIFS, NFS, SMB) or if WAL cannot be activated in production.
7. **Air-Gap Zero-Egress**:
   - `[VERIFIED]`: All external fonts/CDNs are eliminated in favor of offline system typography, and `docker-compose.prod.yml` enforces `internal: true` on `ulpf-airgap-net`.
8. **Three-Tier Health Diagnostics**:
   - `[VERIFIED]`: `/api/pipeline/health` implements `HEALTHY` (200), `DEGRADED` (200, when secondary search sink is down but ingestion and durable outbox are intact), and `UNAVAILABLE` (503, when raw store or disk persistence is impaired).
9. **Blocking CI Vulnerability Audit**:
   - `[VERIFIED]`: `.github/workflows/ci.yml` executes blocking `pip-audit --desc on` (removed `|| true`), failing builds if vulnerabilities are present. Currently reports 0 known vulnerabilities.
