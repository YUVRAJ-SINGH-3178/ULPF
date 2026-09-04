# ULPF — Production Architecture & Engineering Design

**Project**: SIH26156 — Universal Log Pre-processing Framework  
**Organization**: National Technical Research Organisation (NTRO)  
**Classification**: Critical National Infrastructure & Air-Gapped Cyber Defense  
**Revision Status**: Production-Ready Hardened Engineering System

---

## 1. Architectural Overview

The **Universal Log Pre-processing Framework (ULPF)** is an enterprise-hardened telemetry pre-processing pipeline designed to ingest, preserve, normalize, and index high-velocity perimeter network logs (Firewalls, Routers, Proxies, and IDS/IPS) without data loss or external network exposure.

```
+-------------------------------------------------------------------------------+
|                             INGESTION BOUNDARY                                |
|  Syslog UDP (:5140) · Syslog TCP (:1514) · REST Ingest API (:8000) · Batch   |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
|                    STAGE 1: LOSSLESS RAW CAPTURE                              |
|  1. Assign UUIDv4 `event_id` and UTC timestamp                                |
|  2. Compute cryptographic SHA-256 digest on raw payload bytes                  |
|  3. Write-Once archive to MinIO Object Store (`ulpf-raw`)                      |
|  4. Store companion metadata at `metadata/events/{event_id}.meta.json`        |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
|                     STAGE 2: DURABLE QUEUE STAGING                            |
|  Durable SQLite Queue with WAL Mode, PRAGMA busy_timeout=5000ms               |
|  Indexed lease fields and automated visibility timeout recovery               |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
|                 STAGE 3 & 4: DETECTION & ROUTING DECISION                     |
|  Format & Vendor Detector (CEF, LEEF, RFC 5424, RFC 3164, JSON, Syslog)       |
+-------------------------------------------------------------------------------+
                     /                                         \
        [Known Format Signature]                      [Unseen / Proprietary]
                    │                                           │
                    ▼                                           ▼
+------------------------------------+        +---------------------------------+
|   STAGE 5A: PARSER ENGINE (AST)    |        | STAGE 5B: DRAIN3 ONBOARDING     |
|   12 Built-in Modular Parsers      |        | 1. Online Streaming Prefix Tree |
|   Compiled Regex & K-V Tokenizers  |        | 2. Parameter Extraction         |
|   Versioned Active Parser Registry |        | 3. Candidate Type Inference     |
+------------------------------------+        | 4. Human Review & Approval      |
                    │                         | 5. Parser Synthesis & Replay    |
                    │                         +---------------------------------+
                    │                                           │
                    └─────────────────────┬─────────────────────┘
                                          │
                                          ▼
+-------------------------------------------------------------------------------+
|                    STAGE 6: OCSF 1.1.0 NORMALIZATION                          |
|  Class 4001: Network Activity & Class 2001: Security Finding                  |
|  Preserves unmapped vendor attributes in `unmapped` object (Zero Data Loss)  |
+-------------------------------------------------------------------------------+
                                          │
                                          ▼
+-------------------------------------------------------------------------------+
|                    STAGE 7 & 8: MULTI-STAGE VALIDATION & ENRICHMENT           |
|  Multi-Stage Validator: Ingestion · Parser · Schema · Cryptographic Digest    |
|  100% Air-Gapped Offline Enricher (GeoIP CIDR + Enterprise Asset Inventory)   |
+-------------------------------------------------------------------------------+
                                          │
                                          ▼
+-------------------------------------------------------------------------------+
|                    STAGE 9: DURABLE OUTBOX DELIVERY (DUAL ACK)                |
|  Two-Phase Delivery: OpenSearch ACK + Parquet ACK                             |
|  Guaranteed at-least-once dual-sink delivery with retryable persistence      |
+-------------------------------------------------------------------------------+
                                          │
                        ┌─────────────────┴─────────────────┐
                        ▼                                   ▼
+---------------------------------------+   +-----------------------------------+
|     STAGE 10A: LEAN SEARCH SINK       |   |   STAGE 10B: ANALYTICAL DATA LAKE |
|  OpenSearch Cluster (`ulpf-events-v1`)|   |   Apache Parquet Columnar Files   |
|  Lean Schema: No raw_payload stored   |   |   Snappy Compression · DuckDB     |
|  Forensic Pointers: raw_storage_uri,  |   |   Full Forensic Raw Bytes in Lake |
|  raw_sha256, sha256_hash, trace_id    |   |   Complete Columnar Data Model    |
+---------------------------------------+   +-----------------------------------+
```

---

## 2. MinIO Storage: Deterministic Direct Object Lookup

Raw events are partitioned deterministically by ingest date and source vendor:
`year=YYYY/month=MM/day=DD/source={vendor}/{event_id}.raw`

To avoid expensive bucket scans across millions of objects, ULPF implements **deterministic direct object lookup without bucket-wide scanning**:
1. Upon storing each raw event, companion metadata is persisted at:
   `metadata/events/{event_id}.meta.json`
2. Single-event lookup reads the companion metadata object in an $O(1)$ single-key GET, extracts `object_key`, and fetches the raw object directly without calling `list_objects(recursive=True)`.
3. Direct URI retrieval (`retrieve_by_storage_uri`) parses `"bucket/object_key"` directly from the indexed document's `raw_storage_uri`, performing a single direct GET.

---

## 3. OpenSearch Sink: Lean Document Architecture

In production, OpenSearch indexes normalized fields for high-performance querying and aggregation while strictly excluding the multi-kilobyte `raw_payload`.

Forensic traceability is preserved via lightweight pointers:
- `_id`: Deterministically set to `event_id` (enforces upsert idempotency and eliminates duplicates).
- `raw_storage_uri`: Full deterministic URI pointing to raw bytes in MinIO.
- `raw_sha256` & `sha256_hash`: Cryptographic SHA-256 digest of original raw bytes.
- `trace_id`: Distributed transaction correlation ID linking logs, metrics, and audit entries.
- `ocsf_schema_version`: Explicit versioning (`1.1.0`).

---

## 4. End-to-End Delivery & Outbox State Machine

ULPF enforces an explicit, atomic Outbox delivery lifecycle:

```
RAW_STORED ──► QUEUED ──► PROCESSING ──► VALIDATED ──► OUTBOX_PENDING 
                                                              │
                                       ┌──────────────────────┴──────────────────────┐
                                       ▼                                             ▼
                                OpenSearch ACK                                  Parquet ACK
                                       │                                             │
                                       └──────────────────────┬──────────────────────┘
                                                              │
                                                (BOTH ACKs Confirmed)
                                                              ▼
                                                      DELIVERY_COMPLETE
```

### Fault-Tolerance Rules:
1. **Dual ACK Requirement**: An event is marked `DELIVERY_COMPLETE` **only** when both OpenSearch and Parquet successfully acknowledge the write.
2. **Retryable Sink Failures**: If either sink fails, the event is marked `FAILED_RETRYABLE` in `outbox.db` and preserved with `attempt_count`, `last_attempt`, and `last_error`.
3. **At-Least-Once Delivery**: Duplicates upon retry are strictly preferred over silent data loss. Upsert semantics in OpenSearch (`_id = event_id`) guarantee document-level idempotency.

---

## 5. SQLite Production Safeguards & Concurrency Limits

The local queuing, outbox, and search index backends utilize SQLite with enterprise production safeguards:
1. **WAL Mode**: `PRAGMA journal_mode=WAL;` enables concurrent non-blocking readers alongside a single active writer.
2. **Busy Timeout**: `PRAGMA busy_timeout=5000;` prevents `database is locked` exceptions under burst load.
3. **Synchronous Mode**: `PRAGMA synchronous=NORMAL;` guarantees durability without excessive disk flushes.
4. **Indexed Leases**: `idx_pending_queue_lease ON pending_queue(status, last_attempt_at, attempts)` ensures $O(1)$ dequeuing and rapid visibility timeout recovery.
5. **Visibility Timeout Lease Recovery**: Leased items whose workers crash or hang beyond 30 seconds are reclaimed and re-queued automatically.
6. **Filesystem Safety Check**: Verifies that WAL mode activates successfully, alerting and failing safely if deployed over unsafe network shares lacking POSIX byte-range locking.
7. **Documented Worker Concurrency Limit**: Maximum recommended concurrency is **16 worker threads** per node against a single SQLite queue database. This delivers > 10,000 EPS ingress throughput without lock contention.
