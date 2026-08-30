# ULPF Architecture & Technical Design Document
**National Technical Research Organisation (NTRO) · SIH 2026 Problem Statement SIH26156**

---

## 1. Executive Architecture Overview

The **Universal Log Pre-processing Framework (ULPF)** is an enterprise perimeter telemetry pre-processing pipeline purpose-built for air-gapped military, intelligence, and high-security enterprise environments. It addresses the critical challenges of high volume, format fragmentation, lack of cryptographic provenance, and painful onboarding of new log formats.

### The Five Core Architectural Principles:
1. **LOSSLESS**: The raw event payload is archived in write-once immutable storage **before** any parsing or mutation, accompanied by a SHA-256 cryptographic hash.
2. **NORMALIZED**: Ingested telemetry is parsed and mapped into **OCSF 1.1.0 (Open Cybersecurity Schema Framework)** standards.
3. **TRACEABLE**: Every normalized event document maintains bidirectional forensic links to its exact raw source payload via `event_id` and raw SHA-256 hash.
4. **EXTENSIBLE**: Unknown or proprietary log formats are processed by **Drain3 online template mining**, discovering message templates, inferring candidate field types, and offering a 1-click human-assisted publication workflow.
5. **AIR-GAPPED**: Zero runtime network socket calls to cloud services, SaaS APIs, or external AI endpoints.

---

## 2. Component Pipeline Breakdown

```
[Perimeter Network Device] (Firewall / Router / IDS / Proxy)
         │ (UDP:5140, TCP:1514, REST API, File)
         ▼
[1. Ingestion Layer] (EnvelopeFactory)
         ├─ Assign UUIDv4 `event_id`
         ├─ Record nanosecond UTC `ingest_timestamp`
         ├─ Compute `sha256` hash on raw bytes
         └─ Write to [Lossless Raw Storage] (Immutable Blob Store)
         │
         ▼
[2. Format & Vendor Detection Engine]
         ├─ Matches CEF, LEEF, RFC5424, RFC3164, JSON, CSV
         └─ Heuristic vendor tagging (Cisco, Palo Alto, Fortinet, Suricata, Zeek, etc.)
         │
         ├─── [Known Format] ─────────────┐
         │                                │
         └─── [Unseen / Unknown]          │
                   │                      │
                   ▼                      │
         [3. Drain3 Template Miner]       │
                   │                      │
                   ▼                      │
         [4. Field Discovery Engine]      │
                   │                      │
                   ▼                      │
         [5. Human-in-the-Loop Studio]    │
                   │ (Approve & Publish)  │
                   ▼                      │
         [6. Versioned Parser Registry] ◄─┘
                   │
                   ▼
         [7. OCSF Normalization Engine] (OCSF 1.1.0)
                   ├─ Type coercions & standard timestamps
                   ├─ IP & Port normalization
                   ├─ Severity & Disposition mapping
                   └─ Preserves unmapped fields in `unmapped`
                   │
                   ▼
         [8. Multi-Stage Validation Subsystem]
                   ├─ Ingestion boundary validation
                   ├─ OCSF schema compliance validation
                   └─ Cryptographic SHA-256 verification
                   │
                   ▼
         [9. Offline Enrichment Engine]
                   ├─ Offline Enterprise Asset Inventory lookup
                   └─ Offline GeoIP subnet resolution
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
[10. SIEM Search Index]   [11. Columnar Data Lake]
 (SQLite FTS5 / DuckDB)    (Apache Parquet on Disk)
```

---

## 3. Technology Stack & Design Decisions

| Component | Technology Choice | Architectural Rationale |
| :--- | :--- | :--- |
| **Language & Runtime** | Python 3.11+ / FastAPI / Uvicorn | High asynchronous throughput, rich ecosystem for data engineering (`pyarrow`, `duckdb`), and native integration with `drain3`. |
| **Target Security Schema** | **OCSF 1.1.0** (Linux Foundation) | Purpose-built security event taxonomy backed by AWS, Splunk, Broadcom. Eliminates brittle custom schemas while supporting vendor extension points. |
| **Secondary Interoperability** | Elastic Common Schema (ECS) / OpenTelemetry | Supported as a secondary reference in parser architecture. |
| **Lossless Raw Storage** | Write-Once Immutable Disk Blob | Stores exact byte payload. Validated by cryptographic SHA-256 hash checks. |
| **SIEM Search Index** | SQLite FTS5 + DuckDB Analytical Engine | Sub-millisecond full-text and faceted search queries with zero external infrastructure overhead in air-gapped environments. |
| **Data Lake Sink** | Apache Parquet (`pyarrow`) | Columnar format with Snappy compression, partitioned by date/vendor, optimized for downstream ML analytics (CIC-IDS2017 / UNSW-NB15). |
| **Template Miner** | **Drain3** (IBM Research / LogPAI) | Online streaming prefix-tree miner with domain maskers (`<IP>`, `<NUM>`, `<STR>`, `<TIMESTAMP>`) for zero-code onboarding of unseen formats. |
| **UI/UX Framework** | Vanilla HTML5 / Modern CSS / Vanilla JS | High-performance dark glassmorphic cyber-ops interface with zero node build-step runtime dependency in air-gapped mode. |

---

## 4. Scalability & Deployment Architecture

### Single-Node Performance
- Sustained Ingestion & Normalization: **5,000+ events/second** on standard 8-core CPU.
- Extrapolated Daily Volume: **400+ Million events/day/node**.
- End-to-End P95 Latency: **$<1.0$ milliseconds**.

### Horizontal Scaling Strategy
For massive enterprise deployments ($>1$ Billion events/day), ULPF scales horizontally by:
1. Running stateless `ulpf-engine` worker nodes behind a Layer-4 load balancer (e.g. Keepalived / HAProxy).
2. Centralizing immutable raw storage onto a distributed S3-compatible cluster (MinIO distributed mode).
3. Streaming normalized events to distributed OpenSearch / ClickHouse clusters.
