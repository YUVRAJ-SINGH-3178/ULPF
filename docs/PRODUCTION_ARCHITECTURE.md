# ULPF — Production Architecture & Engineering Design

**Project**: SIH26156 — Universal Log Pre-processing Framework  
**Organization**: National Technical Research Organisation (NTRO)  
**Classification**: Critical National Infrastructure & Air-Gapped Cyber Defense  

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
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
|                 STAGE 2 & 3: DETECTION & ROUTING DECISION                     |
|  Format & Vendor Detector (CEF, LEEF, RFC 5424, RFC 3164, JSON, Syslog)       |
+-------------------------------------------------------------------------------+
                     /                                         \
        [Known Format Signature]                      [Unseen / Proprietary]
                    │                                           │
                    ▼                                           ▼
+------------------------------------+        +---------------------------------+
|   STAGE 4A: PARSER ENGINE (AST)    |        | STAGE 4B: DRAIN3 ONBOARDING     |
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
|                    STAGE 5: OCSF 1.1.0 NORMALIZATION                          |
|  Class 4001: Network Activity & Class 2001: Security Finding                  |
|  Preserves unmapped vendor attributes in `unmapped` object (Zero Data Loss)  |
+-------------------------------------------------------------------------------+
                                          │
                                          ▼
+-------------------------------------------------------------------------------+
|                    STAGE 6 & 7: MULTI-STAGE VALIDATION & ENRICHMENT           |
|  Multi-Stage Validator: Ingestion · Parser · Schema · Cryptographic Digest    |
|  100% Air-Gapped Offline Enricher (GeoIP CIDR + Enterprise Asset Inventory)   |
+-------------------------------------------------------------------------------+
                                          │
                        ┌─────────────────┴─────────────────┐
                        ▼                                   ▼
+---------------------------------------+   +-----------------------------------+
|     STAGE 8A: SEARCH & SIEM SINK      |   |   STAGE 8B: ANALYTICAL DATA LAKE  |
|  OpenSearch Cluster (`ulpf-events-v1`)|   |   Apache Parquet Columnar Files   |
|  Explicit Mappings · Sub-ms Queries   |   |   Snappy Compression · DuckDB     |
+---------------------------------------+   +-----------------------------------+
```

---

## 2. Storage Tiering & Sink Separation

ULPF enforces strict separation of concerns across storage tiers:

| Tier | Role | Production Technology | Development / Local Fallback | Key Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **Raw Evidence Store** | Forensics & Cryptographic Integrity | **MinIO (S3)** (`ulpf-raw`) | Local Immutable Store (`data/raw_store`) | Original Raw Bytes Preserved + SHA-256 Digest |
| **Search & SIEM Index** | Operational Querying | **OpenSearch 2.14** (`ulpf-events-v1-*`) | SQLite 3 WAL (FTS5) | Explicit mappings, sub-millisecond faceted search |
| **Analytics Data Lake** | Long-term ML / Deep Analysis | **Apache Parquet (`pyarrow`)** | Apache Parquet on Disk | Snappy-compressed columnar batches partitioned by Date |
| **Operational Metadata** | Audit Trail & Sessions | **SQLite 3 / OpenSearch Audit** | SQLite 3 (`data/search_index.db`) | Immutable administrative action trail |

---

## 3. End-to-End Delivery & State Model

Every log line is tracked through explicit delivery states:

```
RECEIVED ──► RAW_STORED ──► PROCESSING ──► NORMALIZED ──► VALIDATED ──► INDEX_PENDING ──► INDEXED ──► COMPLETED
                                │
                                └──► [On Error] ──► FAILED ──► DEAD-LETTER QUEUE (DLQ) ──► REPLAY
```

---

## 4. Key Production Guarantees

1. **Lossless Evidence Preservation**: Raw event bytes are preserved in MinIO **before** parsing. `POST /events/{event_id}/verify-integrity` recalculates SHA-256 directly from MinIO object bytes to prove integrity.
2. **Zero-Downtime Extensibility**: Unseen formats are clustered online via Drain3, presented to a human reviewer in the UI studio, compiled into versioned AST parsers, and replayed without restarting services.
3. **Verified Air-Gapped Operation**: Verified offline operation with zero runtime external dependencies.
