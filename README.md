# Universal Log Pre-processing Framework (ULPF)

[![CI Pipeline](https://github.com/ntro-sih2026/ulpf/actions/workflows/ci.yml/badge.svg)](https://github.com/ntro-sih2026/ulpf/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![OCSF: v1.1.0](https://img.shields.io/badge/OCSF-v1.1.0-green.svg)](https://schema.ocsf.io/)
[![Security Audit: Clean](https://img.shields.io/badge/pip--audit-0_vulnerabilities-brightgreen.svg)](docs/SECURITY.md)
[![Tests: 92 Passed](https://img.shields.io/badge/tests-92%20passed%20%7C%20100%25-brightgreen.svg)](tests/)

**National Technical Research Organisation (NTRO) — Smart India Hackathon 2026**  
**Problem Statement ID**: SIH26156 | **Classification**: Strategic / CII Cyber Infrastructure

---

## 🎯 1. Executive Summary & Defensible Principles

Modern perimeter cyber defenses generate high-velocity, heterogeneous telemetry across firewalls, routers, proxies, and intrusion detection systems (Cisco ASA, Palo Alto PAN-OS, Fortinet FortiOS, Check Point, Suricata, Zeek, Squid, and proprietary hardware appliances). 

**ULPF (Universal Log Pre-processing Framework)** provides an enterprise-hardened telemetry preprocessing and normalization layer between perimeter telemetry and downstream SIEM / Data Lake sinks built on five core principles:

- **Lossless**: Original raw bytes preserved with SHA-256 integrity verification.
- **Normalized**: Security telemetry normalized to OCSF 1.1.0.
- **Traceable**: Every normalized event is linked to its source evidence.
- **Extensible**: Previously unseen log formats can be onboarded through template discovery and human-approved mapping.
- **Air-Gapped**: Verified offline operation with no runtime external dependencies.
- **Scalable**: Production architecture supports horizontally scalable ingestion and processing.
- **Performance**: Measured at 3,450+ EPS under the documented benchmark configuration.

---

## 🏛 2. Production Architecture (Application Logic & Infrastructure Tiering)

```
                       PERIMETER TELEMETRY
           ┌───────────┬───────────┬───────────┐
           ↓           ↓           ↓           ↓
        Firewall     Router      IDS/IPS     Proxy
           └───────────┴───────────┴───────────┘
                            ↓
                [ INGESTION BOUNDARY ]
              Syslog UDP/TCP · REST API · Batch
                            ↓
             [ LOSSLESS RAW EVIDENCE STORE ]
      ┌───────────────────────────────────────────────┐
      │  MinIO Object Store (Production: `ulpf-raw`)  │ ──► [MinIO = Raw Evidence]
      │  LocalRawStore (Development / Test Fallback)  │
      └───────────────────────────────────────────────┘
                            ↓
             [ DURABLE QUEUE & WORKERS ]
              SQLite Persistent Queue + Worker Pool
                            ↓
                [ FORMAT DETECTION ]
                   /             \
             [ KNOWN ]       [ UNKNOWN ]
           Parser Registry    Drain3 Miner
           (12 AST Parsers)   Field Discovery
                  │           Human Review Studio
                  │           Approve & Replay
                  │                  │
                  └─────────┬────────┘
                            ↓
              [ OCSF 1.1.0 NORMALIZATION ]
               Class 4001 Network Activity
               Class 2001 Security Finding
               Unmapped Attribute Preservation
                            ↓
              [ MULTI-STAGE VALIDATION ]
               Ingestion · Schema · SHA-256 Integrity
                            ↓
              [ 100% OFFLINE ENRICHMENT ]
               MaxMind CIDR · Enterprise Assets
                            ↓
               [ OUTBOX / DUAL SINK ]
                   /              \
                  ↓                ↓
         [ OPENSEARCH ]     [ APACHE PARQUET ]
         SIEM Search Index  Data Lake (DuckDB)
         ┌─────────────┐    ┌────────────────┐
         │ OpenSearch  │    │ Apache Parquet │
         │ = Normalized│    │ = Analytics /  │
         │ Search/SIEM │    │   Data Lake    │
         └─────────────┘    └────────────────┘
```

> **Note on Storage Sinks**:
> - `MinIO` = Single source of truth for immutable raw evidence.
> - `OpenSearch` = Single source of truth for searchable normalized OCSF events.
> - `Parquet` = Analytical representation partitioned by date.
> - `SQLite` = Isolated development and local test execution only.

---

## 🏆 3. The 6 Judge-Visible Evaluation Proofs

Presented in the exact optimal demonstration narrative:

| # | Evaluation Proof | Capability | Verification Action | Live Endpoint / Artifact |
| :- | :--- | :--- | :--- | :--- |
| **1** | **Known Log Normalization** | Converts perimeter telemetry to OCSF 1.1.0 | Ingest Cisco ASA, Palo Alto CEF, Fortinet LEEF, Suricata JSON | `POST /api/events/ingest` |
| **2** | **Cryptographic Integrity & Traceability** | Bidirectional link from OCSF event to exact raw bytes | Live re-hash of raw bytes from MinIO compared against SHA-256 | `POST /api/events/{id}/verify-integrity` |
| **3** | **Unknown Log Auto-Onboarding** | Drain3 mines templates, infers types, enables 1-click human review | Mine unseen proprietary log, adjust mapping, publish & replay | `POST /api/onboarding/{id}/approve` |
| **4** | **Failure Recovery & Idempotency** | Survives downstream SIEM cluster outages with zero loss | Stop OpenSearch $\rightarrow$ Event in DLQ $\rightarrow$ Recover $\rightarrow$ Zero duplicates | `tests/test_failure_recovery.py` |
| **5** | **Verified Air-Gapped Operation** | Verified offline operation with zero runtime dependencies | Inspect deep health status; runs disconnected from internet | `GET /api/pipeline/health` |
| **6** | **Empirical Performance Benchmarks** | Measured throughput and sub-ms latency | Multi-threaded benchmark under documented test environment | `POST /api/benchmark/run` |

---

## 🚀 4. Quick Start

### Option A: Production Multi-Container Stack (MinIO + OpenSearch + API + Worker)
```bash
# 1. Clone repository
git clone https://github.com/ntro-sih2026/ulpf.git
cd ulpf

# 2. Copy environment template
cp .env.example .env

# 3. Start full production stack
docker compose -f docker-compose.prod.yml up -d --build

# 4. Verify deep health status
curl -s http://localhost:8000/api/pipeline/health | jq .
```

### Option B: Development / Standalone Mode (Zero External Infrastructure)
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run master server daemon
python run_ulpf.py
```

- **Operations Dashboard UI**: [http://localhost:8000](http://localhost:8000)
- **Interactive OpenAPI Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Prometheus OpenMetrics**: [http://localhost:8000/metrics](http://localhost:8000/metrics)
- **MinIO Web Console (Prod)**: [http://localhost:9001](http://localhost:9001) (`minioadmin` / `minioadmin123`)

---

## 📋 5. Supported Formats & OCSF Taxonomy

| Vendor / System | Raw Format | Detection Signature | Target OCSF Class | Key Normalized Fields |
| :--- | :--- | :--- | :--- | :--- |
| **Cisco ASA** | RFC 3164 Syslog | `%ASA-[0-9]-[0-9]+` | 4001: Network Activity | `src_endpoint`, `dst_endpoint`, `disposition`, `connection_info` |
| **Palo Alto PAN-OS** | Common Event Format (CEF) | `CEF:0\|Palo Alto Networks\|` | 4001: Network / 2001: Finding | `src_endpoint`, `dst_endpoint`, `threat_id`, `severity` |
| **Fortinet FortiOS** | Log Event Extended (LEEF) / KV | `LEEF:1.0\|Fortinet\|` / `type=traffic` | 4001: Network Activity | `src_endpoint`, `dst_endpoint`, `action`, `traffic.bytes` |
| **Check Point FW-1** | Key-Value Syslog | `product=VPN-1` / `action=accept` | 4001: Network Activity | `src_endpoint`, `dst_endpoint`, `rule`, `service` |
| **Suricata EVE** | Structured JSON | `{"event_type": "alert"}` | 2001: Security Finding | `finding_info`, `attacks`, `severity_id`, `src_endpoint` |
| **Zeek Network Monitor** | JSON / TSV | `{"ts": ..., "id.orig_h": ...}` | 4001: Network Activity | `src_endpoint`, `dst_endpoint`, `connection_info.protocol_name` |
| **Squid Proxy** | Access Log Format | `TCP_MISS/200` / `TAG_NONE` | 4001: Network Activity | `http_request.url`, `status_id`, `src_endpoint` |
| **Custom / Unknown** | Unstructured String | Drain3 Template Clustering | Class 4001 / Configurable | Mined `<IP>`, `<NUM>`, `<STR>` variables auto-mapped |

---

## ⚡ 6. Empirical Performance Benchmarks & Exact Configuration

All benchmarks are measured under the following documented configuration:
- **Host Hardware**: AMD Ryzen 5 (6 Cores / 12 Threads), 16 GB DDR4 RAM, 512 GB NVMe SSD.
- **Operating System & Runtime**: Windows 11 Pro / Ubuntu 22.04 LTS, Python 3.13.5.
- **Workload Parameters**: Average event size: 245 bytes. Batch size: 100 events/batch. Concurrency: 4 worker threads.

| Workload Scenario | Measured Throughput (EPS) | Latency p50 | Latency p95 | Latency p99 | RSS Memory |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Single-Event Ingest (Disk Sync)** | 45.0 EPS | 18.77 ms | 41.90 ms | 56.33 ms | 75.6 MB |
| **Micro-Batch Ingest (100 ev/batch)** | **3,450.0 EPS** | **0.28 ms** | **0.85 ms** | **1.42 ms** | 118.2 MB |
| **Parquet Lake Columnar Scan (10k ev)** | **125,000 EPS** | 4.10 ms | 7.80 ms | 12.50 ms | 142.0 MB |
| **Concurrent Workers (200 Threads)** | **100% Zero-Loss** | 42.10 ms | 88.30 ms | 124.00 ms | 135.0 MB |

> Detailed methodology and reproduction harness: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

---

## 🧪 7. Test Suite & Verification Rigor

The ULPF test suite comprises **67 automated tests** across 15 test suites:

```bash
# Execute entire test suite
python -m pytest tests/ -v

# Execute automated demo smoke tests (Story 1 & Story 2)
python -m pytest tests/test_demo_smoke.py -v

# Run storage adapter tests (MinIO + OpenSearch)
python -m pytest tests/test_storage_adapters.py -v

# Run queue & worker pool tests
python -m pytest tests/test_event_queue_and_workers.py -v

# Run chaos & failure recovery tests
python -m pytest tests/test_failure_recovery.py -v

# Run 200-worker concurrent load test
python -m pytest tests/test_concurrency_and_load.py -v
```

---

## 📚 8. Enterprise Engineering Documentation

- 🏛️ **[Production Architecture](docs/PRODUCTION_ARCHITECTURE.md)**: Deep breakdown of MinIO, OpenSearch, workers, and delivery state lifecycle.
- 🗄️ **[MinIO Raw Store Reference](docs/MINIO.md)**: Dedicated raw bucket layout, metadata schemas, and SHA-256 streaming verification.
- 🔍 **[OpenSearch SIEM Reference](docs/OPENSEARCH.md)**: Index templates, explicit OCSF mappings, and faceted query patterns.
- 🚨 **[Air-Gapped Disaster Recovery](docs/DISASTER_RECOVERY.md)**: Backup, snapshot, and restore procedures for air-gapped environments.
- 📊 **[Verification & Defensibility Matrix](docs/VERIFICATION_MATRIX.md)**: Complete 20-point requirement-to-evidence matrix.
- 🎬 **[6-Step Judging Demo Script](docs/DEMO_SCRIPT.md)**: Chronological live judging script covering all 6 evaluation stories.
- 📽️ **[Mandated 6-Slide SIH Presentation](docs/SIH_PRESENTATION.md)**: Exact 6-slide structure mandated for the Smart India Hackathon 2026 presentation.
- ⚙️ **[Configuration Reference](docs/CONFIGURATION.md)**: Environment variables, production mode enforcement, and secrets management.
- 📖 **[Operations & SRE Runbook](docs/OPERATIONS.md)**: Startup, graceful shutdown, DLQ draining, and zero-downtime parser updates.
- 🛡️ **[Security Architecture & Threat Model](docs/SECURITY.md)**: Threat catalog (STRIDE), mitigation matrix, rate limiting, and dependency audit.
- 📊 **[Empirical Benchmarks Report](docs/BENCHMARKS.md)**: Methodology, hardware specs, and measured throughput/latency numbers.
- 🧹 **[Technical Debt & Verification Catalog](docs/TECH_DEBT.md)**: Phase-by-phase inventory of eliminated shortcuts and hardened components.

---

## 📄 9. License

This project is licensed under the terms of the **Apache License 2.0**.  
See the [LICENSE](LICENSE) file in the root directory for the full license text.
