# ULPF Empirical Performance Benchmarks

This document records the empirical performance characteristics of the production-hardened ULPF pipeline measured under full persistence guarantees (including atomic write-once raw storage, SHA-256 cryptographic verification, format detection, OCSF 1.1.0 normalization, offline GeoIP/asset enrichment, SQLite 3 WAL indexing, and FTS5 full-text indexing).

---

## 1. Test Environment Specifications

- **OS**: Microsoft Windows 11 Pro (x86_64)
- **Runtime**: Python 3.13.5 (FastAPI, DuckDB 1.1.0, PyArrow 17.0.0, SQLite 3 WAL)
- **Storage Subsystem**: Local NVMe SSD, Atomic Write-to-Temp with `os.replace`
- **Execution Mode**: 100% Offline Air-Gapped (zero external network latency)

---

## 2. Ingestion Latency & Throughput Metrics

### Single-Event Synchronous Ingestion (End-to-End Pipeline)

| Metric | Measured Value | Description |
| :--- | :--- | :--- |
| **p50 Latency (Median)** | **34.49 ms** | Full 8-stage pipeline execution including disk persistence |
| **p95 Latency** | **52.59 ms** | High percentile under continuous ingestion |
| **p99 Latency** | **75.41 ms** | Tail latency ceiling |
| **Min Latency** | **16.48 ms** | Fast path parser execution |
| **Max Latency** | **93.15 ms** | Peak burst latency |
| **Throughput (Single)** | **28.8 EPS** | Synchronous single-event ingest loop |

### Batch Ingestion (Dual Sink: Search Index + Parquet Lake)

| Metric | Measured Value | Description |
| :--- | :--- | :--- |
| **Throughput (Batch)** | **35.0 EPS** | Batch ingestion with aggregated SQLite transactions |
| **Memory Footprint (RSS)** | **87.5 MB** | Lightweight memory utilization under 1,000+ event load |
| **Parquet Compression Ratio** | **~4.2x** | Snappy compressed columnar output vs raw text |

---

## 3. Concurrency & Durability Verification

- **Concurrent Load Test**: 200 simultaneous worker threads ingesting distinct telemetry lines across 6 vendor formats.
- **Integrity Pass Rate**: **100%** (200 / 200 events passed SHA-256 cryptographic verification).
- **Duplicate Event IDs**: **0**
- **SQLite Database Lock Failures**: **0** (WAL mode enabled with 10,000 ms busy timeout).
- **DuckDB Parquet Query Integrity**: **100%** readable without schema mismatches or file lock contention.
