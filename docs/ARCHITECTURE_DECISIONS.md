# ULPF Architecture Decision Records (ADRs)

**System**: Universal Log Pre-processing Framework (ULPF)  
**Security Classification**: NTRO Strategic / CII  
**Status**: Accepted & Implemented

---

## ADR-001: SQLite WAL + FTS5 for Low-Latency SIEM Hot Index

### Context
Perimeter security operations require instantaneous search, filtering, and aggregation over recent event envelopes (< 7 days) without incurring the operational overhead and memory consumption of external Elasticsearch or OpenSearch clusters in air-gapped field deployments.

### Decision
Use embedded SQLite 3 with Write-Ahead Logging (`PRAGMA journal_mode=WAL`), memory-mapped I/O (`PRAGMA mmap_size=268435456`), synchronous normal mode, and SQLite Full-Text Search 5 (`FTS5`) with BM25 ranking.

### Consequences
- **Positive**: Zero external service dependencies, sub-5ms query latencies, zero socket overhead, ACID transaction safety under high concurrency (200+ workers).
- **Negative**: Single-writer constraint mitigated by SQLite WAL mode and busy timeout retry loops.

---

## ADR-002: Snappy-Compressed Apache Parquet + DuckDB for Long-Term Data Lake

### Context
Security telemetry retention regulations mandate 90+ days of historical log storage. Storing full JSON documents indefinitely causes exponential disk bloat and slow analytical scans.

### Decision
Implement dual-sink ingestion where normalized OCSF events are buffered into micro-batches and written as columnar Apache Parquet files with Snappy compression, queryable directly via embedded DuckDB.

### Consequences
- **Positive**: ~85% storage compression ratio compared to raw JSON, vectorized analytics scanning millions of records per second without database indexing overhead.
- **Negative**: Requires buffer flushing mechanism on shutdown to prevent unflushed in-memory records.

---

## ADR-003: Lossless Write-Once Storage Architecture with Pre-Promotion SHA-256 Verification

### Context
Forensic readiness and legal admissibility under the Indian Information Technology Act (CERT-In compliance) require that raw original log payloads are preserved exactly as received with cryptographic non-repudiation.

### Decision
Store raw payloads in immutable append-only files structured by `YYYY/MM/DD/`. Prior to file promotion (`os.replace`), verify the SHA-256 digest against the computed envelope hash. Mark all stored files read-only (`0o444`).

### Consequences
- **Positive**: 100% byte-for-byte fidelity guaranteed; tamper detection endpoint allows immediate cryptographic audit.
- **Negative**: Storage requirements scale linearly with raw ingress volume before compression.

---

## ADR-004: OCSF 1.1.0 Standardized Schema Alignment & Explicit Directionality Mapping

### Context
Perimeter firewalls (Cisco ASA, Palo Alto PAN-OS, Fortinet FortiGate, Check Point) emit proprietary syslog and CEF messages with conflicting conventions for NAT/mapped IP addresses and connection directionality.

### Decision
Normalize all incoming perimeter logs into Open Cybersecurity Schema Framework (OCSF v1.1.0) Class 4001 (Network Activity). In Cisco ASA inbound connections (`%ASA-6-302013`), extract the external initiator IP as `src_endpoint` and internal target as `dst_endpoint`, preserving mapped addresses in `unmapped` attributes.

### Consequences
- **Positive**: Cross-vendor query interoperability, uniform SIEM alerting rules, schema adherence.
- **Negative**: Requires strict parser regression testing to prevent direction inversion.

---

## ADR-005: Drain3 Log Mining with Human-in-the-Loop Zero-Downtime Parser Publishing

### Context
Perimeter environments frequently encounter custom or newly deployed proprietary log formats. Hardcoding parsers or requiring service redeployments creates operational friction.

### Decision
Integrate Drain3 online prefix-tree clustering. Unmatched logs are routed to an onboarding queue, where templates and placeholder variable types are inferred. A reviewer approves or adjusts the mapping via UI/API, which immediately compiles and hot-reloads the versioned parser without restarting the daemon.

### Consequences
- **Positive**: Zero-downtime extensibility, human oversight prevents hallucinated schema mappings, automatic post-approval log replay.
- **Negative**: Requires bounded template cache to prevent memory exhaustion on highly unstructured noise.

---

## ADR-006: Air-Gapped Network Design with Offline GeoIP & Asset Inventory Enrichment

### Context
Strategic intelligence and defence networks operate in complete air-gap environments (no outbound DNS or internet access). Standard GeoIP REST lookups or external threat intelligence APIs fail or violate security policy.

### Decision
Implement 100% offline enrichment using local subnet CIDR databases and static enterprise asset inventory dictionaries. Ensure all Docker networks use `internal: true`.

### Consequences
- **Positive**: Zero outbound socket connections, immune to external network outages, zero DNS leakage.
- **Negative**: Threat intelligence and GeoIP databases must be periodically updated via air-gap media bundles.

---

## ADR-007: Enterprise Security Architecture (Rate Limiting, Strict Sanitization, Audit Logging)

### Context
The API must resist malicious input, path traversal exploits, payload flood attacks, and privilege abuse.

### Decision
- Enforce strict identifier regex (`^[a-zA-Z0-9_\-\.:]+$`) rejecting directory traversal sequences (`..`, `/`, `\`).
- Enforce thread-safe sliding-window rate limiting on ingestion and authentication routes.
- Enforce max payload size limit (HTTP 413) on incoming payloads.
- Record administrative audit logs in SQLite for all parser approvals and modifications.

### Consequences
- **Positive**: Clean penetration test / pip-audit results, protection against unhandled 500s.
- **Negative**: Minimal per-request regex validation overhead (< 0.05ms).
