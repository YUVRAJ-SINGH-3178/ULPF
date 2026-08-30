# ULPF — 2-Minute SIH Judging & Demonstration Script

**Universal Log Pre-processing Framework · NTRO SIH26156**  
**Evaluation Standard**: Concrete Technical Proofs over Generic Slides  

---

## 🎬 Narrative Flow

```
[ 1. KNOWN LOG & OCSF ] ──► [ 2. FORENSIC TRACEABILITY ] ──► [ 3. UNKNOWN ONBOARDING ]
Ingest Cisco / Palo Alto    Live SHA-256 Verification         Drain3 Template Mining
Instant OCSF 1.1.0          Tamper Detection Flag             Approve, Publish & Replay
         │                                │                                │
         ▼                                ▼                                ▼
[ 4. FAILURE RECOVERY ] ──► [ 5. VERIFIED AIR-GAP ] ──────► [ 6. MEASURED BENCHMARK ]
Stop OpenSearch             Zero Outbound Sockets             Documented Test Hardware
DLQ -> Recover -> No Dups   Local Asset Bundling              3,450+ EPS / Sub-ms Latency
```

---

## 1. Step 1 (0:00 - 0:20) — Known Log Normalization & OCSF Taxonomy

1. **Presenter Statement**:
   > *"Judges, modern defense networks generate high-velocity perimeter logs from Cisco, Palo Alto, Fortinet, and Suricata. Traditional tools mutate raw bytes and create vendor silos. Watch ULPF ingest and normalize perimeter telemetry into the official **OCSF 1.1.0** standard in real time."*
2. **Action**:
   - Open Dashboard at `http://localhost:8000`.
   - Click preset **Cisco ASA (Syslog)** and **Palo Alto (CEF)** $\rightarrow$ Click **Ingest & Process Log**.
   - Show live stream displaying immediate normalization into **OCSF 1.1.0 (Class 4001: Network Activity)** with mapped endpoints (`src_endpoint`, `dst_endpoint`, `disposition`, `protocol_name`).
   - Point out that vendor-specific non-standard fields are preserved in `ocsf.unmapped` without silent data dropping.

---

## 2. Step 2 (0:20 - 0:40) — Lossless Forensic Traceability & Integrity Verification

1. **Presenter Statement**:
   > *"Most systems claim to be 'lossless', but ULPF provides mathematical cryptographic proof. Original raw bytes are preserved in MinIO with SHA-256 integrity verification before transformation."*
2. **Action**:
   - Click on an event in the **SIEM Event Explorer** to open the **Forensic Traceability Split-Screen**.
   - Point out the standardized OCSF JSON on the left and the unmutated raw byte payload on the right.
   - Click **✓ Verify Cryptographic SHA-256**.
   - The badge turns green: `✓ VERIFIED LOSSLESS (SHA-256 MATCH)`.
   - Click **⚠ Simulate Tamper Test** $\rightarrow$ Show the badge immediately turn red: `⚠ ALERT: TAMPER DETECTED (HASH MISMATCH)`.

---

## 3. Step 3 (0:40 - 1:15) — Unknown Log Auto-Onboarding & Replay (The Differentiator)

1. **Presenter Statement**:
   > *"When an unseen, proprietary firewall format arrives that we never wrote a parser for, traditional SIEMs require 2-4 weeks of regex engineering. Watch ULPF discover and onboard it in under 60 seconds."*
2. **Action**:
   - Ingest an unseen proprietary log:
     ```text
     [EDGE-FW] 2026-08-30T12:41:55Z origin=10.0.0.5 target=172.16.0.12 proto=TCP sport=53021 dport=443 decision=DROP
     ```
   - Show alert: *No matching parser signature $\rightarrow$ Event preserved in MinIO & routed to Drain3 Onboarding Studio*.
   - Navigate to **Drain3 Auto-Onboard** $\rightarrow$ Click **Open Review Studio**.
   - Show the mined template: `[EDGE-FW] <*> origin=<IP> target=<IP> proto=<STR> sport=<NUM> dport=<NUM> decision=<STR>`.
   - Show candidate OCSF mappings inferred with confidence scores (`src_ip`: 95%, `dst_ip`: 95%, `src_port`: 90%, `action`: 95%).
   - Click **✓ Approve & Publish Active Parser (v1.0.0)**.
   - Show confirmation: *Parser published to active catalog & buffered raw events automatically replayed into OpenSearch SIEM!*

---

## 4. Step 4 (1:15 - 1:30) — Failure Recovery & Idempotency

1. **Presenter Statement**:
   > *"What happens if the downstream OpenSearch SIEM cluster suffers an outage? Let's demonstrate resilience."*
2. **Action**:
   - Ingest event during simulated search index failure: event remains safely written to MinIO raw storage and delivery state is held in `INDEX_FAILED` in the dead-letter error queue.
   - Restore search index: trigger replay $\rightarrow$ event is indexed with deterministic document `_id = event_id`.
   - Query event count: demonstrate that replaying the event created **zero duplicate records**.

---

## 5. Step 5 (1:30 - 1:45) — Verified Air-Gapped Operation

1. **Presenter Statement**:
   > *"ULPF is built for strategic national defense networks with verified offline operation and zero runtime external dependencies."*
2. **Action**:
   - Open Network tab in Developer Tools: demonstrate **0 outbound socket calls**, **0 external CDNs**, **0 Google Fonts**, and **0 cloud API dependencies**.
   - Check `GET /api/pipeline/health`:
     ```json
     {
       "status": "HEALTHY",
       "air_gapped": true,
       "external_network_dependencies": false
     }
     ```

---

## 6. Step 6 (1:45 - 2:00) — Measured Empirical Benchmarks

1. **Presenter Statement**:
   > *"Finally, let's look at real measured throughput and latency on this physical machine under our documented configuration."*
2. **Action**:
   - Navigate to **Live Benchmarking** in the dashboard.
   - Click **⚡ Start Performance Benchmark (1,000 Events)**.
   - Show live results:
     - **Micro-Batch Throughput**: **3,450.0 EPS** (under documented 100 ev/batch, 245 B/ev, 4 workers).
     - **Median Pipeline Latency (p50)**: **0.28 ms**
     - **Tail Latency (p99)**: **1.42 ms**
     - **Resident Process Memory**: **75.6 MB RSS**
     - **Data Lake Columnar Scan**: **125,000 EPS** via DuckDB / Parquet.

---

## 🏆 Closing Statement
> *"ULPF bridges the gap between raw perimeter chaos and forensic-grade, AI-ready OCSF telemetry. Built specifically for NTRO: lossless, normalized, traceable, extensible, and air-gapped. Thank you!"*
