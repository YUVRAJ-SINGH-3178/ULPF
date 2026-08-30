# ULPF 2-Minute SIH Judging & Demo Script
**Universal Log Pre-processing Framework · NTRO SIH26156**

Follow this exact chronological script during live evaluation to deliver an unbeatable, winning demonstration.

---

## 🎬 0:00 - 0:25 | Opening: The Problem & Known Log Normalization

1. **Presenter**:
   > "Judges, modern defense networks generate billions of heterogeneous logs from Cisco, Palo Alto, Fortinet, Suricata, and proprietary firewalls. Traditional systems either discard raw events or require weeks to code new parsers. We built **ULPF** with five non-negotiable properties: **Lossless, OCSF-Normalized, Traceable, Extensible with Drain3, and 100% Air-Gapped**."

2. **Action**:
   - Open Dashboard at `http://localhost:8000`.
   - Click the preset button **Cisco ASA (Syslog)** and **Palo Alto (CEF)** $\rightarrow$ Click **Ingest & Process Log**.
   - Show live stream showing instant normalization into **OCSF 1.1.0 (Class 4001: Network Activity)** with $<0.5$ ms latency.

---

## 🔬 0:25 - 0:50 | The Lossless Forensic Proof

1. **Presenter**:
   > "Most teams claim their pipeline is 'lossless', but we provide cryptographic proof. Every normalized event carries a direct link to the exact unmutated raw payload stored before transformation."

2. **Action**:
   - Click on any event in the **SIEM Event Explorer** to open the **Lossless Traceability Split-Screen**.
   - Point out the standardized OCSF JSON on the left and the raw payload on the right.
   - Click **✓ Verify Cryptographic SHA-256**.
   - The badge turns green: `✓ 100% VERIFIED LOSSLESS (SHA-256 MATCH)`.
   - Click **⚠ Simulate Tamper Test** $\rightarrow$ Show the badge immediately turn red: `⚠ ALERT: TAMPER DETECTED (HASH MISMATCH)`.

---

## ⚡ 0:50 - 1:30 | Unknown Log Auto-Onboarding (The Winning Differentiator)

1. **Presenter**:
   > "Now, what happens when an unseen, proprietary appliance format arrives that we never wrote a parser for? Let's feed one live."

2. **Action**:
   - Click **⚡ Unknown Format** preset:
     ```
     [APPLIANCE-FW] 2026-08-27T10:15:40Z DEV=EDGE-FW-09 RULE=BLOCK_SSH_ATTACK SRC=185.220.101.5:49152 DST=10.0.0.5:22 PROTO=TCP ACTION=DENY BYTES=120 REASON="BRUTE_FORCE_BURST"
     ```
   - Click **Ingest & Process Log**.
   - Show alert: *Unknown format routed to Drain3 Onboarding Studio*.
   - Click **Drain3 Auto-Onboard** in the sidebar.
   - Click **Open Review Studio**: Show the discovered template with `<IP>`, `<NUM>`, `<STR>` variables and inferred OCSF mappings (`src_ip` 95%, `dst_ip` 95%, `action` 95%).
   - Click **✓ Approve & Publish Active Parser**.
   - Show confirmation: *Parser published & buffered logs automatically replayed into OCSF!*

---

## 🛡️ 1:30 - 2:00 | Air-Gap Certification & Real Load Benchmark

1. **Presenter**:
   > "Finally, ULPF is 100% air-gapped with zero SaaS or internet dependencies, fanning out simultaneously to a SIEM search index and an Apache Parquet data lake."

2. **Action**:
   - Navigate to **Live Benchmarking**.
   - Select **5,000 Events** $\rightarrow$ Click **⚡ Start Performance Benchmark**.
   - Show real-time gauges: **5,000+ EPS**, **P95 Latency 0.45 ms**, **18% CPU**, and **400+ Million events/day/node capacity**.
   - Show **System & Air-Gap** view confirming **100% Air-Gap Active (0 External Sockets)**.

---

## 🏆 Closing Statement
> "ULPF bridges the gap between raw perimeter chaos and forensic-grade, AI-ready OCSF telemetry. Built specifically for NTRO, lossless, extensible, and completely air-gapped. Thank you!"
