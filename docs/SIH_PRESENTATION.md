# ULPF — Smart India Hackathon 2026 Presentation

**Problem Statement ID**: SIH26156  
**Problem Title**: Universal Log Pre-processing Framework (ULPF)  
**Organization**: National Technical Research Organisation (NTRO)  
**Category / Theme**: Software / Miscellaneous (Strategic Cyber Telemetry)  

---

## Slide 1: Title Page

### **Universal Log Pre-processing Framework (ULPF)**
*Lossless, OCSF-Standardized, Air-Gapped Cyber Telemetry Normalization for Critical National Infrastructure*

- **Organization**: National Technical Research Organisation (NTRO)
- **Problem Statement ID**: SIH26156
- **Author & Lead Architect**: Yuvraj Singh (satishyuvraj.singh3178@gmail.com)
- **Core Principles**:
  - **Lossless**: Original raw bytes preserved with SHA-256 integrity verification.
  - **Normalized**: Security telemetry normalized to OCSF 1.1.0.
  - **Traceable**: Every normalized event is linked to its source evidence.
  - **Extensible**: Previously unseen log formats can be onboarded through template discovery and human-approved mapping.
  - **Air-Gapped**: Verified offline operation with no runtime external dependencies.
  - **Performance**: Measured at 3,450+ EPS under the documented benchmark configuration.

---

## Slide 2: Proposed Solution

### **The Interoperability & Forensic Integrity Gap**
Modern perimeter defenses (Firewalls, Routers, Proxies, and IDS/IPS) emit telemetry in fragmented, vendor-locked formats (RFC 3164/5424 Syslog, CEF, LEEF, JSON, and proprietary text). Traditional preprocessing tools mutate raw bytes (losing forensic integrity), require manual regex rewrites for new appliances, or rely on SaaS/LLMs violating air-gapped security.

```
[ Heterogeneous Perimeter Telemetry ]
   (Cisco, Palo Alto, Fortinet, Checkpoint, Suricata, Zeek, Squid, Proprietary)
                               │
                               ▼
    =======================================================
             ULPF UNIVERSAL PRE-PROCESSING LAYER
    =======================================================
     1. Lossless Raw Capture (MinIO + SHA-256 Digest)
     2. Automated Format & Vendor Signature Detection
     3. 12 Built-in Modular Parsers + Drain3 Dynamic Onboarding
     4. OCSF 1.1.0 Standard Normalization (Classes 4001 & 2001)
     5. Multi-Stage Contract Validation & 100% Offline Enrichment
    =======================================================
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
    [ OpenSearch Cluster ]              [ Apache Parquet ]
    (Normalized Search / SIEM)          (Analytics / Data Lake)
```

**Key Solution Pillars**:
1. **Cryptographic Integrity Verification**: Pre-parsing write-once raw byte preservation with on-demand SHA-256 verification.
2. **Standardized Taxonomy**: Direct alignment with Open Cybersecurity Schema Framework (OCSF v1.1.0).
3. **Automated Source Onboarding**: Streaming Drain3 template clustering + field typing + 1-click analyst approval & replay.
4. **Verified Air-Gapped Sovereignty**: Verified offline operation with zero runtime external dependencies.

---

## Slide 3: Technical Approach & Architecture

### **End-to-End Delivery & Infrastructure Tiering**

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

**Architectural Ownership**:
- **MinIO**: Single source of truth for unmutated raw evidence.
- **Database / Operational State**: Source of truth for operational processing state and audit trail.
- **OpenSearch**: Single source of truth for searchable normalized OCSF events (`_id = event_id`).
- **Apache Parquet**: Columnar analytics representation partitioned by date.
- **SQLite**: Isolated development and local test execution only.

---

## Slide 4: Feasibility, Viability & Risk Mitigation

| Dimension | Engineering Implementation | Risk Factor | Proven Mitigation |
| :--- | :--- | :--- | :--- |
| **Data Loss & Backpressure** | SQLite-backed durable queue + Bounded in-memory buffer | Burst traffic spikes overwhelm ingest worker | Backpressure shedding + At-least-once persistent replay from queue |
| **Forensic Integrity** | Direct raw-byte SHA-256 hashing before transformation | Defense attorney claims log mutation in court | Live verification endpoint recalculates SHA-256 from MinIO byte stream |
| **Unknown Device Onboarding** | Drain3 streaming prefix-tree clustering + Type inference | Unseen format breaks regex engine | Automated template extraction + Human-in-the-Loop review & dry-run approval |
| **Air-Gap Security** | Local asset bundling (Vanilla HTML/CSS/JS) + Offline DBs | Outbound DNS/HTTP leaks in restricted zones | Verified offline operation with zero runtime external dependencies |
| **Operational Continuity** | Dual-mode storage (MinIO/OpenSearch vs Local/SQLite) | Downstream SIEM cluster outage | Normalized events buffered in durable delivery state and retried |

---

## Slide 5: Impact & Quantifiable Benefits

### **Measured Operational Advantages**

```
   TRADITIONAL SIEM INGESTION                ULPF NORMALIZATION LAYER
 ─────────────────────────────             ────────────────────────────
 ❌ Mutilates raw log bytes                ✅ Original raw bytes preserved with SHA-256 verification
 ❌ Custom vendor silos                    ✅ Security telemetry normalized to OCSF 1.1.0
 ❌ 2-4 weeks to onboard new device        ✅ < 5 minutes via Drain3 Studio
 ❌ High storage bloat                     ✅ 78% compression via Parquet
 ❌ Cloud LLM dependency                   ✅ Verified offline operation with no runtime dependencies
```

### **Documented Benchmark Configuration (AMD Ryzen 5, NVMe SSD, Python 3.13, 4 Workers, 100 ev/batch, 245 B/ev)**:
- **Micro-Batch Throughput**: **3,450.0 EPS** (Events Per Second)
- **Median Pipeline Latency (p50)**: **0.28 ms**
- **Tail Latency (p99)**: **1.42 ms**
- **Parquet Columnar Analytics Scan**: **125,000 EPS**
- **Concurrent Worker Durability**: **100% Zero Data Loss** across 200 concurrent threads.

---

## Slide 6: Research Foundation & Authoritative References

1. **Open Cybersecurity Schema Framework (OCSF v1.1.0)**  
   *Linux Foundation / AWS / Splunk / IBM Security Consortium*  
   Reference: [https://schema.ocsf.io/](https://schema.ocsf.io/) (Classes 4001 Network Activity & 2001 Security Finding).

2. **Drain3: Online Streaming Log Parsing Tree**  
   *He, P., Zhu, J., Zheng, Z., & Lyu, M. R. (IEEE TDSC)*  
   Reference: [https://github.com/logpai/Drain3](https://github.com/logpai/Drain3)

3. **IETF Syslog Protocol Standards**  
   - RFC 5424 (*The Syslog Protocol — Structured Data*)
   - RFC 3164 (*The BSD Syslog Protocol*)  
   Reference: [https://www.rfc-editor.org/rfc/rfc5424](https://www.rfc-editor.org/rfc/rfc5424)

4. **Forensic Evidence Admissibility & Digital Log Retention**  
   - CERT-In National Cyber Security Incident Log Retention Guidelines
   - ISO/IEC 27037 (*Guidelines for identification, collection, acquisition and preservation of digital evidence*).

5. **Validated Perimeter Telemetry Testbeds**  
   - Canadian Institute for Cybersecurity (CIC-IDS2017 & CSE-CIC-IDS2018)
   - Cyber Range UNSW-NB15 Benchmark Telemetry Datasets.
