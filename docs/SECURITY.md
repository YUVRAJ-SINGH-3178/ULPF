# ULPF Enterprise Security Architecture & Threat Model

**Project Code**: SIH26156  
**Target Operational Environment**: NTRO & Strategic Air-Gapped Critical Information Infrastructures (CII)  
**Standard Compliance**: OCSF 1.1.0, RFC 3164 / 5424, NIST SP 800-92 (Log Management)

---

## 1. System Overview & Trust Boundaries

The Universal Log Pre-processing Framework (ULPF) operates at the boundary between untrusted telemetry sources (perimeter firewalls, IDS/IPS, proxy servers, edge routers) and strategic SIEM analytics / cold storage lakes.

```
+-----------------------------------------------------------------------------------+
| UNTRUSTED EXTERNAL ZONE                                                           |
| [Cisco ASA] [Palo Alto PAN-OS] [Fortinet FortiOS] [Suricata] [Zeek] [Squid Proxy]  |
+-----------------------------------------------------------------------------------+
                                      │
                                      ▼  (UDP/TCP Syslog, REST API, Batch Ingest)
+═══════════════════════════════════════════════════════════════════════════════════+
| ULPF BOUNDARY & INGESTION CONTROL (Trust Boundary 1)                              |
|  • In-Memory Sliding Window Rate Limiting (Per-IP throttling)                     |
|  • Strict Payload Size Bounds (HTTP 413 backpressure ceiling)                    |
|  • Lossless Write-Once Storage Promotion with SHA-256 Pre-Promotion Validation    |
+═══════════════════════════════════════════════════════════════════════════════════+
                                      │
                                      ▼
+═══════════════════════════════════════════════════════════════════════════════════+
| NORMALIZATION & PARSING PIPELINE (Trust Boundary 2)                               |
|  • Strict Exception Encapsulation (Adversarial Log Fuzzing Protection)            |
|  • Offline GeoIP & Internal Asset Enrichment (Zero External Network Egress)       |
|  • Drain3 Miner Sandboxing (Variable Extraction & Controlled State Persistence)   |
+═══════════════════════════════════════════════════════════════════════════════════+
                                      │
                                      ▼
+═══════════════════════════════════════════════════════════════════════════════════+
| STORAGE & SIEM INTEGRATION (Trust Boundary 3)                                     |
|  • SQLite 3 WAL Mode (FTS5 Tokenized Search, Atomic Audit Log Table)              |
|  • Parquet Data Lake (Snappy-compressed columnar format, DuckDB queryable)        |
|  • RBAC & JWT Authentication (Bcrypt salted password hashes, fail-fast keys)      |
+═══════════════════════════════════════════════════════════════════════════════════+
```

---

## 2. Threat Vector Analysis & Implemented Mitigations

### 2.1 Untrusted Log Payloads & Parser Exploitation
- **Threat**: Maliciously formatted syslog messages containing SQL injection, shell metacharacters, format strings, null bytes (`\x00`), or deeply nested JSON attempting to crash parser threads or poison the search index.
- **Mitigations**:
  1. *Fuzz-Resilient Parsing*: Every native and dynamic parser encapsulates format-specific parsing exceptions (e.g., `ValueError`, `KeyError`, `IndexError`, `json.JSONDecodeError`) without broad `except Exception: pass` masking. Unparsable logs are routed safely to the dead-letter error queue.
  2. *Parameterized SQLite / FTS5 Queries*: All queries against the metadata and full-text index use parameterized SQL (`?` placeholders). SQL injection strings in raw payloads are stored literally and cannot modify query semantics.
  3. *Zero-Shell Execution*: No log parsing or formatting logic delegates to subshells, shell wrappers, or `eval()`.

### 2.2 Path Traversal & File Overwrite Attacks
- **Threat**: Attackers supply path traversal sequences (`../`, `..\`, `/etc/passwd`, `..\windows\system32`) via API path parameters (`event_id`, `parser_id`, `session_id`, `error_id`) to read or overwrite server files.
- **Mitigations**:
  1. *Strict Identifier Validation*: Every endpoint consuming resource identifiers validates against `validate_safe_identifier()`, enforcing alphanumeric character sets (`^[a-zA-Z0-9_\-\.:]+$`), rejecting traversal symbols (`..`, `/`, `\`, null bytes), and bounding lengths to 128 characters.
  2. *Atomic Temporary File Writes*: Raw payloads and Parquet files are written to `.tmp` files and promoted via atomic `os.replace`, preventing partial file writes or race-condition overwrites.

### 2.3 Authentication, Session Security & Privilege Escalation
- **Threat**: Weak JWT secrets, unauthenticated admin bypass in production, brute-force password guessing, or expired token abuse.
- **Mitigations**:
  1. *Fail-Fast Production Secret Key Validation*: In production (`ULPF_DEMO_MODE=False`), startup fails immediately if `ULPF_SECRET_KEY` is unset or less than 16 bytes.
  2. *Bcrypt Salted Password Storage*: User passwords are pre-hashed with SHA-256 (preventing 72-byte truncation) and salted with `bcrypt`.
  3. *Sliding-Window Rate Limiting*: Authentication endpoints enforce 60 attempts/minute per IP, returning HTTP 429 when throttled.
  4. *Short-Lived Access Tokens + Refresh Tokens*: Supports access token rotation via `/api/auth/refresh`.

### 2.4 Human-in-the-Loop Poisoning & Supply Chain Risk
- **Threat**: Malicious or accidental parser rule modifications through the onboarding interface poisoning SIEM detections.
- **Mitigations**:
  1. *Immutable Administrative Audit Trail*: Every parser approval, mapping update, and error replay is recorded to the SQLite `audit_trail` table and `.jsonl` audit log with timestamp, operator username, role, and delta.
  2. *Dry-Run Sandbox Testing*: Parsers cannot be activated without passing dry-run sample evaluation.

---

## 3. Explicit Residual Risks & Out-of-Scope Defenses

| Risk | Status / Rationale | Recommended Deployment Control |
| :--- | :--- | :--- |
| **Physical Disk Theft** | Not mitigated at application layer | Underlying OS volume encryption (BitLocker / LUKS) must be enabled on storage nodes. |
| **Volumetric DDoS / L3/L4 Flood** | Application rate limiter protects HTTP workers, but cannot withstand multi-gigabit raw UDP floods | Enterprise upstream hardware firewall / load balancer rate limiting on port 514 / 5140. |
| **Kernel / Python Zero-Days** | Application relies on CPython 3.13 standard libraries | Deploy containerized (`docker-compose`) with non-root user and minimal base image. |
