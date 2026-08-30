# ULPF Technical Debt & Vulnerability Inventory

> Generated as part of Phase 0 Production Hardening (SIH26156).  
> Every item recorded here is systematically resolved across Phases 1–7.

---

## 1. Known & Latent Correctness Bugs

| Location | Severity | Description | Phase Fix |
| :--- | :--- | :--- | :--- |
| `ulpf/services/parser_engine/cisco_asa_parser.py:81` | **CRITICAL** | Regex `(\d+)(?:\([^\)]+\))?` lacks whitespace handling (`\s*`), causing built connection logs with mapped addresses (e.g. `outside:198.51.100.25/443 (198.51.100.25/443)`) to fail regex match and fall through to naive IP extraction where `src_ip == dst_ip == 198.51.100.25`. | **Phase 1** |
| `ulpf/services/parser_engine/palo_alto_parser.py:66-77` | **MEDIUM** | PAN-OS CSV parser uses fixed index offsets without boundary and quote validation, risking index errors or shifted fields on varying syslog formats. | **Phase 1** |
| `ulpf/services/parser_engine/fortinet_parser.py:70-79` | **LOW** | Protocol mapping handles only 6 (TCP), 17 (UDP), 1 (ICMP); unmapped protocol numbers remain raw strings instead of standard OCSF resolution. | **Phase 1** |
| `ulpf/services/normalization/ocsf_mapper.py:294-305` | **MEDIUM** | Connection direction defaults to "Inbound" without accounting for explicit firewall session directionality in all parser contexts. | **Phase 1** |

---

## 2. Silent Failures & Broad Exceptions (`except Exception: pass`)

| Location | Issue | Remediation |
| :--- | :--- | :--- |
| `ulpf/apps/api/main.py:78,89` | Silent listener bind failure on UDP/TCP ports. | Log error and surface degraded listener state in health check. |
| `ulpf/apps/api/auth.py:98` | Broad JWT error swallowing. | Return explicit 401 with detailed reason when non-demo. |
| `ulpf/services/storage/search_index.py:363` | Silent JSON decode ignore on OCSF document search. | Log warning and return raw data. |
| `ulpf/services/storage/raw_store.py:41` | Silent ignore on corrupted `.meta.json` during startup. | Log corrupted metadata path and recover. |
| `ulpf/services/replay/replay_engine.py:39` | Silent failure reading persisted dead-letter error files. | Structured error logging on corrupt disk entries. |
| `ulpf/services/parser_engine/registry.py:108` | Silent failure loading custom parser JSON. | Log warning with parser filename and syntax error. |
| `ulpf/services/parser_engine/leef_parser.py:77` | Broad exception in delimiter hex decoding. | Catch specific `ValueError` and default gracefully. |
| `ulpf/services/parser_engine/drain3_dynamic_parser.py:51,112` | Broad exceptions in dynamic regex compilation and type transformation. | Surface validation error and mark parser status. |
| `ulpf/services/onboarding/session_manager.py:68` | Silent ignore on corrupted onboarding session files. | Log session file corruption. |
| `ulpf/services/onboarding/field_discovery.py:41` | Silent exception in Drain3 template analysis. | Catch specific regex error and report error message. |
| `ulpf/services/ingestion/listeners.py:52,72,81,122,133,157,219` | Bare exceptions in network socket loops and file batch reading. | Typed socket exceptions, clean socket closure, structured error logging. |
| `ulpf/services/detection/format_detector.py:44` | Broad exception in JSON format detection. | Catch `json.JSONDecodeError` specifically. |

---

## 3. In-Memory State Requiring Durability

| State Object | Current Storage | Target Storage (Phase 2 & 3) |
| :--- | :--- | :--- |
| **User Store & Credentials** | In-memory `USERS_DB` dictionary in `auth.py` | Config-driven / SQLite-persisted user table with bcrypt hashes |
| **Audit Logs** | In-memory `self._audit_trail` list in `session_manager.py` | SQLite table `audit_trail` in `search_index.db` with query API |
| **Active Dynamic Parsers** | In-memory dict with separate JSON files | Atomic JSON files in `data/parsers/` with index syncing |
| **Onboarding Sessions** | In-memory dict with separate JSON files | Atomic JSON files in `data/onboarding_sessions/` with state recovery |
| **Error / Dead-Letter Queue** | In-memory dict with separate JSON files | Atomic JSON files in `data/error_queue/` with status lifecycle |

---

## 4. Hardcoded Secrets, Credentials, and Configuration

| Item | Current Implementation | Target Implementation |
| :--- | :--- | :--- |
| **JWT Secret Key** | Hardcoded default `"ulpf-ntro-sih2026-airgap-secure-key-32bytes"` | Required `ULPF_SECRET_KEY` in production; fail-fast at startup |
| **Demo Mode Bypass** | Missing auth header automatically authenticates as admin | Explicit `ULPF_DEMO_MODE=true` required; 401 when false |
| **Password Hashes** | Plain `hashlib.sha256(password)` | `passlib.context.CryptContext` with `bcrypt` salting |
| **File Paths & Ports** | Hardcoded `"data/raw_store"`, port `8000`, `5140`, `1514` | Centralized `Settings` model in `ulpf/packages/config/settings.py` |

---

## 5. Storage Durability & Security Gaps

| Area | Current Risk | Hardening Action |
| :--- | :--- | :--- |
| **Raw Store Writes** | Direct `open(raw_file, "wb")` can leave partial `.raw` files on crash | Write to `*.tmp` and atomic `os.replace` rename |
| **Path Traversal** | Unvalidated `event_id`, `session_id`, `source_id` in path joins | Strict regex validation `^[a-zA-Z0-9_-]+$` rejecting `..` |
| **Ingestion Backpressure** | Unbounded memory growth under sustained DDoS/overload | Bounded queue with explicit shedding (HTTP 429/503) |
| **Rate Limiting** | Ingestion and auth endpoints have no request throttling | In-memory token bucket rate limiter |
| **Observability** | `/api/pipeline/health` returns static components | Real diagnostic checks (queue depth, storage latency, unhandled errors) |
| **Metrics** | Custom JSON metrics only | Standard Prometheus metrics export at `/metrics` |
