# ULPF Unified Configuration Reference

The Universal Log Pre-processing Framework (ULPF) uses a centralized `pydantic-settings` model defined in [`ulpf/packages/config/settings.py`](file:///c:/Users/satis/OneDrive/Desktop/SIH2026/ulpf/packages/config/settings.py). Settings are loaded with the following precedence:
1. Environment variables
2. `.env` file in the working directory
3. Default values (with strict validation in production mode)

---

## 1. Operational Mode & Security Settings

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `ULPF_DEMO_MODE` | `bool` | `false` | When `true`, enables unauthenticated local demo evaluation mode. When `false` (production default), all API requests strictly require a valid Bearer JWT token. |
| `ULPF_SECRET_KEY` | `str` | *None* | Cryptographic HMAC secret key used to sign and verify JWT authentication tokens. **Mandatory in non-demo mode** (must be at least 16 characters; fails fast at startup if missing). |
| `ULPF_JWT_ALGORITHM` | `str` | `HS256` | Cryptographic signing algorithm for JWT tokens. |
| `ULPF_ACCESS_TOKEN_EXPIRE_MINUTES` | `int` | `1440` (24h) | Lifespan in minutes for issued API access tokens. |
| `ULPF_REFRESH_TOKEN_EXPIRE_MINUTES` | `int` | `10080` (7d) | Lifespan in minutes for issued refresh tokens. |
| `ULPF_AIR_GAPPED` | `bool` | `true` | When `true`, strictly prohibits outbound network calls, enforcing 100% offline air-gapped threat intelligence and asset resolution. |

---

## 2. Network & Ingestion Listener Settings

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `ULPF_API_HOST` | `str` | `0.0.0.0` | IP binding address for the FastAPI HTTP service. |
| `ULPF_API_PORT` | `int` | `8000` | TCP port for the FastAPI HTTP service. |
| `ULPF_UDP_SYSLOG_PORT` | `int` | `5140` | UDP port for RFC3164 / RFC5424 live syslog ingestion. |
| `ULPF_TCP_SYSLOG_PORT` | `int` | `1514` | TCP port for streaming syslog ingestion. |
| `ULPF_ENABLE_SYSLOG_LISTENERS` | `bool` | `true` | Whether background UDP and TCP syslog daemons are initialized on startup. |

---

## 3. Storage & Persistence Paths

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `ULPF_BASE_DATA_DIR` | `str` | `data` | Root directory for all on-disk persistent storage sinks. |
| *Derived:* `raw_store` | `Path` | `data/raw_store` | Immutable raw storage directory (year/month/day/hour sharded `.raw` + `.meta.json`). |
| *Derived:* `parsers` | `Path` | `data/parsers` | Persistent JSON definitions for approved and dynamic parsers. |
| *Derived:* `onboarding_sessions` | `Path` | `data/onboarding_sessions` | Persistent state and audit trail for Drain3 log template discovery sessions. |
| *Derived:* `search_index.db` | `Path` | `data/search_index.db` | SQLite 3 FTS5 database for normalized OCSF event indexing and administrative audit trails. |
| *Derived:* `data_lake` | `Path` | `data/data_lake` | Columnar Apache Parquet partition lake (Hive partitioned: `class_name=.../year=.../month=.../day=...`). |
| *Derived:* `error_queue` | `Path` | `data/error_queue` | Dead-letter queue containing unparseable payloads and error metadata. |

---

## 4. Operational Bounds & Backpressure Limits

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `ULPF_MAX_INGEST_PAYLOAD_BYTES` | `int` | `10485760` (10 MB) | Maximum permitted byte length for a single log event. Larger payloads are rejected with HTTP 413. |
| `ULPF_MAX_INGEST_QUEUE_SIZE` | `int` | `10000` | Bounded memory queue depth before backpressure load-shedding triggers HTTP 429 / 503. |
| `ULPF_RATE_LIMIT_INGEST_PER_MINUTE` | `int` | `60000` | Per-client IP ingestion rate limit threshold. |
| `ULPF_RATE_LIMIT_AUTH_PER_MINUTE` | `int` | `60` | Per-client IP login attempt rate limit threshold. |

---

## 5. Structured Logging & Observability

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `ULPF_LOG_LEVEL` | `str` | `INFO` | Logging threshold level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). |
| `ULPF_LOG_FORMAT` | `str` | `json` | Logging format (`json` for SIEM / machine ingestion, `text` for local development). |

---

## Example `.env` Configuration

```bash
# Production Deployment Environment Example
ULPF_DEMO_MODE=false
ULPF_SECRET_KEY=9f83b2a7d4e1c60f5892c431b87a0256e4c7d91a2853f60b4e
ULPF_BASE_DATA_DIR=/var/lib/ulpf/data
ULPF_API_PORT=8000
ULPF_UDP_SYSLOG_PORT=5140
ULPF_TCP_SYSLOG_PORT=1514
ULPF_LOG_LEVEL=INFO
ULPF_LOG_FORMAT=json
```
