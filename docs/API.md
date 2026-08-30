# ULPF REST API Specification
**Universal Log Pre-processing Framework · NTRO SIH26156**

All REST endpoints run on `http://localhost:8000/api` (Interactive OpenAPI Swagger UI available at `http://localhost:8000/docs`).

---

## 1. Authentication (`/api/auth`)

### `POST /api/auth/login`
Authenticates a user and issues a JWT token.
- **Request Body**:
  ```json
  {
    "username": "admin",
    "password": "admin123"
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1Ni...",
    "token_type": "bearer",
    "username": "admin",
    "role": "ADMIN",
    "full_name": "NTRO Lead Architect (Admin)"
  }
  ```

---

## 2. Ingestion & Events (`/api/events`)

### `POST /api/events/ingest`
Ingests a single raw log event.
- **Request Body**:
  ```json
  {
    "raw_payload": "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection 9812481 for outside:198.51.100.25/443 to inside:10.0.0.5/54321",
    "transport": "api",
    "client_ip": "192.168.1.100"
  }
  ```
- **Response** (`200 OK`):
  Returns the complete normalized `EventEnvelope` with `event_id`, `raw` reference, `ocsf` document, and `traceability`.

### `POST /api/events/batch`
Ingests an array of raw log strings.

### `GET /api/events`
Faceted SIEM search query.
- **Query Parameters**:
  - `query`: Full-text search term
  - `vendor`: Vendor name filter (e.g. Cisco, Palo Alto, Fortinet)
  - `severity_id`: Integer severity (1-6)
  - `disposition`: Allowed / Blocked
  - `limit`: Number of results (default 50)
  - `offset`: Pagination offset

### `GET /api/events/{event_id}`
Retrieves the complete event envelope and OCSF document.

### `GET /api/events/{event_id}/raw`
Retrieves the original unmutated raw payload from write-once storage with SHA-256 hash and byte length.

### `POST /api/events/{event_id}/verify-integrity`
Executes cryptographic SHA-256 byte verification by reading the raw file from disk and comparing against the recorded hash.
- **Response**:
  ```json
  {
    "event_id": "8f3b21c4-...",
    "is_valid": true,
    "stored_sha256": "4a7d...",
    "computed_sha256": "4a7d...",
    "byte_length": 158,
    "tampered": false,
    "details": "Cryptographic integrity verified: SHA-256 matches exactly"
  }
  ```

---

## 3. Parser Registry (`/api/parsers`)

### `GET /api/parsers`
Lists all active, draft, testing, and deprecated parsers.

### `POST /api/parsers`
Registers a new versioned parser.

### `POST /api/parsers/{parser_id}/test`
Runs a dry-run test of a parser on a sample log string.

---

## 4. Drain3 Auto-Onboarding (`/api/onboarding`)

### `GET /api/onboarding`
Lists all onboarding sessions with discovered templates, cluster IDs, and status (`PENDING`, `APPROVED`, `PUBLISHED`).

### `GET /api/onboarding/{session_id}`
Retrieves session details, discovered variable slots, sample values, and OCSF suggestions.

### `PUT /api/onboarding/{session_id}/mapping`
Updates candidate field mappings and transforms for a template variable.

### `POST /api/onboarding/{session_id}/approve`
Human approval endpoint: Compiles the template into an active versioned parser, registers it in the registry, and triggers automated replay of pending logs.

---

## 5. Dead-Letter & Replay (`/api/errors`)

### `GET /api/errors`
Lists dead-letter records with failure reason and stage.

### `POST /api/errors/{error_id}/replay`
Replays a single failed log through the current parser registry.

### `POST /api/errors/replay-all`
Bulk replays all unresolved logs in the dead-letter queue.

---

## 6. Benchmarking & Telemetry (`/api/benchmark` & `/api/pipeline`)

### `POST /api/benchmark/run`
Executes a multi-threaded load test with configurable event count (e.g. 5,000) and returns empirical throughput (EPS), p50/p95/p99 latency, CPU, and RAM usage.

### `GET /api/pipeline/metrics`
Returns live real-time throughput rate, latency percentiles, error count, and vendor distribution.

### `GET /api/pipeline/health`
Returns system component status, air-gap compliance confirmation, and storage utilization.
