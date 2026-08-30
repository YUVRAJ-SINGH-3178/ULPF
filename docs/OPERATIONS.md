# ULPF Enterprise Operations & Site Reliability Runbook

**System**: Universal Log Pre-processing Framework (ULPF)  
**Security Classification**: NTRO Strategic / CII  
**Maintainer**: Cyber Operations & Platform Reliability Engineering

---

## 1. Service Lifecycle Management

### 1.1 Service Startup
ULPF can be run in production as a containerized stack or standalone systemd daemon.

```bash
# Option A: Containerized Deployment (Recommended)
docker-compose up -d --build

# Option B: Bare-Metal / Systemd Daemon Execution
export ULPF_DEMO_MODE=false
export ULPF_SECRET_KEY="<production-secure-key-at-least-32-chars>"
python -m uvicorn ulpf.apps.api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 1.2 Graceful Shutdown Procedure
On receiving `SIGTERM` or `SIGINT`:
1. The framework halts ingress from UDP (5140) and TCP (1514) listeners.
2. Active batches currently in the normalization pipeline finish processing (10-second timeout ceiling).
3. The Parquet buffer is flushed to the Data Lake directory (`data/data_lake/`).
4. SQLite WAL journal files are committed and closed.

---

## 2. Deep Health & Observability Monitoring

### 2.1 Health Check API
- **Endpoint**: `GET /api/pipeline/health`
- **Expected Status**: `200 OK`
- **Degraded Status**: `503 Service Unavailable`
- **Subsystems Verified**:
  - `sqlite_search_index`: Confirms read/write connectivity to `search_index.db`.
  - `duckdb_engine`: Confirms vector analytics engine sanity.
  - `storage_volume`: Confirms storage filesystem has > 100 MB free space.
  - `memory_bounds`: Alerts if RSS exceeds 2,048 MB.

### 2.2 Prometheus Metrics Scraping
- **Scrape Target**: `GET /metrics` or `GET /api/pipeline/metrics/prometheus`
- **Format**: Prometheus OpenMetrics text format (version 0.0.4)
- **Key Alerting Metrics**:
  - `ulpf_events_per_second`: Ingestion throughput rate.
  - `ulpf_events_parsed_total{status="failed"}`: Count of unparseable logs routed to DLQ.
  - `ulpf_pipeline_latency_seconds{quantile="0.99"}`: Tail latency SLA violation alert (> 100ms).
  - `ulpf_backpressure_queue_depth`: Unflushed buffer backlog size.

---

## 3. Storage Backup & Disaster Recovery

### 3.1 SQLite Search Index Backup
SQLite is running in **Write-Ahead Logging (WAL)** mode. Never copy `search_index.db` without its `-wal` and `-shm` companion files.

```bash
# Online hot backup using SQLite CLI
sqlite3 data/search_index.db ".backup 'backups/search_index_$(date +%Y%m%d_%H%M%S).db'"
```

### 3.2 Raw Store & Data Lake Backup
- **Raw Payloads** (`data/raw_store/`): Pure append-only write-once directory hierarchy organized by `YYYY/MM/DD/`. Can be synced via `rsync` or mirrored to tape/cold storage without taking the service offline:
  ```bash
  rsync -av --ignore-existing data/raw_store/ /mnt/backup/ulpf/raw_store/
  ```
- **Parquet Lake** (`data/data_lake/`): Immutable snappy-compressed `.parquet` files. Sync on hourly intervals:
  ```bash
  rsync -av --ignore-existing data/data_lake/ /mnt/backup/ulpf/data_lake/
  ```

---

## 4. Dead-Letter Error Queue Operations

When an incoming log fails format detection or schema mapping, it is safely captured in the dead-letter queue rather than discarded.

### 4.1 Inspecting Failed Events
```bash
curl -s http://localhost:8000/api/errors | jq .
```

### 4.2 Replaying After Parser Update
Once an unknown format is onboarded or a parser bug is fixed:
```bash
# Replay specific error ID
curl -X POST http://localhost:8000/api/errors/{error_id}/replay

# Bulk replay all unresolved dead-letter logs
curl -X POST http://localhost:8000/api/errors/replay-all
```

---

## 5. Hot-Deploying New Parsers Zero-Downtime

To register and activate a new vendor log parser without restarting the ULPF daemon:

1. **Submit via Drain3 Onboarding Workflow**:
   ```bash
   curl -X POST http://localhost:8000/api/onboarding/mine -H "Content-Type: application/json" \
     -d '{"raw_payload": "2026-08-27 fw-custom rule=DENY src=10.0.0.1 dst=10.0.0.2"}'
   ```
2. **Review suggested mappings and approve session**:
   ```bash
   curl -X POST http://localhost:8000/api/onboarding/{session_id}/approve \
     -H "Content-Type: application/json" \
     -d '{"custom_parser_id": "custom_edge_fw", "version": "1.0.0"}'
   ```
3. The parser definition is immediately compiled into `data/parsers/custom_edge_fw_1.0.0.json`, loaded into the in-memory registry, and all buffered logs for that signature are automatically replayed into OCSF. Zero service restarts required.
