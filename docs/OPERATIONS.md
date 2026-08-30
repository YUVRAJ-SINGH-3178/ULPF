# ULPF Enterprise Operations & Site Reliability Runbook

**System**: Universal Log Pre-processing Framework (ULPF)  
**Security Classification**: NTRO Strategic / CII  
**Maintainer**: Cyber Operations & Platform Reliability Engineering  

---

## 1. Service Lifecycle Management

### 1.1 Multi-Container Production Stack (MinIO + OpenSearch + API + Workers)
```bash
# Start full production cluster
docker compose -f docker-compose.prod.yml up -d --build

# Inspect running services
docker compose -f docker-compose.prod.yml ps

# Tail operational logs
docker compose -f docker-compose.prod.yml logs -f ulpf-api ulpf-worker
```

### 1.2 Development / Standalone Daemon Execution
```bash
# Set environment
export ULPF_STORAGE_BACKEND=local
export ULPF_SEARCH_BACKEND=sqlite
python run_ulpf.py
```

### 1.3 Graceful Shutdown Procedure
On receiving `SIGTERM` or `SIGINT`:
1. Ingress listeners on UDP (`5140`) and TCP (`1514`) stop accepting new socket connections.
2. In-flight processing workers complete active event transformations (10-second ceiling).
3. The Parquet buffer is flushed atomically to the Data Lake (`data/data_lake/`).
4. SQLite WAL journal files are committed and closed.

---

## 2. Deep Health & Subsystem Inspection

### 2.1 Deep Health Check API
- **Endpoint**: `GET /api/pipeline/health`
- **Expected Status**: `200 OK`
- **Degraded Status**: `503 Service Unavailable`
- **Subsystems Inspected**:
  - `raw_storage`: Validates MinIO bucket connectivity (`ulpf-raw`) or local disk accessibility.
  - `search_store`: Validates OpenSearch cluster health (`green`/`yellow`) or SQLite queryability.
  - `duckdb_engine`: Confirms vector analytics engine responsiveness.
  - `storage_volume`: Confirms storage filesystem has > 100 MB free space.
  - `memory_bounds`: Alerts if RSS exceeds 2,048 MB.

### 2.2 Prometheus OpenMetrics Scraping
- **Scrape Target**: `GET /metrics` or `GET /api/pipeline/metrics/prometheus`
- **Format**: Prometheus OpenMetrics text format (v0.0.4)
- **Key Alerting Metrics**:
  - `ulpf_events_per_second`: Current 5-second sliding window throughput.
  - `ulpf_events_parsed_total{status="failed"}`: Count of unparseable logs routed to DLQ.
  - `ulpf_pipeline_latency_seconds{quantile="0.99"}`: Tail latency SLA violation alert (> 100ms).
  - `ulpf_backpressure_queue_depth`: Unflushed buffer backlog size.
  - `ulpf_raw_storage_health`: 1 = Healthy, 0 = Unhealthy.
  - `ulpf_search_store_health`: 1 = Healthy, 0 = Unhealthy.

---

## 3. Worker Scaling & Queue Management

### 3.1 Scaling Workers
To scale background processing throughput in Docker Compose:
```bash
docker compose -f docker-compose.prod.yml up -d --scale ulpf-worker=8
```

### 3.2 Dead-Letter Queue (DLQ) Draining & Replay
When unparseable or unknown format logs arrive, they are safely preserved in the dead-letter queue:
```bash
# List all unresolved DLQ events
curl -s http://localhost:8000/api/errors | jq .

# Replay specific error ID
curl -X POST http://localhost:8000/api/errors/{error_id}/replay

# Bulk replay all unresolved dead-letter logs
curl -X POST http://localhost:8000/api/errors/replay-all
```

---

## 4. Zero-Downtime Parser Publication

To register and activate a new vendor log parser without restarting services:
1. **Submit sample log to Drain3 miner**:
   ```bash
   curl -X POST http://localhost:8000/api/onboarding/mine -H "Content-Type: application/json" \
     -d '{"raw_payload": "2026-08-30 [EDGE-FW] origin=10.0.0.1 target=10.0.0.2 proto=TCP action=DROP"}'
   ```
2. **Review suggested mappings and approve session**:
   ```bash
   curl -X POST http://localhost:8000/api/onboarding/{session_id}/approve \
     -H "Content-Type: application/json" \
     -d '{"custom_parser_id": "edge_fw", "version": "1.0.0"}'
   ```
3. The parser definition is written to `data/parsers/edge_fw_1.0.0.json`, hot-loaded into the parser registry, and all buffered raw events for that template are automatically replayed into OpenSearch.

---

## 5. Storage Backup & Disaster Recovery Runbook

See [`docs/DISASTER_RECOVERY.md`](docs/DISASTER_RECOVERY.md) for detailed offline backup and restore procedures for MinIO buckets (`ulpf-raw`), OpenSearch snapshots, SQLite databases, and parser registries.
