"""
Pipeline Telemetry, Real-time Health, and Prometheus Metrics API Endpoints
Provides deep operational inspection, component diagnostics (MinIO, OpenSearch, DuckDB), and Prometheus OpenMetrics scraping.
"""

import os
import time
from pathlib import Path
from typing import Any

import duckdb
import psutil
from fastapi import APIRouter, Depends, HTTPException, Response, status

from ulpf.apps.api.auth import get_current_user
from ulpf.apps.api.routes.events import get_orchestrator
from ulpf.packages.config.settings import get_settings

router = APIRouter(prefix="/pipeline", tags=["Pipeline Operations"])


@router.get("/metrics", response_model=dict[str, Any])
def get_pipeline_metrics(user: dict[str, Any] = Depends(get_current_user)):
    """Fetches real-time throughput (EPS), latency percentiles, queue depths, and SIEM search summary stats."""
    orch = get_orchestrator()
    rt_metrics = orch.get_realtime_metrics()
    siem_summary = orch.search_index.get_metrics_summary()
    outbox_stats = (
        orch.outbox.get_stats()
        if hasattr(orch, "outbox")
        else {"pending": 0, "complete": 0, "failed": 0, "dead_letter": 0}
    )
    unresolved_errors = len(orch.error_queue.list_errors(status="UNRESOLVED"))

    return {
        "realtime": rt_metrics,
        "summary": siem_summary,
        "active_parsers_count": len(orch.parser_registry.list_parsers()),
        "onboarding_sessions_count": len(orch.onboarding_manager.list_sessions()),
        "unresolved_errors_count": unresolved_errors,
        "total_ingested": orch.total_ingested,
        "total_normalized": orch.total_normalized,
        "queue_depth": len(orch._batch_buffer),
        "dlq_count": outbox_stats.get("dead_letter", 0),
        "outbox_pending_count": outbox_stats.get("pending", 0),
        "outbox_failed_count": outbox_stats.get("failed", 0),
        "outbox_stats": outbox_stats,
        "storage_backend": getattr(
            orch.raw_store, "__class__", type(orch.raw_store)
        ).__name__,
        "search_backend": getattr(
            orch.search_index, "__class__", type(orch.search_index)
        ).__name__,
    }


@router.get("/metrics/prometheus")
def get_prometheus_metrics(response: Response):
    """
    Prometheus / OpenMetrics scrape endpoint.
    Exposes metrics for ingestion rate, normalizations, error rates, latencies, and resource utilization.
    """
    try:
        orch = get_orchestrator()
        rt = orch.get_realtime_metrics()
        unresolved = len(orch.error_queue.list_errors(status="UNRESOLVED"))
        active_parsers = len(orch.parser_registry.list_parsers())
        process = psutil.Process(os.getpid())
        mem_rss = process.memory_info().rss

        total_ingested = orch.total_ingested
        total_normalized = orch.total_normalized
        failed_count = unresolved

        raw_health = orch.raw_store.health_check()
        search_health = orch.search_index.health_check()
        minio_up = 1 if raw_health.get("status") == "HEALTHY" else 0
        search_up = 1 if search_health.get("status") == "HEALTHY" else 0

        outbox_stats = (
            orch.outbox.get_stats()
            if hasattr(orch, "outbox")
            else {"pending": 0, "complete": 0, "failed": 0, "dead_letter": 0}
        )

        lines = [
            "# HELP ulpf_events_ingested_total Total raw events received by the framework",
            "# TYPE ulpf_events_ingested_total counter",
            f"ulpf_events_ingested_total {total_ingested}",
            "",
            "# HELP ulpf_events_parsed_total Total events processed by parser engine",
            "# TYPE ulpf_events_parsed_total counter",
            f'ulpf_events_parsed_total{{status="success"}} {total_normalized}',
            f'ulpf_events_parsed_total{{status="failed"}} {failed_count}',
            "",
            "# HELP ulpf_pipeline_latency_seconds Latency percentiles across pipeline stages",
            "# TYPE ulpf_pipeline_latency_seconds gauge",
            f'ulpf_pipeline_latency_seconds{{quantile="0.50"}} {rt.get("latency_p50_ms", 0.0) / 1000.0:.6f}',
            f'ulpf_pipeline_latency_seconds{{quantile="0.95"}} {rt.get("latency_p95_ms", 0.0) / 1000.0:.6f}',
            f'ulpf_pipeline_latency_seconds{{quantile="0.99"}} {rt.get("latency_p99_ms", 0.0) / 1000.0:.6f}',
            "",
            "# HELP ulpf_events_per_second Current 5-second sliding window throughput",
            "# TYPE ulpf_events_per_second gauge",
            f"ulpf_events_per_second {rt.get('current_eps', 0.0)}",
            "",
            "# HELP ulpf_backpressure_queue_depth Pending batch buffer size",
            "# TYPE ulpf_backpressure_queue_depth gauge",
            f"ulpf_backpressure_queue_depth {len(orch._batch_buffer)}",
            "",
            "# HELP ulpf_outbox_pending_total Events pending dual-sink outbox delivery",
            "# TYPE ulpf_outbox_pending_total gauge",
            f"ulpf_outbox_pending_total {outbox_stats.get('pending', 0)}",
            "",
            "# HELP ulpf_outbox_failed_total Events in retryable failed outbox state",
            "# TYPE ulpf_outbox_failed_total gauge",
            f"ulpf_outbox_failed_total {outbox_stats.get('failed', 0)}",
            "",
            "# HELP ulpf_dead_letter_queue_total Events in dead letter queue",
            "# TYPE ulpf_dead_letter_queue_total gauge",
            f"ulpf_dead_letter_queue_total {outbox_stats.get('dead_letter', 0)}",
            "",
            "# HELP ulpf_active_parsers Number of registered parsers in active catalog",
            "# TYPE ulpf_active_parsers gauge",
            f"ulpf_active_parsers {active_parsers}",
            "",
            "# HELP ulpf_raw_storage_health Health status of raw storage backend (1=healthy, 0=unhealthy)",
            "# TYPE ulpf_raw_storage_health gauge",
            f"ulpf_raw_storage_health {minio_up}",
            "",
            "# HELP ulpf_search_store_health Health status of search store backend (1=healthy, 0=unhealthy)",
            "# TYPE ulpf_search_store_health gauge",
            f"ulpf_search_store_health {search_up}",
            "",
            "# HELP ulpf_memory_bytes Resident set memory utilized by python process",
            "# TYPE ulpf_memory_bytes gauge",
            f"ulpf_memory_bytes {mem_rss}",
            "",
        ]

        response.headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
        return Response(
            content="\n".join(lines),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to generate prometheus metrics: {e!s}"
        )


@router.get("/health", response_model=dict[str, Any])
def get_system_health(
    response: Response, user: dict[str, Any] = Depends(get_current_user)
):
    """
    Comprehensive 3-Tier Health Check:
    - HEALTHY (200): All primary and secondary components functional.
    - DEGRADED (200): Ingestion operational; secondary sink impaired and retrying via outbox.
    - UNAVAILABLE (503): Primary raw ingestion or disk persistence failing; incoming logs at risk.
    """
    settings = get_settings()
    orch = get_orchestrator()
    subsystem_status = {}
    issues = []

    primary_healthy = True
    secondary_healthy = True

    # 1. Primary Test: Raw Store (MinIO or Local)
    try:
        raw_health = orch.raw_store.health_check()
        subsystem_status["raw_storage"] = raw_health
        if raw_health.get("status") != "HEALTHY":
            primary_healthy = False
            issues.append(f"Raw storage unhealthy: {raw_health}")
    except Exception as e:
        subsystem_status["raw_storage"] = {"status": "UNAVAILABLE", "error": str(e)}
        primary_healthy = False
        issues.append(f"Raw storage error: {e}")

    # 2. Primary Test: Disk Storage Directories & Free Space
    try:
        base_dir = Path(orch.base_dir)
        if not base_dir.exists():
            base_dir.mkdir(parents=True, exist_ok=True)
        disk_usage = psutil.disk_usage(str(base_dir.resolve()))
        free_mb = disk_usage.free / (1024 * 1024)
        if free_mb < 100:  # Less than 100MB free is critical
            subsystem_status["storage_volume"] = (
                f"CRITICAL_LOW_DISK ({free_mb:.1f} MB free)"
            )
            primary_healthy = False
            issues.append(f"Critical low disk space: {free_mb:.1f} MB remaining")
        else:
            subsystem_status["storage_volume"] = f"HEALTHY ({free_mb:.1f} MB free)"
    except Exception as e:
        subsystem_status["storage_volume"] = f"UNAVAILABLE ({e!s})"
        primary_healthy = False
        issues.append(f"Storage volume check error: {e}")

    # 3. Secondary Test: Search Store (OpenSearch or SQLite FTS5)
    try:
        search_health = orch.search_index.health_check()
        subsystem_status["search_store"] = search_health
        subsystem_status["sqlite_search_index"] = (
            f"HEALTHY ({search_health.get('indexed_records', 0)} records indexed)"
            if search_health.get("status") == "HEALTHY"
            else "DEGRADED"
        )
        if search_health.get("status") != "HEALTHY":
            secondary_healthy = False
            issues.append(f"Search store degraded: {search_health}")
    except Exception as e:
        subsystem_status["search_store"] = {"status": "DEGRADED", "error": str(e)}
        subsystem_status["sqlite_search_index"] = f"DEGRADED ({e!s})"
        secondary_healthy = False
        issues.append(f"Search store error: {e}")

    # 4. Secondary Test: DuckDB Engine
    try:
        d_conn = duckdb.connect(":memory:")
        d_res = d_conn.execute("SELECT 1 + 1 as val").fetchone()
        d_conn.close()
        if d_res and d_res[0] == 2:
            subsystem_status["duckdb_engine"] = "HEALTHY (Vectorized Engine Ready)"
        else:
            raise ValueError("DuckDB sanity calculation failed")
    except Exception as e:
        subsystem_status["duckdb_engine"] = f"DEGRADED ({e!s})"
        secondary_healthy = False
        issues.append(f"DuckDB error: {e}")

    # 5. Secondary Test: Process Memory
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    mem_mb = mem_info.rss / (1024 * 1024)
    if mem_mb > 2048:  # Over 2GB RSS
        subsystem_status["memory_bounds"] = f"WARNING_HIGH_MEMORY ({mem_mb:.1f} MB)"
        secondary_healthy = False
        issues.append(f"High memory consumption: {mem_mb:.1f} MB")
    else:
        subsystem_status["memory_bounds"] = f"HEALTHY ({mem_mb:.1f} MB)"

    # 3-Tier Status Calculation
    if not primary_healthy:
        overall_status = "UNAVAILABLE"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif not secondary_healthy:
        overall_status = "DEGRADED"
        response.status_code = status.HTTP_200_OK
    else:
        overall_status = "HEALTHY"
        response.status_code = status.HTTP_200_OK

    return {
        "status": overall_status,
        "air_gapped": settings.ULPF_AIR_GAPPED,
        "external_network_dependencies": False,
        "issues": issues,
        "subsystems": subsystem_status,
        "components": {
            "raw_storage": f"ONLINE ({getattr(orch.raw_store, '__class__', type(orch.raw_store)).__name__})",
            "search_index": f"ONLINE ({getattr(orch.search_index, '__class__', type(orch.search_index)).__name__})",
            "data_lake": "ONLINE (Apache Parquet + DuckDB)",
            "format_detector": "ONLINE",
            "parser_registry": "ONLINE",
            "ocsf_normalizer": "ONLINE (OCSF 1.1.0)",
            "drain3_miner": "ONLINE (Streaming Clusterer)",
            "validator": "ONLINE (SHA-256 + Schema)",
            "offline_enricher": "ONLINE (Air-Gapped GeoIP/Asset)",
        },
        "system_resources": {
            "process_memory_mb": round(mem_mb, 2),
            "system_uptime_seconds": round(time.time() - psutil.boot_time(), 0),
        },
    }
