"""
Benchmarking API Endpoints
Execute live load tests and fetch empirical performance measurements.
"""

from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from ulpf.packages.schemas.models import UserRole
from ulpf.apps.api.auth import get_current_user, require_roles
from ulpf.apps.api.routes.events import get_orchestrator
from ulpf.services.benchmark.load_runner import BenchmarkRunner

router = APIRouter(prefix="/benchmark", tags=["Benchmarking"])


class BenchmarkRequest(BaseModel):
    event_count: int = 5000
    concurrency: int = 4


@router.post("/run", response_model=Dict[str, Any])
def run_benchmark_test(
    req: BenchmarkRequest,
    user: Dict[str, Any] = Depends(require_roles([UserRole.ADMIN, UserRole.OPERATOR]))
):
    """
    Executes an empirical load test on the local machine and measures true events/sec,
    latencies (p50/p95/p99), memory usage, and CPU load.
    """
    orch = get_orchestrator()
    runner = BenchmarkRunner(orch)
    # Bound event count
    count = max(100, min(50000, req.event_count))
    concurrency = max(1, min(16, req.concurrency))
    result = runner.run_benchmark(event_count=count, concurrency=concurrency)
    return result
