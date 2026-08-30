"""
Error & Replay API Endpoints
Dead-letter queue inspection and log re-execution.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ulpf.apps.api.auth import get_current_user, require_roles
from ulpf.apps.api.routes.events import get_orchestrator
from ulpf.packages.schemas.models import UserRole
from ulpf.packages.security.sanitization import validate_safe_identifier

router = APIRouter(prefix="/errors", tags=["Error & Replay Queue"])


@router.get("", response_model=list[dict[str, Any]])
def list_errors(
    status: str | None = None, user: dict[str, Any] = Depends(get_current_user)
):
    """Lists dead-letter events with error reasons and stage."""
    orch = get_orchestrator()
    return orch.error_queue.list_errors(status)


@router.post("/{error_id}/replay", response_model=dict[str, Any])
def replay_single_error(
    error_id: str,
    user: dict[str, Any] = Depends(require_roles([UserRole.ADMIN, UserRole.OPERATOR])),
):
    """Re-executes a failed log through the current pipeline and active parsers."""
    validate_safe_identifier(error_id, "error_id")
    orch = get_orchestrator()
    err = orch.error_queue.get_error(error_id)
    if not err:
        raise HTTPException(status_code=404, detail="Error record not found")

    raw_payload = err["raw_payload"]
    envelope = orch.process_raw_log(raw_payload, transport="replay")
    orch.error_queue.mark_replayed(error_id)

    return {
        "status": "replayed",
        "error_id": error_id,
        "new_event_id": envelope.event_id,
        "parsing_status": "success" if envelope.ocsf else "failed",
        "errors": envelope.parsing.errors,
    }


@router.post("/replay-all", response_model=dict[str, Any])
def replay_all_unresolved(
    user: dict[str, Any] = Depends(require_roles([UserRole.ADMIN, UserRole.OPERATOR])),
):
    """Bulk replays all unresolved dead-letter logs."""
    orch = get_orchestrator()
    errors = orch.error_queue.list_errors(status="UNRESOLVED")
    replayed_count = 0
    success_count = 0

    for err in errors:
        raw_payload = err["raw_payload"]
        env = orch.process_raw_log(raw_payload, transport="replay_bulk")
        orch.error_queue.mark_replayed(err["error_id"])
        replayed_count += 1
        if env.ocsf:
            success_count += 1

    return {
        "status": "bulk_replay_completed",
        "total_replayed": replayed_count,
        "successful_normalizations": success_count,
    }
