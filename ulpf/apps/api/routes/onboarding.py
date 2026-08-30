"""
Unknown Log Auto-Onboarding API Endpoints
Drain3 template discovery, variable review, OCSF mapping adjustment, human approval, and automated replay.
"""

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

from ulpf.apps.api.auth import get_current_user, require_roles
from ulpf.apps.api.routes.events import get_orchestrator
from ulpf.packages.schemas.models import UserRole
from ulpf.packages.security.sanitization import validate_safe_identifier

router = APIRouter(prefix="/onboarding", tags=["Drain3 Auto-Onboarding"])


class UpdateMappingRequest(BaseModel):
    var_index: int
    target_ocsf_field: str
    inferred_type: str | None = None
    transform: str | None = None


class ApproveSessionRequest(BaseModel):
    custom_parser_id: str | None = None
    version: str | None = "1.0.0"


class MineRawLogRequest(BaseModel):
    raw_payload: str
    vendor_hint: str | None = None
    product_hint: str | None = None


@router.get("", response_model=list[dict[str, Any]])
def list_onboarding_sessions(user: dict[str, Any] = Depends(get_current_user)):
    """Lists all active and historical onboarding sessions."""
    orch = get_orchestrator()
    return orch.onboarding_manager.list_sessions()


@router.get("/{session_id}", response_model=dict[str, Any])
def get_onboarding_session(
    session_id: str,
    user: dict[str, Any] = Depends(get_current_user)
):
    """Retrieves session details, discovered template, variables, sample values, and OCSF suggestions."""
    validate_safe_identifier(session_id, "session_id")
    orch = get_orchestrator()
    session = orch.onboarding_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Onboarding session {session_id} not found")
    return session


@router.post("/mine", response_model=dict[str, Any])
def mine_unknown_log_manually(
    req: MineRawLogRequest,
    user: dict[str, Any] = Depends(require_roles([UserRole.ADMIN, UserRole.REVIEWER, UserRole.OPERATOR]))
):
    """Feeds an unseen raw log directly to the Drain3 miner to trigger template discovery."""
    orch = get_orchestrator()
    session = orch.onboarding_manager.process_unknown_log(
        raw_payload=req.raw_payload,
        vendor_hint=req.vendor_hint,
        product_hint=req.product_hint
    )
    return session.model_dump()


@router.put("/{session_id}/mapping", response_model=dict[str, Any])
def update_variable_mapping(
    session_id: str,
    req: UpdateMappingRequest,
    user: dict[str, Any] = Depends(require_roles([UserRole.ADMIN, UserRole.REVIEWER]))
):
    """
    Human-in-the-Loop Override:
    Allows security analyst / reviewer to adjust inferred field name, OCSF mapping, or transformation rule.
    """
    validate_safe_identifier(session_id, "session_id")
    orch = get_orchestrator()
    success = orch.onboarding_manager.update_variable_mapping(
        session_id=session_id,
        var_index=req.var_index,
        target_ocsf_field=req.target_ocsf_field,
        inferred_type=req.inferred_type,
        transform=req.transform
    )
    if not success:
        raise HTTPException(status_code=404, detail="Session or variable index not found")
    return {"status": "success", "session_id": session_id, "var_index": req.var_index, "mapped_to": req.target_ocsf_field}


@router.post("/{session_id}/approve", response_model=dict[str, Any])
def approve_and_publish_session(
    session_id: str,
    req: ApproveSessionRequest = Body(...),
    user: dict[str, Any] = Depends(require_roles([UserRole.ADMIN, UserRole.REVIEWER]))
):
    """
    Human Approval & Publish:
    1. Compiles discovered template & approved rules into an active versioned parser.
    2. Registers parser in the ParserRegistry.
    3. Replays buffered unknown logs.
    """
    validate_safe_identifier(session_id, "session_id")
    if req.custom_parser_id:
        validate_safe_identifier(req.custom_parser_id, "custom_parser_id")

    orch = get_orchestrator()
    res = orch.onboarding_manager.approve_and_publish(
        session_id=session_id,
        reviewed_by=user.get("username", "security-reviewer"),
        custom_parser_id=req.custom_parser_id,
        version=req.version or "1.0.0"
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Approval failed"))
    return res


@router.post("/{session_id}/reject", response_model=dict[str, Any])
def reject_session(
    session_id: str,
    reason: str = Body(..., embed=True),
    user: dict[str, Any] = Depends(require_roles([UserRole.ADMIN, UserRole.REVIEWER]))
):
    """Rejects an onboarding session."""
    validate_safe_identifier(session_id, "session_id")
    orch = get_orchestrator()
    success = orch.onboarding_manager.reject_session(
        session_id=session_id,
        reason=reason,
        reviewed_by=user.get("username", "security-reviewer")
    )
    if not success:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "rejected", "session_id": session_id}


@router.get("/audit/logs", response_model=list[dict[str, Any]])
def get_onboarding_audit_trail(user: dict[str, Any] = Depends(get_current_user)):
    """Retrieves immutable audit trail of onboarding approvals and parser changes."""
    orch = get_orchestrator()
    return orch.onboarding_manager.get_audit_trail()
