"""
Parser Registry API Endpoints
Cataloging, Testing, Versioning, and Publishing Log Parsers.
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel

from ulpf.packages.schemas.models import ParserDefinition, UserRole
from ulpf.apps.api.auth import get_current_user, require_roles
from ulpf.apps.api.routes.events import get_orchestrator
from ulpf.packages.security.sanitization import validate_safe_identifier

router = APIRouter(prefix="/parsers", tags=["Parser Registry"])


class ParserTestRequest(BaseModel):
    sample_payload: str
    version: Optional[str] = None


@router.get("", response_model=List[Dict[str, Any]])
def list_parsers(user: Dict[str, Any] = Depends(get_current_user)):
    """Lists all registered parsers, versions, and statuses."""
    orch = get_orchestrator()
    return orch.parser_registry.list_parsers()


@router.get("/{parser_id}", response_model=Dict[str, Any])
def get_parser_details(
    parser_id: str,
    version: Optional[str] = None,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieves specific parser definition and rules."""
    validate_safe_identifier(parser_id, "parser_id")
    orch = get_orchestrator()
    p = orch.parser_registry.get_parser(parser_id, version)
    if not p:
        raise HTTPException(status_code=404, detail=f"Parser {parser_id} not found")
    return {
        "parser_id": p.parser_id,
        "vendor": p.vendor,
        "product": p.product,
        "format": p.format_type.value if hasattr(p.format_type, "value") else p.format_type,
        "version": p.version,
        "target_class": p.target_class,
        "target_class_uid": p.target_class_uid,
        "status": p.status.value if hasattr(p.status, "value") else p.status
    }


@router.post("", response_model=Dict[str, Any])
def create_or_update_parser(
    p_def: ParserDefinition,
    user: Dict[str, Any] = Depends(require_roles([UserRole.ADMIN, UserRole.REVIEWER]))
):
    """Registers a new or versioned parser. Active parsers cannot be overwritten in place."""
    validate_safe_identifier(p_def.parser_id, "parser_id")
    orch = get_orchestrator()
    try:
        key = orch.parser_registry.register_parser_definition(p_def)
        return {"status": "success", "key": key, "parser_id": p_def.parser_id, "version": p_def.version}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{parser_id}/test", response_model=Dict[str, Any])
def test_parser(
    parser_id: str,
    req: ParserTestRequest,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """Executes a dry-run test of a parser against a sample raw log."""
    validate_safe_identifier(parser_id, "parser_id")
    orch = get_orchestrator()
    res = orch.parser_registry.test_parser(parser_id, req.sample_payload, req.version)
    return res
