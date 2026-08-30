"""
Events API Endpoints
Ingestion, SIEM Search, Forensic Lookup, Lossless Raw Retrieval, and SHA-256 Integrity Verification.
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query, Body
from pydantic import BaseModel

from ulpf.packages.schemas.models import UserRole, VerificationResult
from ulpf.apps.api.auth import get_current_user, require_roles
from ulpf.services.pipeline_orchestrator import PipelineOrchestrator
from ulpf.packages.config.settings import get_settings
from ulpf.packages.security.sanitization import validate_safe_identifier, ingest_rate_limiter

router = APIRouter(prefix="/events", tags=["Events & Ingestion"])

# Global orchestrator reference injected at app startup
_orchestrator: Optional[PipelineOrchestrator] = None


def set_orchestrator(orchestrator: PipelineOrchestrator):
    global _orchestrator
    _orchestrator = orchestrator


def get_orchestrator() -> PipelineOrchestrator:
    if not _orchestrator:
        raise HTTPException(status_code=500, detail="Pipeline orchestrator not initialized")
    return _orchestrator


class SingleIngestRequest(BaseModel):
    raw_payload: str
    transport: Optional[str] = "api"
    client_ip: Optional[str] = "127.0.0.1"
    vendor_hint: Optional[str] = None
    product_hint: Optional[str] = None


class BatchIngestRequest(BaseModel):
    logs: List[str]
    transport: Optional[str] = "batch_api"
    client_ip: Optional[str] = "127.0.0.1"


@router.post("/ingest", response_model=Dict[str, Any])
def ingest_single_event(
    req: SingleIngestRequest,
    user: Dict[str, Any] = Depends(require_roles([UserRole.ADMIN, UserRole.OPERATOR, UserRole.ANALYST]))
):
    """
    Ingests a single raw log payload, executes lossless archiving, format detection,
    parsing, OCSF normalization, validation, and dual-sink indexing.
    """
    settings = get_settings()
    client_ip = req.client_ip or "127.0.0.1"
    if not ingest_rate_limiter.check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for ingestion. Please throttle client stream."
        )

    raw_bytes_len = len(req.raw_payload.encode("utf-8"))
    if raw_bytes_len > settings.ULPF_MAX_INGEST_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Payload size ({raw_bytes_len} bytes) exceeds maximum limit of {settings.ULPF_MAX_INGEST_PAYLOAD_BYTES} bytes."
        )

    orch = get_orchestrator()
    envelope = orch.process_raw_log(
        raw_payload=req.raw_payload,
        transport=req.transport or "api",
        client_ip=client_ip,
        vendor_hint=req.vendor_hint,
        product_hint=req.product_hint
    )
    return envelope.model_dump()


@router.post("/batch", response_model=Dict[str, Any])
def ingest_batch_events(
    req: BatchIngestRequest,
    user: Dict[str, Any] = Depends(require_roles([UserRole.ADMIN, UserRole.OPERATOR]))
):
    """
    Ingests a batch of raw log strings into the ULPF pipeline.
    """
    settings = get_settings()
    total_bytes = sum(len(log.encode("utf-8")) for log in req.logs)
    if total_bytes > settings.ULPF_MAX_INGEST_PAYLOAD_BYTES * 5:
        raise HTTPException(
            status_code=413,
            detail=f"Total batch size ({total_bytes} bytes) exceeds permitted batch ceiling."
        )

    orch = get_orchestrator()
    envelopes = orch.process_batch(req.logs, transport=req.transport or "batch", client_ip=req.client_ip or "127.0.0.1")
    return {
        "status": "success",
        "processed_count": len(envelopes),
        "event_ids": [e.event_id for e in envelopes]
    }


@router.get("", response_model=Dict[str, Any])
def search_events(
    query: Optional[str] = Query(None, description="Full-text search query across raw and OCSF documents"),
    vendor: Optional[str] = Query(None, description="Filter by vendor name (e.g. Cisco, Palo Alto, Fortinet)"),
    product: Optional[str] = Query(None, description="Filter by product name (e.g. ASA, PAN-OS, FortiOS)"),
    detected_format: Optional[str] = Query(None, description="Filter by detected format"),
    severity_id: Optional[int] = Query(None, description="Filter by OCSF severity_id (1-6)"),
    disposition: Optional[str] = Query(None, description="Filter by disposition (Allowed, Blocked)"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Faceted SIEM search and inspection endpoint.
    """
    orch = get_orchestrator()
    results = orch.search_index.search_events(
        query=query,
        vendor=vendor,
        product=product,
        detected_format=detected_format,
        severity_id=severity_id,
        disposition=disposition,
        src_ip=src_ip,
        dst_ip=dst_ip,
        limit=limit,
        offset=offset
    )
    return results


@router.get("/{event_id}", response_model=Dict[str, Any])
def get_event_details(
    event_id: str,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves full event envelope including OCSF normalized event, parsing metadata, and traceability links.
    """
    validate_safe_identifier(event_id, "event_id")
    orch = get_orchestrator()
    event_data = orch.search_index.get_event_by_id(event_id)
    if not event_data:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found in search index")
    return event_data


@router.get("/{event_id}/raw", response_model=Dict[str, Any])
def get_raw_event(
    event_id: str,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves exact unmutated raw payload and storage reference from the write-once store.
    """
    validate_safe_identifier(event_id, "event_id")
    orch = get_orchestrator()
    res = orch.raw_store.retrieve_raw(event_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Raw event {event_id} not found in raw storage")
    raw_payload, storage_ref = res
    return {
        "event_id": event_id,
        "raw_payload": raw_payload,
        "sha256": storage_ref.sha256,
        "byte_length": storage_ref.byte_length,
        "bucket": storage_ref.bucket,
        "object_key": storage_ref.object_key
    }


@router.post("/{event_id}/verify-integrity", response_model=Dict[str, Any])
def verify_event_integrity(
    event_id: str,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Cryptographic Verification: Re-reads raw payload from disk, calculates SHA-256 hash,
    and compares against the stored hash. Proves byte-for-byte authenticity.
    """
    validate_safe_identifier(event_id, "event_id")
    orch = get_orchestrator()
    res: VerificationResult = orch.verify_event_integrity(event_id)
    return res.model_dump()


@router.post("/{event_id}/tamper-test", response_model=Dict[str, Any])
def tamper_test_helper(
    event_id: str,
    user: Dict[str, Any] = Depends(require_roles([UserRole.ADMIN]))
):
    """
    Demonstration helper to simulate payload tampering on disk and test tamper detection.
    """
    validate_safe_identifier(event_id, "event_id")
    orch = get_orchestrator()
    success = orch.raw_store.tamper_for_test(event_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    # Verify immediately to show the tamper result
    verify_res = orch.raw_store.verify_integrity(event_id)
    return {
        "status": "tampered_for_demo",
        "verification_result": verify_res.model_dump()
    }
