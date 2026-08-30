"""
Multi-Stage Validation Subsystem
Enforces Ingestion validation, Parser validation, OCSF 1.1.0 schema compliance, and Cryptographic SHA-256 verification.
"""

import ipaddress
import re
import uuid
from typing import Any

from ulpf.packages.schemas.models import (
    EventEnvelope,
    ParsingMetadata,
    VerificationResult,
)
from ulpf.services.storage.raw_store import BaseRawStore


class PipelineValidator:
    """
    Multi-stage validator enforcing data contracts across the entire ingestion and normalization pipeline.
    """

    def __init__(self, raw_store: BaseRawStore):
        self.raw_store = raw_store

    def validate_ingestion(self, envelope: EventEnvelope) -> tuple[bool, list[str]]:
        """Stage 1: Validates raw payload integrity, bounds, and ingestion headers."""
        errors = []
        if not envelope.raw.raw_payload or not envelope.raw.raw_payload.strip():
            errors.append("Ingestion Error: Raw payload is empty")

        if envelope.raw.byte_length > 10 * 1024 * 1024:  # 10 MB limit
            errors.append(
                f"Ingestion Error: Raw payload exceeds max size (size: {envelope.raw.byte_length} bytes)"
            )

        try:
            uuid.UUID(envelope.event_id)
        except ValueError:
            errors.append(
                f"Ingestion Error: Invalid event_id format '{envelope.event_id}' (must be UUIDv4)"
            )

        if not envelope.raw.sha256 or len(envelope.raw.sha256) != 64:
            errors.append("Ingestion Error: Invalid or missing SHA-256 hash")

        return len(errors) == 0, errors

    def validate_parsing(
        self, parsed_fields: dict[str, Any], meta: ParsingMetadata
    ) -> tuple[bool, list[str]]:
        """Stage 2: Validates parser extraction outputs and parser errors."""
        errors = list(meta.errors)
        if not parsed_fields:
            errors.append("Parser Error: Parser produced no extracted fields")
        return len(errors) == 0, errors

    def validate_ocsf(self, ocsf_doc: dict[str, Any]) -> tuple[bool, list[str]]:
        """Stage 3: Validates OCSF 1.1.0 schema compliance."""
        errors = []

        # Required root fields
        required_fields = [
            "class_uid",
            "category_uid",
            "class_name",
            "category_name",
            "severity_id",
            "status_id",
            "time",
            "metadata",
        ]
        for f in required_fields:
            if f not in ocsf_doc:
                errors.append(f"OCSF Validation Error: Missing mandatory field '{f}'")

        # Enum validations
        if "severity_id" in ocsf_doc:
            if ocsf_doc["severity_id"] not in [0, 1, 2, 3, 4, 5, 6, 99]:
                errors.append(
                    f"OCSF Validation Error: Invalid severity_id '{ocsf_doc['severity_id']}'"
                )

        if "disposition_id" in ocsf_doc and ocsf_doc["disposition_id"] is not None:
            if ocsf_doc["disposition_id"] not in [0, 1, 2, 3, 4, 5, 6, 7, 99]:
                errors.append(
                    f"OCSF Validation Error: Invalid disposition_id '{ocsf_doc['disposition_id']}'"
                )

        # Timestamp validation
        if "time" in ocsf_doc:
            if not isinstance(ocsf_doc["time"], (int, float)) or ocsf_doc["time"] <= 0:
                errors.append(
                    f"OCSF Validation Error: Invalid epoch timestamp '{ocsf_doc['time']}'"
                )

        # Metadata validation
        meta = ocsf_doc.get("metadata", {})
        if not isinstance(meta, dict) or "product" not in meta:
            errors.append(
                "OCSF Validation Error: 'metadata.product' object is required"
            )
        else:
            prod = meta.get("product", {})
            if not prod.get("vendor_name"):
                errors.append(
                    "OCSF Validation Error: 'metadata.product.vendor_name' is required"
                )

        # Endpoints validation
        for ep_key in ["src_endpoint", "dst_endpoint"]:
            if ep_key in ocsf_doc and isinstance(ocsf_doc[ep_key], dict):
                ep = ocsf_doc[ep_key]
                if "port" in ep and ep["port"] is not None:
                    if not (1 <= ep["port"] <= 65535):
                        errors.append(
                            f"OCSF Validation Error: Port out of range in {ep_key}: {ep['port']}"
                        )
                if ep.get("ip"):
                    # Clean and check IP format
                    ip_str = str(ep["ip"]).strip()
                    try:
                        ipaddress.ip_address(ip_str)
                    except ValueError:
                        # Allow hostname or string if not pure IP, but check if invalid format
                        if re.match(r"^[0-9.]+$", ip_str) and not re.match(
                            r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_str
                        ):
                            errors.append(
                                f"OCSF Validation Error: Malformed IPv4 address in {ep_key}: '{ip_str}'"
                            )

        return len(errors) == 0, errors

    def validate_integrity(self, event_id: str) -> VerificationResult:
        """Stage 4: Performs cryptographic SHA-256 byte-for-byte verification against disk storage."""
        return self.raw_store.verify_integrity(event_id)
