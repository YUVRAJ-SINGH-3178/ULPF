"""
Zeek / Bro Network Monitor Parser
Parses Zeek conn.log JSON and TSV records.
"""

import json
from typing import Any

from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.parser_engine.base import BaseParser


class ZeekConnParser(BaseParser):
    """
    Parses Zeek (Bro) connection telemetry logs.
    """

    def __init__(
        self,
        parser_id: str = "zeek-conn-parser",
        vendor: str = "Zeek",
        product: str = "Network-Monitor",
        version: str = "1.0.0",
    ):
        super().__init__(
            parser_id=parser_id,
            vendor=vendor,
            product=product,
            format_type=FormatType.JSON,
            version=version,
            target_class="Network Activity",
            target_class_uid=4001,
        )

    def matches(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> bool:
        raw = raw_payload.strip()
        if raw.startswith("{") and raw.endswith("}"):
            return (
                "id.orig_h" in raw
                or "id.resp_h" in raw
                or ("ts" in raw and "conn_state" in raw)
            )
        return False

    def parse_fields(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> dict[str, Any]:
        data = json.loads(raw_payload.strip())
        if not isinstance(data, dict):
            raise ValueError("Zeek payload is not a JSON object")

        orig_h = data.get("id.orig_h") or data.get("src_ip") or data.get("orig_h")
        orig_p = data.get("id.orig_p") or data.get("src_port") or data.get("orig_p")
        resp_h = data.get("id.resp_h") or data.get("dst_ip") or data.get("resp_h")
        resp_p = data.get("id.resp_p") or data.get("dst_port") or data.get("resp_p")

        parsed: dict[str, Any] = {
            "device_vendor": "Zeek",
            "device_product": "Network-Monitor",
            "uid": data.get("uid"),
            "timestamp": data.get("ts"),
            "src_ip": str(orig_h) if orig_h else None,
            "src_port": int(orig_p) if orig_p is not None else None,
            "dst_ip": str(resp_h) if resp_h else None,
            "dst_port": int(resp_p) if resp_p is not None else None,
            "protocol": (data.get("proto") or "TCP").upper(),
            "service": data.get("service"),
            "app_name": data.get("service"),
            "duration": data.get("duration"),
            "bytes_out": data.get("orig_bytes") or data.get("orig_ip_bytes"),
            "bytes_in": data.get("resp_bytes") or data.get("resp_ip_bytes"),
            "conn_state": data.get("conn_state"),
            "history": data.get("history"),
            "action": "allow",
            "disposition": "Allowed",
            "disposition_id": 1,
            "severity": "Informational",
            "severity_id": 1,
            "message": f"Zeek connection {orig_h}:{orig_p} -> {resp_h}:{resp_p}",
        }

        # Check for rejected connection state (e.g. REJ, RSTO, RSTR)
        conn_state = str(data.get("conn_state", "")).upper()
        if conn_state in ["REJ", "RSTO", "RSTR", "RSTOS0"]:
            parsed["disposition"] = "Blocked"
            parsed["disposition_id"] = 2
            parsed["action"] = "reject"
            parsed["severity"] = "Low"
            parsed["severity_id"] = 2

        return parsed
