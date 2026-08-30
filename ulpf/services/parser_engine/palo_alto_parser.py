"""
Palo Alto PAN-OS Firewall Parser
Parses PAN-OS Traffic, Threat, and System logs in CEF and CSV formats.
"""

import re
from typing import Any

from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.parser_engine.base import BaseParser
from ulpf.services.parser_engine.cef_parser import CEFParser


class PaloAltoParser(BaseParser):
    """
    Parses Palo Alto Networks (PAN-OS) firewall events.
    """

    def __init__(
        self,
        parser_id: str = "palo-alto-panos-parser",
        vendor: str = "Palo Alto Networks",
        product: str = "PAN-OS",
        version: str = "1.0.0",
    ):
        super().__init__(
            parser_id=parser_id,
            vendor=vendor,
            product=product,
            format_type=FormatType.CEF,
            version=version,
            target_class="Network Activity",
            target_class_uid=4001,
        )
        self._cef_parser = CEFParser()

    def matches(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> bool:
        lower = raw_payload.lower()
        return (
            "palo alto" in lower
            or "pan-os" in lower
            or "panos" in lower
            or "1,202" in raw_payload
            or (source_meta and source_meta.vendor.lower() == "palo alto")
        )

    def parse_fields(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> dict[str, Any]:
        raw = raw_payload.strip()

        # If CEF formatted
        if "CEF:" in raw:
            cef_fields = self._cef_parser.parse_fields(raw, source_meta)
            cef_fields["device_vendor"] = "Palo Alto Networks"
            cef_fields["device_product"] = "PAN-OS"

            # Normalize PAN-OS specific CEF extensions
            action_raw = cef_fields.get("action") or cef_fields.get("act", "")
            if action_raw.lower() in ["allow", "permitted"]:
                cef_fields["disposition"] = "Allowed"
                cef_fields["disposition_id"] = 1
            elif action_raw.lower() in [
                "deny",
                "drop",
                "reset-client",
                "reset-server",
                "reset-both",
                "block",
            ]:
                cef_fields["disposition"] = "Blocked"
                cef_fields["disposition_id"] = 2
            else:
                cef_fields["disposition"] = "Allowed"
                cef_fields["disposition_id"] = 1

            return cef_fields

        # If CSV PAN-OS format (e.g. 1,2026/08/27 10:15:30,001801000001,TRAFFIC,drop,...)
        if "," in raw and ("TRAFFIC" in raw or "THREAT" in raw):
            parts = [p.strip() for p in raw.split(",")]
            if len(parts) >= 15:
                log_type = parts[3] if len(parts) > 3 else "TRAFFIC"
                src_ip = parts[7] if len(parts) > 7 else ""
                dst_ip = parts[8] if len(parts) > 8 else ""
                src_port = (
                    int(parts[24])
                    if len(parts) > 24 and parts[24].isdigit()
                    else (int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0)
                )
                dst_port = (
                    int(parts[25])
                    if len(parts) > 25 and parts[25].isdigit()
                    else (
                        int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else 0
                    )
                )
                proto = (
                    parts[29]
                    if len(parts) > 29
                    else (parts[13] if len(parts) > 13 else "TCP")
                )
                action = (
                    parts[30]
                    if len(parts) > 30
                    else (parts[14] if len(parts) > 14 else "allow")
                )
                rule = parts[11] if len(parts) > 11 else ""
                app = parts[14] if len(parts) > 14 else ""

                disposition = (
                    "Blocked"
                    if action.lower() in ["drop", "deny", "reset-both", "block"]
                    else "Allowed"
                )
                disposition_id = 2 if disposition == "Blocked" else 1

                return {
                    "device_vendor": "Palo Alto Networks",
                    "device_product": "PAN-OS",
                    "log_type": log_type,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto.upper(),
                    "action": action,
                    "disposition": disposition,
                    "disposition_id": disposition_id,
                    "rule_name": rule,
                    "app_name": app,
                    "message": f"PAN-OS {log_type} {action} {src_ip}->{dst_ip}",
                }

        # Fallback Key-Value
        kv = {}
        for match in re.finditer(r"([a-zA-Z0-9_]+)=([^\s,]+)", raw):
            kv[match.group(1)] = match.group(2)

        kv["device_vendor"] = "Palo Alto Networks"
        kv["device_product"] = "PAN-OS"
        kv["message"] = raw
        return kv
