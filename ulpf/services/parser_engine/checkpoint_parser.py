"""
Checkpoint Firewall-1 Parser
Parses Checkpoint syslog security events.
"""

import re
from typing import Any

from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.parser_engine.base import BaseParser


class CheckpointParser(BaseParser):
    """
    Parses Checkpoint Firewall-1 syslog events.
    """

    def __init__(
        self,
        parser_id: str = "checkpoint-fw1-parser",
        vendor: str = "Checkpoint",
        product: str = "Firewall-1",
        version: str = "1.0.0"
    ):
        super().__init__(
            parser_id=parser_id,
            vendor=vendor,
            product=product,
            format_type=FormatType.SYSLOG_RFC3164,
            version=version,
            target_class="Network Activity",
            target_class_uid=4001
        )

    def matches(self, raw_payload: str, source_meta: SourceMetadata | None = None) -> bool:
        lower = raw_payload.lower()
        return ("checkpoint" in lower or "fw1" in lower or "log_uid=" in lower or (source_meta and source_meta.vendor.lower() == "checkpoint"))

    def parse_fields(self, raw_payload: str, source_meta: SourceMetadata | None = None) -> dict[str, Any]:
        raw = raw_payload.strip()

        parsed: dict[str, Any] = {
            "device_vendor": "Checkpoint",
            "device_product": "Firewall-1",
            "message": raw
        }

        # Checkpoint uses key: value or key="value" or key=value;
        kv_regex = re.compile(r'([a-zA-Z0-9_]+)[:=](?:"([^"]*)"|([^\s;]+))')
        for match in kv_regex.finditer(raw):
            k = match.group(1)
            v = match.group(2) if match.group(2) is not None else match.group(3)
            parsed[k] = v

        if "src" in parsed:
            parsed["src_ip"] = parsed["src"]
        if "dst" in parsed:
            parsed["dst_ip"] = parsed["dst"]
        if "s_port" in parsed:
            try:
                parsed["src_port"] = int(parsed["s_port"])
            except (ValueError, TypeError):
                pass
        if "service" in parsed:
            try:
                parsed["dst_port"] = int(parsed["service"])
            except (ValueError, TypeError):
                parsed["service_name"] = parsed["service"]
        if "proto" in parsed:
            parsed["protocol"] = str(parsed["proto"]).upper()

        if "action" in parsed:
            act = parsed["action"].lower()
            if act in ["accept", "allow", "permit"]:
                parsed["disposition"] = "Allowed"
                parsed["disposition_id"] = 1
                parsed["severity"] = "Informational"
                parsed["severity_id"] = 1
            elif act in ["drop", "reject", "block", "deny"]:
                parsed["disposition"] = "Blocked"
                parsed["disposition_id"] = 2
                parsed["severity"] = "Medium"
                parsed["severity_id"] = 3
            else:
                parsed["disposition"] = "Allowed"
                parsed["disposition_id"] = 1
                parsed["severity"] = "Informational"
                parsed["severity_id"] = 1
        else:
            parsed["disposition"] = "Allowed"
            parsed["disposition_id"] = 1
            parsed["severity"] = "Informational"
            parsed["severity_id"] = 1

        if "rule_name" in parsed:
            parsed["rule_name"] = parsed["rule_name"]
        elif "rule" in parsed:
            parsed["rule_name"] = parsed["rule"]

        return parsed
