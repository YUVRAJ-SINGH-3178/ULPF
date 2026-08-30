"""
Fortinet FortiOS Parser
Parses FortiGate / FortiOS Key-Value and LEEF structured security logs.
"""

import re
from typing import Dict, Any, Optional

from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.parser_engine.base import BaseParser
from ulpf.services.parser_engine.leef_parser import LEEFParser


class FortinetParser(BaseParser):
    """
    Parses Fortinet FortiGate traffic, UTM, and security events.
    """

    def __init__(
        self,
        parser_id: str = "fortinet-fortios-parser",
        vendor: str = "Fortinet",
        product: str = "FortiOS",
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
        self._leef_parser = LEEFParser()

    def matches(self, raw_payload: str, source_meta: Optional[SourceMetadata] = None) -> bool:
        lower = raw_payload.lower()
        return ("devname=" in lower or "fortigate" in lower or "fortios" in lower or (source_meta and source_meta.vendor.lower() == "fortinet"))

    def parse_fields(self, raw_payload: str, source_meta: Optional[SourceMetadata] = None) -> Dict[str, Any]:
        raw = raw_payload.strip()

        # If LEEF formatted Fortinet event
        if "LEEF:" in raw:
            leef_fields = self._leef_parser.parse_fields(raw, source_meta)
            leef_fields["device_vendor"] = "Fortinet"
            leef_fields["device_product"] = "FortiOS"
            return leef_fields

        parsed: Dict[str, Any] = {
            "device_vendor": "Fortinet",
            "device_product": "FortiOS",
            "message": raw
        }

        # Regex for key=value or key="quoted value"
        kv_regex = re.compile(r'([a-zA-Z0-9_]+)=(?:"([^"]*)"|([^\s]+))')
        for match in kv_regex.finditer(raw):
            key = match.group(1)
            val = match.group(2) if match.group(2) is not None else match.group(3)
            parsed[key] = val

        # Field Normalization
        if "srcip" in parsed:
            parsed["src_ip"] = parsed["srcip"]
        if "dstip" in parsed:
            parsed["dst_ip"] = parsed["dstip"]
        if "srcport" in parsed:
            try:
                parsed["src_port"] = int(parsed["srcport"])
            except (ValueError, TypeError):
                pass
        if "dstport" in parsed:
            try:
                parsed["dst_port"] = int(parsed["dstport"])
            except (ValueError, TypeError):
                pass
        if "proto" in parsed:
            proto_val = str(parsed["proto"]).strip()
            proto_map = {
                "1": "ICMP",
                "6": "TCP",
                "17": "UDP",
                "47": "GRE",
                "50": "ESP",
                "51": "AH",
                "58": "ICMPv6"
            }
            parsed["protocol"] = proto_map.get(proto_val, proto_val.upper())

        if "policyid" in parsed:
            parsed["rule_id"] = str(parsed["policyid"])
            parsed["rule_name"] = f"Policy-{parsed['policyid']}"

        if "service" in parsed:
            parsed["app_name"] = parsed["service"]
        elif "app" in parsed:
            parsed["app_name"] = parsed["app"]

        if "action" in parsed:
            act = parsed["action"].lower()
            if act in ["accept", "allow", "passthrough", "permit"]:
                parsed["disposition"] = "Allowed"
                parsed["disposition_id"] = 1
            elif act in ["deny", "drop", "block", "close", "timeout", "client-rst", "server-rst"]:
                parsed["disposition"] = "Blocked"
                parsed["disposition_id"] = 2
            else:
                parsed["disposition"] = "Allowed"
                parsed["disposition_id"] = 1

        if "sentbyte" in parsed:
            try:
                parsed["bytes_out"] = int(parsed["sentbyte"])
            except (ValueError, TypeError):
                pass
        if "rcvdbyte" in parsed:
            try:
                parsed["bytes_in"] = int(parsed["rcvdbyte"])
            except (ValueError, TypeError):
                pass
        if "level" in parsed:
            lvl = parsed["level"].lower()
            if lvl in ["critical", "emergency", "alert"]:
                parsed["severity"] = "Critical"
                parsed["severity_id"] = 5
            elif lvl == "error":
                parsed["severity"] = "High"
                parsed["severity_id"] = 4
            elif lvl == "warning":
                parsed["severity"] = "Medium"
                parsed["severity_id"] = 3
            elif lvl == "notice":
                parsed["severity"] = "Low"
                parsed["severity_id"] = 2
            else:
                parsed["severity"] = "Informational"
                parsed["severity_id"] = 1
        elif "disposition_id" in parsed and parsed["disposition_id"] == 2:
            parsed["severity"] = "Medium"
            parsed["severity_id"] = 3

        return parsed
