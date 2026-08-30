"""
Generic Log Parsers (RFC 5424, RFC 3164, Generic JSON, Generic KV)
Fallback parsers for standard formatted telemetry.
"""

import json
import re
from typing import Any

from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.parser_engine.base import BaseParser


class GenericRFC5424Parser(BaseParser):
    """
    Parses RFC 5424 structured syslog events:
    <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    """

    def __init__(
        self,
        parser_id: str = "syslog-rfc5424-generic",
        vendor: str = "Generic",
        product: str = "Syslog-RFC5424",
        version: str = "1.0.0",
    ):
        super().__init__(
            parser_id=parser_id,
            vendor=vendor,
            product=product,
            format_type=FormatType.SYSLOG_RFC5424,
            version=version,
            target_class="Network Activity",
            target_class_uid=4001,
        )
        self.pattern = re.compile(
            r"^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)?\s*(.*)$",
            re.DOTALL,
        )

    def matches(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> bool:
        return bool(self.pattern.match(raw_payload.strip()))

    def parse_fields(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> dict[str, Any]:
        raw = raw_payload.strip()
        m = self.pattern.match(raw)
        if not m:
            raise ValueError("Not a valid RFC 5424 syslog message")

        pri = int(m.group(1))
        ts = m.group(2)
        hostname = m.group(3)
        app_name = m.group(4)
        proc_id = m.group(5)
        msg_id = m.group(6)
        sd = m.group(7)
        msg = m.group(8)

        facility = pri >> 3
        severity_code = pri & 7

        # Severity mapping (0=Emerg, 1=Alert, 2=Crit, 3=Err, 4=Warn, 5=Notice, 6=Info, 7=Debug)
        sev_map = {
            0: (6, "Fatal"),
            1: (5, "Critical"),
            2: (5, "Critical"),
            3: (4, "High"),
            4: (3, "Medium"),
            5: (2, "Low"),
            6: (1, "Informational"),
            7: (1, "Informational"),
        }
        sev_id, sev_name = sev_map.get(severity_code, (1, "Informational"))

        parsed = {
            "device_vendor": "Generic-Syslog",
            "device_product": app_name if app_name != "-" else "RFC5424",
            "facility": facility,
            "severity_code": severity_code,
            "severity": sev_name,
            "severity_id": sev_id,
            "timestamp": ts if ts != "-" else None,
            "src_hostname": hostname if hostname != "-" else None,
            "app_name": app_name if app_name != "-" else None,
            "proc_id": proc_id if proc_id != "-" else None,
            "msg_id": msg_id if msg_id != "-" else None,
            "structured_data": sd if sd != "-" else None,
            "message": msg.strip() if msg else f"Syslog {app_name} event",
            "action": "allow",
            "disposition": "Allowed",
            "disposition_id": 1,
        }

        # Heuristic IP extraction from message body
        self._extract_ips_from_msg(msg, parsed)
        return parsed

    def _extract_ips_from_msg(self, msg: str, parsed: dict[str, Any]):
        if not msg:
            return
        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", msg)
        if len(ips) >= 2:
            parsed["src_ip"] = ips[0]
            parsed["dst_ip"] = ips[1]
        elif len(ips) == 1:
            parsed["src_ip"] = ips[0]


class GenericRFC3164Parser(BaseParser):
    """
    Parses legacy BSD Syslog (RFC 3164):
    <PRI>TIMESTAMP HOSTNAME TAG: MSG
    """

    def __init__(
        self,
        parser_id: str = "syslog-rfc3164-generic",
        vendor: str = "Generic",
        product: str = "Syslog-RFC3164",
        version: str = "1.0.0",
    ):
        super().__init__(
            parser_id=parser_id,
            vendor=vendor,
            product=product,
            format_type=FormatType.SYSLOG_RFC3164,
            version=version,
            target_class="Network Activity",
            target_class_uid=4001,
        )
        self.pattern = re.compile(
            r"^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^\s:]+)\s+([^:]+):\s*(.*)$",
            re.DOTALL,
        )

    def matches(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> bool:
        return bool(self.pattern.match(raw_payload.strip()))

    def parse_fields(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> dict[str, Any]:
        raw = raw_payload.strip()
        m = self.pattern.match(raw)
        if not m:
            raise ValueError("Not a valid RFC 3164 syslog message")

        pri = int(m.group(1))
        ts = m.group(2)
        host = m.group(3)
        tag = m.group(4)
        msg = m.group(5)

        facility = pri >> 3
        severity_code = pri & 7

        parsed = {
            "device_vendor": "Generic-Syslog",
            "device_product": tag,
            "facility": facility,
            "severity_code": severity_code,
            "severity": "Informational"
            if severity_code >= 6
            else ("Warning" if severity_code >= 4 else "High"),
            "severity_id": 1
            if severity_code >= 6
            else (3 if severity_code >= 4 else 4),
            "timestamp": ts,
            "src_hostname": host,
            "app_name": tag,
            "message": msg.strip(),
            "action": "allow",
            "disposition": "Allowed",
            "disposition_id": 1,
        }

        # Check for deny / drop keywords in message
        if any(
            w in msg.lower()
            for w in ["deny", "denied", "drop", "dropped", "block", "blocked", "reject"]
        ):
            parsed["action"] = "deny"
            parsed["disposition"] = "Blocked"
            parsed["disposition_id"] = 2
            parsed["severity"] = "Medium"
            parsed["severity_id"] = 3

        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", msg)
        if len(ips) >= 2:
            parsed["src_ip"] = ips[0]
            parsed["dst_ip"] = ips[1]
        elif len(ips) == 1:
            parsed["src_ip"] = ips[0]

        return parsed


class GenericJSONParser(BaseParser):
    """
    Parses generic JSON telemetry and extracts standard network keys.
    """

    def __init__(
        self,
        parser_id: str = "json-generic-parser",
        vendor: str = "Generic",
        product: str = "JSON-Log",
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
        return raw.startswith("{") and raw.endswith("}")

    def parse_fields(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> dict[str, Any]:
        data = json.loads(raw_payload.strip())
        if not isinstance(data, dict):
            raise ValueError("Generic JSON payload must be an object")

        parsed = dict(data)
        parsed["device_vendor"] = data.get("vendor", "Generic-JSON")
        parsed["device_product"] = data.get("product", "JSON-Telemetry")
        parsed["message"] = data.get("message") or data.get("msg") or "JSON Event"

        # Search for typical IP / port fields
        for src_k in ["src_ip", "src", "source_ip", "client_ip", "srcip", "ip_src"]:
            if src_k in data:
                parsed["src_ip"] = data[src_k]
                break
        for dst_k in [
            "dst_ip",
            "dst",
            "dest_ip",
            "destination_ip",
            "server_ip",
            "dstip",
            "ip_dst",
        ]:
            if dst_k in data:
                parsed["dst_ip"] = data[dst_k]
                break
        for spt_k in ["src_port", "spt", "source_port", "client_port", "srcport"]:
            if spt_k in data:
                try:
                    parsed["src_port"] = int(data[spt_k])
                except (ValueError, TypeError):
                    pass
                break
        for dpt_k in [
            "dst_port",
            "dpt",
            "dest_port",
            "destination_port",
            "server_port",
            "dstport",
        ]:
            if dpt_k in data:
                try:
                    parsed["dst_port"] = int(data[dpt_k])
                except (ValueError, TypeError):
                    pass
                break
        for proto_k in ["proto", "protocol", "proto_name"]:
            if proto_k in data:
                parsed["protocol"] = str(data[proto_k]).upper()
                break

        action = str(data.get("action", data.get("act", "allow"))).lower()
        if action in ["allow", "permit", "accept", "pass"]:
            parsed["disposition"] = "Allowed"
            parsed["disposition_id"] = 1
        elif action in ["deny", "drop", "block", "reject", "reset"]:
            parsed["disposition"] = "Blocked"
            parsed["disposition_id"] = 2
        else:
            parsed["disposition"] = "Allowed"
            parsed["disposition_id"] = 1

        return parsed
