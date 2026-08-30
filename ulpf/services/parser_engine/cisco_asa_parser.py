"""
Cisco ASA / FTD Firewall Parser
Parses Cisco Adaptive Security Appliance syslog events (Built connections, Teardowns, ACL Denials, NAT).
"""

import re
from typing import Any

from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.parser_engine.base import BaseParser


class CiscoASAParser(BaseParser):
    """
    Parses Cisco ASA / FTD firewall syslog events.
    """

    def __init__(
        self,
        parser_id: str = "cisco-asa-firewall-parser",
        vendor: str = "Cisco",
        product: str = "ASA",
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

    def matches(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> bool:
        return bool(re.search(r"%ASA-\d+-\d+|%FTD-\d+-\d+", raw_payload))

    def parse_fields(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> dict[str, Any]:
        raw = raw_payload.strip()

        parsed: dict[str, Any] = {
            "device_vendor": "Cisco",
            "device_product": "ASA",
            "message": raw,
        }

        # Extract message code e.g. %ASA-6-302013
        code_match = re.search(r"%(ASA|FTD)-(\d+)-(\d+):\s*(.*)$", raw)
        if not code_match:
            raise ValueError("No Cisco ASA/FTD message code found")

        facility = code_match.group(1)
        severity_level = int(code_match.group(2))
        message_id = code_match.group(3)
        body = code_match.group(4).strip()

        parsed["facility"] = facility
        parsed["cisco_severity"] = severity_level
        parsed["cisco_message_id"] = message_id
        parsed["message_body"] = body

        # Map Cisco severity (1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notification, 6=Informational, 7=Debug)
        if severity_level in [1, 2]:
            parsed["severity"] = "Critical"
            parsed["severity_id"] = 5
        elif severity_level == 3:
            parsed["severity"] = "High"
            parsed["severity_id"] = 4
        elif severity_level == 4:
            parsed["severity"] = "Medium"
            parsed["severity_id"] = 3
        elif severity_level == 5:
            parsed["severity"] = "Low"
            parsed["severity_id"] = 2
        else:
            parsed["severity"] = "Informational"
            parsed["severity_id"] = 1

        # Pattern 1: %ASA-6-302013 / 302015: Built {inbound|outbound} {TCP|UDP} connection {id} for {src_if}:{src_ip}/{src_port} ... to {dst_if}:{dst_ip}/{dst_port}
        built_match = re.search(
            r"Built\s+(inbound|outbound)?\s*(\w+)\s+connection\s+(\d+)\s+for\s+(?:([\w-]+):)?([0-9.]+)/(\d+)(?:\s*\([^\)]+\))?\s+to\s+(?:([\w-]+):)?([0-9.]+)/(\d+)",
            body,
            re.IGNORECASE,
        )
        if built_match:
            direction_str = (built_match.group(1) or "inbound").lower()
            parsed["direction"] = direction_str
            parsed["protocol"] = built_match.group(2).upper()
            parsed["connection_id"] = built_match.group(3)
            parsed["src_zone"] = built_match.group(4) or ""
            parsed["src_ip"] = built_match.group(5)
            parsed["src_port"] = int(built_match.group(6))
            parsed["dst_zone"] = built_match.group(7) or ""
            parsed["dst_ip"] = built_match.group(8)
            parsed["dst_port"] = int(built_match.group(9))
            parsed["action"] = "allow"
            parsed["disposition"] = "Allowed"
            parsed["disposition_id"] = 1
            return parsed

        # Pattern 2: %ASA-6-302014 / 302016: Teardown {TCP|UDP} connection {id} for ... duration {dur} bytes {bytes}
        teardown_match = re.search(
            r"Teardown\s+(?:(inbound|outbound)\s+)?(\w+)\s+connection\s+(\d+)\s+for\s+(?:([\w-]+):)?([0-9.]+)/(\d+)(?:\s*\([^\)]+\))?\s+to\s+(?:([\w-]+):)?([0-9.]+)/(\d+)(?:\s*\([^\)]+\))?\s+duration\s+([0-9:]+)\s+bytes\s+(\d+)",
            body,
            re.IGNORECASE,
        )
        if teardown_match:
            parsed["direction"] = (teardown_match.group(1) or "inbound").lower()
            parsed["protocol"] = teardown_match.group(2).upper()
            parsed["connection_id"] = teardown_match.group(3)
            parsed["src_zone"] = teardown_match.group(4) or ""
            parsed["src_ip"] = teardown_match.group(5)
            parsed["src_port"] = int(teardown_match.group(6))
            parsed["dst_zone"] = teardown_match.group(7) or ""
            parsed["dst_ip"] = teardown_match.group(8)
            parsed["dst_port"] = int(teardown_match.group(9))
            parsed["duration"] = teardown_match.group(10)
            parsed["bytes"] = int(teardown_match.group(11))
            parsed["action"] = "close"
            parsed["disposition"] = "Allowed"
            parsed["disposition_id"] = 1
            return parsed

        # Pattern 3: %ASA-4-106023: Deny {proto} src {src_if}:{src_ip}/{src_port} dst {dst_if}:{dst_ip}/{dst_port} by access-group "{rule}"
        deny_match = re.search(
            r"Deny\s+(\w+)\s+src\s+(?:([\w-]+):)?([0-9.]+)/(\d+)\s+dst\s+(?:([\w-]+):)?([0-9.]+)/(\d+)(?:\s+by\s+access-group\s+\"([^\"]+)\")?",
            body,
            re.IGNORECASE,
        )
        if deny_match:
            parsed["protocol"] = deny_match.group(1).upper()
            parsed["src_zone"] = deny_match.group(2) or ""
            parsed["src_ip"] = deny_match.group(3)
            parsed["src_port"] = int(deny_match.group(4))
            parsed["dst_zone"] = deny_match.group(5) or ""
            parsed["dst_ip"] = deny_match.group(6)
            parsed["dst_port"] = int(deny_match.group(7))
            parsed["rule_name"] = deny_match.group(8) or "access-group"
            parsed["action"] = "deny"
            parsed["disposition"] = "Blocked"
            parsed["disposition_id"] = 2
            parsed["severity"] = "Medium"
            parsed["severity_id"] = 3
            return parsed

        # Pattern 4: %ASA-2-106001 / 106006: Inbound TCP connection denied from {src_ip}/{src_port} to {dst_ip}/{dst_port}
        denied_gen = re.search(
            r"(?:(Inbound|Outbound)\s+)?(\w+)?\s*connection\s+denied\s+from\s+([0-9.]+)/(\d+)\s+to\s+([0-9.]+)/(\d+)(?:\s+flags\s+(\w+))?(?:\s+on\s+interface\s+([\w-]+))?",
            body,
            re.IGNORECASE,
        )
        if denied_gen:
            parsed["direction"] = (denied_gen.group(1) or "inbound").lower()
            parsed["protocol"] = (denied_gen.group(2) or "TCP").upper()
            parsed["src_ip"] = denied_gen.group(3)
            parsed["src_port"] = int(denied_gen.group(4))
            parsed["dst_ip"] = denied_gen.group(5)
            parsed["dst_port"] = int(denied_gen.group(6))
            if denied_gen.group(7):
                parsed["tcp_flags"] = denied_gen.group(7)
            if denied_gen.group(8):
                parsed["src_zone"] = denied_gen.group(8)
            parsed["action"] = "deny"
            parsed["disposition"] = "Blocked"
            parsed["disposition_id"] = 2
            parsed["severity"] = "High"
            parsed["severity_id"] = 4
            return parsed

        # Pattern 5: %ASA-6-305011: Built dynamic {proto} translation from {src_if}:{src_ip}/{src_port} to {dst_if}:{dst_ip}/{dst_port}
        nat_match = re.search(
            r"Built\s+(?:dynamic|static)\s+(\w+)\s+translation\s+from\s+(?:([\w-]+):)?([0-9.]+)/(\d+)\s+to\s+(?:([\w-]+):)?([0-9.]+)/(\d+)",
            body,
            re.IGNORECASE,
        )
        if nat_match:
            parsed["protocol"] = nat_match.group(1).upper()
            parsed["src_zone"] = nat_match.group(2) or ""
            parsed["src_ip"] = nat_match.group(3)
            parsed["src_port"] = int(nat_match.group(4))
            parsed["dst_zone"] = nat_match.group(5) or ""
            parsed["dst_ip"] = nat_match.group(6)
            parsed["dst_port"] = int(nat_match.group(7))
            parsed["action"] = "allow"
            parsed["disposition"] = "Allowed"
            parsed["disposition_id"] = 1
            return parsed

        # Fallback: Extract unique IPs and ports if present in text
        # Filter out consecutive duplicate IPs (e.g. from mapped addresses like "198.51.100.25/443 (198.51.100.25/443)")
        raw_ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", body)
        unique_ips = []
        for ip in raw_ips:
            if not unique_ips or ip != unique_ips[-1]:
                unique_ips.append(ip)

        if len(unique_ips) >= 2:
            parsed["src_ip"] = unique_ips[0]
            parsed["dst_ip"] = unique_ips[1]
        elif len(unique_ips) == 1:
            parsed["src_ip"] = unique_ips[0]

        parsed["action"] = (
            "deny" if "denied" in body.lower() or "deny" in body.lower() else "allow"
        )
        parsed["disposition"] = "Blocked" if parsed["action"] == "deny" else "Allowed"
        parsed["disposition_id"] = 2 if parsed["action"] == "deny" else 1

        return parsed
