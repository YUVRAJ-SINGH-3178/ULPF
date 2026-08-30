"""
Squid Proxy Parser
Parses Squid native access logs and HTTP activity.
"""

import re
from typing import Dict, Any, Optional

from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.parser_engine.base import BaseParser


class SquidProxyParser(BaseParser):
    """
    Parses standard Squid proxy access logs:
    <timestamp> <elapsed> <client_ip> <action/code> <bytes> <method> <url> <user> <peer/status> <type>
    """

    def __init__(
        self,
        parser_id: str = "squid-proxy-parser",
        vendor: str = "Squid",
        product: str = "Proxy",
        version: str = "1.0.0"
    ):
        super().__init__(
            parser_id=parser_id,
            vendor=vendor,
            product=product,
            format_type=FormatType.PROPRIETARY,
            version=version,
            target_class="Network Activity",
            target_class_uid=4001
        )
        self.pattern = re.compile(
            r"^(\d+\.\d+)\s+(\d+)\s+([0-9.]+)\s+([A-Z_]+)/(\d{3})\s+(\d+)\s+([A-Z]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$"
        )

    def matches(self, raw_payload: str, source_meta: Optional[SourceMetadata] = None) -> bool:
        return bool(self.pattern.match(raw_payload.strip())) or "TCP_DENIED/" in raw_payload or "TCP_MISS/" in raw_payload

    def parse_fields(self, raw_payload: str, source_meta: Optional[SourceMetadata] = None) -> Dict[str, Any]:
        raw = raw_payload.strip()
        m = self.pattern.match(raw)
        peer_info = ""
        if not m:
            # Try space split
            parts = raw.split()
            if len(parts) >= 7:
                epoch_ts = parts[0]
                elapsed = parts[1]
                client_ip = parts[2]
                cache_status, http_code = parts[3].split("/") if "/" in parts[3] else (parts[3], "200")
                bytes_trans = parts[4]
                method = parts[5]
                url = parts[6]
                if len(parts) >= 9:
                    peer_info = parts[8]
            else:
                raise ValueError("Cannot parse Squid proxy access line")
        else:
            epoch_ts = m.group(1)
            elapsed = m.group(2)
            client_ip = m.group(3)
            cache_status = m.group(4)
            http_code = m.group(5)
            bytes_trans = m.group(6)
            method = m.group(7)
            url = m.group(8)
            peer_info = m.group(10) if len(m.groups()) >= 10 else ""

        try:
            status_code = int(http_code)
        except (ValueError, TypeError):
            status_code = 200

        disposition = "Blocked" if "DENIED" in cache_status or status_code in [403, 401] else "Allowed"
        disposition_id = 2 if disposition == "Blocked" else 1

        parsed: Dict[str, Any] = {
            "device_vendor": "Squid",
            "device_product": "Proxy",
            "src_ip": client_ip,
            "http_method": method,
            "http_url": url,
            "http_status": status_code,
            "cache_status": cache_status,
            "bytes_out": int(bytes_trans) if str(bytes_trans).isdigit() else 0,
            "elapsed_ms": int(elapsed) if str(elapsed).isdigit() else 0,
            "protocol": "TCP",
            "app_name": "HTTP",
            "action": "deny" if disposition == "Blocked" else "allow",
            "disposition": disposition,
            "disposition_id": disposition_id,
            "severity": "Medium" if disposition == "Blocked" else "Informational",
            "severity_id": 3 if disposition == "Blocked" else 1,
            "message": f"Squid {method} {url} -> {http_code} ({cache_status})"
        }

        # Extract host and port from URL if present
        host_match = re.search(r"https?://([^/:]+)(?::(\d+))?", url)
        if host_match:
            parsed["dst_hostname"] = host_match.group(1)
            if host_match.group(2):
                parsed["dst_port"] = int(host_match.group(2))
            else:
                parsed["dst_port"] = 443 if url.startswith("https") else 80

        # Extract destination IP from peer info if available (e.g. DIRECT/198.51.100.25)
        if peer_info and "/" in peer_info:
            peer_ip = peer_info.split("/")[1]
            if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", peer_ip):
                parsed["dst_ip"] = peer_ip

        return parsed
