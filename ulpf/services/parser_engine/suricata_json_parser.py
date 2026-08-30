"""
Suricata EVE JSON IDS/IPS Parser
Parses Suricata EVE telemetry including Alerts, DNS, HTTP, Flow, and TLS records.
"""

import json
from typing import Dict, Any, Optional

from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.parser_engine.base import BaseParser


class SuricataEVEParser(BaseParser):
    """
    Parses Suricata EVE JSON records. Maps 'alert' events to Security Finding (2001)
    and flow/dns/http to Network Activity (4001).
    """

    def __init__(
        self,
        parser_id: str = "suricata-eve-json-parser",
        vendor: str = "Suricata",
        product: str = "EVE-IDS",
        version: str = "1.0.0"
    ):
        super().__init__(
            parser_id=parser_id,
            vendor=vendor,
            product=product,
            format_type=FormatType.JSON,
            version=version,
            target_class="Network Activity",
            target_class_uid=4001
        )

    def matches(self, raw_payload: str, source_meta: Optional[SourceMetadata] = None) -> bool:
        raw = raw_payload.strip()
        if not (raw.startswith("{") and raw.endswith("}")):
            return False
        return ("event_type" in raw and ("flow_id" in raw or "src_ip" in raw or "alert" in raw))

    def parse_fields(self, raw_payload: str, source_meta: Optional[SourceMetadata] = None) -> Dict[str, Any]:
        data = json.loads(raw_payload.strip())
        if not isinstance(data, dict):
            raise ValueError("Suricata payload is not a JSON dictionary")

        event_type = data.get("event_type", "flow")
        
        parsed: Dict[str, Any] = {
            "device_vendor": "Suricata",
            "device_product": "EVE-IDS",
            "event_type": event_type,
            "timestamp": data.get("timestamp"),
            "flow_id": data.get("flow_id"),
            "in_iface": data.get("in_iface"),
            "src_ip": data.get("src_ip"),
            "src_port": data.get("src_port"),
            "dst_ip": data.get("dest_ip") or data.get("dst_ip"),
            "dst_port": data.get("dest_port") or data.get("dst_port"),
            "protocol": data.get("proto", "TCP").upper(),
            "app_name": data.get("app_proto"),
            "message": f"Suricata {event_type} event"
        }

        # If it is an alert event, map to Security Finding
        if event_type == "alert" and "alert" in data:
            alert_info = data["alert"]
            parsed["target_class_uid"] = 2001
            parsed["target_class"] = "Security Finding"
            parsed["signature"] = alert_info.get("signature")
            parsed["signature_id"] = alert_info.get("signature_id")
            parsed["category"] = alert_info.get("category")
            parsed["message"] = alert_info.get("signature", "Suricata Alert")
            
            # Map Suricata severity (1=High, 2=Medium, 3=Low, 4=Info)
            sev_num = alert_info.get("severity", 3)
            if sev_num == 1:
                parsed["severity"] = "High"
                parsed["severity_id"] = 4
            elif sev_num == 2:
                parsed["severity"] = "Medium"
                parsed["severity_id"] = 3
            elif sev_num == 3:
                parsed["severity"] = "Low"
                parsed["severity_id"] = 2
            else:
                parsed["severity"] = "Informational"
                parsed["severity_id"] = 1

            action = alert_info.get("action", "allowed")
            parsed["action"] = action
            if action in ["blocked", "drop", "reject"]:
                parsed["disposition"] = "Blocked"
                parsed["disposition_id"] = 2
            else:
                parsed["disposition"] = "Allowed"
                parsed["disposition_id"] = 1
        else:
            # Flow or HTTP or DNS
            parsed["target_class_uid"] = 4001
            parsed["target_class"] = "Network Activity"
            parsed["action"] = "allow"
            parsed["severity"] = "Informational"
            parsed["severity_id"] = 1
            parsed["disposition"] = "Allowed"
            parsed["disposition_id"] = 1

            if "http" in data:
                http_info = data["http"]
                parsed["http_hostname"] = http_info.get("hostname")
                parsed["dst_hostname"] = http_info.get("hostname")
                parsed["http_url"] = http_info.get("url")
                parsed["http_method"] = http_info.get("http_method")
                parsed["http_status"] = http_info.get("status")
            if "dns" in data:
                dns_info = data["dns"]
                parsed["dns_query"] = dns_info.get("rrname")
                parsed["dst_hostname"] = dns_info.get("rrname")
                parsed["dns_type"] = dns_info.get("rrtype")
            if "flow" in data:
                flow_info = data["flow"]
                parsed["bytes_in"] = flow_info.get("bytes_toclient")
                parsed["bytes_out"] = flow_info.get("bytes_toserver")
                parsed["packets_in"] = flow_info.get("pkts_toclient")
                parsed["packets_out"] = flow_info.get("pkts_toserver")

        return parsed
