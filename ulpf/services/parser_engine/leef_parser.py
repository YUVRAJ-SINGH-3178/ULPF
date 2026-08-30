"""
IBM QRadar Log Event Extended Format (LEEF 1.0 & 2.0) Parser
Handles custom delimiter specifications and tab/delimiter-separated key-value pairs.
Format: LEEF:Version|Vendor|Product|Version|EventID|[Delimiter|]Extension
"""

import re
from typing import Any

from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.parser_engine.base import BaseParser


class LEEFParser(BaseParser):
    """
    Parses standard LEEF 1.0 and 2.0 logs.
    """

    def __init__(
        self,
        parser_id: str = "leef-standard-parser",
        vendor: str = "IBM-QRadar",
        product: str = "LEEF-Engine",
        version: str = "1.0.0"
    ):
        super().__init__(
            parser_id=parser_id,
            vendor=vendor,
            product=product,
            format_type=FormatType.LEEF,
            version=version,
            target_class="Network Activity",
            target_class_uid=4001
        )

    def matches(self, raw_payload: str, source_meta: SourceMetadata | None = None) -> bool:
        return "LEEF:" in raw_payload

    def parse_fields(self, raw_payload: str, source_meta: SourceMetadata | None = None) -> dict[str, Any]:
        raw = raw_payload.strip()
        leef_start = raw.find("LEEF:")
        if leef_start == -1:
            raise ValueError("Not a valid LEEF event: missing 'LEEF:' prefix")

        leef_str = raw[leef_start:]
        parts = leef_str.split("|")

        if len(parts) < 5:
            raise ValueError(f"Malformed LEEF header: too few pipe segments ({len(parts)})")

        ver_tag = parts[0].replace("LEEF:", "").strip()
        vendor = parts[1].strip()
        product = parts[2].strip()
        version = parts[3].strip()
        event_id = parts[4].strip()

        parsed: dict[str, Any] = {
            "leef_version": ver_tag,
            "device_vendor": vendor,
            "device_product": product,
            "device_version": version,
            "event_id_raw": event_id,
            "message": f"{vendor} {product} {event_id}"
        }

        # LEEF 2.0 may include a custom delimiter specification in header index 5
        delimiter = "\t"
        ext_index = 5

        if ver_tag.startswith("2.0") and len(parts) >= 7:
            delim_spec = parts[5]
            if delim_spec:
                # Delimiter can be single char or hex (e.g. 0x09, x09, 0x20)
                if delim_spec.startswith("0x") or delim_spec.startswith("x"):
                    try:
                        hex_val = delim_spec.replace("0x", "").replace("x", "")
                        delimiter = chr(int(hex_val, 16))
                    except (ValueError, OverflowError):
                        delimiter = "\t"
                else:
                    delimiter = delim_spec
            ext_index = 6
            ext_str = "|".join(parts[ext_index:])
        else:
            ext_str = "|".join(parts[ext_index:])

        # Parse key=value attributes separated by delimiter (or tab or space fallback)
        if ext_str:
            if delimiter in ext_str:
                items = ext_str.split(delimiter)
            elif "\t" in ext_str:
                items = ext_str.split("\t")
            else:
                items = [f"{k}={v}" for k, v in re.findall(r'(\w+)=(.*?)(?=(?:\s+\w+=|$))', ext_str)]

            for item in items:
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    parsed[k.strip()] = v.strip()

        self._normalize_common_leef_fields(parsed)
        return parsed

    def _normalize_common_leef_fields(self, d: dict[str, Any]):
        """Map standard LEEF keys to intermediate fields."""
        if "src" in d:
            d["src_ip"] = d["src"]
        if "dst" in d:
            d["dst_ip"] = d["dst"]
        if "srcPort" in d:
            try:
                d["src_port"] = int(d["srcPort"])
            except (ValueError, TypeError):
                pass
        if "dstPort" in d:
            try:
                d["dst_port"] = int(d["dstPort"])
            except (ValueError, TypeError):
                pass
        if "proto" in d:
            d["protocol"] = d["proto"]
        if "usrName" in d:
            d["user_name"] = d["usrName"]
        if "srcMAC" in d:
            d["src_mac"] = d["srcMAC"]
        if "dstMAC" in d:
            d["dst_mac"] = d["dstMAC"]
        if "action" in d:
            d["action"] = d["action"]
        elif "act" in d:
            d["action"] = d["act"]
        if "policyid" in d:
            d["rule_id"] = d["policyid"]
            d["rule_name"] = f"Policy-{d['policyid']}"
        if "totalBytes" in d:
            try:
                d["bytes"] = int(d["totalBytes"])
            except (ValueError, TypeError):
                pass

        # Action & Disposition
        act_raw = str(d.get("action", "")).lower()
        if act_raw in ["allow", "allowed", "permit", "permitted", "accept", "pass"]:
            d["disposition"] = "Allowed"
            d["disposition_id"] = 1
        elif act_raw in ["deny", "denied", "drop", "dropped", "block", "blocked", "close", "reject"]:
            d["disposition"] = "Blocked"
            d["disposition_id"] = 2
        elif not d.get("disposition"):
            d["disposition"] = "Allowed"
            d["disposition_id"] = 1

        # Severity Mapping (sev: 1-10)
        sev_val = str(d.get("sev") or d.get("severity", "")).strip()
        if sev_val.isdigit():
            s_int = int(sev_val)
            if s_int >= 8:
                d["severity"] = "High"
                d["severity_id"] = 4
            elif s_int >= 5:
                d["severity"] = "Medium"
                d["severity_id"] = 3
            elif s_int >= 3:
                d["severity"] = "Low"
                d["severity_id"] = 2
            else:
                d["severity"] = "Informational"
                d["severity_id"] = 1
        elif not d.get("severity"):
            d["severity"] = "Medium" if d.get("disposition_id") == 2 else "Informational"
            d["severity_id"] = 3 if d.get("disposition_id") == 2 else 1
