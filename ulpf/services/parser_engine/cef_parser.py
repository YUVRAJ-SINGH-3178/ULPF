"""
ArcSight Common Event Format (CEF) Parser
Compliant with Micro Focus / ArcSight CEF Standards.
Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
"""

import re
from typing import Any

from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.parser_engine.base import BaseParser


class CEFParser(BaseParser):
    """
    Parses standard CEF formatted logs, handling pipe delimiters, backslash escaping, and extension pairs.
    """

    def __init__(
        self,
        parser_id: str = "cef-standard-parser",
        vendor: str = "ArcSight",
        product: str = "CEF-Engine",
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

    def matches(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> bool:
        return "CEF:" in raw_payload

    def parse_fields(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> dict[str, Any]:
        raw = raw_payload.strip()
        cef_start = raw.find("CEF:")
        if cef_start == -1:
            raise ValueError("Not a valid CEF event: missing 'CEF:' prefix")

        cef_str = raw[cef_start:]

        # Split headers (respecting unescaped pipes)
        # Standard: 7 header pipes separating 8 segments (prefix + 7 header parts)
        parts = []
        current = []
        escaped = False
        pipe_count = 0

        for idx, char in enumerate(cef_str):
            if pipe_count < 7:
                if escaped:
                    current.append(char)
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "|":
                    parts.append("".join(current))
                    current = []
                    pipe_count += 1
                else:
                    current.append(char)
            else:
                # Rest is extension
                current.append(char)

        parts.append("".join(current))

        if len(parts) < 8:
            raise ValueError(
                f"Malformed CEF header: expected 7 pipes, found {len(parts) - 1}"
            )

        prefix_ver = parts[0]  # CEF:0 or CEF:1
        version_num = prefix_ver.replace("CEF:", "").strip()
        vendor = parts[1].strip()
        product = parts[2].strip()
        dev_version = parts[3].strip()
        class_id = parts[4].strip()
        name = parts[5].strip()
        severity = parts[6].strip()
        extension_str = parts[7].strip() if len(parts) > 7 else ""

        parsed: dict[str, Any] = {
            "cef_version": version_num,
            "device_vendor": vendor,
            "device_product": product,
            "device_version": dev_version,
            "device_event_class_id": class_id,
            "event_name": name,
            "severity_raw": severity,
            "message": name,
        }

        # Parse Extension key=value pairs
        # Keys are alphanumeric; values can be unquoted or quoted, with backslash escaping
        if extension_str:
            ext_dict = self._parse_extension(extension_str)
            parsed.update(ext_dict)

        # Standard field mapping
        self._normalize_common_cef_fields(parsed)
        return parsed

    def _parse_extension(self, ext_str: str) -> dict[str, Any]:
        """Parses CEF extension key-value pairs with tokenization."""
        kv_pairs: dict[str, Any] = {}
        # Match pattern: key=value pairs where key is word chars
        pattern = re.compile(r"([a-zA-Z0-9_]+)=")
        matches = list(pattern.finditer(ext_str))

        for i, match in enumerate(matches):
            key = match.group(1)
            start_val = match.end()
            if i + 1 < len(matches):
                end_val = matches[i + 1].start()
            else:
                end_val = len(ext_str)

            val = ext_str[start_val:end_val].strip()
            # Clean trailing spaces and unescape \=, \|, \\
            val = (
                val.replace(r"\=", "=")
                .replace(r"\|", "|")
                .replace(r"\\", "\\")
                .replace(r"\n", "\n")
            )
            kv_pairs[key] = val

        return kv_pairs

    def _normalize_common_cef_fields(self, d: dict[str, Any]):
        """Map common CEF extension keys to intermediate network fields."""
        if "src" in d:
            d["src_ip"] = d["src"]
        if "dst" in d:
            d["dst_ip"] = d["dst"]
        if "spt" in d:
            try:
                d["src_port"] = int(d["spt"])
            except (ValueError, TypeError):
                pass
        if "dpt" in d:
            try:
                d["dst_port"] = int(d["dpt"])
            except (ValueError, TypeError):
                pass
        if "proto" in d:
            d["protocol"] = d["proto"]
        if "act" in d:
            d["action"] = d["act"]
        if "action" not in d and "act" in d:
            d["action"] = d["act"]
        if "in" in d:
            try:
                d["bytes_in"] = int(d["in"])
            except (ValueError, TypeError):
                pass
        if "out" in d:
            try:
                d["bytes_out"] = int(d["out"])
            except (ValueError, TypeError):
                pass
        if "app" in d:
            d["app_name"] = d["app"]
        if "shost" in d:
            d["src_hostname"] = d["shost"]
        if "dhost" in d:
            d["dst_hostname"] = d["dhost"]
        if "smac" in d:
            d["src_mac"] = d["smac"]
        if "dmac" in d:
            d["dst_mac"] = d["dmac"]
        if "cs1" in d:
            d["rule_name"] = d["cs1"]
        elif "deviceCustomString1" in d:
            d["rule_name"] = d["deviceCustomString1"]

        # Action & Disposition
        act_raw = str(d.get("action") or d.get("act", "")).lower()
        if act_raw in ["allow", "allowed", "permit", "permitted", "accept", "pass"]:
            d["disposition"] = "Allowed"
            d["disposition_id"] = 1
        elif act_raw in [
            "deny",
            "denied",
            "drop",
            "dropped",
            "block",
            "blocked",
            "reset",
            "reset-both",
            "reset-client",
            "reset-server",
        ]:
            d["disposition"] = "Blocked"
            d["disposition_id"] = 2
        elif not d.get("disposition"):
            d["disposition"] = "Allowed"
            d["disposition_id"] = 1

        # Severity Mapping
        sev_raw = str(d.get("severity_raw", "")).strip()
        if sev_raw.isdigit():
            sev_int = int(sev_raw)
            if sev_int >= 9:
                d["severity"] = "Critical"
                d["severity_id"] = 5
            elif sev_int >= 7:
                d["severity"] = "High"
                d["severity_id"] = 4
            elif sev_int >= 4:
                d["severity"] = "Medium"
                d["severity_id"] = 3
            elif sev_int >= 2:
                d["severity"] = "Low"
                d["severity_id"] = 2
            else:
                d["severity"] = "Informational"
                d["severity_id"] = 1
        elif sev_raw.lower() in ["critical", "crit", "very-high"]:
            d["severity"] = "Critical"
            d["severity_id"] = 5
        elif sev_raw.lower() in ["high", "err", "error"]:
            d["severity"] = "High"
            d["severity_id"] = 4
        elif sev_raw.lower() in ["medium", "med", "warning", "warn"]:
            d["severity"] = "Medium"
            d["severity_id"] = 3
        elif sev_raw.lower() in ["low", "notice"]:
            d["severity"] = "Low"
            d["severity_id"] = 2
        elif sev_raw.lower() in ["info", "informational", "debug", "unknown"]:
            d["severity"] = "Informational"
            d["severity_id"] = 1
