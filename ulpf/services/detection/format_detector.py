"""
Format & Source Detection Engine
Uses structural signatures, headers, and heuristics to accurately identify log formats and vendor origins.
"""

import json
import re
from typing import Tuple, Optional, Dict, Any

from ulpf.packages.schemas.models import FormatType, SourceMetadata


class FormatDetector:
    """
    Identifies log format (CEF, LEEF, RFC5424, RFC3164, JSON, CSV, Proprietary) and source vendor.
    """

    RFC5424_REGEX = re.compile(r"^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)?\s*(.*)$", re.DOTALL)
    RFC3164_REGEX = re.compile(r"^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^\s:]+)\s+([^:]+):\s*(.*)$", re.DOTALL)
    CISCO_ASA_REGEX = re.compile(r"(?:%ASA-\d+-\d+|%FTD-\d+-\d+)", re.IGNORECASE)
    FORTINET_KV_REGEX = re.compile(r"(?:date=\S+\s+time=\S+\s+devname=\S+|type=(?:traffic|utm|event)\s+subtype=)", re.IGNORECASE)

    def detect(self, raw_payload: str) -> Tuple[FormatType, str, str, float]:
        """
        Detects format, vendor, product, and detection confidence.
        Returns (format_type, vendor, product, confidence)
        """
        raw = raw_payload.strip()
        if not raw:
            return FormatType.UNKNOWN, "unknown", "unknown", 0.0

        # Check JSON first
        if (raw.startswith("{") and raw.endswith("}")) or (raw.startswith("[") and raw.endswith("]")):
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    if "event_type" in data and ("src_ip" in data or "flow_id" in data or "alert" in data):
                        return FormatType.JSON, "Suricata", "EVE-IDS", 0.99
                    elif "ts" in data and ("id.orig_h" in data or "id.resp_h" in data or "proto" in data):
                        return FormatType.JSON, "Zeek", "Network-Monitor", 0.99
                    elif "rule_name" in data or "firewall" in data:
                        return FormatType.JSON, "Generic-Firewall", "Cloud-FW", 0.95
                    return FormatType.JSON, "Generic", "JSON-Telemetry", 0.90
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                pass

        # Check CEF
        if raw.startswith("CEF:") or " CEF:" in raw:
            cef_idx = raw.find("CEF:")
            parts = raw[cef_idx:].split("|")
            vendor = parts[1].strip() if len(parts) > 1 else "Generic-CEF"
            product = parts[2].strip() if len(parts) > 2 else "CEF-Device"
            return FormatType.CEF, vendor, product, 0.98

        # Check LEEF
        if raw.startswith("LEEF:") or " LEEF:" in raw:
            leef_idx = raw.find("LEEF:")
            parts = raw[leef_idx:].split("|")
            vendor = parts[1].strip() if len(parts) > 1 else "Generic-LEEF"
            product = parts[2].strip() if len(parts) > 2 else "LEEF-Device"
            return FormatType.LEEF, vendor, product, 0.98

        # Check Fortinet Key-Value
        if self.FORTINET_KV_REGEX.search(raw):
            return FormatType.SYSLOG_RFC3164, "Fortinet", "FortiOS", 0.95

        # Check Cisco ASA / FTD Syslog
        if self.CISCO_ASA_REGEX.search(raw):
            return FormatType.SYSLOG_RFC3164, "Cisco", "ASA", 0.98

        # Check Checkpoint
        if "CheckPoint" in raw or "fw1" in raw or "log_uid" in raw:
            return FormatType.SYSLOG_RFC3164, "Checkpoint", "Firewall-1", 0.92

        # Check Squid Proxy
        if re.match(r"^\d{10}\.\d{3}\s+\d+\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+[A-Z_]+/\d{3}\s+\d+\s+[A-Z]+\s+", raw):
            return FormatType.PROPRIETARY, "Squid", "Proxy", 0.96

        # Check RFC 5424 Syslog
        if self.RFC5424_REGEX.match(raw):
            m = self.RFC5424_REGEX.match(raw)
            app_name = m.group(4) if m else "Syslog"
            return FormatType.SYSLOG_RFC5424, "Generic-Syslog", app_name, 0.90

        # Check RFC 3164 Syslog
        if self.RFC3164_REGEX.match(raw):
            m = self.RFC3164_REGEX.match(raw)
            tag = m.group(4) if m else "Syslog"
            return FormatType.SYSLOG_RFC3164, "Generic-Syslog", tag, 0.85

        # If it contains key-value pairs or proprietary tokens
        if "=" in raw and ("src" in raw.lower() or "dst" in raw.lower() or "action" in raw.lower() or "proto" in raw.lower()):
            return FormatType.PROPRIETARY, "Unknown-Vendor", "Proprietary-Appliance", 0.70

        # Unseen / Unknown format
        return FormatType.UNKNOWN, "Unknown", "Unknown-Device", 0.50

    def enrich_metadata(self, raw_payload: str, existing_meta: SourceMetadata) -> SourceMetadata:
        """
        Updates metadata with detected format, vendor, and product if currently unknown.
        """
        fmt, vendor, product, _ = self.detect(raw_payload)
        
        meta = existing_meta.model_copy()
        if meta.detected_format == FormatType.UNKNOWN:
            meta.detected_format = fmt
        if meta.vendor == "unknown":
            meta.vendor = vendor
        if meta.product == "unknown":
            meta.product = product

        return meta
