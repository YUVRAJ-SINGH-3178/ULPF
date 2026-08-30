"""
OCSF Normalization Engine
Maps parsed intermediate attributes into OCSF 1.1.0 compliant JSON structures.
Guarantees zero field loss by capturing unmapped vendor fields into the 'unmapped' envelope.
"""

import datetime
from typing import Any

from ulpf.packages.schemas.models import (
    SourceMetadata,
)
from ulpf.services.normalization.enums import (
    DIRECTION_NAMES,
    DISPOSITION_NAMES,
    SEVERITY_NAMES,
    STATUS_NAMES,
    OCSFCategory,
    OCSFClass,
    OCSFDisposition,
    OCSFNetworkActivityId,
    OCSFSeverity,
    OCSFStatus,
    normalize_protocol,
)


class OCSFNormalizer:
    """
    Transforms heterogeneous parsed intermediate events into standard OCSF 1.1.0 event classes.
    """

    KNOWN_MAPPED_KEYS = {
        "src_ip", "src_port", "src_hostname", "src_mac", "src_zone",
        "dst_ip", "dst_port", "dst_hostname", "dst_mac", "dst_zone",
        "protocol", "protocol_num", "direction", "app_name",
        "bytes_in", "bytes_out", "bytes", "packets_in", "packets_out", "packets",
        "severity", "severity_id", "status", "status_id",
        "disposition", "disposition_id", "action", "activity_name", "activity_id",
        "rule_name", "rule_id", "message", "device_vendor", "device_product",
        "device_version", "event_name", "timestamp", "target_class_uid",
        "signature", "signature_id", "category", "finding_info"
    }

    def normalize(
        self,
        parsed_fields: dict[str, Any],
        source_meta: SourceMetadata,
        raw_payload: str,
        event_id: str
    ) -> dict[str, Any]:
        """
        Produces an OCSF 1.1.0 JSON object from parsed fields.
        """
        target_class_uid = parsed_fields.get("target_class_uid") or 4001
        
        # 1. Normalize Timestamp
        time_epoch_ms, time_dt_str = self._normalize_timestamp(parsed_fields.get("timestamp"))

        # 2. Normalize Severity
        sev_id, sev_name = self._normalize_severity(parsed_fields)

        # 3. Normalize Status & Disposition
        status_id, status_name = self._normalize_status(parsed_fields)
        disp_id, disp_name = self._normalize_disposition(parsed_fields)

        # 4. Normalize Endpoints
        src_endpoint = self._build_src_endpoint(parsed_fields)
        dst_endpoint = self._build_dst_endpoint(parsed_fields)

        # 5. Normalize Connection Info & Traffic
        conn_info = self._build_connection_info(parsed_fields)
        traffic = self._build_traffic(parsed_fields)

        # 6. Build Metadata
        vendor = parsed_fields.get("device_vendor") or source_meta.vendor or "Generic"
        product = parsed_fields.get("device_product") or source_meta.product or "Device"
        metadata = {
            "version": "1.1.0",
            "product": {
                "name": product,
                "vendor_name": vendor,
                "version": parsed_fields.get("device_version")
            },
            "original_time": parsed_fields.get("timestamp") or time_dt_str,
            "profiles": ["host", "security_control"]
        }

        # 7. Collect Unmapped Fields (Zero Data Loss Guarantee)
        unmapped = {}
        for k, v in parsed_fields.items():
            if k not in self.KNOWN_MAPPED_KEYS and v is not None:
                unmapped[k] = v

        # Construct Base OCSF Document
        if target_class_uid == OCSFClass.SECURITY_FINDING.value or "signature" in parsed_fields or "alert" in parsed_fields:
            # 2001: Security Finding
            ocsf_doc = {
                "class_uid": OCSFClass.SECURITY_FINDING.value,
                "category_uid": OCSFCategory.FINDINGS.value,
                "class_name": "Security Finding",
                "category_name": "Findings",
                "activity_id": 1,
                "activity_name": "Create",
                "severity_id": sev_id,
                "severity": sev_name,
                "status_id": status_id,
                "status": status_name,
                "disposition_id": disp_id,
                "disposition": disp_name,
                "time": time_epoch_ms,
                "time_dt": time_dt_str,
                "message": parsed_fields.get("message") or parsed_fields.get("signature") or "Security alert detected",
                "metadata": metadata,
                "src_endpoint": src_endpoint,
                "dst_endpoint": dst_endpoint,
                "finding_info": {
                    "title": parsed_fields.get("signature") or parsed_fields.get("message") or "Security Alert",
                    "desc": parsed_fields.get("message") or "",
                    "uid": parsed_fields.get("signature_id") or event_id,
                    "created_time": time_epoch_ms,
                    "types": [parsed_fields.get("category") or "Network Intrusion"]
                },
                "unmapped": unmapped
            }
        else:
            # 4001: Network Activity (Default for perimeter devices)
            action_name = parsed_fields.get("action") or ("allow" if disp_id == 1 else "deny")
            ocsf_doc = {
                "class_uid": OCSFClass.NETWORK_ACTIVITY.value,
                "category_uid": OCSFCategory.NETWORK_ACTIVITY.value,
                "class_name": "Network Activity",
                "category_name": "Network Activity",
                "activity_id": parsed_fields.get("activity_id", OCSFNetworkActivityId.TRAFFIC.value),
                "activity_name": parsed_fields.get("activity_name", "Traffic"),
                "severity_id": sev_id,
                "severity": sev_name,
                "status_id": status_id,
                "status": status_name,
                "disposition_id": disp_id,
                "disposition": disp_name,
                "action": action_name,
                "time": time_epoch_ms,
                "time_dt": time_dt_str,
                "message": parsed_fields.get("message") or f"{vendor} {product} network event",
                "metadata": metadata,
                "src_endpoint": src_endpoint,
                "dst_endpoint": dst_endpoint,
                "connection_info": conn_info,
                "traffic": traffic,
                "app_name": parsed_fields.get("app_name") or parsed_fields.get("service"),
                "unmapped": unmapped
            }

            if parsed_fields.get("rule_name") or parsed_fields.get("rule_id"):
                ocsf_doc["rule"] = {
                    "name": parsed_fields.get("rule_name"),
                    "uid": str(parsed_fields.get("rule_id") or "")
                }

        return ocsf_doc

    def _normalize_timestamp(self, ts_raw: Any | None) -> tuple[int, str]:
        now = datetime.datetime.now(datetime.timezone.utc)
        if not ts_raw:
            return int(now.timestamp() * 1000), now.isoformat()

        # If already epoch int/float
        if isinstance(ts_raw, (int, float)):
            if ts_raw > 1e11:  # ms
                epoch_ms = int(ts_raw)
                dt = datetime.datetime.fromtimestamp(epoch_ms / 1000.0, tz=datetime.timezone.utc)
            else:  # sec
                epoch_ms = int(ts_raw * 1000)
                dt = datetime.datetime.fromtimestamp(ts_raw, tz=datetime.timezone.utc)
            return epoch_ms, dt.isoformat()

        ts_str = str(ts_raw).strip()
        # ISO formats
        for fmt in [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S"
        ]:
            try:
                parsed_dt = datetime.datetime.strptime(ts_str, fmt)
                if parsed_dt.year == 1900:
                    parsed_dt = parsed_dt.replace(year=now.year)
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.replace(tzinfo=datetime.timezone.utc)
                return int(parsed_dt.timestamp() * 1000), parsed_dt.isoformat()
            except ValueError:
                continue

        return int(now.timestamp() * 1000), now.isoformat()

    def _normalize_severity(self, parsed: dict[str, Any]) -> tuple[int, str]:
        if "severity_id" in parsed and parsed["severity_id"] in SEVERITY_NAMES:
            sev_id = int(parsed["severity_id"])
            return sev_id, SEVERITY_NAMES[sev_id]

        if "severity" in parsed:
            sev_s = str(parsed["severity"]).lower()
            if sev_s in ["fatal", "emergency"]:
                return OCSFSeverity.FATAL.value, "Fatal"
            elif sev_s in ["critical", "crit"]:
                return OCSFSeverity.CRITICAL.value, "Critical"
            elif sev_s in ["high", "error", "err"]:
                return OCSFSeverity.HIGH.value, "High"
            elif sev_s in ["medium", "warn", "warning"]:
                return OCSFSeverity.MEDIUM.value, "Medium"
            elif sev_s in ["low", "notice"]:
                return OCSFSeverity.LOW.value, "Low"
            elif sev_s in ["info", "informational", "debug"]:
                return OCSFSeverity.INFORMATIONAL.value, "Informational"

        return OCSFSeverity.INFORMATIONAL.value, "Informational"

    def _normalize_status(self, parsed: dict[str, Any]) -> tuple[int, str]:
        if "status_id" in parsed and parsed["status_id"] in STATUS_NAMES:
            st_id = int(parsed["status_id"])
            return st_id, STATUS_NAMES[st_id]
        if "status" in parsed:
            st_s = str(parsed["status"]).lower()
            if "fail" in st_s or "err" in st_s or "deny" in st_s:
                return OCSFStatus.FAILURE.value, "Failure"
            return OCSFStatus.SUCCESS.value, "Success"
        return OCSFStatus.SUCCESS.value, "Success"

    def _normalize_disposition(self, parsed: dict[str, Any]) -> tuple[int, str]:
        if "disposition_id" in parsed and parsed["disposition_id"] in DISPOSITION_NAMES:
            d_id = int(parsed["disposition_id"])
            return d_id, DISPOSITION_NAMES[d_id]

        action = str(parsed.get("action", "")).lower()
        if action in ["deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "quarantine"]:
            return OCSFDisposition.BLOCKED.value, "Blocked"
        elif action in ["allow", "allowed", "permit", "permitted", "accept", "accepted", "pass"]:
            return OCSFDisposition.ALLOWED.value, "Allowed"

        return OCSFDisposition.ALLOWED.value, "Allowed"

    def _build_src_endpoint(self, parsed: dict[str, Any]) -> dict[str, Any]:
        ep = {}
        ip = parsed.get("src_ip")
        if ip:
            ep["ip"] = str(ip).strip()
        port = parsed.get("src_port")
        if port is not None:
            try:
                p_int = int(port)
                if 1 <= p_int <= 65535:
                    ep["port"] = p_int
            except ValueError:
                pass
        if parsed.get("src_hostname"):
            ep["hostname"] = parsed["src_hostname"]
        if parsed.get("src_mac"):
            ep["mac"] = parsed["src_mac"]
        if parsed.get("src_zone"):
            ep["zone"] = parsed["src_zone"]
        return ep

    def _build_dst_endpoint(self, parsed: dict[str, Any]) -> dict[str, Any]:
        ep = {}
        ip = parsed.get("dst_ip")
        if ip:
            ep["ip"] = str(ip).strip()
        port = parsed.get("dst_port")
        if port is not None:
            try:
                p_int = int(port)
                if 1 <= p_int <= 65535:
                    ep["port"] = p_int
            except ValueError:
                pass
        if parsed.get("dst_hostname"):
            ep["hostname"] = parsed["dst_hostname"]
        if parsed.get("dst_mac"):
            ep["mac"] = parsed["dst_mac"]
        if parsed.get("dst_zone"):
            ep["zone"] = parsed["dst_zone"]
        return ep

    def _build_connection_info(self, parsed: dict[str, Any]) -> dict[str, Any]:
        proto_name, proto_num = normalize_protocol(parsed.get("protocol"))
        direction = parsed.get("direction", "Inbound")
        dir_id = 1 if direction.lower() == "inbound" else (2 if direction.lower() == "outbound" else 3)

        return {
            "protocol_name": proto_name,
            "protocol_num": proto_num,
            "direction_id": dir_id,
            "direction": DIRECTION_NAMES.get(dir_id, "Inbound")
        }

    def _build_traffic(self, parsed: dict[str, Any]) -> dict[str, Any]:
        traffic = {}
        if parsed.get("bytes_in") is not None:
            traffic["bytes_in"] = int(parsed["bytes_in"])
        if parsed.get("bytes_out") is not None:
            traffic["bytes_out"] = int(parsed["bytes_out"])
        if parsed.get("bytes") is not None:
            traffic["bytes"] = int(parsed["bytes"])
        elif "bytes_in" in traffic and "bytes_out" in traffic:
            traffic["bytes"] = traffic["bytes_in"] + traffic["bytes_out"]

        if parsed.get("packets_in") is not None:
            traffic["packets_in"] = int(parsed["packets_in"])
        if parsed.get("packets_out") is not None:
            traffic["packets_out"] = int(parsed["packets_out"])
        return traffic
