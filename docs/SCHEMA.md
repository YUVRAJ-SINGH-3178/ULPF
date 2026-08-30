# ULPF OCSF 1.1.0 Schema Specification & Mapping Guide
**Open Cybersecurity Schema Framework (OCSF 1.1.0) Integration**

---

## 1. Schema Selection Rationale

Rather than inventing a proprietary taxonomy, ULPF strictly targets **OCSF 1.1.0** (Open Cybersecurity Schema Framework), supported by the Linux Foundation, AWS, Splunk, and Broadcom.

OCSF defines standard event categories, class IDs, required fields, and controlled enumerations purpose-built for cybersecurity telemetry.

---

## 2. Core OCSF Classes in ULPF

### Class 4001: Network Activity
- **Category UID**: `4` (Network Activity)
- **Class UID**: `4001` (Network Activity)
- **Use Case**: Firewalls (Cisco ASA, Palo Alto, Fortinet, Checkpoint), Routers, Proxies (Squid), and Network Monitors (Zeek).
- **Core Attributes**:
  ```json
  {
    "class_uid": 4001,
    "category_uid": 4,
    "class_name": "Network Activity",
    "category_name": "Network Activity",
    "activity_id": 6,
    "activity_name": "Traffic",
    "severity_id": 1,
    "severity": "Informational",
    "status_id": 1,
    "status": "Success",
    "disposition_id": 1,
    "disposition": "Allowed",
    "action": "allow",
    "time": 1756289730000,
    "time_dt": "2026-08-27T10:15:30Z",
    "message": "Cisco ASA built TCP connection",
    "metadata": {
      "version": "1.1.0",
      "product": {
        "name": "ASA",
        "vendor_name": "Cisco",
        "version": "9.16"
      },
      "original_time": "Aug 27 10:15:30"
    },
    "src_endpoint": {
      "ip": "198.51.100.25",
      "port": 443,
      "hostname": "WEB-SRV-01",
      "zone": "outside"
    },
    "dst_endpoint": {
      "ip": "10.0.0.5",
      "port": 54321,
      "hostname": "DC-PRIMARY-01",
      "zone": "inside"
    },
    "connection_info": {
      "protocol_name": "TCP",
      "protocol_num": 6,
      "direction_id": 1,
      "direction": "Inbound"
    },
    "traffic": {
      "bytes_in": 1420,
      "bytes_out": 5820,
      "bytes": 7240
    },
    "app_name": "HTTPS",
    "unmapped": {
      "cisco_message_id": "302013",
      "connection_id": "9812481"
    }
  }
  ```

### Class 2001: Security Finding
- **Category UID**: `2` (Findings)
- **Class UID**: `2001` (Security Finding)
- **Use Case**: IDS/IPS Alerts (Suricata, Snort, Palo Alto Threat Prevention).
- **Core Attributes**:
  - `finding_info.title`, `finding_info.uid`, `finding_info.types`
  - `attacks` / `signatures`
  - `severity_id`: `4` (High), `5` (Critical)
  - `disposition_id`: `2` (Blocked)

---

## 3. Controlled Enumerations

### `severity_id` (OCSF Standard)
| ID | Caption | Description |
| :--- | :--- | :--- |
| `0` | Unknown | Severity unknown or unrecorded |
| `1` | Informational | Informational event (normal network traffic) |
| `2` | Low | Minor policy alert or notice |
| `3` | Medium | Warning or minor access denial |
| `4` | High | High-risk attack or exploit attempt |
| `5` | Critical | Severe compromise or active intrusion |
| `6` | Fatal | Catastrophic device/system failure |
| `99` | Other | Non-standard severity |

### `disposition_id` (OCSF Standard)
| ID | Caption | Description |
| :--- | :--- | :--- |
| `0` | Unknown | Action unknown |
| `1` | Allowed | Traffic was permitted / passed through |
| `2` | Blocked | Traffic was actively denied / dropped / reset |
| `3` | Denied | Policy explicit deny |
| `4` | Quarantined | Endpoint or packet placed in quarantine |
| `5` | Isolated | Endpoint isolated |
| `6` | Dropped | Silent packet drop |
| `7` | Reset | TCP RST sent to client/server |

---

## 4. Zero Data Loss Guarantee (`unmapped`)

Whenever a vendor log contains proprietary fields not directly represented in standard OCSF top-level attributes (e.g. `policy_uuid`, `asic_drop_counter`, `threat_id`, `nat_translation_pool`), ULPF preserves them in the `unmapped` dictionary. **No telemetry is ever discarded.**
