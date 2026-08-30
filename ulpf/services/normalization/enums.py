"""
OCSF 1.1.0 Controlled Enumerations & Type Constants
Compliant with Linux Foundation / Open Cybersecurity Schema Framework (OCSF 1.1.0).
"""

from enum import IntEnum


class OCSFCategory(IntEnum):
    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IDENTITY_ACCESS = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5
    APPLICATION_ACTIVITY = 6


class OCSFClass(IntEnum):
    SECURITY_FINDING = 2001
    AUTHENTICATION = 3001
    ACCOUNT_CHANGE = 3002
    NETWORK_ACTIVITY = 4001
    HTTP_ACTIVITY = 4002
    DNS_ACTIVITY = 4003
    DHCP_ACTIVITY = 4004
    RDP_ACTIVITY = 4005
    SMB_ACTIVITY = 4006
    SSH_ACTIVITY = 4007
    FTP_ACTIVITY = 4008
    EMAIL_ACTIVITY = 4009
    API_ACTIVITY = 6001


class OCSFSeverity(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6
    OTHER = 99


class OCSFStatus(IntEnum):
    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2
    OTHER = 99


class OCSFDisposition(IntEnum):
    UNKNOWN = 0
    ALLOWED = 1
    BLOCKED = 2
    DENIED = 3
    QUARANTINED = 4
    ISOLATED = 5
    DROPPED = 6
    RESET = 7
    OTHER = 99


class OCSFDirection(IntEnum):
    UNKNOWN = 0
    INBOUND = 1
    OUTBOUND = 2
    LATERAL = 3
    OTHER = 99


class OCSFNetworkActivityId(IntEnum):
    UNKNOWN = 0
    OPEN = 1
    CLOSE = 2
    RESET = 3
    FAIL = 4
    REFUSE = 5
    TRAFFIC = 6
    LISTEN = 7
    OTHER = 99


# Helper lookup dictionaries
SEVERITY_NAMES: dict[int, str] = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
    99: "Other"
}

DISPOSITION_NAMES: dict[int, str] = {
    0: "Unknown",
    1: "Allowed",
    2: "Blocked",
    3: "Denied",
    4: "Quarantined",
    5: "Isolated",
    6: "Dropped",
    7: "Reset",
    99: "Other"
}

STATUS_NAMES: dict[int, str] = {
    0: "Unknown",
    1: "Success",
    2: "Failure",
    99: "Other"
}

DIRECTION_NAMES: dict[int, str] = {
    0: "Unknown",
    1: "Inbound",
    2: "Outbound",
    3: "Lateral",
    99: "Other"
}

PROTOCOL_NUMBERS: dict[str, int] = {
    "HOPOPT": 0,
    "ICMP": 1,
    "IGMP": 2,
    "GGP": 3,
    "IP-IN-IP": 4,
    "ST": 5,
    "TCP": 6,
    "CBT": 7,
    "EGP": 8,
    "IGP": 9,
    "UDP": 17,
    "GRE": 47,
    "ESP": 50,
    "AH": 51,
    "ICMPV6": 58,
    "OSPF": 89,
    "SCTP": 132
}


def normalize_protocol(proto: str | None) -> tuple[str, int]:
    """Resolves protocol name and number."""
    if not proto:
        return "TCP", 6
    p_str = str(proto).upper().strip()
    if p_str.isdigit():
        p_num = int(p_str)
        # Reverse lookup
        for name, num in PROTOCOL_NUMBERS.items():
            if num == p_num:
                return name, p_num
        return f"PROTO-{p_num}", p_num
    
    p_num = PROTOCOL_NUMBERS.get(p_str, 6)
    return p_str, p_num
