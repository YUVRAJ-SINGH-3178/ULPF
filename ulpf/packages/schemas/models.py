"""
ULPF Core Data Models & Schemas
Implements OCSF 1.1.0 schemas, Raw Event Envelopes, Parser Definitions, and Verification types.
"""

from enum import Enum
from typing import Dict, Any, Optional, List, Union
from pydantic import BaseModel, Field
import datetime
import uuid


class FormatType(str, Enum):
    SYSLOG_RFC3164 = "syslog_rfc3164"
    SYSLOG_RFC5424 = "syslog_rfc5424"
    CEF = "cef"
    LEEF = "leef"
    JSON = "json"
    CSV = "csv"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


class ParserStatus(str, Enum):
    DRAFT = "DRAFT"
    TESTING = "TESTING"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"


class OnboardingStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    PUBLISHED = "PUBLISHED"


class SeverityId(int, Enum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6
    OTHER = 99


class DispositionId(int, Enum):
    UNKNOWN = 0
    ALLOWED = 1
    BLOCKED = 2
    DENIED = 3
    QUARANTINED = 4
    ISOLATED = 5
    DROPPED = 6
    RESET = 7
    OTHER = 99


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    ANALYST = "ANALYST"
    REVIEWER = "REVIEWER"


# Source Metadata
class SourceMetadata(BaseModel):
    vendor: str = "unknown"
    product: str = "unknown"
    detected_format: FormatType = FormatType.UNKNOWN
    collector_host: str = "ulpf-node-01"
    client_ip: Optional[str] = None
    transport: str = "api"  # udp, tcp, file, api
    facility: Optional[int] = None
    priority: Optional[int] = None


# Raw Storage Info
class RawStorageRef(BaseModel):
    bucket: str = "ulpf-raw-events"
    object_key: str
    sha256: str
    byte_length: int
    raw_payload: str
    compression: str = "none"


# Parsing Metadata
class ParsingMetadata(BaseModel):
    parser_used: Optional[str] = None
    parser_version: Optional[str] = None
    mapping_version: Optional[str] = "1.0.0"
    template_id: Optional[int] = None
    confidence: float = 1.0
    parse_duration_ms: float = 0.0
    unparsed_fields: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)


# OCSF Sub-objects
class OCSFEndpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    mac: Optional[str] = None
    domain: Optional[str] = None
    autonomous_system: Optional[Dict[str, Any]] = None
    location: Optional[Dict[str, Any]] = None
    zone: Optional[str] = None


class OCSFConnectionInfo(BaseModel):
    protocol_name: Optional[str] = "TCP"
    protocol_num: Optional[int] = 6
    direction_id: Optional[int] = 1  # 1: Inbound, 2: Outbound, 3: Lateral
    direction: Optional[str] = "Inbound"
    tcp_flags: Optional[int] = None
    boundary: Optional[str] = None


class OCSFTraffic(BaseModel):
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    bytes: Optional[int] = None
    packets_in: Optional[int] = None
    packets_out: Optional[int] = None
    packets: Optional[int] = None


class OCSFMetadataProduct(BaseModel):
    name: str
    vendor_name: str
    version: Optional[str] = None
    feature: Optional[Dict[str, Any]] = None


class OCSFMetadata(BaseModel):
    version: str = "1.1.0"
    product: OCSFMetadataProduct
    original_time: Optional[str] = None
    profiles: List[str] = Field(default_factory=list)
    labels: List[str] = Field(default_factory=list)


# OCSF Base Event
class OCSFEventBase(BaseModel):
    class_uid: int
    category_uid: int
    class_name: str
    category_name: str
    activity_id: int = 1
    activity_name: Optional[str] = None
    severity_id: int = SeverityId.INFORMATIONAL.value
    severity: str = "Informational"
    status_id: int = 1  # 1: Success, 2: Failure, 99: Other
    status: str = "Success"
    disposition_id: Optional[int] = DispositionId.ALLOWED.value
    disposition: Optional[str] = "Allowed"
    time: int = Field(default_factory=lambda: int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000))
    time_dt: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    message: Optional[str] = None
    metadata: OCSFMetadata
    raw_data: Optional[str] = None
    unmapped: Dict[str, Any] = Field(default_factory=dict)


# OCSF 4001: Network Activity
class OCSFNetworkActivity(OCSFEventBase):
    class_uid: int = 4001
    category_uid: int = 4
    class_name: str = "Network Activity"
    category_name: str = "Network Activity"
    src_endpoint: Optional[OCSFEndpoint] = None
    dst_endpoint: Optional[OCSFEndpoint] = None
    connection_info: Optional[OCSFConnectionInfo] = None
    traffic: Optional[OCSFTraffic] = None
    app_name: Optional[str] = None
    action_id: Optional[int] = None
    action: Optional[str] = None
    rule: Optional[Dict[str, Any]] = None


# OCSF 2001: Security Finding
class OCSFSecurityFinding(OCSFEventBase):
    class_uid: int = 2001
    category_uid: int = 2
    class_name: str = "Security Finding"
    category_name: str = "Findings"
    finding_info: Dict[str, Any] = Field(default_factory=dict)
    src_endpoint: Optional[OCSFEndpoint] = None
    dst_endpoint: Optional[OCSFEndpoint] = None
    attacks: Optional[List[Dict[str, Any]]] = None
    confidence_id: Optional[int] = None
    confidence: Optional[str] = None


# The Universal Normalized Event Envelope
class EventEnvelope(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ingest_timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    source: SourceMetadata = Field(default_factory=SourceMetadata)
    raw: RawStorageRef
    parsing: ParsingMetadata = Field(default_factory=ParsingMetadata)
    ocsf: Optional[Dict[str, Any]] = None
    traceability: Dict[str, Any] = Field(default_factory=dict)


# Parser Definition Schema
class ParserRule(BaseModel):
    field_name: str
    target_ocsf_field: str
    transform: Optional[str] = None  # to_int, to_ip, to_lower, map_severity, etc.
    default_value: Optional[Any] = None


class ParserDefinition(BaseModel):
    parser_id: str
    vendor: str
    product: str
    format: FormatType
    version: str = "1.0.0"
    parser_type: str = "regex"  # regex, grok, kv, json, drain3_template
    pattern: Optional[str] = None
    rules: List[ParserRule] = Field(default_factory=list)
    target_class: str = "Network Activity"
    target_class_uid: int = 4001
    status: ParserStatus = ParserStatus.ACTIVE
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    author: str = "system"
    sample_raw: Optional[str] = None


# Drain3 Onboarding Models
class TemplateVariable(BaseModel):
    var_index: int
    placeholder: str  # e.g., <IP_1>, <NUM_2>, <STR_3>
    sample_values: List[str] = Field(default_factory=list)
    inferred_type: str = "string"  # ipv4, ipv6, port, timestamp, integer, float, action, severity, string
    suggested_ocsf_field: str = "unmapped"
    confidence: float = 0.8


class OnboardingSession(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor: str
    product: str
    format: FormatType = FormatType.PROPRIETARY
    discovered_template: str
    template_id: int
    raw_sample_logs: List[str] = Field(default_factory=list)
    variables: List[TemplateVariable] = Field(default_factory=list)
    target_class: str = "Network Activity"
    target_class_uid: int = 4001
    status: OnboardingStatus = OnboardingStatus.PENDING
    confidence_score: float = 0.85
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    published_parser_id: Optional[str] = None
    published_version: Optional[str] = None


# Integrity Verification Model
class VerificationResult(BaseModel):
    event_id: str
    is_valid: bool
    stored_sha256: str
    computed_sha256: str
    byte_length: int
    tampered: bool
    checked_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    details: str


# Audit Log Model
class AuditRecord(BaseModel):
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    user: str
    role: str
    action: str  # e.g. "PARSER_PUBLISHED", "ONBOARDING_APPROVED", "REPLAY_TRIGGERED"
    resource_type: str
    resource_id: str
    details: Dict[str, Any] = Field(default_factory=dict)
