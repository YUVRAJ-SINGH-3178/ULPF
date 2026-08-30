"""
Unit & Integration Tests: Parsers & OCSF 1.1.0 Normalization Engine
Tests Golden Fixtures for Cisco ASA, Palo Alto, Fortinet, Checkpoint, Suricata, Zeek, Squid, CEF, and LEEF.
"""

import pytest

from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.normalization.ocsf_mapper import OCSFNormalizer
from ulpf.services.parser_engine.registry import ParserRegistry


@pytest.fixture
def parser_registry():
    return ParserRegistry(persistence_dir="data/test_parsers")


@pytest.fixture
def normalizer():
    return OCSFNormalizer()


def test_cisco_asa_inbound_connection_mapped_ip_regression(parser_registry, normalizer):
    """
    Regression Test for Confirmed Bug:
    Cisco ASA inbound connection with mapped IP in parentheses must NOT cause
    src_endpoint.ip and dst_endpoint.ip to resolve to the same address.
    """
    log = "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection 9812481 for outside:198.51.100.25/443 (198.51.100.25/443) to inside:10.0.0.5/54321 (10.0.0.5/54321)"
    meta = SourceMetadata(
        vendor="Cisco", product="ASA", detected_format=FormatType.SYSLOG_RFC3164
    )

    parser = parser_registry.find_parser(log, meta)
    assert parser is not None
    assert parser.parser_id == "cisco-asa-firewall-parser"

    parsed_fields, p_meta = parser.parse(log, meta)
    assert len(p_meta.errors) == 0
    assert parsed_fields["src_ip"] == "198.51.100.25"
    assert parsed_fields["src_port"] == 443
    assert parsed_fields["dst_ip"] == "10.0.0.5"
    assert parsed_fields["dst_port"] == 54321
    assert parsed_fields["src_ip"] != parsed_fields["dst_ip"]
    assert parsed_fields["protocol"] == "TCP"
    assert parsed_fields["action"] == "allow"
    assert parsed_fields["disposition"] == "Allowed"

    ocsf = normalizer.normalize(parsed_fields, meta, log, "event-cisco-built-01")
    assert ocsf["class_uid"] == 4001
    assert ocsf["src_endpoint"]["ip"] == "198.51.100.25"
    assert ocsf["src_endpoint"]["port"] == 443
    assert ocsf["dst_endpoint"]["ip"] == "10.0.0.5"
    assert ocsf["dst_endpoint"]["port"] == 54321
    assert ocsf["src_endpoint"]["ip"] != ocsf["dst_endpoint"]["ip"]
    assert ocsf["disposition_id"] == 1


def test_cisco_asa_deny_and_teardown(parser_registry, normalizer):
    deny_log = '<164>Aug 27 10:15:31 fw-edge-01 %ASA-4-106023: Deny tcp src dmz:192.168.1.50/443 dst outside:203.0.113.10/51234 by access-group "OUTSIDE_BLOCK" [0x12345678, 0x0]'
    meta = SourceMetadata(
        vendor="Cisco", product="ASA", detected_format=FormatType.SYSLOG_RFC3164
    )

    parser = parser_registry.find_parser(deny_log, meta)
    parsed_fields, _ = parser.parse(deny_log, meta)
    assert parsed_fields["src_ip"] == "192.168.1.50"
    assert parsed_fields["src_port"] == 443
    assert parsed_fields["dst_ip"] == "203.0.113.10"
    assert parsed_fields["dst_port"] == 51234
    assert parsed_fields["disposition"] == "Blocked"
    assert parsed_fields["disposition_id"] == 2
    assert parsed_fields["rule_name"] == "OUTSIDE_BLOCK"

    ocsf = normalizer.normalize(parsed_fields, meta, deny_log, "event-cisco-deny-01")
    assert ocsf["disposition_id"] == 2
    assert ocsf["severity_id"] == 3  # Medium

    # Teardown sample
    teardown_log = "<166>Aug 27 10:15:33 fw-edge-01 %ASA-6-302014: Teardown TCP connection 9812481 for outside:198.51.100.25/443 to inside:10.0.0.5/54321 duration 0:02:15 bytes 48123 TCP FINs"
    parsed_td, _ = parser.parse(teardown_log, meta)
    assert parsed_td["src_ip"] == "198.51.100.25"
    assert parsed_td["dst_ip"] == "10.0.0.5"
    assert parsed_td["bytes"] == 48123
    assert parsed_td["action"] == "close"


def test_palo_alto_cef_traffic_and_threat(parser_registry, normalizer):
    # Allow traffic
    allow_log = "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|allow|1|src=198.51.100.88 dst=10.0.1.50 spt=61234 dpt=80 proto=TCP act=allow in=1420 out=5820 app=web-browsing cs1=RULE_WEB_PERMIT"
    meta = SourceMetadata(
        vendor="Palo Alto Networks", product="PAN-OS", detected_format=FormatType.CEF
    )

    parser = parser_registry.find_parser(allow_log, meta)
    assert parser is not None
    parsed_allow, _ = parser.parse(allow_log, meta)
    assert parsed_allow["src_ip"] == "198.51.100.88"
    assert parsed_allow["dst_ip"] == "10.0.1.50"
    assert parsed_allow["src_port"] == 61234
    assert parsed_allow["dst_port"] == 80
    assert parsed_allow["bytes_in"] == 1420
    assert parsed_allow["bytes_out"] == 5820
    assert parsed_allow["disposition"] == "Allowed"
    assert parsed_allow["disposition_id"] == 1

    # Threat vulnerability drop
    threat_log = "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|THREAT|vulnerability|8|src=203.0.113.88 dst=10.0.0.10 spt=55123 dpt=5432 proto=TCP act=reset-both app=postgresql cs1=THREAT_SQL_INJECTION"
    parsed_threat, _ = parser.parse(threat_log, meta)
    assert parsed_threat["src_ip"] == "203.0.113.88"
    assert parsed_threat["dst_ip"] == "10.0.0.10"
    assert parsed_threat["disposition"] == "Blocked"
    assert parsed_threat["disposition_id"] == 2
    assert parsed_threat["severity_id"] == 4  # High (8/10)


def test_fortinet_kv_and_leef(parser_registry, normalizer):
    kv_log = 'date=2026-08-27 time=10:15:32 devname="FGT-60D" devid="FGT60D0001" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=192.168.1.100 srcport=54321 dstip=198.51.100.25 dstport=443 proto=6 action="accept" policyid=1 sentbyte=512 rcvdbyte=1024'
    meta = SourceMetadata(
        vendor="Fortinet", product="FortiOS", detected_format=FormatType.SYSLOG_RFC3164
    )

    parser = parser_registry.find_parser(kv_log, meta)
    assert parser is not None
    parsed_kv, _ = parser.parse(kv_log, meta)
    assert parsed_kv["src_ip"] == "192.168.1.100"
    assert parsed_kv["dst_ip"] == "198.51.100.25"
    assert parsed_kv["src_port"] == 54321
    assert parsed_kv["dst_port"] == 443
    assert parsed_kv["protocol"] == "TCP"
    assert parsed_kv["disposition"] == "Allowed"
    assert parsed_kv["bytes_out"] == 512
    assert parsed_kv["bytes_in"] == 1024

    # LEEF Fortinet format
    leef_log = "LEEF:2.0|Fortinet|FortiGate|6.4.5|0000000015|\tsrc=185.220.101.5\tdst=10.0.0.5\tsrcPort=44123\tdstPort=22\tproto=TCP\taction=deny\tpolicyid=12"
    leef_meta = SourceMetadata(
        vendor="Fortinet", product="FortiGate", detected_format=FormatType.LEEF
    )
    leef_parser = parser_registry.find_parser(leef_log, leef_meta)
    assert leef_parser is not None
    parsed_leef, _ = leef_parser.parse(leef_log, leef_meta)
    assert parsed_leef["src_ip"] == "185.220.101.5"
    assert parsed_leef["dst_ip"] == "10.0.0.5"
    assert parsed_leef["src_port"] == 44123
    assert parsed_leef["dst_port"] == 22
    assert parsed_leef["disposition"] == "Blocked"
    assert parsed_leef["disposition_id"] == 2


def test_checkpoint_fw1(parser_registry, normalizer):
    drop_log = "<134>Aug 27 10:15:35 chkp-fw01 CheckPoint: action=drop; src=203.0.113.88; dst=10.0.0.1; proto=tcp; s_port=55123; service=23; rule_name=DROP_TELNET;"
    meta = SourceMetadata(
        vendor="Checkpoint",
        product="Firewall-1",
        detected_format=FormatType.SYSLOG_RFC3164,
    )

    parser = parser_registry.find_parser(drop_log, meta)
    assert parser is not None
    parsed_cp, _ = parser.parse(drop_log, meta)
    assert parsed_cp["src_ip"] == "203.0.113.88"
    assert parsed_cp["dst_ip"] == "10.0.0.1"
    assert parsed_cp["src_port"] == 55123
    assert parsed_cp["dst_port"] == 23
    assert parsed_cp["protocol"] == "TCP"
    assert parsed_cp["disposition"] == "Blocked"
    assert parsed_cp["disposition_id"] == 2
    assert parsed_cp["rule_name"] == "DROP_TELNET"


def test_squid_proxy_access(parser_registry, normalizer):
    denied_log = "1693131336.120    15 192.168.1.100 TCP_DENIED/403 1420 GET http://malicious-domain.xyz/payload.exe - NONE/- text/html"
    meta = SourceMetadata(
        vendor="Squid", product="Proxy", detected_format=FormatType.PROPRIETARY
    )

    parser = parser_registry.find_parser(denied_log, meta)
    assert parser is not None
    parsed_sq, _ = parser.parse(denied_log, meta)
    assert parsed_sq["src_ip"] == "192.168.1.100"
    assert parsed_sq["http_status"] == 403
    assert parsed_sq["disposition"] == "Blocked"
    assert parsed_sq["disposition_id"] == 2
    assert parsed_sq["dst_hostname"] == "malicious-domain.xyz"

    miss_log = "1693131337.350    42 192.168.1.105 TCP_MISS/200 8520 GET http://update.security.org/signatures.dat - DIRECT/198.51.100.25 application/octet-stream"
    parsed_miss, _ = parser.parse(miss_log, meta)
    assert parsed_miss["src_ip"] == "192.168.1.105"
    assert parsed_miss["dst_ip"] == "198.51.100.25"
    assert parsed_miss["http_status"] == 200
    assert parsed_miss["disposition"] == "Allowed"
    assert parsed_miss["disposition_id"] == 1


def test_zeek_conn_telemetry(parser_registry, normalizer):
    conn_log = '{"ts":1693131334.5,"uid":"C1234567890","id.orig_h":"192.168.1.105","id.orig_p":49152,"id.resp_h":"10.0.0.10","id.resp_p":5432,"proto":"tcp","service":"postgresql","duration":0.045,"orig_bytes":1024,"resp_bytes":4096,"conn_state":"SF"}'
    meta = SourceMetadata(
        vendor="Zeek", product="Network-Monitor", detected_format=FormatType.JSON
    )

    parser = parser_registry.find_parser(conn_log, meta)
    assert parser is not None
    parsed_zk, _ = parser.parse(conn_log, meta)
    assert parsed_zk["src_ip"] == "192.168.1.105"
    assert parsed_zk["dst_ip"] == "10.0.0.10"
    assert parsed_zk["src_port"] == 49152
    assert parsed_zk["dst_port"] == 5432
    assert parsed_zk["protocol"] == "TCP"
    assert parsed_zk["app_name"] == "postgresql"
    assert parsed_zk["disposition"] == "Allowed"
    assert parsed_zk["disposition_id"] == 1


def test_suricata_eve_alert_and_http(parser_registry, normalizer):
    alert_log = '{"timestamp":"2026-08-27T10:15:33.123456+0000","flow_id":87654321,"event_type":"alert","src_ip":"185.220.101.5","src_port":44123,"dest_ip":"10.0.0.5","dest_port":22,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2001219,"rev":1,"signature":"ET SCAN Potential SSH Brute Force Detected","category":"Attempted Information Leak","severity":1}}'
    meta = SourceMetadata(
        vendor="Suricata", product="EVE-IDS", detected_format=FormatType.JSON
    )

    parser = parser_registry.find_parser(alert_log, meta)
    assert parser is not None
    parsed_alert, _ = parser.parse(alert_log, meta)
    assert parsed_alert["target_class_uid"] == 2001
    assert parsed_alert["src_ip"] == "185.220.101.5"
    assert parsed_alert["dst_ip"] == "10.0.0.5"
    assert parsed_alert["src_port"] == 44123
    assert parsed_alert["dst_port"] == 22
    assert parsed_alert["disposition"] == "Blocked"
    assert parsed_alert["disposition_id"] == 2

    http_log = '{"timestamp":"2026-08-27T10:15:34.654321+0000","flow_id":87654322,"event_type":"http","src_ip":"192.168.1.105","src_port":51234,"dest_ip":"10.0.1.50","dest_port":80,"proto":"TCP","http":{"hostname":"internal.ntro.gov.in","url":"/api/v1/telemetry","http_method":"GET","status":200}}'
    parsed_http, _ = parser.parse(http_log, meta)
    assert parsed_http["target_class_uid"] == 4001
    assert parsed_http["src_ip"] == "192.168.1.105"
    assert parsed_http["dst_ip"] == "10.0.1.50"
    assert parsed_http["dst_hostname"] == "internal.ntro.gov.in"
    assert parsed_http["http_status"] == 200


def test_unmapped_fields_preservation(normalizer):
    """Asserts that custom vendor attributes are preserved in unmapped without data loss."""
    parsed_fields = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": "TCP",
        "vendor_proprietary_tag_x": "CRITICAL_SESSION_VAL",
        "custom_asic_counter": 98124,
    }
    meta = SourceMetadata(vendor="CustomVendor", product="CustomAppliance")
    ocsf = normalizer.normalize(parsed_fields, meta, "raw text", "event-test-unmap")

    assert "unmapped" in ocsf
    assert ocsf["unmapped"]["vendor_proprietary_tag_x"] == "CRITICAL_SESSION_VAL"
    assert ocsf["unmapped"]["custom_asic_counter"] == 98124
