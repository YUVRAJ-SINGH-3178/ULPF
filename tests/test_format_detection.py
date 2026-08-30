"""
Unit Tests: Format & Source Detection Engine
"""

import pytest

from ulpf.packages.schemas.models import FormatType
from ulpf.services.detection.format_detector import FormatDetector


@pytest.fixture
def detector():
    return FormatDetector()


def test_detect_cef(detector):
    log = "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|allow|1|src=198.51.100.88 dst=10.0.1.50 spt=61234 dpt=80 proto=TCP"
    fmt, vendor, product, conf = detector.detect(log)
    assert fmt == FormatType.CEF
    assert vendor == "Palo Alto Networks"
    assert product == "PAN-OS"
    assert conf >= 0.90


def test_detect_leef(detector):
    log = "LEEF:2.0|Fortinet|FortiGate|6.4.5|0000000015|\tsrc=185.220.101.5\tdst=10.0.0.5\tproto=TCP"
    fmt, vendor, product, conf = detector.detect(log)
    assert fmt == FormatType.LEEF
    assert vendor == "Fortinet"
    assert product == "FortiGate"
    assert conf >= 0.90


def test_detect_cisco_asa(detector):
    log = "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection 9812481 for outside:198.51.100.25/443 to inside:10.0.0.5/54321"
    fmt, vendor, product, conf = detector.detect(log)
    assert fmt == FormatType.SYSLOG_RFC3164
    assert vendor == "Cisco"
    assert product == "ASA"
    assert conf >= 0.90


def test_detect_suricata_json(detector):
    log = '{"timestamp":"2026-08-27T10:15:33+0000","event_type":"alert","src_ip":"185.220.101.5","alert":{"signature":"ET SCAN SSH"}}'
    fmt, vendor, product, conf = detector.detect(log)
    assert fmt == FormatType.JSON
    assert vendor == "Suricata"
    assert product == "EVE-IDS"
    assert conf >= 0.90


def test_detect_zeek_json(detector):
    log = '{"ts":1693131334.5,"uid":"C1234567890","id.orig_h":"192.168.1.105","id.resp_h":"10.0.0.10","proto":"tcp"}'
    fmt, vendor, product, conf = detector.detect(log)
    assert fmt == FormatType.JSON
    assert vendor == "Zeek"
    assert conf >= 0.90


def test_detect_squid_proxy(detector):
    log = "1693131336.120    15 192.168.1.100 TCP_DENIED/403 1420 GET http://malicious.xyz/payload.exe - NONE/- text/html"
    fmt, vendor, product, conf = detector.detect(log)
    assert fmt == FormatType.PROPRIETARY
    assert vendor == "Squid"
    assert conf >= 0.90


def test_detect_unknown_proprietary(detector):
    log = "[APPLIANCE-FW] 2026-08-27T10:15:40Z DEV=EDGE-FW-09 RULE=BLOCK_SSH SRC=185.220.101.5:49152 DST=10.0.0.5:22 PROTO=TCP"
    fmt, vendor, product, conf = detector.detect(log)
    assert fmt in [FormatType.PROPRIETARY, FormatType.UNKNOWN]
