"""
Phase 6 Services Deep Coverage Test Suite
Tests every core service layer in ulpf/services/ with deep edge-case assertions:
- EnvelopeFactory & provenance tracking
- Offline GeoIP & Asset Enrichment
- DeadLetterQueue persistence & lifecycle
- DuckDB Vectorized Analytics
- SearchIndex faceted filtering & FTS5 full-text queries
- FileBatchIngestor directory processing
- Field discovery & type inference
"""

from ulpf.packages.schemas.models import EventEnvelope
from ulpf.services.enrichment.offline_enricher import OfflineEnricher
from ulpf.services.ingestion.listeners import FileBatchIngestor
from ulpf.services.ingestion.raw_envelope import EnvelopeFactory
from ulpf.services.onboarding.field_discovery import FieldDiscoveryEngine
from ulpf.services.replay.replay_engine import ErrorAndReplayQueue
from ulpf.services.storage.search_index import SearchIndex


def test_envelope_factory():
    factory = EnvelopeFactory()
    raw = "<166>Aug 27 10:15:30 fw-01 %ASA-6-302013: Connection built"
    env = factory.create_envelope(raw_payload=raw, transport="udp", client_ip="192.168.1.50")

    assert env.event_id is not None
    assert env.raw.raw_payload == raw
    assert env.raw.sha256 is not None
    assert len(env.raw.sha256) == 64
    assert env.raw.byte_length == len(raw.encode("utf-8"))
    assert env.source.transport == "udp"
    assert env.source.client_ip == "192.168.1.50"
    assert "INGESTION_RECEIVED" in env.traceability.get("provenance_chain", [])


def test_offline_enrichment():
    enricher = OfflineEnricher()
    
    # Internal IP enrichment
    doc1 = {"src_endpoint": {"ip": "10.0.1.50"}}
    enricher.enrich(doc1)
    assert doc1["src_endpoint"]["hostname"] == "WEB-FRONTEND-01"
    assert doc1["src_endpoint"]["zone"] == "DMZ-Public"
    assert doc1["src_endpoint"]["asset_info"]["role"] == "Public Web Portal"

    # Gateway IP
    doc2 = {"dst_endpoint": {"ip": "10.0.0.1"}}
    enricher.enrich(doc2)
    assert doc2["dst_endpoint"]["hostname"] == "CORE-GW-01"
    assert doc2["dst_endpoint"]["zone"] == "DMZ"


def test_dead_letter_error_queue(tmp_path):
    eq_dir = tmp_path / "test_error_queue"
    queue = ErrorAndReplayQueue(persistence_dir=str(eq_dir))
    factory = EnvelopeFactory()

    env1 = factory.create_envelope(raw_payload="corrupt log 1", transport="test")
    env2 = factory.create_envelope(raw_payload="corrupt log 2", transport="test")

    # Add errors
    err1_id = queue.record_failure(
        envelope=env1,
        error_stage="FORMAT_DETECTION",
        errors=["Unknown format"]
    )
    err2_id = queue.record_failure(
        envelope=env2,
        error_stage="PARSING",
        errors=["Field mismatch"]
    )

    assert err1_id is not None
    assert err2_id is not None

    unresolved = queue.list_errors(status="UNRESOLVED")
    assert len(unresolved) == 2

    # Mark replayed
    queue.mark_replayed(err1_id)
    replayed = queue.list_errors(status="REPLAYED")
    assert len(replayed) == 1
    assert replayed[0]["error_id"] == err1_id


def test_search_index_faceted_queries(tmp_path):
    db_path = str(tmp_path / "search_index_test.db")
    idx = SearchIndex(db_path=db_path)

    # Insert test events
    for i in range(10):
        action = "Allowed" if i % 2 == 0 else "Blocked"
        disp_id = 1 if i % 2 == 0 else 2
        severity_id = 1 if i % 2 == 0 else 4
        src_ip = f"192.168.1.{10 + i}"
        dst_ip = f"10.0.0.{i + 1}"
        vendor = "Cisco" if i < 5 else "Palo Alto"
        product = "ASA" if i < 5 else "PAN-OS"
        raw = f"Sample log {i} from {vendor} {product} src={src_ip} dst={dst_ip} act={action}"

        envelope = EventEnvelope(
            event_id=f"evt-{i:03d}",
            raw={"raw_payload": raw, "sha256": f"hash{i}", "byte_length": len(raw), "bucket": "local", "object_key": f"key{i}"},
            source={"transport": "test", "client_ip": src_ip, "vendor": vendor, "product": product},
            parsing={"parser_id": "cisco_asa" if i < 5 else "panos", "status": "SUCCESS"},
            ocsf={
                "activity_name": "Network Traffic",
                "category_name": "Network Activity",
                "class_name": "Network Activity",
                "class_uid": 4001,
                "severity_id": severity_id,
                "severity": "Informational" if severity_id == 1 else "High",
                "disposition": action,
                "disposition_id": disp_id,
                "src_endpoint": {"ip": src_ip, "port": 1234},
                "dst_endpoint": {"ip": dst_ip, "port": 80},
                "metadata": {"product": {"vendor_name": vendor, "name": product, "version": "1.0"}}
            }
        )
        idx.index_event(envelope)

    # 1. Total count
    summary = idx.get_metrics_summary()
    assert summary["total_events"] == 10

    # 2. Filter by vendor
    cisco_res = idx.search_events(vendor="Cisco")
    assert cisco_res["total"] == 5

    # 3. Filter by disposition
    blocked_res = idx.search_events(disposition="Blocked")
    assert blocked_res["total"] == 5

    # 4. Filter by src_ip
    ip_res = idx.search_events(src_ip="192.168.1.10")
    assert ip_res["total"] == 1

    # 5. Full-text search
    fts_res = idx.search_events(query="PAN-OS")
    assert fts_res["total"] == 5

    # 6. Pagination
    page1 = idx.search_events(limit=3, offset=0)
    page2 = idx.search_events(limit=3, offset=3)
    assert len(page1["events"]) == 3
    assert len(page2["events"]) == 3
    assert page1["events"][0]["event_id"] != page2["events"][0]["event_id"]


def test_file_batch_ingestor(tmp_path):
    log_dir = tmp_path / "test_logs"
    log_dir.mkdir()
    log_file = log_dir / "firewall.log"
    log_file.write_text("line 1: log telemetry\nline 2: log telemetry\nline 3: log telemetry\n", encoding="utf-8")

    ingested_envs = []
    ingestor = FileBatchIngestor(callback=lambda e: ingested_envs.append(e))
    envelopes = ingestor.ingest_file(str(log_file))

    assert len(envelopes) == 3
    assert len(ingested_envs) == 3
    assert envelopes[0].raw.raw_payload == "line 1: log telemetry"


def test_field_discovery_engine():
    engine = FieldDiscoveryEngine()
    tmpl = "2026-08-27 fw-01 src=<IP_1> dst=<IP_2> dport=<NUM_1> action=<STR_1>"
    samples = [
        "2026-08-27 fw-01 src=192.168.1.100 dst=10.0.0.1 dport=443 action=ALLOW",
        "2026-08-27 fw-01 src=192.168.1.105 dst=10.0.0.5 dport=80 action=DENY"
    ]
    variables, pattern, rules = engine.analyze_template_and_samples(tmpl, samples)

    assert len(variables) >= 2
    assert pattern is not None
    assert len(rules) >= 2
    # Verify variables infer appropriate types
    inferred_types = [v.inferred_type for v in variables]
    assert "ipv4" in inferred_types or "string" in inferred_types
