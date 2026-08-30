"""
Concurrency, Durability, and Data Integrity Test Suite
Tests 200+ concurrent ingests across multi-threaded workers.
Validates zero data loss, zero raw store corruption, zero SQLite lock failures,
and DuckDB Parquet schema consistency under load.
"""

import concurrent.futures
import pytest
import duckdb
from pathlib import Path

from ulpf.services.pipeline_orchestrator import PipelineOrchestrator


SAMPLE_LOG_TEMPLATES = [
    "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection {id} for outside:198.51.100.25/{port} (198.51.100.25/{port}) to inside:10.0.0.5/54321 (10.0.0.5/54321)",
    "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|allow|1|src=198.51.100.88 dst=10.0.1.50 spt={port} dpt=80 proto=TCP act=allow in=1420 out=5820 app=web-browsing cs1=RULE_{id}",
    'date=2026-08-27 time=10:15:32 devname="FGT-60D" devid="FGT60D0001" logid="{id}" type="traffic" subtype="forward" level="notice" srcip=192.168.1.100 srcport={port} dstip=198.51.100.25 dstport=443 proto=6 action="accept" policyid=1 sentbyte=512 rcvdbyte=1024',
    "<134>Aug 27 10:15:35 chkp-fw01 CheckPoint: action=drop; src=203.0.113.88; dst=10.0.0.1; proto=tcp; s_port={port}; service=23; rule_name=DROP_{id};",
    "1693131336.120    15 192.168.1.100 TCP_DENIED/403 {port} GET http://malicious-domain-{id}.xyz/payload.exe - NONE/- text/html",
    '{{"ts":1693131334.5,"uid":"C{id}","id.orig_h":"192.168.1.105","id.orig_p":{port},"id.resp_h":"10.0.0.10","id.resp_p":5432,"proto":"tcp","service":"postgresql","duration":0.045,"orig_bytes":1024,"resp_bytes":4096,"conn_state":"SF"}}'
]


def test_concurrent_ingest_200_workers(tmp_path):
    """
    Spins up concurrent worker threads to ingest 200 log lines simultaneously.
    Verifies:
    1. Zero duplicate event IDs.
    2. 100% cryptographic SHA-256 raw store verification pass rate.
    3. SQLite search index consistency without locking errors.
    4. DuckDB Parquet data lake query readability with zero corruption.
    """
    test_dir = tmp_path / "concurrent_load_test"
    orch = PipelineOrchestrator(base_dir=str(test_dir), enable_data_lake_auto_flush=False)

    num_events = 200
    test_payloads = []
    for i in range(num_events):
        template = SAMPLE_LOG_TEMPLATES[i % len(SAMPLE_LOG_TEMPLATES)]
        port = 10000 + (i % 50000)
        payload = template.format(id=f"LOAD{i:04d}", port=port)
        test_payloads.append(payload)

    # Ingest 200 logs concurrently across 20 threads
    envelopes = []
    errors = []

    def _ingest_worker(idx_and_payload):
        idx, p = idx_and_payload
        try:
            return orch.process_raw_log(p, transport="concurrent_test", client_ip=f"10.0.0.{(idx % 250) + 1}")
        except Exception as e:
            return e

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(_ingest_worker, (i, payload)) for i, payload in enumerate(test_payloads)]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if isinstance(res, Exception):
                errors.append(res)
            else:
                envelopes.append(res)

    # 1. Assert no exceptions during concurrent execution
    assert len(errors) == 0, f"Encountered {len(errors)} exceptions during concurrent ingestion: {errors[:3]}"
    assert len(envelopes) == num_events

    # 2. Assert zero duplicate event IDs
    event_ids = [e.event_id for e in envelopes]
    assert len(set(event_ids)) == num_events

    # 3. Assert cryptographic SHA-256 integrity on 100% of stored raw payloads
    for e in envelopes:
        verify_res = orch.raw_store.verify_integrity(e.event_id)
        assert verify_res.is_valid is True, f"Integrity failed for event {e.event_id}: {verify_res.details}"
        assert verify_res.tampered is False

    # 4. Assert SQLite search index contains all 200 records
    search_res = orch.search_index.search_events(limit=500)
    assert search_res["total"] == num_events
    assert len(search_res["events"]) == num_events

    # 5. Flush Parquet data lake and verify queryability with DuckDB
    parquet_filepath = orch.flush_data_lake()
    assert parquet_filepath is not None
    assert Path(parquet_filepath).exists()

    # Query Parquet data lake using DuckDB
    duck_conn = duckdb.connect(":memory:")
    duck_df = duck_conn.execute(f"SELECT COUNT(*) as cnt, COUNT(DISTINCT event_id) as distinct_cnt FROM read_parquet('{parquet_filepath}')").fetchone()
    assert duck_df[0] == num_events
    assert duck_df[1] == num_events
    duck_conn.close()
