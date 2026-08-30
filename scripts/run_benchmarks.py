"""
ULPF Empirical Performance Benchmark Harness
Measures synchronous single-event and batch ingestion throughput, percentiles, and memory footprint.
"""

import json
import os
import sys
import time
from pathlib import Path

import psutil

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ulpf.services.pipeline_orchestrator import PipelineOrchestrator

SAMPLE_LOGS = [
    "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection 9812481 for outside:198.51.100.25/443 (198.51.100.25/443) to inside:10.0.0.5/54321 (10.0.0.5/54321)",
    "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|allow|1|src=198.51.100.88 dst=10.0.1.50 spt=61234 dpt=80 proto=TCP act=allow in=1420 out=5820 app=web-browsing cs1=RULE_WEB_PERMIT",
    'date=2026-08-27 time=10:15:32 devname="FGT-60D" devid="FGT60D0001" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=192.168.1.100 srcport=54321 dstip=198.51.100.25 dstport=443 proto=6 action="accept" policyid=1 sentbyte=512 rcvdbyte=1024',
    "<134>Aug 27 10:15:35 chkp-fw01 CheckPoint: action=drop; src=203.0.113.88; dst=10.0.0.1; proto=tcp; s_port=55123; service=23; rule_name=DROP_TELNET;",
    "1693131336.120    15 192.168.1.100 TCP_DENIED/403 1420 GET http://malicious-domain.xyz/payload.exe - NONE/- text/html",
    '{"ts":1693131334.5,"uid":"C1234567890","id.orig_h":"192.168.1.105","id.orig_p":49152,"id.resp_h":"10.0.0.10","id.resp_p":5432,"proto":"tcp","service":"postgresql","duration":0.045,"orig_bytes":1024,"resp_bytes":4096,"conn_state":"SF"}',
]


def run_benchmark():
    bench_dir = Path("data/benchmarks_run")
    orch = PipelineOrchestrator(
        base_dir=str(bench_dir), enable_data_lake_auto_flush=False
    )

    print("--- Running Single Ingest Benchmark (300 events) ---")
    single_lats = []
    t0 = time.perf_counter()
    for i in range(300):
        log = SAMPLE_LOGS[i % len(SAMPLE_LOGS)]
        s = time.perf_counter()
        orch.process_raw_log(log, transport="bench_single")
        single_lats.append((time.perf_counter() - s) * 1000)
    single_dur = time.perf_counter() - t0
    single_eps = 300 / single_dur
    single_lats.sort()

    print("--- Running Batch Ingest Benchmark (1,000 events) ---")
    batch_logs = [SAMPLE_LOGS[i % len(SAMPLE_LOGS)] for i in range(1000)]
    t1 = time.perf_counter()
    orch.process_batch(batch_logs, transport="bench_batch")
    batch_dur = time.perf_counter() - t1
    batch_eps = 1000 / batch_dur

    mem_mb = psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)

    results = {
        "single_event": {
            "total_events": 300,
            "duration_sec": round(single_dur, 3),
            "throughput_eps": round(single_eps, 1),
            "p50_latency_ms": round(single_lats[150], 3),
            "p95_latency_ms": round(single_lats[int(len(single_lats) * 0.95)], 3),
            "p99_latency_ms": round(single_lats[int(len(single_lats) * 0.99)], 3),
            "min_latency_ms": round(single_lats[0], 3),
            "max_latency_ms": round(single_lats[-1], 3),
        },
        "batch_ingest": {
            "total_events": 1000,
            "duration_sec": round(batch_dur, 3),
            "throughput_eps": round(batch_eps, 1),
        },
        "system": {
            "process_memory_rss_mb": round(mem_mb, 1),
            "python_version": "3.13.5",
            "os": "Windows 11",
        },
    }

    print("\n=== ULPF EMPIRICAL BENCHMARK RESULTS ===")
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    run_benchmark()
