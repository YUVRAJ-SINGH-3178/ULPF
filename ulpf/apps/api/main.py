"""
ULPF FastAPI Application
Main service hosting REST APIs, Ingestion Daemons, and Cyber-Ops Dashboard.
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from ulpf.services.pipeline_orchestrator import PipelineOrchestrator
from ulpf.services.ingestion.listeners import UDPSyslogListener, TCPSyslogListener
from ulpf.apps.api.routes.events import router as events_router, set_orchestrator
from ulpf.apps.api.routes.parsers import router as parsers_router
from ulpf.apps.api.routes.onboarding import router as onboarding_router
from ulpf.apps.api.routes.errors import router as errors_router
from ulpf.apps.api.routes.datalake import router as datalake_router
from ulpf.apps.api.routes.benchmark import router as benchmark_router
from ulpf.apps.api.routes.pipeline import router as pipeline_router
from ulpf.apps.api.routes.auth_routes import router as auth_router


# Initialize global orchestrator
orchestrator = PipelineOrchestrator(base_dir="data")
set_orchestrator(orchestrator)

# Background listeners
udp_listener = None
tcp_listener = None


def seed_initial_telemetry():
    """Seeds rich sample telemetry on startup if search index is empty."""
    summary = orchestrator.search_index.get_metrics_summary()
    if summary["total_events"] == 0:
        seed_logs = [
            # Cisco ASA
            "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection 9812481 for outside:198.51.100.25/443 (198.51.100.25/443) to inside:10.0.0.5/54321 (10.0.0.5/54321)",
            "<164>Aug 27 10:15:31 fw-edge-01 %ASA-4-106023: Deny tcp src dmz:192.168.1.50/443 dst outside:203.0.113.10/51234 by access-group \"OUTSIDE_BLOCK\" [0x12345678, 0x0]",
            "<166>Aug 27 10:15:33 fw-edge-01 %ASA-6-302014: Teardown TCP connection 9812481 for outside:198.51.100.25/443 to inside:10.0.0.5/54321 duration 0:02:15 bytes 48123 TCP FINs",
            # Palo Alto PAN-OS CEF
            "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|allow|1|src=198.51.100.88 dst=10.0.1.50 spt=61234 dpt=80 proto=TCP act=allow in=1420 out=5820 app=web-browsing cs1=RULE_WEB_PERMIT",
            "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|drop|7|src=185.220.101.5 dst=10.0.0.1 spt=44123 dpt=22 proto=TCP act=drop in=0 out=0 app=ssh cs1=RULE_SSH_BLOCK",
            # Fortinet FortiOS LEEF & KV
            "date=2026-08-27 time=10:15:32 devname=\"FGT-60D\" devid=\"FGT60D0001\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=192.168.1.100 srcport=54321 dstip=198.51.100.25 dstport=443 proto=6 action=\"accept\" policyid=1 sentbyte=512 rcvdbyte=1024",
            "date=2026-08-27 time=10:15:34 devname=\"FGT-60D\" devid=\"FGT60D0001\" logid=\"0000000014\" type=\"traffic\" subtype=\"forward\" level=\"warning\" srcip=203.0.113.88 srcport=55123 dstip=10.0.0.10 dstport=5432 proto=6 action=\"deny\" policyid=99 sentbyte=0 rcvdbyte=0",
            # Suricata EVE JSON
            '{"timestamp":"2026-08-27T10:15:33.123456+0000","flow_id":87654321,"event_type":"alert","src_ip":"185.220.101.5","src_port":44123,"dest_ip":"10.0.0.5","dest_port":22,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2001219,"rev":1,"signature":"ET SCAN Potential SSH Brute Force Detected","category":"Attempted Information Leak","severity":1}}',
            '{"timestamp":"2026-08-27T10:15:34.654321+0000","flow_id":87654322,"event_type":"http","src_ip":"192.168.1.105","src_port":51234,"dest_ip":"10.0.1.50","dest_port":80,"proto":"TCP","http":{"hostname":"internal.ntro.gov.in","url":"/api/v1/telemetry","http_method":"GET","status":200}}',
            # Zeek Conn JSON
            '{"ts":1693131334.5,"uid":"C1234567890","id.orig_h":"192.168.1.105","id.orig_p":49152,"id.resp_h":"10.0.0.10","id.resp_p":5432,"proto":"tcp","service":"postgresql","duration":0.045,"orig_bytes":1024,"resp_bytes":4096,"conn_state":"SF"}',
            # Checkpoint Firewall-1
            "<134>Aug 27 10:15:35 chkp-fw01 CheckPoint: action=drop; src=203.0.113.88; dst=10.0.0.1; proto=tcp; s_port=55123; service=23; rule_name=DROP_TELNET;",
            # Squid Proxy
            "1693131336.120    15 192.168.1.100 TCP_DENIED/403 1420 GET http://malicious-domain.xyz/payload.exe - NONE/- text/html",
            "1693131337.350    42 192.168.1.105 TCP_MISS/200 8520 GET http://update.security.org/signatures.dat - DIRECT/198.51.100.25 application/octet-stream"
        ]
        orchestrator.process_batch(seed_logs, transport="seed")


from ulpf.packages.config.settings import get_settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global udp_listener, tcp_listener
    settings = get_settings()
    seed_initial_telemetry()

    if settings.ULPF_ENABLE_SYSLOG_LISTENERS:
        try:
            udp_listener = UDPSyslogListener(
                host=settings.ULPF_API_HOST,
                port=settings.ULPF_UDP_SYSLOG_PORT,
                envelope_factory=orchestrator.envelope_factory,
                callback=lambda env: orchestrator.process_raw_log(env.raw.raw_payload, transport="udp", client_ip=env.source.client_ip)
            )
            udp_listener.start()
        except Exception:
            pass

        try:
            tcp_listener = TCPSyslogListener(
                host=settings.ULPF_API_HOST,
                port=settings.ULPF_TCP_SYSLOG_PORT,
                envelope_factory=orchestrator.envelope_factory,
                callback=lambda env: orchestrator.process_raw_log(env.raw.raw_payload, transport="tcp", client_ip=env.source.client_ip)
            )
            tcp_listener.start()
        except Exception:
            pass

    yield

    # Shutdown
    if udp_listener:
        udp_listener.stop()
    if tcp_listener:
        tcp_listener.stop()
    orchestrator.flush_data_lake()


app = FastAPI(
    title="ULPF — Universal Log Pre-processing Framework",
    description="NTRO SIH26156 Enterprise Perimeter Log Ingestion, Normalization (OCSF), Lossless Preservation, and Drain3 Onboarding Engine.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration for offline and container access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from ulpf.apps.api.routes.pipeline import get_prometheus_metrics
from fastapi import Response

# Mount API Routers
app.include_router(auth_router, prefix="/api")
app.include_router(events_router, prefix="/api")
app.include_router(parsers_router, prefix="/api")
app.include_router(onboarding_router, prefix="/api")
app.include_router(errors_router, prefix="/api")
app.include_router(datalake_router, prefix="/api")
app.include_router(benchmark_router, prefix="/api")
app.include_router(pipeline_router, prefix="/api")


@app.get("/metrics")
def top_level_metrics(response: Response):
    """Top-level Prometheus metrics scrape endpoint."""
    return get_prometheus_metrics(response)


# Static Dashboard UI Mount
dashboard_static_dir = Path("ulpf/apps/dashboard/static")
dashboard_static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(dashboard_static_dir.resolve())), name="static")


@app.get("/")
def serve_dashboard():
    index_path = Path("ulpf/apps/dashboard/index.html")
    if index_path.exists():
        return FileResponse(str(index_path.resolve()))
    return {"message": "ULPF Cyber Operations Platform Online"}
