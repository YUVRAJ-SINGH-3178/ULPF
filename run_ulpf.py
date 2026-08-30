"""
ULPF — Master Offline Launcher
Launches ULPF FastAPI Application, Ingestion Daemons (UDP/TCP), and Cyber-Ops Dashboard.
"""

import os
import sys

import uvicorn

# Ensure repository root is on Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def main():
    print("=" * 70)
    print("  ULPF — Universal Log Pre-processing Framework (SIH26156)")
    print("  National Technical Research Organisation (NTRO)")
    print("=" * 70)
    print("  [+] Mode: AIR-GAPPED (100% Offline, Zero Cloud Dependencies)")
    print("  [+] Dashboard UI: http://localhost:8000")
    print("  [+] REST API Docs: http://localhost:8000/docs")
    print("  [+] UDP Syslog Listener: port 5140 (UDP)")
    print("  [+] TCP Syslog Listener: port 1514 (TCP)")
    print("  [+] Schema: OCSF 1.1.0 (Open Cybersecurity Schema Framework)")
    print("  [+] Template Miner: Drain3 Streaming Clustering Engine")
    print("=" * 70)
    print("  Press Ctrl+C to stop server.")
    print("=" * 70)

    try:
        config = uvicorn.Config(
            "ulpf.apps.api.main:app",
            host="0.0.0.0",
            port=8000,
            reload=False,
            log_level="info",
            loop="asyncio",
        )
        server = uvicorn.Server(config)
        server.run()
    except (KeyboardInterrupt, SystemExit):
        print("\n" + "=" * 70)
        print("  [✓] ULPF Server safely stopped (SIGINT / KeyboardInterrupt).")
        print("=" * 70)


if __name__ == "__main__":
    main()
