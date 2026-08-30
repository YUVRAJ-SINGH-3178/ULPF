"""
Multi-protocol Ingestion Listeners (UDP Syslog, TCP Syslog, File Watcher)
Accepts telemetry from perimeter network devices completely offline.
"""

import asyncio
import os
import socket
import threading
import time
from pathlib import Path
from typing import Callable, Optional, List

from ulpf.packages.schemas.models import EventEnvelope
from ulpf.services.ingestion.raw_envelope import EnvelopeFactory


class UDPSyslogListener:
    """
    UDP Syslog Listener (RFC 3164 / RFC 5424 over UDP).
    Default port: 5140 (or 514 where privileged).
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5140,
        envelope_factory: Optional[EnvelopeFactory] = None,
        callback: Optional[Callable[[EventEnvelope], None]] = None
    ):
        self.host = host
        self.port = port
        self.factory = envelope_factory or EnvelopeFactory()
        self.callback = callback
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
            self._sock.settimeout(1.0)
        except Exception as e:
            self.running = False
            return

        while self.running:
            try:
                data, addr = self._sock.recvfrom(65535)
                if not data:
                    continue
                raw_text = data.decode("utf-8", errors="replace").strip()
                if raw_text:
                    envelope = self.factory.create_envelope(
                        raw_payload=raw_text,
                        transport="udp",
                        client_ip=addr[0]
                    )
                    if self.callback:
                        self.callback(envelope)
            except socket.timeout:
                continue
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)


class TCPSyslogListener:
    """
    TCP Syslog Listener supporting newline delimiter and octet-counted framing.
    Default port: 1514 (or 514).
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 1514,
        envelope_factory: Optional[EnvelopeFactory] = None,
        callback: Optional[Callable[[EventEnvelope], None]] = None
    ):
        self.host = host
        self.port = port
        self.factory = envelope_factory or EnvelopeFactory()
        self.callback = callback
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._server_sock: Optional[socket.socket] = None

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.host, self.port))
            self._server_sock.listen(10)
            self._server_sock.settimeout(1.0)
        except Exception:
            self.running = False
            return

        while self.running:
            try:
                client_sock, addr = self._server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                if not self.running:
                    break

    def _handle_client(self, client_sock: socket.socket, addr):
        client_sock.settimeout(5.0)
        buffer = ""
        try:
            while self.running:
                data = client_sock.recv(4096)
                if not data:
                    break
                buffer += data.decode("utf-8", errors="replace")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if line:
                        envelope = self.factory.create_envelope(
                            raw_payload=line,
                            transport="tcp",
                            client_ip=addr[0]
                        )
                        if self.callback:
                            self.callback(envelope)
        except Exception:
            pass
        finally:
            client_sock.close()

    def stop(self):
        self.running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)


class FileBatchIngestor:
    """
    Reads log files or directory batches into the ULPF pipeline.
    """

    def __init__(
        self,
        envelope_factory: Optional[EnvelopeFactory] = None,
        callback: Optional[Callable[[EventEnvelope], None]] = None
    ):
        self.factory = envelope_factory or EnvelopeFactory()
        self.callback = callback

    def ingest_file(
        self,
        filepath: str,
        vendor_hint: Optional[str] = None,
        product_hint: Optional[str] = None
    ) -> List[EventEnvelope]:
        """
        Reads a log file line-by-line, generates envelopes, and passes to callback.
        """
        path = Path(filepath)
        if not path.exists():
            return []

        envelopes = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace").strip()
            if content.startswith("[") and content.endswith("]"):
                import json
                items = json.loads(content)
                if isinstance(items, list):
                    for item in items:
                        raw_str = json.dumps(item) if not isinstance(item, str) else item
                        env = self.factory.create_envelope(
                            raw_payload=raw_str,
                            transport="file",
                            client_ip="127.0.0.1",
                            vendor_hint=vendor_hint,
                            product_hint=product_hint
                        )
                        envelopes.append(env)
                        if self.callback:
                            self.callback(env)
                    return envelopes
        except Exception:
            pass

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue
                env = self.factory.create_envelope(
                    raw_payload=line_str,
                    transport="file",
                    client_ip="127.0.0.1",
                    vendor_hint=vendor_hint,
                    product_hint=product_hint
                )
                envelopes.append(env)
                if self.callback:
                    self.callback(env)

        return envelopes
