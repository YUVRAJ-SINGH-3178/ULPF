"""
Asynchronous Ingestion Worker Daemon
Pulls raw items from DurableEventQueue, drives end-to-end normalization, and manages delivery lifecycle.
Can run embedded in FastAPI or as a standalone containerized worker service (ulpf-worker).
"""

import logging
import signal
import sys
import threading
import time
from typing import Any

from ulpf.packages.config.settings import get_settings
from ulpf.services.pipeline_orchestrator import PipelineOrchestrator
from ulpf.services.processing.event_queue import DurableEventQueue

logger = logging.getLogger("ulpf.worker")


class ProcessingWorkerPool:
    """
    Worker pool consuming from a DurableEventQueue and processing telemetry through PipelineOrchestrator.
    """

    def __init__(
        self,
        queue: DurableEventQueue,
        orchestrator: PipelineOrchestrator,
        concurrency: int = 4,
    ):
        self.queue = queue
        self.orchestrator = orchestrator
        self.concurrency = concurrency
        self.running = False
        self.threads: list[threading.Thread] = []
        self.processed_count = 0
        self.failed_count = 0
        self._lock = threading.Lock()

    def start(self):
        if self.running:
            return
        self.running = True
        for i in range(self.concurrency):
            t = threading.Thread(
                target=self._worker_loop, name=f"ulpf-worker-{i}", daemon=True
            )
            self.threads.append(t)
            t.start()
        logger.info(f"Started {self.concurrency} ULPF processing workers")

    def _worker_loop(self):
        while self.running:
            item = self.queue.get(timeout=1.0)
            if not item:
                continue

            try:
                self.orchestrator.process_raw_log(
                    raw_payload=item.raw_payload,
                    transport=item.transport,
                    client_ip=item.client_ip,
                    vendor_hint=item.vendor_hint,
                    product_hint=item.product_hint,
                )
                with self._lock:
                    self.processed_count += 1
                self.queue.task_done(item.item_id)
            except Exception as e:
                logger.error(f"Worker failed processing item {item.item_id}: {e}")
                with self._lock:
                    self.failed_count += 1
                self.queue.task_done(item.item_id)

    def stop(self):
        self.running = False
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=2.0)
        self.threads.clear()
        logger.info("Stopped ULPF processing workers")

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active_workers": len([t for t in self.threads if t.is_alive()]),
                "total_processed": self.processed_count,
                "total_failed": self.failed_count,
                "queue_pending": self.queue.size(),
            }


def main():
    """Standalone worker daemon entry point for containerized worker deployments."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    settings = get_settings()
    logger.info("Starting standalone ULPF processing worker daemon...")

    orchestrator = PipelineOrchestrator(base_dir=settings.ULPF_BASE_DATA_DIR)
    q = DurableEventQueue(maxsize=settings.ULPF_MAX_INGEST_QUEUE_SIZE)
    pool = ProcessingWorkerPool(
        q, orchestrator, concurrency=settings.ULPF_WORKER_CONCURRENCY
    )
    pool.start()

    stop_event = threading.Event()

    def _signal_handler(sig, frame):
        logger.info("Shutdown signal received. Stopping worker pool...")
        pool.stop()
        stop_event.set()
        sys.exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    while not stop_event.is_set():
        time.sleep(1)


if __name__ == "__main__":
    main()
