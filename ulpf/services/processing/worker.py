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
from pathlib import Path
from typing import Any

from ulpf.packages.config.settings import get_settings
from ulpf.services.pipeline_orchestrator import PipelineOrchestrator
from ulpf.services.processing.event_queue import DurableEventQueue
from ulpf.services.storage.raw_store import get_raw_store
from ulpf.services.storage.search_index import get_search_store

logger = logging.getLogger("ulpf.worker")


class ProcessingWorkerPool:
    """
    Worker pool consuming from a DurableEventQueue and processing telemetry through PipelineOrchestrator.
    Features lease timeout monitoring, SQLite WAL compatibility, and automated crash recovery.
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
        self.reclaimer_thread: threading.Thread | None = None
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

        self.reclaimer_thread = threading.Thread(
            target=self._reclaimer_loop, name="ulpf-lease-reclaimer", daemon=True
        )
        self.reclaimer_thread.start()
        logger.info(
            f"Started {self.concurrency} ULPF processing workers and lease reclaimer"
        )

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
                self.queue.record_retry(item.item_id, str(e))
                self.queue.task_done(item_id=None)

    def _reclaimer_loop(self):
        """Periodically scans for expired worker leases and schedules eligible retries."""
        while self.running:
            try:
                reclaimed = self.queue.reclaim_expired_leases()
                if reclaimed > 0:
                    logger.info(
                        f"Reclaimed {reclaimed} expired leases from halted workers"
                    )
            except Exception as e:
                logger.error(f"Error reclaiming expired leases: {e}")

            try:
                requeued = self.queue.requeue_eligible_retries()
                if requeued > 0:
                    logger.info(
                        f"Requeued {requeued} retry-pending items for processing"
                    )
            except Exception as e:
                logger.error(f"Error requeuing retries: {e}")

            for _ in range(5):
                if not self.running:
                    break
                time.sleep(1.0)

    def stop(self):
        self.running = False
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=2.0)
        self.threads.clear()
        if self.reclaimer_thread and self.reclaimer_thread.is_alive():
            self.reclaimer_thread.join(timeout=2.0)
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
    logger.info(
        "Starting standalone ULPF processing worker daemon with unified factory..."
    )

    base_dir = Path(settings.ULPF_BASE_DATA_DIR)
    base_dir.mkdir(parents=True, exist_ok=True)
    db_path = str(base_dir / "durable_queue.db")

    raw_store = get_raw_store(settings)
    search_store = get_search_store(settings)
    orchestrator = PipelineOrchestrator(
        base_dir=settings.ULPF_BASE_DATA_DIR,
        raw_store=raw_store,
        search_index=search_store,
    )
    q = DurableEventQueue(
        maxsize=settings.ULPF_MAX_INGEST_QUEUE_SIZE,
        db_path=db_path,
        visibility_timeout_sec=30.0,
    )
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
