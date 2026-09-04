"""
Integration Tests: Worker Production Path & SQLite Concurrency Safeguards
Tests concurrent API enqueue + worker dequeue, SQLite WAL mode, busy_timeout,
visibility timeout lease reclamation, and verified lock-free concurrency.
"""

import concurrent.futures
import sqlite3
import time

from ulpf.services.pipeline_orchestrator import PipelineOrchestrator
from ulpf.services.processing.event_queue import DurableEventQueue, QueueItem
from ulpf.services.processing.worker import ProcessingWorkerPool


def test_sqlite_wal_mode_and_safeguards(tmp_path):
    """Verifies that DurableEventQueue enables WAL journal mode and busy_timeout."""
    db_file = str(tmp_path / "wal_test.db")
    q = DurableEventQueue(maxsize=50, db_path=db_file)

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode;")
    mode = cur.fetchone()[0].lower()
    assert mode == "wal", f"Expected WAL mode, got {mode}"

    cur.execute("PRAGMA busy_timeout;")
    timeout = cur.fetchone()[0]
    assert timeout >= 5000, f"Expected busy_timeout >= 5000, got {timeout}"
    conn.close()


def test_concurrent_api_enqueue_and_worker_dequeue(tmp_path):
    """
    Simulates high-concurrency ingestion: 8 threads enqueuing while
    4 worker threads dequeue and process concurrently against the shared SQLite queue.
    Verifies that no deadlocks occur and all items are safely processed.
    """
    db_file = str(tmp_path / "concurrent_queue.db")
    q = DurableEventQueue(maxsize=1000, db_path=db_file)
    orch = PipelineOrchestrator(base_dir=str(tmp_path))

    worker_pool = ProcessingWorkerPool(queue=q, orchestrator=orch, concurrency=4)
    worker_pool.start()

    num_producers = 8
    items_per_producer = 25
    total_expected = num_producers * items_per_producer

    sample_log = "<134>1 2026-08-27T10:15:30.123Z edge-firewall PaloAlto 10.1.0 TRAFFIC allow 1 src=192.168.1.10 dst=10.0.0.5"

    def producer_task(producer_id: int):
        for i in range(items_per_producer):
            item = QueueItem(
                item_id=f"prod-{producer_id}-item-{i}",
                raw_payload=sample_log,
                transport="api",
                client_ip=f"10.0.{producer_id}.{i}",
            )
            success = q.put(item, timeout=5.0)
            assert success is True

    # Run producers concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_producers) as executor:
        futures = [
            executor.submit(producer_task, p_id) for p_id in range(num_producers)
        ]
        concurrent.futures.wait(futures)

    # Wait for worker pool to drain and process all items
    max_wait = 35.0
    start = time.time()
    while time.time() - start < max_wait:
        stats = worker_pool.get_stats()
        if stats["total_processed"] >= total_expected:
            break
        time.sleep(0.2)

    worker_pool.stop()

    final_stats = worker_pool.get_stats()
    assert final_stats["total_processed"] == total_expected, (
        f"Expected {total_expected} processed, got {final_stats['total_processed']}"
    )
    assert final_stats["total_failed"] == 0
    assert q.size() == 0


def test_worker_lease_expiration_and_reclamation(tmp_path):
    """
    Verifies that when a worker crashes or abandons a lease beyond visibility_timeout_sec,
    the lease reclaimer detects it and puts the item back in the active queue.
    """
    db_file = str(tmp_path / "lease_test.db")
    # Set short visibility timeout for fast test execution
    q = DurableEventQueue(maxsize=10, db_path=db_file, visibility_timeout_sec=0.5)

    item = QueueItem(item_id="lease-abandoned-1", raw_payload="test payload line")
    q.put(item)

    # Worker leases item
    leased = q.get(timeout=1.0)
    assert leased is not None
    assert leased.item_id == "lease-abandoned-1"

    # Simulate worker crash (task_done is NEVER called)
    # Wait for visibility timeout to expire
    time.sleep(0.7)

    # Trigger lease reclamation
    reclaimed = q.reclaim_expired_leases()
    assert reclaimed == 1

    # Verify item is available again for another worker
    re_leased = q.get(timeout=1.0)
    assert re_leased is not None
    assert re_leased.item_id == "lease-abandoned-1"
    q.task_done(re_leased.item_id)


def test_worker_exponential_backoff_and_retry_scheduling(tmp_path):
    """
    Verifies that worker errors record exponential backoff, set status to RETRY_PENDING,
    and are re-queued into _mem_queue once next_attempt_at has elapsed.
    """
    db_file = str(tmp_path / "backoff_test.db")
    q = DurableEventQueue(maxsize=10, db_path=db_file)

    item = QueueItem(item_id="retry-item-1", raw_payload="bad payload", max_attempts=3)
    q.put(item)

    # Worker leases the item
    leased = q.get(timeout=1.0)
    assert leased is not None
    assert leased.item_id == "retry-item-1"

    # Simulate worker error with a short base delay of 0.2s
    q.record_retry("retry-item-1", error="Simulated transient failure", base_delay=0.2)
    q.task_done(item_id=None)

    # Check status in database is RETRY_PENDING
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(
        "SELECT status, attempts, next_attempt_at FROM pending_queue WHERE item_id = ?",
        ("retry-item-1",),
    )
    row = cur.fetchone()
    assert row[0] == "RETRY_PENDING"
    assert row[1] == 1
    next_attempt = row[2]
    conn.close()

    # Before delay elapses, requeue does not pick it up
    requeued_early = q.requeue_eligible_retries()
    assert requeued_early == 0
    assert q.size() == 0

    # Wait for the delay (0.2s + jitter) to pass
    time.sleep(0.8)

    # Now requeue eligible retries
    requeued = q.requeue_eligible_retries()
    assert requeued == 1
    assert q.size() == 1

    # Dequeue the item again
    second_lease = q.get(timeout=1.0)
    assert second_lease is not None
    assert second_lease.item_id == "retry-item-1"
    assert second_lease.attempts == 2
    q.task_done(second_lease.item_id)


def test_outbox_dual_ack_and_unacknowledged_sink_only_retry(tmp_path):
    """
    Verifies that DELIVERY_COMPLETE requires BOTH OpenSearch ACK and Parquet ACK.
    When one sink succeeds and the other fails, only the failed sink is retried.
    """
    from unittest.mock import MagicMock
    from ulpf.packages.schemas.models import EventEnvelope, RawStorageRef
    from ulpf.services.storage.outbox import OutboxManager, OutboxState

    db_file = str(tmp_path / "outbox_test.db")
    outbox = OutboxManager(db_path=db_file)

    ref = RawStorageRef(
        bucket="test-bucket",
        object_key="test-key",
        sha256="abc123hash",
        byte_length=10,
        raw_payload="test payload",
    )
    envelope = EventEnvelope(
        event_id="outbox-dual-ack-01",
        raw=ref,
        vendor_normalized="test",
        product_normalized="test",
        category="security",
        event_type="test",
        severity="low",
    )

    # Mock OpenSearch (succeeds) and Parquet (fails on first attempt)
    search_store = MagicMock()
    data_lake = MagicMock()
    data_lake.write_batch.side_effect = OSError("Simulated disk full in data lake")

    success = outbox.deliver_event(envelope, search_store, data_lake)
    assert success is False

    status = outbox.get_outbox_status("outbox-dual-ack-01")
    assert status["state"] == OutboxState.FAILED_RETRYABLE
    assert status["opensearch_ack"] is True
    assert status["parquet_ack"] is False
    assert "Simulated disk full" in status["last_error"]

    # Now fix Parquet sink and reset mocks
    search_store.reset_mock()
    data_lake.reset_mock()
    data_lake.write_batch.side_effect = None

    # Retry pending outbox
    retried_count = outbox.retry_pending_outbox(search_store, data_lake)
    assert retried_count == 1

    # CRITICAL: OpenSearch was already ACKed, so it must NEVER be called again!
    search_store.index_event.assert_not_called()
    # Parquet was unacknowledged, so it MUST have been called!
    data_lake.write_batch.assert_called_once()

    # Now status must be DELIVERY_COMPLETE with BOTH ACKs = True
    final_status = outbox.get_outbox_status("outbox-dual-ack-01")
    assert final_status["state"] == OutboxState.DELIVERY_COMPLETE
    assert final_status["opensearch_ack"] is True
    assert final_status["parquet_ack"] is True

