"""
Unit & Integration Tests for Event Queue and Asynchronous Processing Workers
Tests bounded capacity, worker consumption, task completion, and crash-recovery reconstitution.
"""

import time

from ulpf.services.pipeline_orchestrator import PipelineOrchestrator
from ulpf.services.processing.event_queue import DurableEventQueue, QueueItem
from ulpf.services.processing.worker import ProcessingWorkerPool


def test_durable_event_queue_bounded_and_lifecycle(tmp_path):
    q = DurableEventQueue(maxsize=3, db_path=str(tmp_path / "queue.db"))

    item1 = QueueItem(item_id="1", raw_payload="log line 1")
    item2 = QueueItem(item_id="2", raw_payload="log line 2")
    item3 = QueueItem(item_id="3", raw_payload="log line 3")
    item4 = QueueItem(item_id="4", raw_payload="log line 4")

    assert q.put(item1) is True
    assert q.put(item2) is True
    assert q.put(item3) is True
    # Backpressure check on full queue
    assert q.put(item4, timeout=0.1) is False

    assert q.size() == 3

    retrieved = q.get(timeout=0.5)
    assert retrieved is not None
    assert retrieved.item_id == "1"
    q.task_done(retrieved.item_id)
    assert q.size() == 2


def test_durable_queue_crash_recovery(tmp_path):
    """
    Verifies that unacknowledged items in SQLite persistent queue
    are reconstituted back into memory when the process restarts.
    """
    db_file = str(tmp_path / "crash_test.db")
    q1 = DurableEventQueue(maxsize=10, db_path=db_file)
    q1.put(QueueItem(item_id="crash-1", raw_payload="critical log 1"))
    q1.put(QueueItem(item_id="crash-2", raw_payload="critical log 2"))

    # Simulate worker crash before calling task_done
    del q1

    # Restart queue
    q2 = DurableEventQueue(maxsize=10, db_path=db_file)
    assert q2.size() == 2

    r1 = q2.get(timeout=0.5)
    assert r1.item_id == "crash-1"
    q2.task_done(r1.item_id)

    r2 = q2.get(timeout=0.5)
    assert r2.item_id == "crash-2"
    q2.task_done(r2.item_id)

    assert q2.size() == 0


def test_worker_pool_processing(tmp_path):
    orch = PipelineOrchestrator(base_dir=str(tmp_path))
    q = DurableEventQueue(maxsize=100)
    pool = ProcessingWorkerPool(queue=q, orchestrator=orch, concurrency=2)

    pool.start()

    sample_log = "<166>Aug 27 10:15:30 fw-edge-01 %ASA-6-302013: Built inbound TCP connection 9812481 for outside:198.51.100.25/443 (198.51.100.25/443) to inside:10.0.0.5/54321 (10.0.0.5/54321)"
    q.put(QueueItem(item_id="w-1", raw_payload=sample_log))

    # Give workers time to process
    time.sleep(0.5)

    stats = pool.get_stats()
    assert stats["total_processed"] >= 1
    assert stats["total_failed"] == 0

    pool.stop()
