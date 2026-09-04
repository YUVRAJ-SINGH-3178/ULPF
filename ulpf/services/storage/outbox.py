"""
Durable Outbox Delivery Subsystem
Enforces two-phase delivery tracking and guarantees at-least-once dual-sink delivery:
VALIDATED -> OUTBOX_PENDING -> (OpenSearch ACK + Parquet ACK) -> DELIVERY_COMPLETE.

Both sinks MUST acknowledge successful write before the event is marked DELIVERY_COMPLETE.
If either sink fails, the event remains durable in the outbox for retry.
Duplicates are strictly preferred over silent data loss.
"""

import json
import logging
import sqlite3
import threading
import time
from typing import Any

from ulpf.packages.schemas.models import EventEnvelope

logger = logging.getLogger("ulpf.outbox")


class OutboxState:
    OUTBOX_PENDING = "OUTBOX_PENDING"
    DELIVERY_COMPLETE = "DELIVERY_COMPLETE"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    DEAD_LETTER = "DEAD_LETTER"


class OutboxManager:
    """
    SQLite-backed Outbox Manager tracking atomic dual-sink delivery
    to OpenSearch and Parquet Data Lake.
    """

    def __init__(self, db_path: str, max_retry_attempts: int = 5):
        self.db_path = db_path
        self.max_retry_attempts = max_retry_attempts
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS outbox_entries (
                            event_id TEXT PRIMARY KEY,
                            envelope_json TEXT,
                            state TEXT DEFAULT 'OUTBOX_PENDING',
                            opensearch_ack INTEGER DEFAULT 0,
                            parquet_ack INTEGER DEFAULT 0,
                            attempt_count INTEGER DEFAULT 0,
                            last_error TEXT,
                            last_attempt REAL,
                            created_at REAL
                        )
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_outbox_state 
                        ON outbox_entries(state, opensearch_ack, parquet_ack);
                    """)
            finally:
                conn.close()

    def stage_outbox(self, envelope: EventEnvelope) -> str:
        """
        Stages a validated event envelope into the durable outbox before dispatching to sinks.
        Explicit state: VALIDATED -> OUTBOX_PENDING.
        """
        envelope.traceability["processing_status"] = OutboxState.OUTBOX_PENDING
        envelope_json = envelope.model_dump_json()
        now = time.time()

        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO outbox_entries 
                        (event_id, envelope_json, state, opensearch_ack, parquet_ack, attempt_count, created_at)
                        VALUES (?, ?, ?, 0, 0, 0, ?)
                    """,
                        (
                            envelope.event_id,
                            envelope_json,
                            OutboxState.OUTBOX_PENDING,
                            now,
                        ),
                    )
            finally:
                conn.close()

        return envelope.event_id

    def deliver_event(
        self,
        envelope: EventEnvelope,
        search_store: Any,
        data_lake: Any,
    ) -> bool:
        """
        Executes dual-sink delivery requiring BOTH OpenSearch ACK + Parquet ACK.
        If any sink fails, state is set to FAILED_RETRYABLE and event remains durable.
        """
        event_id = envelope.event_id
        self.stage_outbox(envelope)

        opensearch_ack = False
        parquet_ack = False
        errors: list[str] = []

        now = time.time()

        # Step 1: OpenSearch Sink Delivery
        try:
            search_store.index_event(envelope)
            opensearch_ack = True
        except Exception as e:
            err = f"OpenSearch delivery failed: {e}"
            logger.error(err)
            errors.append(err)

        # Step 2: Parquet Data Lake Sink Delivery
        try:
            data_lake.write_batch([envelope])
            parquet_ack = True
        except Exception as e:
            err = f"Parquet Data Lake delivery failed: {e}"
            logger.error(err)
            errors.append(err)

        # Step 3: Atomic Delivery State Evaluation
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    if opensearch_ack and parquet_ack:
                        # BOTH acknowledged
                        conn.execute(
                            """
                            UPDATE outbox_entries
                            SET state = ?, opensearch_ack = 1, parquet_ack = 1, 
                                attempt_count = attempt_count + 1, last_attempt = ?
                            WHERE event_id = ?
                        """,
                            (OutboxState.DELIVERY_COMPLETE, now, event_id),
                        )
                        envelope.traceability["processing_status"] = "COMPLETED"
                        envelope.traceability.setdefault("provenance_chain", []).append(
                            "DELIVERY_COMPLETE_DUAL_ACK"
                        )
                        return True
                    else:
                        # At least one sink failed
                        combined_error = " | ".join(errors)
                        conn.execute(
                            """
                            UPDATE outbox_entries
                            SET state = ?, opensearch_ack = ?, parquet_ack = ?, 
                                attempt_count = attempt_count + 1, last_attempt = ?, last_error = ?
                            WHERE event_id = ?
                        """,
                            (
                                OutboxState.FAILED_RETRYABLE,
                                1 if opensearch_ack else 0,
                                1 if parquet_ack else 0,
                                now,
                                combined_error,
                                event_id,
                            ),
                        )
                        envelope.traceability["processing_status"] = (
                            OutboxState.FAILED_RETRYABLE
                        )
                        return False
            finally:
                conn.close()

    def retry_pending_outbox(
        self,
        search_store: Any,
        data_lake: Any,
    ) -> int:
        """
        Retries all events in OUTBOX_PENDING or FAILED_RETRYABLE status
        where either OpenSearch or Parquet has not yet acknowledged delivery.
        """
        now = time.time()
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT event_id, envelope_json, opensearch_ack, parquet_ack, attempt_count
                    FROM outbox_entries
                    WHERE state IN (?, ?) AND attempt_count < ?
                """,
                    (
                        OutboxState.OUTBOX_PENDING,
                        OutboxState.FAILED_RETRYABLE,
                        self.max_retry_attempts,
                    ),
                )
                pending_rows = cur.fetchall()
            finally:
                conn.close()

        delivered_count = 0
        for row in pending_rows:
            event_id, env_json, os_ack, pq_ack, attempts = row
            try:
                env_dict = json.loads(env_json)
                envelope = EventEnvelope.model_validate(env_dict)
            except Exception as e:
                logger.error(f"Failed deserializing outbox envelope {event_id}: {e}")
                continue

            errors = []
            new_os_ack = bool(os_ack)
            new_pq_ack = bool(pq_ack)

            if not new_os_ack:
                try:
                    search_store.index_event(envelope)
                    new_os_ack = True
                except Exception as e:
                    errors.append(f"OpenSearch retry failed: {e}")

            if not new_pq_ack:
                try:
                    data_lake.write_batch([envelope])
                    new_pq_ack = True
                except Exception as e:
                    errors.append(f"Parquet retry failed: {e}")

            with self._lock:
                conn = self._get_connection()
                try:
                    with conn:
                        if new_os_ack and new_pq_ack:
                            conn.execute(
                                """
                                UPDATE outbox_entries
                                SET state = ?, opensearch_ack = 1, parquet_ack = 1,
                                    attempt_count = attempt_count + 1, last_attempt = ?
                                WHERE event_id = ?
                            """,
                                (OutboxState.DELIVERY_COMPLETE, now, event_id),
                            )
                            delivered_count += 1
                        else:
                            next_state = (
                                OutboxState.DEAD_LETTER
                                if attempts + 1 >= self.max_retry_attempts
                                else OutboxState.FAILED_RETRYABLE
                            )
                            conn.execute(
                                """
                                UPDATE outbox_entries
                                SET state = ?, opensearch_ack = ?, parquet_ack = ?,
                                    attempt_count = attempt_count + 1, last_attempt = ?, last_error = ?
                                WHERE event_id = ?
                            """,
                                (
                                    next_state,
                                    1 if new_os_ack else 0,
                                    1 if new_pq_ack else 0,
                                    now,
                                    " | ".join(errors),
                                    event_id,
                                ),
                            )
                finally:
                    conn.close()

        return delivered_count

    def get_outbox_status(self, event_id: str) -> dict[str, Any] | None:
        """Retrieves exact outbox delivery status for an event."""
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT event_id, state, opensearch_ack, parquet_ack, attempt_count, last_error, last_attempt, created_at
                    FROM outbox_entries
                    WHERE event_id = ?
                """,
                    (event_id,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return {
                    "event_id": row[0],
                    "state": row[1],
                    "opensearch_ack": bool(row[2]),
                    "parquet_ack": bool(row[3]),
                    "attempt_count": row[4],
                    "last_error": row[5],
                    "last_attempt": row[6],
                    "created_at": row[7],
                }
            finally:
                conn.close()
