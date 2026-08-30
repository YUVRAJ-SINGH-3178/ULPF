"""
Error & Replay Subsystem
Maintains dead-letter error queue for unparseable logs and executes replay workflows.
"""

import datetime
import json
import threading
import uuid
from pathlib import Path
from typing import Any

from ulpf.packages.schemas.models import EventEnvelope


class ErrorAndReplayQueue:
    """
    Persists unparseable or validation-failed events into a dead-letter queue.
    Provides batch and selective replay capabilities.
    """

    def __init__(self, persistence_dir: str = "data/error_queue"):
        self.persistence_dir = Path(persistence_dir)
        self.persistence_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._queue: dict[str, dict[str, Any]] = {}
        self._load_persisted_errors()

    def _load_persisted_errors(self):
        if not self.persistence_dir.exists():
            return
        for err_file in self.persistence_dir.glob("*.json"):
            try:
                with open(err_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    err_id = data.get("error_id")
                    if err_id:
                        self._queue[err_id] = data
            except Exception:
                pass

    def record_failure(
        self, envelope: EventEnvelope, error_stage: str, errors: list[str]
    ) -> str:
        """Records an event processing failure."""
        error_id = str(uuid.uuid4())
        record = {
            "error_id": error_id,
            "event_id": envelope.event_id,
            "raw_sha256": envelope.raw.sha256,
            "raw_payload": envelope.raw.raw_payload,
            "error_stage": error_stage,  # INGESTION, PARSER, OCSF_VALIDATION, UNKNOWN_FORMAT
            "errors": errors,
            "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "UNRESOLVED",  # UNRESOLVED, REPLAYED, DISMISSED
            "replay_count": 0,
        }

        with self._lock:
            self._queue[error_id] = record
            out_file = self.persistence_dir / f"{error_id}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2)

        return error_id

    def list_errors(self, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if status:
                return [r for r in self._queue.values() if r["status"] == status]
            return list(self._queue.values())

    def get_error(self, error_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._queue.get(error_id)

    def mark_replayed(self, error_id: str) -> bool:
        with self._lock:
            record = self._queue.get(error_id)
            if not record:
                return False
            record["status"] = "REPLAYED"
            record["replay_count"] += 1
            record["last_replayed_at"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()

            out_file = self.persistence_dir / f"{error_id}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2)
            return True

    def clear_resolved(self):
        with self._lock:
            to_remove = [k for k, v in self._queue.items() if v["status"] == "REPLAYED"]
            for k in to_remove:
                del self._queue[k]
                file_path = self.persistence_dir / f"{k}.json"
                if file_path.exists():
                    file_path.unlink()
