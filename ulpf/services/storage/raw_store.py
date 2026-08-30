"""
Immutable Lossless Raw Storage Engine
Guarantees byte-for-byte preservation and SHA-256 cryptographic integrity verification.
"""

import datetime
import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any

from ulpf.packages.schemas.models import RawStorageRef, VerificationResult


class ImmutableRawStore:
    """
    Thread-safe, write-once immutable storage for raw events.
    Stores exact unmutated payloads on disk with companion metadata.
    """

    def __init__(self, base_dir: str = "data/raw_store"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._index: dict[str, dict[str, Any]] = {}
        self._load_existing_index()

    def _load_existing_index(self):
        """Preload fast lookup index from existing metadata files on disk."""
        if not self.base_dir.exists():
            return
        for meta_file in self.base_dir.glob("**/*.meta.json"):
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    event_id = data.get("event_id")
                    if event_id:
                        self._index[event_id] = data
            except Exception:
                pass

    def store_raw(
        self,
        raw_payload: str,
        event_id: str,
        source_meta: dict[str, Any] | None = None,
        bucket: str = "ulpf-raw-events"
    ) -> RawStorageRef:
        """
        Calculates SHA-256 hash, writes raw bytes to write-once storage, and records metadata.
        """
        raw_bytes = raw_payload.encode("utf-8")
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        byte_length = len(raw_bytes)
        
        now = datetime.datetime.now(datetime.timezone.utc)
        date_folder = now.strftime("%Y-%m-%d")
        target_dir = self.base_dir / date_folder
        target_dir.mkdir(parents=True, exist_ok=True)

        raw_file = target_dir / f"{event_id}.raw"
        meta_file = target_dir / f"{event_id}.meta.json"
        raw_tmp = target_dir / f"{event_id}.raw.tmp"
        meta_tmp = target_dir / f"{event_id}.meta.json.tmp"
        object_key = f"{date_folder}/{event_id}.raw"

        with self._lock:
            if not raw_file.exists():
                # 1. Write raw payload to temp file
                with open(raw_tmp, "wb") as f:
                    f.write(raw_bytes)
                    f.flush()

                # 2. Verify SHA-256 of written file before promoting
                with open(raw_tmp, "rb") as f:
                    written_bytes = f.read()
                actual_sha = hashlib.sha256(written_bytes).hexdigest()
                if actual_sha != sha256_hash:
                    if raw_tmp.exists():
                        raw_tmp.unlink()
                    raise OSError(f"Atomic raw store write integrity failure for event {event_id}: hash mismatch")

                # 3. Write metadata to temp file
                meta_data = {
                    "event_id": event_id,
                    "bucket": bucket,
                    "object_key": object_key,
                    "sha256": sha256_hash,
                    "byte_length": byte_length,
                    "stored_at": now.isoformat(),
                    "source": source_meta or {},
                    "raw_file_path": str(raw_file.resolve()),
                    "meta_file_path": str(meta_file.resolve())
                }

                with open(meta_tmp, "w", encoding="utf-8") as f:
                    json.dump(meta_data, f, indent=2)
                    f.flush()

                # 4. Atomic promotions via os.replace
                os.replace(raw_tmp, raw_file)
                os.replace(meta_tmp, meta_file)

                self._index[event_id] = meta_data
            else:
                meta_data = self._index.get(event_id) or {
                    "event_id": event_id,
                    "bucket": bucket,
                    "object_key": object_key,
                    "sha256": sha256_hash,
                    "byte_length": byte_length,
                    "stored_at": now.isoformat(),
                    "source": source_meta or {},
                    "raw_file_path": str(raw_file.resolve()),
                    "meta_file_path": str(meta_file.resolve())
                }

        return RawStorageRef(
            bucket=bucket,
            object_key=object_key,
            sha256=sha256_hash,
            byte_length=byte_length,
            raw_payload=raw_payload,
            compression="none"
        )

    def retrieve_raw(self, event_id: str) -> tuple[str, RawStorageRef] | None:
        """
        Retrieves original raw payload and its storage reference by event_id.
        """
        with self._lock:
            meta = self._index.get(event_id)
            if not meta:
                # Search disk if not in memory index
                matches = list(self.base_dir.glob(f"**/{event_id}.meta.json"))
                if matches:
                    with open(matches[0], "r", encoding="utf-8") as f:
                        meta = json.load(f)
                        self._index[event_id] = meta
                else:
                    return None

        raw_path = Path(meta["raw_file_path"])
        if not raw_path.exists():
            return None

        with open(raw_path, "rb") as f:
            raw_bytes = f.read()

        raw_payload = raw_bytes.decode("utf-8", errors="replace")

        storage_ref = RawStorageRef(
            bucket=meta["bucket"],
            object_key=meta["object_key"],
            sha256=meta["sha256"],
            byte_length=meta["byte_length"],
            raw_payload=raw_payload,
            compression="none"
        )
        return raw_payload, storage_ref

    def verify_integrity(self, event_id: str) -> VerificationResult:
        """
        Cryptographic verification: Re-reads raw payload from disk, computes SHA-256,
        and compares with recorded hash. Proves byte-for-byte authenticity.
        """
        with self._lock:
            meta = self._index.get(event_id)
            if not meta:
                matches = list(self.base_dir.glob(f"**/{event_id}.meta.json"))
                if matches:
                    with open(matches[0], "r", encoding="utf-8") as f:
                        meta = json.load(f)
                        self._index[event_id] = meta
                else:
                    return VerificationResult(
                        event_id=event_id,
                        is_valid=False,
                        stored_sha256="",
                        computed_sha256="",
                        byte_length=0,
                        tampered=False,
                        details=f"Event ID {event_id} not found in raw storage"
                    )

        raw_path = Path(meta["raw_file_path"])
        if not raw_path.exists():
            return VerificationResult(
                event_id=event_id,
                is_valid=False,
                stored_sha256=meta["sha256"],
                computed_sha256="",
                byte_length=0,
                tampered=True,
                details=f"Raw payload file missing on disk for event {event_id}"
            )

        with open(raw_path, "rb") as f:
            current_bytes = f.read()

        computed_hash = hashlib.sha256(current_bytes).hexdigest()
        stored_hash = meta["sha256"]
        is_valid = (computed_hash == stored_hash)

        return VerificationResult(
            event_id=event_id,
            is_valid=is_valid,
            stored_sha256=stored_hash,
            computed_sha256=computed_hash,
            byte_length=len(current_bytes),
            tampered=(not is_valid),
            details="Cryptographic integrity verified: SHA-256 matches exactly" if is_valid else "ALERT: Stored SHA-256 hash mismatch! Payload has been tampered with."
        )

    def tamper_for_test(self, event_id: str, append_str: str = " [TAMPERED]") -> bool:
        """
        Test helper to simulate unauthorized payload modification and verify detection.
        """
        with self._lock:
            meta = self._index.get(event_id)
            if not meta:
                return False
            raw_path = Path(meta["raw_file_path"])
            if not raw_path.exists():
                return False
            with open(raw_path, "ab") as f:
                f.write(append_str.encode("utf-8"))
            return True
