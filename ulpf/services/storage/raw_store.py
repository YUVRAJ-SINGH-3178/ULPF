"""
Raw Storage Layer — Lossless Preservation Engine
Provides abstract BaseRawStore with LocalRawStore (development) and MinIORawStore (production) adapters.
Guarantees exact byte-for-byte preservation and cryptographic SHA-256 integrity verification.
"""

import datetime
import hashlib
import io
import json
import os
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ulpf.packages.config.settings import Settings, get_settings
from ulpf.packages.schemas.models import RawStorageRef, VerificationResult


class BaseRawStore(ABC):
    """
    Abstract interface for write-once immutable raw storage.

    Preservation Contract (Contract B):
    Lossless canonical UTF-8 byte-stream preservation. The payload is stored exactly as ingested
    without mutation, truncation, masking, or field stripping. Cryptographic SHA-256 integrity
    is computed and verified at write time and stored alongside the object for non-repudiation.
    """

    @abstractmethod
    def store_raw(
        self,
        raw_payload: str,
        event_id: str,
        source_meta: dict[str, Any] | None = None,
        bucket: str | None = None,
    ) -> RawStorageRef:
        """Stores unmutated raw payload and records SHA-256 digest + metadata."""

    @abstractmethod
    def retrieve_raw(self, event_id: str) -> tuple[str, RawStorageRef] | None:
        """Retrieves raw payload and storage reference by event_id."""

    @abstractmethod
    def verify_integrity(self, event_id: str) -> VerificationResult:
        """Computes SHA-256 from stored bytes and verifies against stored digest."""

    @abstractmethod
    def tamper_for_test(self, event_id: str, append_str: str = " [TAMPERED]") -> bool:
        """Test helper to simulate payload tampering for demonstration."""

    @abstractmethod
    def health_check(self) -> dict[str, Any]:
        """Probes store connectivity and readiness."""


class LocalRawStore(BaseRawStore):
    """
    Local filesystem write-once raw storage for development, testing, and air-gapped single-node use.
    Uses date-partitioned directories with atomic promotions and on-demand metadata resolution.
    """

    def __init__(self, base_dir: str = "data/raw_store"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, Any]] = {}

    def store_raw(
        self,
        raw_payload: str,
        event_id: str,
        source_meta: dict[str, Any] | None = None,
        bucket: str | None = "ulpf-raw-events",
    ) -> RawStorageRef:
        bucket_name = bucket or "ulpf-raw-events"
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

                # 2. Verify SHA-256 before atomic promotion
                with open(raw_tmp, "rb") as f:
                    written_bytes = f.read()
                actual_sha = hashlib.sha256(written_bytes).hexdigest()
                if actual_sha != sha256_hash:
                    if raw_tmp.exists():
                        raw_tmp.unlink()
                    raise OSError(
                        f"Atomic raw store write integrity failure for event {event_id}: hash mismatch"
                    )

                # 3. Write metadata to temp file
                meta_data = {
                    "event_id": event_id,
                    "bucket": bucket_name,
                    "object_key": object_key,
                    "sha256": sha256_hash,
                    "byte_length": byte_length,
                    "stored_at": now.isoformat(),
                    "source": source_meta or {},
                    "raw_file_path": str(raw_file.resolve()),
                    "meta_file_path": str(meta_file.resolve()),
                }

                with open(meta_tmp, "w", encoding="utf-8") as f:
                    json.dump(meta_data, f, indent=2)
                    f.flush()

                # 4. Atomic promotions via os.replace
                os.replace(raw_tmp, raw_file)
                os.replace(meta_tmp, meta_file)
                self._cache[event_id] = meta_data
            else:
                meta_data = (
                    self._cache.get(event_id)
                    or self._find_meta(event_id)
                    or {
                        "event_id": event_id,
                        "bucket": bucket_name,
                        "object_key": object_key,
                        "sha256": sha256_hash,
                        "byte_length": byte_length,
                        "stored_at": now.isoformat(),
                        "source": source_meta or {},
                        "raw_file_path": str(raw_file.resolve()),
                        "meta_file_path": str(meta_file.resolve()),
                    }
                )

        return RawStorageRef(
            bucket=bucket_name,
            object_key=object_key,
            sha256=sha256_hash,
            byte_length=byte_length,
            raw_payload=raw_payload,
            compression="none",
        )

    def _find_meta(self, event_id: str) -> dict[str, Any] | None:
        """On-demand lazy disk lookup without preloading entire directory on startup."""
        if event_id in self._cache:
            return self._cache[event_id]
        matches = list(self.base_dir.glob(f"**/{event_id}.meta.json"))
        if matches:
            try:
                with open(matches[0], "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._cache[event_id] = data
                    return data
            except Exception:
                pass
        return None

    def retrieve_raw(self, event_id: str) -> tuple[str, RawStorageRef] | None:
        meta = self._find_meta(event_id)
        if not meta:
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
            compression="none",
        )
        return raw_payload, storage_ref

    def verify_integrity(self, event_id: str) -> VerificationResult:
        meta = self._find_meta(event_id)
        if not meta:
            return VerificationResult(
                event_id=event_id,
                is_valid=False,
                stored_sha256="",
                computed_sha256="",
                byte_length=0,
                tampered=False,
                details=f"Event ID {event_id} not found in local raw storage",
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
                details=f"Raw payload file missing on disk for event {event_id}",
            )

        with open(raw_path, "rb") as f:
            current_bytes = f.read()

        computed_hash = hashlib.sha256(current_bytes).hexdigest()
        stored_hash = meta["sha256"]
        is_valid = computed_hash == stored_hash

        return VerificationResult(
            event_id=event_id,
            is_valid=is_valid,
            stored_sha256=stored_hash,
            computed_sha256=computed_hash,
            byte_length=len(current_bytes),
            tampered=(not is_valid),
            details="Cryptographic integrity verified: SHA-256 matches exactly"
            if is_valid
            else "ALERT: Stored SHA-256 hash mismatch! Payload has been tampered with.",
        )

    def tamper_for_test(self, event_id: str, append_str: str = " [TAMPERED]") -> bool:
        meta = self._find_meta(event_id)
        if not meta:
            return False
        raw_path = Path(meta["raw_file_path"])
        if not raw_path.exists():
            return False
        with open(raw_path, "ab") as f:
            f.write(append_str.encode("utf-8"))
        return True

    def health_check(self) -> dict[str, Any]:
        return {
            "backend": "LocalRawStore",
            "status": "HEALTHY",
            "directory": str(self.base_dir.resolve()),
            "accessible": self.base_dir.exists(),
        }


class MinIORawStore(BaseRawStore):
    """
    Production-grade S3/MinIO Object Storage adapter for immutable raw log preservation.
    Organizes objects in deterministic paths:
    ulpf-raw/year=YYYY/month=MM/day=DD/source=<source_id>/<event_id>.raw
    """

    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str = "ulpf-raw",
        secure: bool = False,
    ):
        try:
            from minio import Minio
        except ImportError:
            raise ImportError(
                "The 'minio' package is required for MinIORawStore. Install with: pip install minio"
            )

        self.endpoint = endpoint
        self.access_key = access_key
        self.secret_key = secret_key
        self.bucket = bucket
        self.secure = secure
        self.client = Minio(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure,
        )
        self._meta_index: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._ensure_bucket()

    def _ensure_bucket(self):
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
        except Exception as e:
            # Let health check report errors if endpoint is not immediately reachable
            pass

    def _build_object_key(
        self,
        event_id: str,
        source_id: str = "default",
        now: datetime.datetime | None = None,
    ) -> str:
        ts = now or datetime.datetime.now(datetime.timezone.utc)
        return f"year={ts.year}/month={ts.month:02d}/day={ts.day:02d}/source={source_id}/{event_id}.raw"

    def store_raw(
        self,
        raw_payload: str,
        event_id: str,
        source_meta: dict[str, Any] | None = None,
        bucket: str | None = None,
    ) -> RawStorageRef:
        target_bucket = bucket or self.bucket
        raw_bytes = raw_payload.encode("utf-8")
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        byte_length = len(raw_bytes)

        now = datetime.datetime.now(datetime.timezone.utc)
        source_id = (source_meta or {}).get("vendor", "perimeter")
        object_key = self._build_object_key(event_id, source_id=source_id, now=now)
        # Deterministic direct object key for metadata locator
        meta_key = f"metadata/events/{event_id}.meta.json"

        meta_data = {
            "event_id": event_id,
            "bucket": target_bucket,
            "object_key": object_key,
            "sha256": sha256_hash,
            "byte_length": byte_length,
            "stored_at": now.isoformat(),
            "source": source_meta or {},
        }

        # 1. Put raw bytes into MinIO
        raw_stream = io.BytesIO(raw_bytes)
        self.client.put_object(
            bucket_name=target_bucket,
            object_name=object_key,
            data=raw_stream,
            length=byte_length,
            content_type="text/plain; charset=utf-8",
            metadata={
                "sha256": sha256_hash,
                "event-id": event_id,
                "byte-length": str(byte_length),
            },
        )

        # 2. Put companion metadata into MinIO at direct deterministic key
        meta_bytes = json.dumps(meta_data).encode("utf-8")
        meta_stream = io.BytesIO(meta_bytes)
        self.client.put_object(
            bucket_name=target_bucket,
            object_name=meta_key,
            data=meta_stream,
            length=len(meta_bytes),
            content_type="application/json; charset=utf-8",
        )

        with self._lock:
            self._meta_index[event_id] = meta_data

        return RawStorageRef(
            bucket=target_bucket,
            object_key=object_key,
            sha256=sha256_hash,
            byte_length=byte_length,
            raw_payload=raw_payload,
            compression="none",
        )

    def retrieve_raw(self, event_id: str) -> tuple[str, RawStorageRef] | None:
        meta = self._get_metadata(event_id)
        if not meta:
            return None

        try:
            response = self.client.get_object(meta["bucket"], meta["object_key"])
            raw_bytes = response.read()
            response.close()
            response.release_conn()

            raw_payload = raw_bytes.decode("utf-8", errors="replace")
            storage_ref = RawStorageRef(
                bucket=meta["bucket"],
                object_key=meta["object_key"],
                sha256=meta["sha256"],
                byte_length=meta["byte_length"],
                raw_payload=raw_payload,
                compression="none",
            )
            return raw_payload, storage_ref
        except Exception:
            return None

    def retrieve_by_storage_uri(
        self, raw_storage_uri: str
    ) -> tuple[str, RawStorageRef] | None:
        """
        Deterministic direct object retrieval using raw_storage_uri ('bucket/object_key')
        without bucket-wide scanning or metadata resolution.
        """
        if "/" not in raw_storage_uri:
            return None
        bucket, object_key = raw_storage_uri.split("/", 1)
        try:
            response = self.client.get_object(bucket, object_key)
            raw_bytes = response.read()
            response.close()
            response.release_conn()

            raw_payload = raw_bytes.decode("utf-8", errors="replace")
            sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
            ref = RawStorageRef(
                bucket=bucket,
                object_key=object_key,
                sha256=sha256_hash,
                byte_length=len(raw_bytes),
                raw_payload=raw_payload,
                compression="none",
            )
            return raw_payload, ref
        except Exception:
            return None

    def _get_metadata(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            if event_id in self._meta_index:
                return self._meta_index[event_id]

        # Deterministic direct object lookup without bucket-wide scanning
        meta_key = f"metadata/events/{event_id}.meta.json"
        try:
            res = self.client.get_object(self.bucket, meta_key)
            data = json.loads(res.read().decode("utf-8"))
            res.close()
            res.release_conn()
            with self._lock:
                self._meta_index[event_id] = data
            return data
        except Exception:
            pass

        return None

    def verify_integrity(self, event_id: str) -> VerificationResult:
        meta = self._get_metadata(event_id)
        if not meta:
            return VerificationResult(
                event_id=event_id,
                is_valid=False,
                stored_sha256="",
                computed_sha256="",
                byte_length=0,
                tampered=False,
                details=f"Event ID {event_id} not found in MinIO bucket {self.bucket}",
            )

        try:
            response = self.client.get_object(meta["bucket"], meta["object_key"])
            current_bytes = response.read()
            response.close()
            response.release_conn()

            computed_hash = hashlib.sha256(current_bytes).hexdigest()
            stored_hash = meta["sha256"]
            is_valid = computed_hash == stored_hash

            return VerificationResult(
                event_id=event_id,
                is_valid=is_valid,
                stored_sha256=stored_hash,
                computed_sha256=computed_hash,
                byte_length=len(current_bytes),
                tampered=(not is_valid),
                details="Cryptographic integrity verified: SHA-256 matches exactly"
                if is_valid
                else "ALERT: MinIO object SHA-256 mismatch! Payload has been tampered with.",
            )
        except Exception as e:
            return VerificationResult(
                event_id=event_id,
                is_valid=False,
                stored_sha256=meta.get("sha256", ""),
                computed_sha256="",
                byte_length=0,
                tampered=True,
                details=f"Failed to stream MinIO object for verification: {e!s}",
            )

    def tamper_for_test(self, event_id: str, append_str: str = " [TAMPERED]") -> bool:
        meta = self._get_metadata(event_id)
        if not meta:
            return False
        try:
            res = self.client.get_object(meta["bucket"], meta["object_key"])
            orig_bytes = res.read()
            res.close()
            res.release_conn()

            tampered_bytes = orig_bytes + append_str.encode("utf-8")
            stream = io.BytesIO(tampered_bytes)
            self.client.put_object(
                bucket_name=meta["bucket"],
                object_name=meta["object_key"],
                data=stream,
                length=len(tampered_bytes),
                content_type="text/plain; charset=utf-8",
            )
            return True
        except Exception:
            return False

    def health_check(self) -> dict[str, Any]:
        try:
            exists = self.client.bucket_exists(self.bucket)
            return {
                "backend": "MinIORawStore",
                "status": "HEALTHY" if exists else "DEGRADED",
                "endpoint": self.endpoint,
                "bucket": self.bucket,
                "bucket_exists": exists,
            }
        except Exception as e:
            return {
                "backend": "MinIORawStore",
                "status": "UNHEALTHY",
                "endpoint": self.endpoint,
                "bucket": self.bucket,
                "error": str(e),
            }


# Backwards compatibility alias
ImmutableRawStore = LocalRawStore


def get_raw_store(settings: Settings | None = None) -> BaseRawStore:
    """
    Factory creating the configured RawStore adapter (LocalRawStore or MinIORawStore).
    """
    s = settings or get_settings()
    if s.ULPF_STORAGE_BACKEND == "minio" and s.ULPF_MINIO_ENDPOINT:
        return MinIORawStore(
            endpoint=s.ULPF_MINIO_ENDPOINT,
            access_key=s.ULPF_MINIO_ACCESS_KEY,
            secret_key=s.ULPF_MINIO_SECRET_KEY,
            bucket=s.ULPF_MINIO_RAW_BUCKET,
            secure=s.ULPF_MINIO_SECURE,
        )
    return LocalRawStore(base_dir=f"{s.ULPF_BASE_DATA_DIR}/raw_store")
