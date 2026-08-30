"""
Data Lake Storage Writer (Apache Parquet & DuckDB)
Provides high-performance columnar storage partitioned for AI/ML and SIEM analytics.
"""

import datetime
import os
import threading
import uuid
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from ulpf.packages.schemas.models import EventEnvelope


class ParquetDataLakeWriter:
    """
    Batched columnar Parquet file writer for analytics/ML consumption (e.g. CIC-IDS2017 / UNSW-NB15).
    Partitioned by date and vendor.
    """

    def __init__(self, base_dir: str = "data/data_lake"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write_batch(self, envelopes: list[EventEnvelope]) -> str:
        """
        Flushes a batch of normalized envelopes into a timestamped Parquet file.
        """
        if not envelopes:
            return ""

        records = []
        for env in envelopes:
            ocsf = env.ocsf or {}
            src = (
                ocsf.get("src_endpoint", {})
                if isinstance(ocsf.get("src_endpoint"), dict)
                else {}
            )
            dst = (
                ocsf.get("dst_endpoint", {})
                if isinstance(ocsf.get("dst_endpoint"), dict)
                else {}
            )
            conn_info = (
                ocsf.get("connection_info", {})
                if isinstance(ocsf.get("connection_info"), dict)
                else {}
            )
            traffic = (
                ocsf.get("traffic", {}) if isinstance(ocsf.get("traffic"), dict) else {}
            )

            records.append(
                {
                    "event_id": env.event_id,
                    "ingest_timestamp": env.ingest_timestamp,
                    "time_epoch": ocsf.get("time", 0),
                    "vendor": env.source.vendor,
                    "product": env.source.product,
                    "detected_format": str(
                        env.source.detected_format.value
                        if hasattr(env.source.detected_format, "value")
                        else env.source.detected_format
                    ),
                    "class_uid": ocsf.get("class_uid", 4001),
                    "class_name": ocsf.get("class_name", "Network Activity"),
                    "severity_id": ocsf.get("severity_id", 1),
                    "severity": ocsf.get("severity", "Informational"),
                    "status_id": ocsf.get("status_id", 1),
                    "status": ocsf.get("status", "Success"),
                    "disposition_id": ocsf.get("disposition_id", 1),
                    "disposition": ocsf.get("disposition", "Allowed"),
                    "action": ocsf.get("action")
                    or ocsf.get("activity_name")
                    or "allow",
                    "src_ip": src.get("ip") or "",
                    "src_port": src.get("port") or 0,
                    "dst_ip": dst.get("ip") or "",
                    "dst_port": dst.get("port") or 0,
                    "protocol": conn_info.get("protocol_name") or "TCP",
                    "bytes_in": traffic.get("bytes_in") or 0,
                    "bytes_out": traffic.get("bytes_out") or 0,
                    "raw_sha256": env.raw.sha256,
                    "parser_used": env.parsing.parser_used or "unknown",
                }
            )

        table = pa.Table.from_pylist(records)

        now = datetime.datetime.now(datetime.timezone.utc)
        partition_dir = (
            self.base_dir
            / f"year={now.year}"
            / f"month={now.month:02d}"
            / f"day={now.day:02d}"
        )
        partition_dir.mkdir(parents=True, exist_ok=True)

        file_stem = f"events_{now.strftime('%Y%m%d_%H%M%S_%f')}_{uuid.uuid4().hex[:8]}_{len(envelopes)}"
        final_filename = partition_dir / f"{file_stem}.parquet"
        tmp_filename = partition_dir / f"{file_stem}.parquet.tmp"

        with self._lock:
            pq.write_table(table, tmp_filename, compression="SNAPPY")
            os.replace(tmp_filename, final_filename)

        return str(final_filename.resolve())

    def list_parquet_files(self) -> list[dict[str, Any]]:
        """Returns list of parquet files in the data lake with sizes and timestamps."""
        files = []
        for p in self.base_dir.glob("**/*.parquet"):
            stat = p.stat()
            files.append(
                {
                    "path": str(p.resolve()),
                    "filename": p.name,
                    "size_bytes": stat.st_size,
                    "modified_at": datetime.datetime.fromtimestamp(
                        stat.st_mtime, tz=datetime.timezone.utc
                    ).isoformat(),
                }
            )
        return sorted(files, key=lambda x: x["modified_at"], reverse=True)
