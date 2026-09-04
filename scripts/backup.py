"""
ULPF Production Backup Utility
Creates an atomic, point-in-time backup bundle of all critical persistence stores:
1. SQLite Databases (Queue, Search Index, Outbox) using sqlite3.Connection.backup() for safe WAL consistency.
2. Raw Object Storage and Parquet Data Lake.
3. Computes cryptographic SHA-256 manifest of all archived components.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import time
from pathlib import Path


def backup_sqlite_db(source_path: Path, target_path: Path):
    """Performs an online, point-in-time backup using SQLite's native backup API."""
    if not source_path.exists():
        return
    target_path.parent.mkdir(parents=True, exist_ok=True)
    src_conn = sqlite3.connect(str(source_path))
    dst_conn = sqlite3.connect(str(target_path))
    with dst_conn:
        src_conn.backup(dst_conn)
    dst_conn.close()
    src_conn.close()


def create_backup(base_data_dir: Path, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    staging_dir = output_dir / f"ulpf_backup_{timestamp}"
    staging_dir.mkdir(parents=True, exist_ok=True)

    manifest = {"timestamp": timestamp, "files": {}}

    # 1. Back up SQLite databases safely
    db_names = ["durable_queue.db", "search_index.db", "outbox.db"]
    for db_name in db_names:
        db_file = base_data_dir / db_name
        if db_file.exists():
            target_db = staging_dir / db_name
            backup_sqlite_db(db_file, target_db)

    # 2. Back up file stores (raw_store, data_lake, parsers)
    dirs_to_copy = ["raw_store", "data_lake", "parsers", "error_queue"]
    for d in dirs_to_copy:
        src_sub = base_data_dir / d
        if src_sub.exists() and src_sub.is_dir():
            shutil.copytree(src_sub, staging_dir / d, dirs_exist_ok=True)

    # 3. Calculate SHA-256 for all files in staging
    for root, _, files in os.walk(staging_dir):
        for f in files:
            fp = Path(root) / f
            rel_p = str(fp.relative_to(staging_dir)).replace("\\", "/")
            h = hashlib.sha256(fp.read_bytes()).hexdigest()
            manifest["files"][rel_p] = h

    manifest_path = staging_dir / "backup_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # 4. Package as compressed tar.gz archive
    archive_path = output_dir / f"ulpf_backup_{timestamp}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(staging_dir, arcname=staging_dir.name)

    # Clean up staging
    shutil.rmtree(staging_dir)
    return archive_path


if __name__ == "__main__":
    data_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data")
    dest_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("backups")
    archive = create_backup(data_dir, dest_dir)
    print(f"Backup completed successfully: {archive}")
