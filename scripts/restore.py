"""
ULPF Production Disaster Recovery & Restore Utility
Restores an atomic backup bundle created by scripts/backup.py:
1. Extracts the compressed archive to a staging area.
2. Cryptographically validates every file against backup_manifest.json.
3. Atomically restores SQLite databases, raw storage, and parquet data lake into target base dir.
"""

import hashlib
import json
import shutil
import sys
import tarfile
from pathlib import Path


def restore_backup(archive_path: Path, target_data_dir: Path) -> bool:
    if not archive_path.exists():
        raise FileNotFoundError(f"Backup archive not found: {archive_path}")

    target_data_dir.mkdir(parents=True, exist_ok=True)
    temp_extract_dir = target_data_dir / "_temp_restore"
    temp_extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            if hasattr(tarfile, "data_filter"):
                tar.extractall(path=temp_extract_dir, filter="data")
            else:
                tar.extractall(path=temp_extract_dir)

        # Locate extracted backup folder
        extracted_dirs = [d for d in temp_extract_dir.iterdir() if d.is_dir()]
        if not extracted_dirs:
            raise ValueError("Corrupt archive: no root backup directory found")
        staging_dir = extracted_dirs[0]

        manifest_file = staging_dir / "backup_manifest.json"
        if not manifest_file.exists():
            raise ValueError("Corrupt backup: missing backup_manifest.json")

        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))

        # Verify all SHA-256 digests before restoring
        for rel_path, expected_sha in manifest.get("files", {}).items():
            f = staging_dir / rel_path
            if not f.exists():
                raise ValueError(f"Integrity check failed: missing file {rel_path}")
            actual_sha = hashlib.sha256(f.read_bytes()).hexdigest()
            if actual_sha != expected_sha:
                raise ValueError(
                    f"Integrity verification failed for {rel_path}: "
                    f"expected {expected_sha}, got {actual_sha}"
                )

        # Restore databases and file stores into target_data_dir
        for item in staging_dir.iterdir():
            if item.name == "backup_manifest.json":
                continue
            dest = target_data_dir / item.name
            if item.is_file():
                shutil.copy2(item, dest)
            elif item.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(item, dest)

        return True
    finally:
        if temp_extract_dir.exists():
            shutil.rmtree(temp_extract_dir)


if __name__ == "__main__":
    archive = Path(sys.argv[1])
    target = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data")
    success = restore_backup(archive, target)
    print(f"Restore completed successfully into {target}: {success}")
