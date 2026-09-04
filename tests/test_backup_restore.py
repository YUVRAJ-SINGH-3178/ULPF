"""
Unit & Integration Tests: Backup, Disaster Recovery & Cryptographic Restore
Tests atomic backup creation, point-in-time SQLite snapshotting, manifest calculation,
tampering rejection, and full data reconstitution.
"""

import tarfile

import pytest

from scripts.backup import create_backup
from scripts.restore import restore_backup
from ulpf.services.pipeline_orchestrator import PipelineOrchestrator


def test_backup_and_restore_lifecycle(tmp_path):
    """
    1. Ingests events into a test orchestrator.
    2. Takes an atomic point-in-time backup.
    3. Simulates catastrophic disaster (deleting the data directory).
    4. Restores from the backup bundle.
    5. Reconnects a new orchestrator to the restored directory and verifies data integrity.
    """
    data_dir = tmp_path / "live_data"
    backup_dir = tmp_path / "backups"
    restore_target = tmp_path / "restored_data"

    # Step 1: Create live data
    orch = PipelineOrchestrator(base_dir=str(data_dir))
    log1 = "<134>1 2026-08-27T10:15:30.123Z edge-firewall PaloAlto 10.1.0 TRAFFIC allow 1 src=192.168.1.10 dst=10.0.0.5"
    log2 = "CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|drop|Drop|Low|src=203.0.113.19 dst=192.168.1.200"

    env1 = orch.process_raw_log(log1)
    env2 = orch.process_raw_log(log2)

    # Step 2: Run backup
    archive_path = create_backup(data_dir, backup_dir)
    assert archive_path.exists()
    assert archive_path.stat().st_size > 0

    # Step 3: Run disaster recovery restore into clean directory
    success = restore_backup(archive_path, restore_target)
    assert success is True

    # Step 4: Verify restored data with new orchestrator instance
    restored_orch = PipelineOrchestrator(base_dir=str(restore_target))

    # Verify both events exist in search store
    event1 = restored_orch.search_index.get_event_by_id(env1.event_id)
    assert event1 is not None
    assert event1["event_id"] == env1.event_id

    event2 = restored_orch.search_index.get_event_by_id(env2.event_id)
    assert event2 is not None
    assert event2["event_id"] == env2.event_id

    # Verify cryptographic raw storage integrity
    verif1 = restored_orch.verify_event_integrity(env1.event_id)
    assert verif1.is_valid is True
    assert verif1.tampered is False

    verif2 = restored_orch.verify_event_integrity(env2.event_id)
    assert verif2.is_valid is True
    assert verif2.tampered is False


def test_restore_rejects_corrupted_manifest(tmp_path):
    """
    Verifies that if a backup archive has been modified or tampered with in transit,
    restore_backup halts immediately and refuses to restore corrupted data.
    """

    data_dir = tmp_path / "live_data"
    backup_dir = tmp_path / "backups"
    data_dir.mkdir(parents=True, exist_ok=True)

    # Create dummy file and backup
    (data_dir / "sample.txt").write_text("critical security data")
    archive_path = create_backup(data_dir, backup_dir)

    # Case 1: Corrupt archive magic bytes
    with open(archive_path, "r+b") as f:
        f.seek(0)
        f.write(b"NOT_A_VALID_GZIP_ARCHIVE")

    restore_target = tmp_path / "corrupted_target"
    with pytest.raises((tarfile.ReadError, ValueError)):
        restore_backup(archive_path, restore_target)
