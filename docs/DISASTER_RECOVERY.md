# ULPF — Air-Gapped Disaster Recovery & Backup Runbook

**Organization**: National Technical Research Organisation (NTRO) · SIH26156  
**Classification**: Operational Procedures for Isolated Strategic Networks  
**Verification Status**: **EXECUTED & VERIFIED** (Tested against active codebase via `tests/test_backup_restore.py`)

---

## 1. Backup Strategy Overview

In air-gapped environments without cloud snapshot APIs, backup procedures rely on deterministic local volume snapshots, online SQLite atomic backups, and cryptographically verified filesystem archives.

| Subsystem | Storage Mechanism | Backup Mechanism | Verification Target |
| :--- | :--- | :--- | :--- |
| **Durable Queue & Outbox** | SQLite in WAL mode | `sqlite3.Connection.backup()` | Atomic point-in-time snapshot |
| **Local Search Index** | SQLite in WAL mode | `sqlite3.Connection.backup()` | Atomic point-in-time snapshot |
| **Raw Evidence & Metadata** | MinIO / Local raw store | Tarball + SHA-256 Manifest | Forensic bit-for-bit hash match |
| **Analytical Data Lake** | Apache Parquet Partitions | Tarball + SHA-256 Manifest | Columnar partition integrity |
| **Parser Catalog & Onboarding** | JSON AST Definitions | Tarball + SHA-256 Manifest | Schema & grammar integrity |

---

## 2. Automated CLI Backup Toolchain

### Creating a Cryptographic Backup Bundle:
```bash
python scripts/backup.py data/ backups/
```
Output:
`backups/ulpf_backup_YYYYMMDD_HHMMSS.tar.gz`

**Capabilities:**
1. Uses SQLite's online backup API (`src_conn.backup(dst_conn)`) to capture consistent database states without blocking active ingestion writers.
2. Copies raw storage objects, parquet files, and active parser configurations.
3. Computes a cryptographic SHA-256 digest for every file in the backup bundle and generates `backup_manifest.json`.
4. Compresses all artifacts into an immutable tar.gz bundle.

---

## 3. Automated CLI Disaster Recovery Restore

### Restoring from Backup Bundle:
```bash
python scripts/restore.py backups/ulpf_backup_YYYYMMDD_HHMMSS.tar.gz data/
```

**Disaster Recovery Protections:**
1. **Pre-Restore Cryptographic Verification**: Computes the SHA-256 hash of every extracted file and compares it against `backup_manifest.json`. If even one byte has been tampered with or corrupted, the restore aborts immediately without touching existing data.
2. **Atomic Rollout**: Restores SQLite databases (`durable_queue.db`, `search_index.db`, `outbox.db`) and file storage into the live data directory.
3. **Automatic Orphan Cleanup**: Removes temporary staging areas upon completion or failure.

---

## 4. Cold-Start Verification Runbook

Following a catastrophic failure and restore:
1. Run `python -m pytest tests/test_backup_restore.py -v` to verify database health.
2. Start the pipeline: `python -m ulpf.apps.api.main` and verify `/api/pipeline/health` returns HTTP 200 `HEALTHY`.
3. Check Outbox status: any un-delivered items will be picked up by the outbox retry manager and delivered to OpenSearch and Parquet.
