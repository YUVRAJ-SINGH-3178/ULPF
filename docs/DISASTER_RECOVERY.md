# ULPF — Air-Gapped Disaster Recovery & Backup Runbook

**Organization**: National Technical Research Organisation (NTRO) · SIH26156  
**Classification**: Operational Procedures for Isolated Strategic Networks  

---

## 1. Backup Strategy Overview

In 100% air-gapped environments without external cloud snapshot APIs, backup procedures must rely on deterministic local volume snapshots, offline object synchronization, and filesystem backups.

| Subsystem | Storage Mechanism | Backup Frequency | Target Artifact |
| :--- | :--- | :--- | :--- |
| **Raw Evidence (MinIO)** | S3 Object Bucket (`ulpf-raw`) | Continuous / Daily | MinIO Bucket Mirror (`mc mirror`) |
| **SIEM Search Index (OpenSearch)** | Sharded Index Patterns | Daily | OpenSearch Snapshot API to local shared filesystem |
| **Local Search Index (SQLite)** | SQLite 3 WAL file | Daily | SQLite VACUUM INTO command |
| **Parser Catalog & Onboarding** | JSON AST Definitions | Post-publication / Daily | Directory Tarball (`data/parsers`, `data/onboarding_sessions`) |
| **Analytical Data Lake** | Apache Parquet Partitions | Weekly | Date-partitioned directory tarball (`data/data_lake`) |

---

## 2. MinIO Air-Gapped Backup & Restore

### Backup:
```bash
# Using the offline MinIO client (mc)
mc alias set local-minio http://127.0.0.1:9000 minioadmin minioadmin123
mc mirror --overwrite local-minio/ulpf-raw /backup/storage/minio/ulpf-raw-$(date +%F)
```

### Restore:
```bash
mc mirror --overwrite /backup/storage/minio/ulpf-raw-2026-08-30 local-minio/ulpf-raw
```

---

## 3. SQLite Search Index Backup (Development / Standalone Mode)

```bash
# Safely snapshot live SQLite WAL database without service interruption
sqlite3 data/search_index.db "VACUUM INTO '/backup/storage/sqlite/search_index_$(date +%F).db';"
```

---

## 4. Parser Registry & Onboarding Configuration Backup

```bash
# Archive all compiled parsers, active mappings, and audit trails
tar -czf /backup/storage/config/ulpf_parsers_$(date +%F).tar.gz data/parsers/ data/onboarding_sessions/ data/error_queue/
```
