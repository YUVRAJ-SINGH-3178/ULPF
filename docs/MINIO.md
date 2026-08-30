# ULPF — MinIO Raw Object Store Architecture & Operations

**Organization**: National Technical Research Organisation (NTRO) · SIH26156  
**Component**: Lossless Raw Evidence Preservation Store (`MinIORawStore`)  

---

## 1. Overview & Forensic Principle

In critical security infrastructure, log transformations (parsing, field extraction, enrichment) must never destroy or alter original evidence. **ULPF** writes the unmutated byte stream of every raw log directly into **MinIO** (S3-compatible object storage) **before** format detection or normalization takes place.

Every raw object is permanently linked to:
- `event_id`: Unique UUIDv4 identifier
- `sha256`: Cryptographic SHA-256 digest computed from exact raw bytes
- `raw_storage_uri`: Deterministic S3 URI (`ulpf-raw/year=YYYY/month=MM/day=DD/source=<source_id>/<event_id>.raw`)

---

## 2. Bucket Architecture & Object Layout

### Dedicated Evidence Bucket: `ulpf-raw`

```
ulpf-raw/
  year=2026/
    month=08/
      day=30/
        source=cisco/
          0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d.raw
          0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d.meta.json
        source=palo_alto/
          1f2e3d4c-5b6a-7890-abcd-ef0123456789.raw
          1f2e3d4c-5b6a-7890-abcd-ef0123456789.meta.json
```

### Companion Metadata Format (`.meta.json`)
```json
{
  "event_id": "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
  "bucket": "ulpf-raw",
  "object_key": "year=2026/month=08/day=30/source=cisco/0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d.raw",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "byte_length": 245,
  "stored_at": "2026-08-30T10:15:30.123456Z",
  "source": {
    "vendor": "cisco",
    "product": "asa",
    "detected_format": "rfc3164"
  }
}
```

---

## 3. Cryptographic Integrity Verification

When an analyst or auditor requests verification of an event, the system does not trust database records. It executes `POST /api/events/{event_id}/verify-integrity`:

```
1. Fetch exact raw byte stream from MinIO object: `GET /ulpf-raw/.../<event_id>.raw`
2. Stream raw bytes through hashlib.sha256() in memory
3. Compare computed SHA-256 with stored metadata hash
4. Return:
   {
     "is_valid": true,
     "tampered": false,
     "stored_sha256": "e3b0c44...",
     "computed_sha256": "e3b0c44...",
     "byte_length": 245
   }
```

---

## 4. Configuration Reference

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `ULPF_STORAGE_BACKEND` | `minio` (prod) / `local` (dev) | Storage backend switch |
| `ULPF_MINIO_ENDPOINT` | `minio:9000` | Host and port for MinIO server |
| `ULPF_MINIO_ACCESS_KEY` | `minioadmin` | Access key / root user |
| `ULPF_MINIO_SECRET_KEY` | `minioadmin123` | Secret key / root password |
| `ULPF_MINIO_RAW_BUCKET` | `ulpf-raw` | Dedicated raw evidence bucket name |
| `ULPF_MINIO_SECURE` | `false` | Enable TLS/HTTPS for MinIO |
| `ULPF_RAW_RETENTION_DAYS` | `365` | Retention policy for raw evidence |
