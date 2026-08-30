# ULPF — OpenSearch SIEM Storage & Search Architecture

**Organization**: National Technical Research Organisation (NTRO) · SIH26156  
**Component**: Production SIEM Index Engine (`OpenSearchStore`)  

---

## 1. Overview

**OpenSearch** serves as the production search and operational analytics backend for ULPF. It stores structured, validated **OCSF 1.1.0** events alongside routing and parsing metadata, enabling SOC analysts to perform sub-millisecond full-text searches, faceted aggregations, and threat correlation.

---

## 2. Index Templates & Explicit Schema Mappings

To prevent dynamic mapping explosion and ensure optimal search performance across millions of events, ULPF registers an explicit index template (`ulpf-events-v1-template`) for index pattern `ulpf-events-v1-*`.

### Key Field Mappings

```json
{
  "properties": {
    "event_id": { "type": "keyword" },
    "ingest_timestamp": { "type": "date" },
    "time_epoch": { "type": "long" },
    "time_dt": { "type": "date" },
    "vendor": { "type": "keyword" },
    "product": { "type": "keyword" },
    "detected_format": { "type": "keyword" },
    "class_uid": { "type": "integer" },
    "class_name": { "type": "keyword" },
    "category_uid": { "type": "integer" },
    "severity_id": { "type": "integer" },
    "severity": { "type": "keyword" },
    "disposition_id": { "type": "integer" },
    "disposition": { "type": "keyword" },
    "action": { "type": "keyword" },
    "src_ip": { "type": "ip" },
    "src_port": { "type": "integer" },
    "dst_ip": { "type": "ip" },
    "dst_port": { "type": "integer" },
    "protocol_name": { "type": "keyword" },
    "raw_sha256": { "type": "keyword" },
    "raw_storage_uri": { "type": "keyword" },
    "byte_length": { "type": "integer" },
    "parser_used": { "type": "keyword" },
    "parser_version": { "type": "keyword" },
    "ocsf": { "type": "object", "dynamic": true }
  }
}
```

---

## 3. Idempotency & Duplicate Prevention

ULPF indexes documents using deterministic document IDs:
`_id = envelope.event_id`

If the same event is replayed or re-ingested, OpenSearch updates the existing document rather than creating conflicting duplicates.

---

## 4. Configuration Reference

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `ULPF_SEARCH_BACKEND` | `opensearch` (prod) / `sqlite` (dev) | Search store switch |
| `ULPF_OPENSEARCH_URL` | `http://opensearch:9200` | OpenSearch cluster host URL |
| `ULPF_OPENSEARCH_USERNAME` | `admin` | Cluster username |
| `ULPF_OPENSEARCH_PASSWORD` | `admin` | Cluster password |
| `ULPF_OPENSEARCH_INDEX_PREFIX` | `ulpf-events-v1` | Index pattern prefix |
| `ULPF_OPENSEARCH_VERIFY_CERTS` | `false` | SSL certificate verification |
| `ULPF_NORMALIZED_RETENTION_DAYS`| `90` | SIEM index retention policy (days) |
