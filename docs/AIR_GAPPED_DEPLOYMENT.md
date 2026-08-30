# ULPF Air-Gapped Deployment Guide
**Zero-Network Operational Certification for High-Security / Defense Environments**

---

## 1. Air-Gapped Architectural Guarantees

ULPF is engineered to operate in **100% isolated, physically air-gapped secure facilities** (e.g. SCIFs, military operations centers, isolated sovereign networks).

### Absolute Air-Gap Rules Enforced:
1. **Zero Outbound Sockets**: No external DNS queries, cloud API calls, telemetry beacons, or external CDN dependencies.
2. **Offline Web Assets**: All fonts, CSS, JavaScript, and icons are bundled locally or gracefully fallback to offline system fonts without broken styling.
3. **Offline Intelligence & Assets**: GeoIP resolution and Enterprise Asset Inventory are bundled into static offline tables with zero live network calls.
4. **Embedded Search & Storage**: Embedded SQLite FTS5, DuckDB analytical engine, and local Parquet writers eliminate the need for heavy external cloud databases.

---

## 2. Air-Gap Packaging Workflow

### Step 1: Exporting Docker Image for Offline Transfer
On an internet-connected build station:
```bash
# Build the self-contained image
docker build -t ulpf:1.0.0 -f docker/Dockerfile .

# Save the image tarball to USB/optical media
docker save ulpf:1.0.0 | gzip > ulpf_airgap_bundle_v1.0.0.tar.gz
```

### Step 2: Loading & Running on the Air-Gapped Target Host
On the isolated air-gapped system:
```bash
# Load Docker image
docker load < ulpf_airgap_bundle_v1.0.0.tar.gz

# Start ULPF container in isolated bridge network
docker run -d \
  --name ulpf-secure \
  --restart unless-stopped \
  --network none \
  -p 8000:8000 \
  -p 5140:5140/udp \
  -p 1514:1514 \
  -v /opt/ulpf/data:/app/data \
  ulpf:1.0.0
```

---

## 3. Verification of Air-Gap Compliance

To prove air-gap compliance to evaluators:
1. Disconnect the physical Ethernet cable / disable the network adapter on the host.
2. Ingest telemetry logs via the web UI or local replay.
3. Observe that log parsing, OCSF normalization, cryptographic hashing, Drain3 template mining, and SIEM search proceed without a single timeout or network error!
