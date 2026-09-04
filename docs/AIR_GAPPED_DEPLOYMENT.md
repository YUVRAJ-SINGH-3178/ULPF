# ULPF Air-Gapped Deployment Guide
**Zero-Network Operational Certification for High-Security / Defense Environments**

**Organization**: National Technical Research Organisation (NTRO) · SIH26156  
**Verification Status**: **EXECUTED & VERIFIED** (Automated validation via `tests/test_airgap.py`)

---

## 1. Air-Gapped Architectural Guarantees

ULPF is engineered to operate in **100% isolated, physically air-gapped secure facilities** (e.g., SCIFs, defense operations centers, sovereign strategic enclaves).

### Absolute Air-Gap Rules Enforced:
1. **Zero External Sockets**: No external DNS queries, cloud API calls, telemetry beacons, or external CDN dependencies.
2. **Offline System Typography & Assets**: All web fonts, CSS, JavaScript, and icons are bundled locally or resolve to system fonts (`Segoe UI`, `SF Pro`, `Inter`, `Roboto`, `sans-serif`) without remote `@import` rules or broken styling.
3. **Internal Container Isolation**: In `docker-compose.prod.yml`, the bridge network `ulpf-airgap-net` enforces `internal: true`, blocking container egress to external gateways.
4. **Internal Port Restriction**: Internal databases (MinIO, OpenSearch) do not expose management ports on the host network.
5. **Offline Intelligence & Assets**: GeoIP resolution and Enterprise Asset Inventory are bundled into static offline tables with zero live network calls.
6. **Embedded Engine Fallback**: Embedded SQLite FTS5, DuckDB vectorized engine, and local Parquet writers allow full operational capabilities without external network dependencies.

---

## 2. Air-Gap Packaging Workflow

### Step 1: Exporting Docker Image for Offline Transfer
On an air-gap staging / signing station:
```bash
# Build self-contained image
docker build -t ulpf:1.0.0 -f docker/Dockerfile .

# Save image tarball to optical media / approved data diode
docker save ulpf:1.0.0 | gzip > ulpf_airgap_bundle_v1.0.0.tar.gz
```

### Step 2: Loading & Running on the Air-Gapped Host
On the isolated strategic system:
```bash
# Load Docker image
docker load < ulpf_airgap_bundle_v1.0.0.tar.gz

# Start ULPF with production compose
docker compose -f docker-compose.prod.yml up -d
```

---

## 3. Verification of Air-Gap Compliance

To verify air-gap compliance:
1. Run automated air-gap regression suite:
   ```bash
   python -m pytest tests/test_airgap.py -v
   ```
   - Checks that zero remote HTTP/HTTPS/CDN references exist across all dashboard HTML, CSS, and JS.
   - Verifies `docker-compose.prod.yml` enforces `internal: true` on `ulpf-airgap-net`.
   - Verifies MinIO and OpenSearch do not expose ports to the host network.
2. Verify deep health check `/api/pipeline/health` returns `air_gapped: true` and `external_network_dependencies: false`.
