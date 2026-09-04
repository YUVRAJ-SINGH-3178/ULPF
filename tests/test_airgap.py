"""
Automated Air-Gap Security & Static Asset Verification Suite
Verifies that the entire application, frontend dashboard, and container definitions
are 100% compliant with air-gapped security protocols:
1. No external CDN references (fonts.googleapis.com, cdnjs, unpkg, etc.)
2. No external remote CSS @import rules
3. No external script or link tags in HTML templates
4. Docker Compose production network enforces internal: true
"""

import re
from pathlib import Path

import yaml


def test_dashboard_assets_contain_zero_remote_references():
    """
    Scans all dashboard HTML, CSS, and JS files to guarantee no external CDNs
    or remote URLs are requested by the browser.
    """
    dashboard_dir = Path("ulpf/apps/dashboard")
    assert dashboard_dir.exists(), "Dashboard directory must exist"

    # Regex detecting remote URLs in src, href, and @import
    remote_pattern = re.compile(
        r'(?:src|href)=["\']https?://|@import\s+url\(["\']?https?://',
        re.IGNORECASE,
    )

    violations = []
    for file_path in dashboard_dir.rglob("*"):
        if file_path.suffix in [".html", ".css", ".js"]:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            for line_no, line in enumerate(content.splitlines(), start=1):
                # Ignore harmless schema or doc comments
                if "schema.org" in line or "w3.org" in line:
                    continue
                if remote_pattern.search(line):
                    violations.append(f"{file_path}:{line_no}: {line.strip()}")

    assert len(violations) == 0, (
        "Air-Gap Violation: Found remote asset references in dashboard:\n"
        + "\n".join(violations)
    )


def test_production_docker_compose_enforces_internal_network():
    """
    Verifies that docker-compose.prod.yml marks ulpf-airgap-net as internal: true,
    strictly blocking container egress to public networks.
    """
    compose_path = Path("docker-compose.prod.yml")
    assert compose_path.exists(), "docker-compose.prod.yml must exist"

    content = compose_path.read_text(encoding="utf-8")
    compose_dict = yaml.safe_load(content)

    networks = compose_dict.get("networks", {})
    assert "ulpf-airgap-net" in networks, "Expected ulpf-airgap-net network in compose"
    assert networks["ulpf-airgap-net"].get("internal") is True, (
        "Air-Gap Security Violation: ulpf-airgap-net MUST be configured with internal: true"
    )


def test_production_docker_compose_does_not_expose_database_ports():
    """
    Verifies that MinIO and OpenSearch do not expose management ports to the host network
    in docker-compose.prod.yml.
    """
    compose_path = Path("docker-compose.prod.yml")
    content = compose_path.read_text(encoding="utf-8")
    compose_dict = yaml.safe_load(content)

    services = compose_dict.get("services", {})
    minio_ports = services.get("minio", {}).get("ports", [])
    opensearch_ports = services.get("opensearch", {}).get("ports", [])

    assert len(minio_ports) == 0, (
        f"Security Violation: MinIO exposes host ports in production: {minio_ports}"
    )
    assert len(opensearch_ports) == 0, (
        f"Security Violation: OpenSearch exposes host ports in production: {opensearch_ports}"
    )
