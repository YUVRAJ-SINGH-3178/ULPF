"""
Offline Enrichment Engine
Provides GeoIP resolution, RFC1918 classification, and internal enterprise asset inventory lookups with zero network calls.
"""

import ipaddress
from typing import Any


class OfflineEnricher:
    """
    Offline enricher that annotates IP endpoints with enterprise asset inventory and offline geographic metadata.
    100% air-gapped safe.
    """

    # Static Enterprise Asset Inventory for NTRO / Enterprise Perimeter
    ASSET_INVENTORY: dict[str, dict[str, Any]] = {
        "10.0.0.1": {"name": "CORE-GW-01", "role": "Core Perimeter Gateway", "zone": "DMZ", "criticality": "High"},
        "10.0.0.5": {"name": "DC-PRIMARY-01", "role": "Domain Controller Active Directory", "zone": "Internal-Core", "criticality": "Critical"},
        "10.0.0.10": {"name": "DB-PROD-CLUSTER", "role": "Primary Database Cluster", "zone": "Database-Secure", "criticality": "Critical"},
        "10.0.1.50": {"name": "WEB-FRONTEND-01", "role": "Public Web Portal", "zone": "DMZ-Public", "criticality": "High"},
        "192.168.1.1": {"name": "FW-EDGE-PRIMARY", "role": "NextGen Perimeter Firewall", "zone": "Perimeter", "criticality": "Critical"},
        "192.168.1.100": {"name": "ADMIN-SEC-STATION", "role": "SOC Analyst Workstation", "zone": "Management", "criticality": "Medium"},
        "192.168.1.105": {"name": "DEV-BUILD-RUNNER", "role": "Internal Build Agent", "zone": "Development", "criticality": "Low"},
        "172.16.0.1": {"name": "VPN-CONCENTRATOR", "role": "Remote Access Gateway", "zone": "VPN-Edge", "criticality": "High"}
    }

    # Offline GeoIP Subnet Ranges
    OFFLINE_GEO_RANGES = [
        {"network": "8.8.8.0/24", "country": "United States", "country_code": "US", "city": "Mountain View", "as_name": "Google LLC", "as_num": 15169},
        {"network": "1.1.1.0/24", "country": "Australia", "country_code": "AU", "city": "Sydney", "as_name": "Cloudflare Inc", "as_num": 13335},
        {"network": "203.0.113.0/24", "country": "India", "country_code": "IN", "city": "New Delhi", "as_name": "NTRO Secure Backbone", "as_num": 55836},
        {"network": "198.51.100.0/24", "country": "Germany", "country_code": "DE", "city": "Frankfurt", "as_name": "European IX", "as_num": 24940},
        {"network": "185.220.101.0/24", "country": "Netherlands", "country_code": "NL", "city": "Amsterdam", "as_name": "Tor Exit Node Network", "as_num": 60729}
    ]

    def enrich(self, ocsf_doc: dict[str, Any]) -> dict[str, Any]:
        """
        Enriches src_endpoint and dst_endpoint in place.
        """
        if "src_endpoint" in ocsf_doc and isinstance(ocsf_doc["src_endpoint"], dict):
            self._enrich_endpoint(ocsf_doc["src_endpoint"])
        if "dst_endpoint" in ocsf_doc and isinstance(ocsf_doc["dst_endpoint"], dict):
            self._enrich_endpoint(ocsf_doc["dst_endpoint"])
        return ocsf_doc

    def _enrich_endpoint(self, ep: dict[str, Any]):
        ip_str = ep.get("ip")
        if not ip_str:
            return

        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return

        # 1. Private / RFC1918 classification
        is_private = ip_obj.is_private
        is_loopback = ip_obj.is_loopback

        # 2. Check Static Asset Inventory
        if ip_str in self.ASSET_INVENTORY:
            asset = self.ASSET_INVENTORY[ip_str]
            if not ep.get("hostname"):
                ep["hostname"] = asset["name"]
            if not ep.get("zone"):
                ep["zone"] = asset["zone"]
            ep["asset_info"] = {
                "name": asset["name"],
                "role": asset["role"],
                "zone": asset["zone"],
                "criticality": asset["criticality"]
            }

        # 3. Offline GeoIP check for public IPs
        if not is_private and not is_loopback:
            for geo in self.OFFLINE_GEO_RANGES:
                net = ipaddress.ip_network(geo["network"])
                if ip_obj in net:
                    ep["location"] = {
                        "country": geo["country"],
                        "city": geo["city"],
                        "country_code": geo["country_code"]
                    }
                    ep["autonomous_system"] = {
                        "name": geo["as_name"],
                        "number": geo["as_num"]
                    }
                    break
