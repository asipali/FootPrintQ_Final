"""
FootprintIQ - RDAP (Registration Data Access Protocol) Collector
Modern RESTful IP, ASN, and Domain registration data collector.
Complements and enhances traditional WHOIS reconnaissance.
"""

import logging
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger("FootprintIQ.RDAP")

DEFAULT_RDAP_TIMEOUT = 10


class RDAPCollector:
    def __init__(self, timeout: int = DEFAULT_RDAP_TIMEOUT):
        self.timeout = timeout

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Queries RDAP for an IPv4 or IPv6 address.
        """
        # Handle private/lab IP addresses gracefully
        if ip_address.startswith(("127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
            return {
                "status": "LOCAL_PRIVATE_IP",
                "ip": ip_address,
                "name": "Private/Local Address Space (RFC 1918)",
                "cidr": f"{ip_address}/24",
                "country": "LOCAL_LAB",
                "org": "Internal Lab Environment",
                "remarks": ["Private address range, RDAP queries are not sent to public RIRs."]
            }

        url = f"https://rdap.arin.net/registry/ip/{ip_address}"
        try:
            resp = requests.get(url, headers={"Accept": "application/rdap+json"}, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return self._parse_rdap_response(data, ip_address)
            return {"status": "NOT_FOUND", "http_code": resp.status_code, "ip": ip_address}
        except Exception as e:
            logger.warning(f"RDAP query failed for IP {ip_address}: {e}")
            return {"status": "ERROR", "error": str(e), "ip": ip_address}

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Queries RDAP for a domain name.
        """
        url = f"https://rdap.org/domain/{domain}"
        try:
            resp = requests.get(url, headers={"Accept": "application/rdap+json"}, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return self._parse_rdap_response(data, domain)
            return {"status": "NOT_FOUND", "http_code": resp.status_code, "domain": domain}
        except Exception as e:
            logger.warning(f"RDAP query failed for domain {domain}: {e}")
            return {"status": "ERROR", "error": str(e), "domain": domain}

    def _parse_rdap_response(self, data: Dict[str, Any], query: str) -> Dict[str, Any]:
        name = data.get("name") or data.get("handle", "")
        entities = []
        for ent in data.get("entities", []):
            handle = ent.get("handle")
            roles = ent.get("roles", [])
            entities.append({"handle": handle, "roles": roles})

        return {
            "status": "SUCCESS",
            "query": query,
            "handle": data.get("handle"),
            "name": name,
            "start_address": data.get("startAddress"),
            "end_address": data.get("endAddress"),
            "ip_version": data.get("ipVersion"),
            "country": data.get("country"),
            "entities": entities,
            "status_list": data.get("status", [])
        }

