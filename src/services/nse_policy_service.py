"""
FootprintIQ - NSE Script Policy Service
Maintains approved script allowlists, enforces execution tiers (safe, discovery, vuln),
and prevents command injection or arbitrary intrusive script execution.
"""

from typing import List, Dict, Any, Tuple
import re

# Approved scripts categorized by risk and purpose
APPROVED_NSE_SCRIPTS: Dict[str, Dict[str, Any]] = {
    # Discovery & Service Information (Safe)
    "banner": {"category": "discovery", "risk_tier": "safe", "ports": "all", "description": "Banner grabber"},
    "http-title": {"category": "discovery", "risk_tier": "safe", "ports": "80,443,8080,3000", "description": "Fetches web page title"},
    "http-headers": {"category": "discovery", "risk_tier": "safe", "ports": "80,443,8080,3000", "description": "Inspects HTTP response headers"},
    "http-methods": {"category": "discovery", "risk_tier": "safe", "ports": "80,443,8080,3000", "description": "Finds supported HTTP request methods"},
    "ssl-cert": {"category": "discovery", "risk_tier": "safe", "ports": "443,8443", "description": "Retrieves SSL/TLS certificate information"},
    "ssh2-enum-algos": {"category": "discovery", "risk_tier": "safe", "ports": "22", "description": "Enumerates supported SSH cryptographic algorithms"},
    "ftp-anon": {"category": "discovery", "risk_tier": "safe", "ports": "21", "description": "Checks if anonymous FTP login is permitted"},
    "smb-os-discovery": {"category": "discovery", "risk_tier": "safe", "ports": "139,445", "description": "Determines target OS and SMB dialect"},
    "smb-security-mode": {"category": "discovery", "risk_tier": "safe", "ports": "139,445", "description": "Checks SMB message signing and security level"},
    "mysql-info": {"category": "discovery", "risk_tier": "safe", "ports": "3306", "description": "Connects and retrieves MySQL version and flags"},
    "postgresql-info": {"category": "discovery", "risk_tier": "safe", "ports": "5432", "description": "Retrieves PostgreSQL server protocol and parameters"},

    # Safe Vulnerability Detection Checks (Non-destructive)
    "ftp-vsftpd-backdoor": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "ports": "21",
        "cve": "CVE-2011-2523",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Checks for vsftpd 2.3.4 Smiley Face Backdoor"
    },
    "ssl-heartbleed": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "ports": "443,8443",
        "cve": "CVE-2014-0160",
        "cvss": 7.5,
        "severity": "High",
        "description": "Checks OpenSSL TLS heartbeat information disclosure"
    },
    "ssl-poodle": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "ports": "443,8443",
        "cve": "CVE-2014-3566",
        "cvss": 4.3,
        "severity": "Medium",
        "description": "Checks for SSLv3 CBC ciphersuite vulnerability (POODLE)"
    },
    "ssl-ccs-injection": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "ports": "443,8443",
        "cve": "CVE-2014-0224",
        "cvss": 6.8,
        "severity": "Medium",
        "description": "Checks for OpenSSL ChangeCipherSpec injection"
    },
    "smb-vuln-ms17-010": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "ports": "445",
        "cve": "CVE-2017-0143",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Checks for SMBv1 remote code execution (EternalBlue)"
    },
    "smb-vuln-ms08-067": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "ports": "139,445",
        "cve": "CVE-2008-4250",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Checks for Windows Server service RPC path vulnerability"
    },
    "http-vuln-cve2014-3704": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "ports": "80,443",
        "cve": "CVE-2014-3704",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Checks for Drupalgeddon SQL injection vulnerability"
    }
}

# Strict script identifier regex to prevent command injection
SCRIPT_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]{2,50}$')


class NSEPolicyService:
    @staticmethod
    def get_allowed_scripts(category: str = "all") -> List[str]:
        """
        Returns list of script names in the specified category.
        """
        if category == "all":
            return list(APPROVED_NSE_SCRIPTS.keys())
        return [k for k, v in APPROVED_NSE_SCRIPTS.items() if v.get("category") == category]

    @staticmethod
    def validate_scripts(requested_scripts: List[str], allow_vuln_checks: bool = True) -> Tuple[List[str], List[str]]:
        """
        Validates requested script names against the allowlist and safety policy.
        Returns: (approved_list, rejected_list)
        """
        approved = []
        rejected = []

        for script in requested_scripts:
            clean_name = script.strip().lower()
            if not SCRIPT_NAME_REGEX.match(clean_name):
                rejected.append(f"{script} (invalid script name format)")
                continue

            if clean_name not in APPROVED_NSE_SCRIPTS:
                rejected.append(f"{script} (not on approved allowlist)")
                continue

            script_meta = APPROVED_NSE_SCRIPTS[clean_name]
            if script_meta.get("risk_tier") == "vuln_check" and not allow_vuln_checks:
                rejected.append(f"{script} (vulnerability check requires authorization)")
                continue

            approved.append(clean_name)

        return approved, rejected

    @staticmethod
    def get_script_metadata(script_name: str) -> Dict[str, Any]:
        return APPROVED_NSE_SCRIPTS.get(script_name.strip().lower(), {})

