"""
OSINT-RECON Target Authorization & Scope Control Module
Enforces strict lab scope allowlists, input validation, and authorization records
prior to executing active reconnaissance.
"""

import os
import re
import json
import socket
import ipaddress
import subprocess
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

from src.schema import TargetAuthorizationRecord

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_CONFIG_PATH = os.path.join(PROJECT_ROOT, "config", "target_authorization.json")


class TargetAuthorizationError(PermissionError):
    """Raised when a target or profile violates authorization boundaries."""
    pass


class TargetSyntaxError(ValueError):
    """Raised when a target format is invalid, malformed, or unauthorized CIDR."""
    pass


class TargetAuthorizer:
    """
    Validates target formatting and enforces configuration allowlists
    for active reconnaissance.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self.config = self._load_config()
        self.default_target = self.config.get("default_target", "192.168.56.111")
        self.authorized_targets = self.config.get("authorized_targets", [])
        self.rules = self.config.get("rules", {
            "allow_cidr_ranges": False,
            "allow_public_ips": False,
            "allow_unlisted_targets": False,
            "require_explicit_authorization": True
        })

    def _load_config(self) -> Dict[str, Any]:
        """Loads target authorization allowlist from configuration file."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                raise RuntimeError(f"Failed to load authorization config from {self.config_path}: {e}")
        return {
            "default_target": "192.168.56.111",
            "authorized_targets": [
                {
                  "target": "192.168.56.111",
                  "target_type": "ipv4",
                  "name": "Metasploitable2 (Local VirtualBox Lab VM)",
                  "category": "intentionally_vulnerable_lab",
                  "authorization_status": "AUTHORIZED_LOCAL_LAB",
                  "scope": "192.168.56.111 (Host-Only Network 192.168.56.0/24)",
                  "permitted_profiles": ["lab-basic", "lab-safe-minimal", "lab-common-services"],
                  "allowed_ports": "1-65535",
                  "operator": "asip_ali"
                }
            ],
            "rules": {
                "allow_cidr_ranges": False,
                "allow_public_ips": False,
                "allow_unlisted_targets": False,
                "require_explicit_authorization": True
            }
        }

    def validate_target_syntax(self, target: str) -> Tuple[str, str]:
        """
        Validates target format.
        Rejects CIDR notations, URLs, shell characters, and invalid syntaxes.
        Returns: (clean_target, target_type) where target_type is 'ipv4', 'ipv6', or 'hostname'.
        """
        if not target or not isinstance(target, str):
            raise TargetSyntaxError("Target must be a non-empty string.")

        clean = target.strip()

        # Reject URL prefixes
        if clean.lower().startswith(("http://", "https://", "ftp://", "ssh://")):
            raise TargetSyntaxError(f"Target '{target}' contains URL protocol scheme. Specify host/IP only.")

        # Reject CIDR ranges (prohibit broad network sweeps)
        if "/" in clean:
            raise TargetSyntaxError(
                f"Target '{target}' contains CIDR range notation. "
                "Arbitrary subnet scanning and CIDR ranges are strictly forbidden."
            )

        # Reject shell metacharacters and suspicious control sequences
        if any(c in clean for c in [";", "&", "|", "`", "$", " ", "\t", "\n", "\r", ">", "<", "\"", "'", "\\"]):
            raise TargetSyntaxError(f"Target '{target}' contains invalid or unsafe shell characters.")

        # Remove port if specified as host:port
        clean = clean.split(":")[0]

        # 1. Check IP address
        try:
            ip_obj = ipaddress.ip_address(clean)
            target_type = "ipv4" if ip_obj.version == 4 else "ipv6"

            # Check if public IP and rule forbids public scanning
            if not self.rules.get("allow_public_ips", False) and not (ip_obj.is_private or ip_obj.is_loopback):
                raise TargetAuthorizationError(
                    f"Target IP '{clean}' is a public routable address. "
                    "Active reconnaissance against unauthorized public internet infrastructure is strictly prohibited."
                )

            return clean, target_type
        except ValueError:
            pass  # Not an IP address, proceed to hostname check

        # 2. Hostname validation (RFC 1123)
        hostname_regex = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if not re.match(hostname_regex, clean) and clean != "localhost":
            raise TargetSyntaxError(f"Invalid target IP address or hostname format: '{clean}'")

        # Public hostname check
        if not self.rules.get("allow_public_ips", False):
            raise TargetAuthorizationError(
                f"Target hostname '{clean}' resolves to or represents external infrastructure. "
                "Active reconnaissance is strictly confined to authorized local lab targets."
            )

        return clean.lower(), "hostname"

    def authorize_target(
        self,
        target: Optional[str] = None,
        profile: str = "lab-basic",
        operator: str = "asip_ali",
        investigation_id: Optional[str] = None,
        repo: Optional[Any] = None
    ) -> TargetAuthorizationRecord:
        """
        Enforces target authorization against explicit configuration allowlist and
        optional investigation-specific database target registration.
        Generates and returns a signed TargetAuthorizationRecord.
        """
        # Default to initial lab target if none provided
        effective_target = target.strip() if target else self.default_target

        # Validate syntax and safety
        clean_target, target_type = self.validate_target_syntax(effective_target)

        # If repo and investigation_id are provided, verify database registration
        db_entry = None
        if repo is not None and investigation_id is not None:
            inv_targets = repo.list_authorized_targets(investigation_id=investigation_id)
            db_entry = next((item for item in inv_targets if item.get("target") == clean_target), None)
            if not db_entry:
                raise TargetAuthorizationError(
                    f"Target '{clean_target}' is NOT registered as an authorized target under investigation '{investigation_id}'. "
                    "Target must be explicitly added to the investigation before active reconnaissance can be launched."
                )

        # Match against allowlist
        entry = next((item for item in self.authorized_targets if item.get("target") == clean_target), None)
        if not entry and not db_entry:
            raise TargetAuthorizationError(
                f"Target '{clean_target}' is NOT in the authorized active reconnaissance allowlist.\n"
                f"Authorized lab targets: {[t.get('target') for t in self.authorized_targets]}.\n"
                "To scan a target, it must be explicitly configured in config/target_authorization.json."
            )

        permitted_profiles = ["lab-basic"]
        if db_entry:
            permitted_profiles_raw = db_entry.get("permitted_profiles", "lab-basic")
            if isinstance(permitted_profiles_raw, list):
                permitted_profiles = permitted_profiles_raw
            else:
                permitted_profiles = [p.strip() for p in str(permitted_profiles_raw).split(",") if p.strip()]
        elif entry:
            permitted_profiles = entry.get("permitted_profiles", ["lab-basic"])

        if profile not in permitted_profiles and profile != "default":
            raise TargetAuthorizationError(
                f"Scan profile '{profile}' is not authorized for target '{clean_target}'.\n"
                f"Permitted profiles for this target: {permitted_profiles}"
            )

        auth_status = "AUTHORIZED_LOCAL_LAB"
        category = "intentionally_vulnerable_lab"
        scope = f"{clean_target} scope"
        notes = None

        if db_entry:
            auth_status = db_entry.get("authorization_status", "AUTHORIZED_LOCAL_LAB")
            scope = db_entry.get("scope", scope)
            operator = db_entry.get("authorized_by", operator)
        elif entry:
            auth_status = entry.get("authorization_status", "AUTHORIZED_LOCAL_LAB")
            category = entry.get("category", "intentionally_vulnerable_lab")
            scope = entry.get("scope", scope)
            notes = entry.get("notes")

        return TargetAuthorizationRecord(
            target=clean_target,
            authorized=True,
            authorization_status=auth_status,
            category=category,
            scope=scope,
            permitted_profiles=permitted_profiles,
            scan_profile=profile,
            operator=operator,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            notes=notes
        )

    @staticmethod
    def verify_target_connectivity(target: str, timeout: float = 1.5) -> Tuple[bool, str]:
        """
        Checks whether target host is responsive on the network.
        CRITICAL: A responsive target does NOT imply authorization.
        Authorization must always be verified first.
        """
        # Non-destructive TCP probe on common ports
        for test_port in [22, 80, 21, 23, 445]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                res = s.connect_ex((target, test_port))
                s.close()
                if res == 0:
                    return True, f"Target {target} is UP (responding on TCP port {test_port})"
            except Exception:
                pass

        # Try ICMP ping probe (1 packet)
        try:
            res = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout)), target],
                capture_output=True,
                text=True,
                timeout=timeout + 1
            )
            if res.returncode == 0:
                return True, f"Target {target} is UP (responding to ICMP echo)"
        except Exception:
            pass

        return False, f"Target {target} is UNREACHABLE or OFFLINE (no TCP handshake or ICMP echo received)"

