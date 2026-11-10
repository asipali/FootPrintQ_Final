"""
OSINT-RECON Greenbone GMP Client Integration Module
Interfaces directly with the Greenbone Vulnerability Management (gvmd) daemon
via official GMP protocols over Unix domain sockets or TLS.
"""

import os
from typing import Optional, Dict, List, Any, Tuple
import xml.etree.ElementTree as ET

try:
    import gvm
    from gvm.connections import UnixSocketConnection, TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.errors import GvmError, GvmResponseError
    HAVE_PYTHON_GVM = True
except ImportError:
    HAVE_PYTHON_GVM = False
    GvmError = Exception
    GvmResponseError = Exception

from src.integrations.greenbone_auth import GreenboneAuthConfig


class GreenboneClientError(Exception):
    """Base exception for Greenbone integration errors."""
    pass


class GreenboneConnectionError(GreenboneClientError):
    """Raised when communication with GVM daemon fails."""
    pass


class GreenboneAuthError(GreenboneClientError):
    """Raised when authentication with GVM fails."""
    pass


class GreenboneReadinessError(GreenboneClientError):
    """Raised when scanner or feeds are not ready."""
    pass


class GreenboneClient:
    """
    Client for Greenbone Management Protocol (GMP).
    Wraps python-gvm to execute scans, poll status, and retrieve vulnerability reports.
    """

    def __init__(self, auth_config: Optional[GreenboneAuthConfig] = None):
        self.auth_config = auth_config or GreenboneAuthConfig()
        self.connection = None
        self.gmp: Optional[Gmp] = None
        self._authenticated = False

    def is_library_available(self) -> bool:
        """Checks if python-gvm is installed in the active environment."""
        return HAVE_PYTHON_GVM

    def connect(self):
        """Establishes connection to GVM socket or TLS port."""
        if not HAVE_PYTHON_GVM:
            raise GreenboneConnectionError(
                "python-gvm library is not available. Please install it with 'pip install python-gvm'."
            )

        try:
            if self.auth_config.host:
                self.connection = TLSConnection(
                    hostname=self.auth_config.host,
                    port=self.auth_config.port or 9390,
                    timeout=self.auth_config.timeout
                )
            else:
                sock_path = self.auth_config.socket_path
                if not os.path.exists(sock_path):
                    raise GreenboneConnectionError(
                        f"GVM Unix socket '{sock_path}' does not exist. Verify gvmd service is running."
                    )
                self.connection = UnixSocketConnection(
                    path=sock_path,
                    timeout=self.auth_config.timeout
                )

            self.gmp = Gmp(connection=self.connection)
            self.gmp.connect()
        except (ConnectionRefusedError, FileNotFoundError, PermissionError) as e:
            raise GreenboneConnectionError(f"Failed to connect to GVM endpoint: {str(e)}") from e
        except Exception as e:
            raise GreenboneConnectionError(f"Unexpected connection error to GVM: {str(e)}") from e

    def authenticate(self):
        """Authenticates session using configured credentials."""
        if not self.gmp:
            self.connect()

        valid, msg = self.auth_config.validate_credentials()
        if not valid:
            raise GreenboneAuthError(msg)

        try:
            self.gmp.authenticate(
                username=self.auth_config.username,
                password=self.auth_config.password
            )
            self._authenticated = True
        except GvmResponseError as gre:
            raise GreenboneAuthError(f"GVM authentication failed: {str(gre)}") from gre
        except Exception as e:
            raise GreenboneAuthError(f"Authentication error: {str(e)}") from e

    def get_version(self) -> str:
        """Retrieves GMP and GVM version string."""
        if not self.gmp:
            self.connect()
        try:
            resp = self.gmp.get_version()
            root = ET.fromstring(resp) if isinstance(resp, str) else resp
            ver = root.findtext("version") or "Unknown"
            return ver
        except Exception as e:
            raise GreenboneConnectionError(f"Failed to retrieve GVM version: {str(e)}") from e

    def check_readiness(self) -> Dict[str, Any]:
        """
        Verifies scanner registration and vulnerability feed readiness.
        Returns:
            {
                "ready": bool,
                "scanners": [{"name": str, "status": str, "id": str}],
                "feeds": [{"type": str, "version": str, "status": str}],
                "errors": [str]
            }
        """
        if not self._authenticated:
            self.authenticate()

        readiness: Dict[str, Any] = {
            "ready": True,
            "scanners": [],
            "feeds": [],
            "errors": []
        }

        # 1. Check Scanners
        try:
            resp = self.gmp.get_scanners()
            root = ET.fromstring(resp) if isinstance(resp, str) else resp
            scanners = root.findall(".//scanner")
            for sc in scanners:
                sc_id = sc.get("id")
                sc_name = sc.findtext("name") or "Unnamed"
                sc_status = sc.findtext("status") or "Unknown"
                readiness["scanners"].append({
                    "id": sc_id,
                    "name": sc_name,
                    "status": sc_status
                })

            if not scanners:
                readiness["ready"] = False
                readiness["errors"].append("No vulnerability scanners registered in GVM.")
        except Exception as e:
            readiness["ready"] = False
            readiness["errors"].append(f"Scanner check failed: {str(e)}")

        # 2. Check Feeds
        try:
            resp = self.gmp.get_feeds()
            root = ET.fromstring(resp) if isinstance(resp, str) else resp
            feeds = root.findall(".//feed")
            for fd in feeds:
                f_type = fd.findtext("type") or "Unknown"
                f_ver = fd.findtext("version") or "None"
                f_stat = fd.findtext("status") or "Unknown"
                readiness["feeds"].append({
                    "type": f_type,
                    "version": f_ver,
                    "status": f_stat
                })
                if f_stat.lower() in ("failed", "incomplete", "outdated") or f_ver in ("None", ""):
                    readiness["ready"] = False
                    readiness["errors"].append(f"Feed '{f_type}' is unready or incomplete (version: {f_ver}, status: {f_stat}).")

            if not feeds:
                readiness["ready"] = False
                readiness["errors"].append("No vulnerability test feeds found in GVM.")
        except Exception as e:
            readiness["ready"] = False
            readiness["errors"].append(f"Feed status check failed: {str(e)}")

        return readiness

    def get_scan_configs(self) -> List[Dict[str, str]]:
        """Lists available scan configurations (e.g. 'Full and fast', 'Base')."""
        if not self._authenticated:
            self.authenticate()

        configs: List[Dict[str, str]] = []
        try:
            resp = self.gmp.get_scan_configs()
            root = ET.fromstring(resp) if isinstance(resp, str) else resp
            for cfg in root.findall(".//config"):
                configs.append({
                    "id": cfg.get("id", ""),
                    "name": cfg.findtext("name") or "Unnamed",
                    "comment": cfg.findtext("comment") or ""
                })
            return configs
        except Exception as e:
            raise GreenboneClientError(f"Failed to list scan configs: {str(e)}") from e

    def get_or_create_target(self, name: str, hosts: List[str], port_list_id: Optional[str] = None) -> str:
        """Creates a scan target or reuses an existing matching target. Returns target UUID."""
        if not self._authenticated:
            self.authenticate()

        hosts_str = ", ".join(hosts)
        try:
            # Check existing targets
            resp = self.gmp.get_targets(filter_string=f"name={name}")
            root = ET.fromstring(resp) if isinstance(resp, str) else resp
            existing = root.find(".//target")
            if existing is not None:
                return existing.get("id")

            # Create new target
            create_resp = self.gmp.create_target(
                name=name,
                hosts=hosts,
                port_list_id=port_list_id
            )
            c_root = ET.fromstring(create_resp) if isinstance(create_resp, str) else create_resp
            target_id = c_root.get("id")
            if not target_id:
                raise GreenboneClientError("Target creation response did not return target UUID.")
            return target_id
        except Exception as e:
            raise GreenboneClientError(f"Failed to create target '{name}' for '{hosts_str}': {str(e)}") from e

    def create_task(
        self,
        name: str,
        config_id: str,
        target_id: str,
        scanner_id: Optional[str] = None
    ) -> str:
        """Creates a vulnerability assessment task. Returns task UUID."""
        if not self._authenticated:
            self.authenticate()

        try:
            resp = self.gmp.create_task(
                name=name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id
            )
            root = ET.fromstring(resp) if isinstance(resp, str) else resp
            task_id = root.get("id")
            if not task_id:
                raise GreenboneClientError("Task creation response did not return task UUID.")
            return task_id
        except Exception as e:
            raise GreenboneClientError(f"Failed to create scan task '{name}': {str(e)}") from e

    def start_task(self, task_id: str) -> str:
        """Starts task execution. Returns report UUID."""
        if not self._authenticated:
            self.authenticate()

        try:
            resp = self.gmp.start_task(task_id=task_id)
            root = ET.fromstring(resp) if isinstance(resp, str) else resp
            report_id = root.findtext(".//report_id") or ""
            return report_id
        except Exception as e:
            raise GreenboneClientError(f"Failed to start scan task '{task_id}': {str(e)}") from e

    def get_task_status(self, task_id: str) -> Tuple[str, int]:
        """Returns: (status_str, progress_percent)."""
        if not self._authenticated:
            self.authenticate()

        try:
            resp = self.gmp.get_task(task_id=task_id)
            root = ET.fromstring(resp) if isinstance(resp, str) else resp
            task = root.find(".//task")
            if task is None:
                return "Unknown", 0
            status = task.findtext("status") or "Unknown"
            progress_str = task.findtext("progress") or "0"
            try:
                progress = int(progress_str)
            except ValueError:
                progress = 0
            return status, progress
        except Exception as e:
            raise GreenboneClientError(f"Failed to query task status for '{task_id}': {str(e)}") from e

    def stop_task(self, task_id: str):
        """Stops/cancels a running task."""
        if not self._authenticated:
            self.authenticate()
        try:
            self.gmp.stop_task(task_id=task_id)
        except Exception as e:
            raise GreenboneClientError(f"Failed to stop task '{task_id}': {str(e)}") from e

    def get_report(self, report_id: str, report_format_id: Optional[str] = None) -> str:
        """Retrieves raw report XML content string."""
        if not self._authenticated:
            self.authenticate()

        try:
            resp = self.gmp.get_report(
                report_id=report_id,
                report_format_id=report_format_id
            )
            if isinstance(resp, str):
                return resp
            return ET.tostring(resp, encoding="utf-8").decode("utf-8")
        except Exception as e:
            raise GreenboneClientError(f"Failed to retrieve report '{report_id}': {str(e)}") from e

    def disconnect(self):
        """Safely disconnects from GVM."""
        if self.gmp:
            try:
                self.gmp.disconnect()
            except Exception:
                pass
        self._authenticated = False
        self.gmp = None
        self.connection = None

