"""
OSINT-RECON Greenbone Collector Module
Coordinates with Greenbone GMP client to verify scanner/feed readiness, execute non-destructive
vulnerability scans against authorized targets, poll task status, and preserve raw evidence.
"""

import os
import time
import json
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

from src.integrations.greenbone_auth import GreenboneAuthConfig
from src.integrations.greenbone_client import (
    GreenboneClient,
    GreenboneClientError,
    GreenboneConnectionError,
    GreenboneAuthError
)


def compute_sha256(filepath: str) -> Optional[str]:
    """Computes SHA256 hash of a file."""
    if not filepath or not os.path.isfile(filepath):
        return None
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


class GreenboneCollectorResult:
    """Holds artifacts and execution metadata returned by GreenboneCollector."""

    def __init__(
        self,
        xml_path: Optional[str] = None,
        xml_content: Optional[str] = None,
        metadata_path: Optional[str] = None,
        task_id: Optional[str] = None,
        report_id: Optional[str] = None,
        status: str = "SUCCESS",
        duration_seconds: float = 0.0,
        file_hashes: Optional[Dict[str, str]] = None,
        error_message: Optional[str] = None
    ):
        self.xml_path = xml_path
        self.xml_content = xml_content
        self.metadata_path = metadata_path
        self.task_id = task_id
        self.report_id = report_id
        self.status = status
        self.duration_seconds = duration_seconds
        self.file_hashes = file_hashes or {}
        self.error_message = error_message


class GreenboneCollector:
    """
    Executes and monitors vulnerability scans through the Greenbone GMP client.
    Handles timeout management, polling, and cryptographic evidence preservation.
    """

    def __init__(
        self,
        auth_config: Optional[GreenboneAuthConfig] = None,
        client: Optional[GreenboneClient] = None
    ):
        self.auth_config = auth_config or GreenboneAuthConfig()
        self.client = client or GreenboneClient(auth_config=self.auth_config)

    def check_readiness(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Verifies local socket/TLS connectivity, authentication, scanner presence, and feed readiness.
        Returns: (is_ready, details_dict)
        """
        details: Dict[str, Any] = {
            "socket_exists": False,
            "connected": False,
            "authenticated": False,
            "scanners_ready": False,
            "feeds_ready": False,
            "gvm_version": None,
            "scanners": [],
            "feeds": [],
            "errors": []
        }

        # 1. Check socket or host
        ok_conn, conn_msg = self.auth_config.validate_connection_target()
        if not ok_conn:
            details["errors"].append(conn_msg)
            return False, details
        details["socket_exists"] = True

        # 2. Check credentials
        ok_cred, cred_msg = self.auth_config.validate_credentials()
        if not ok_cred:
            details["errors"].append(cred_msg)
            return False, details

        # 3. Connect & Authenticate
        try:
            self.client.connect()
            details["connected"] = True
            details["gvm_version"] = self.client.get_version()

            self.client.authenticate()
            details["authenticated"] = True
        except (GreenboneConnectionError, GreenboneAuthError) as e:
            details["errors"].append(str(e))
            return False, details
        except Exception as e:
            details["errors"].append(f"Unexpected error during GVM connection: {str(e)}")
            return False, details

        # 4. Check Scanner & Feed Readiness
        readiness_resp = self.client.check_readiness()
        details["scanners"] = readiness_resp.get("scanners", [])
        details["feeds"] = readiness_resp.get("feeds", [])
        details["scanners_ready"] = len(readiness_resp.get("scanners", [])) > 0
        details["feeds_ready"] = readiness_resp.get("ready", False)

        if readiness_resp.get("errors"):
            details["errors"].extend(readiness_resp["errors"])

        is_overall_ready = (
            details["connected"] and
            details["authenticated"] and
            details["scanners_ready"] and
            details["feeds_ready"]
        )
        return is_overall_ready, details

    def execute_scan(
        self,
        target_ip: str,
        config_name: str = "Full and fast",
        timeout: int = 1800,
        poll_interval: int = 10,
        output_dir: Optional[str] = None
    ) -> GreenboneCollectorResult:
        """
        Executes a live Greenbone vulnerability scan against the target IP.
        Polls until completion or timeout.
        """
        start_time = time.time()
        out_dir = output_dir or os.getcwd()
        os.makedirs(out_dir, exist_ok=True)

        # Readiness check
        is_ready, details = self.check_readiness()
        if not is_ready:
            err_msg = "; ".join(details["errors"]) or "Greenbone service or feeds not ready."
            return GreenboneCollectorResult(
                status="FAILED",
                duration_seconds=round(time.time() - start_time, 2),
                error_message=err_msg
            )

        try:
            # 1. Resolve Config UUID
            configs = self.client.get_scan_configs()
            cfg_obj = next((c for c in configs if c["name"].lower() == config_name.lower()), None)
            if not cfg_obj:
                cfg_obj = configs[0] if configs else None
            if not cfg_obj:
                raise GreenboneClientError(f"No scan configs found matching '{config_name}'.")

            config_id = cfg_obj["id"]

            # 2. Create Target
            target_name = f"OSINT-RECON Target {target_ip}"
            target_id = self.client.get_or_create_target(name=target_name, hosts=[target_ip])

            # 3. Create Task
            task_name = f"OSINT-RECON Assessment {target_ip} ({datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')})"
            task_id = self.client.create_task(name=task_name, config_id=config_id, target_id=target_id)

            # 4. Start Task
            report_id = self.client.start_task(task_id=task_id)

            # 5. Poll Task Status
            elapsed = 0
            while elapsed < timeout:
                status, progress = self.client.get_task_status(task_id)
                if status in ("Done", "Stopped"):
                    break
                elif status in ("Internal Error", "Error"):
                    raise GreenboneClientError(f"GVM task '{task_id}' failed with status: {status}")

                time.sleep(poll_interval)
                elapsed = int(time.time() - start_time)

            if elapsed >= timeout:
                # Attempt to stop task on timeout
                try:
                    self.client.stop_task(task_id)
                except Exception:
                    pass
                return GreenboneCollectorResult(
                    task_id=task_id,
                    report_id=report_id,
                    status="TIMEOUT",
                    duration_seconds=round(time.time() - start_time, 2),
                    error_message=f"Assessment exceeded maximum configured timeout of {timeout}s."
                )

            # 6. Retrieve Report XML
            xml_content = self.client.get_report(report_id=report_id)

            # 7. Persist Evidence to disk
            xml_path = os.path.join(out_dir, "greenbone_report.xml")
            with open(xml_path, "w", encoding="utf-8") as xf:
                xf.write(xml_content)

            xml_hash = compute_sha256(xml_path) or ""

            # Metadata
            meta_path = os.path.join(out_dir, "greenbone_metadata.json")
            meta_dict = {
                "task_id": task_id,
                "target_id": target_id,
                "report_id": report_id,
                "config_name": config_name,
                "config_id": config_id,
                "target_ip": target_ip,
                "duration_seconds": round(time.time() - start_time, 2),
                "xml_sha256": xml_hash
            }
            with open(meta_path, "w", encoding="utf-8") as mf:
                json.dump(meta_dict, mf, indent=2)

            meta_hash = compute_sha256(meta_path) or ""

            return GreenboneCollectorResult(
                xml_path=xml_path,
                xml_content=xml_content,
                metadata_path=meta_path,
                task_id=task_id,
                report_id=report_id,
                status="SUCCESS",
                duration_seconds=round(time.time() - start_time, 2),
                file_hashes={"xml": xml_hash, "metadata": meta_hash}
            )

        except Exception as e:
            return GreenboneCollectorResult(
                status="FAILED",
                duration_seconds=round(time.time() - start_time, 2),
                error_message=str(e)
            )
        finally:
            self.client.disconnect()

    def import_report_file(self, xml_file_path: str, output_dir: Optional[str] = None) -> GreenboneCollectorResult:
        """
        Imports an existing Greenbone XML report file directly without initiating a new scan.
        """
        start_time = time.time()
        if not os.path.isfile(xml_file_path):
            return GreenboneCollectorResult(
                status="FAILED",
                error_message=f"Report file not found: {xml_file_path}"
            )

        try:
            with open(xml_file_path, "r", encoding="utf-8") as f:
                content = f.read()

            out_dir = output_dir or os.path.dirname(xml_file_path)
            xml_hash = compute_sha256(xml_file_path) or ""

            return GreenboneCollectorResult(
                xml_path=xml_file_path,
                xml_content=content,
                status="SUCCESS",
                duration_seconds=round(time.time() - start_time, 2),
                file_hashes={"xml": xml_hash}
            )
        except Exception as e:
            return GreenboneCollectorResult(
                status="FAILED",
                error_message=f"Failed to read report XML file: {str(e)}"
            )

