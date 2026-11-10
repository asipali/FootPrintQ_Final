"""
FootprintIQ - Nmap Scripting Engine (NSE) Collector
Executes authorized, safe NSE scripts against validated targets,
parses XML results into normalized vulnerability findings,
and preserves original XML evidence in SeaweedFS.
"""

import os
import subprocess
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
import hashlib

from src.authorization.target_authorizer import TargetAuthorizer
from src.services.nse_policy_service import NSEPolicyService, APPROVED_NSE_SCRIPTS
from src.storage.seaweedfs_client import SeaweedFSClient
from src.collectors.nmap_collector import resolve_nmap_binary

logger = logging.getLogger("FootprintIQ.NSECollector")


class NSECollector:
    def __init__(
        self,
        authorizer: Optional[TargetAuthorizer] = None,
        storage_client: Optional[SeaweedFSClient] = None,
        timeout: int = 120
    ):
        self.authorizer = authorizer or TargetAuthorizer()
        self.storage_client = storage_client or SeaweedFSClient()
        self.timeout = timeout

    def scan_target(
        self,
        target: str,
        scripts: Optional[List[str]] = None,
        ports: Optional[str] = None,
        investigation_id: str = "DEFAULT",
        scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes policy-controlled NSE scan against an authorized target.
        """
        # 1. Enforce strict fail-closed authorization
        auth_record = self.authorizer.authorize_target(target, profile="lab-basic")
        if not auth_record.authorized:
            raise PermissionError(f"Target '{target}' is not authorized: {auth_record.failure_reason}")

        # 2. Enforce script policy
        requested_scripts = scripts or ["http-title", "http-headers", "ftp-anon", "ftp-vsftpd-backdoor"]
        approved_scripts, rejected_scripts = NSEPolicyService.validate_scripts(requested_scripts)
        if not approved_scripts:
            raise ValueError(f"No valid authorized scripts to execute. Rejected: {rejected_scripts}")

        script_arg = ",".join(approved_scripts)

        # 3. Construct safe Nmap command (Strictly shell=False)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_")
        xml_dir = os.path.abspath("data/raw/nse")
        os.makedirs(xml_dir, exist_ok=True)
        xml_path = os.path.join(xml_dir, f"nse_{safe_target}_{timestamp}.xml")

        cmd = [
            resolve_nmap_binary(),
            "-sV",
            "--script", script_arg,
            "-oX", xml_path,
            "-T4"
        ]

        if ports:
            # Validate ports format (e.g., "21,22,80" or "1-1000")
            clean_ports = "".join(c for c in ports if c.isdigit() or c in ",-")
            if clean_ports:
                cmd.extend(["-p", clean_ports])
        else:
            cmd.extend(["-F"])  # Fast scan default if no ports specified

        cmd.append(target)

        logger.info(f"Executing NSE command: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )
        except subprocess.TimeoutExpired:
            logger.error(f"NSE scan timed out after {self.timeout}s")
            raise TimeoutError(f"NSE scan timed out after {self.timeout}s")

        # 4. Parse XML output
        findings: List[Dict[str, Any]] = []
        script_results: List[Dict[str, Any]] = []

        if os.path.exists(xml_path) and os.path.getsize(xml_path) > 0:
            findings, script_results = self._parse_nse_xml(xml_path, target, investigation_id, scan_id)

            # 5. Preserve evidence in SeaweedFS
            with open(xml_path, "rb") as f:
                xml_bytes = f.read()
            evidence_meta = self.storage_client.upload_content(
                content=xml_bytes,
                file_name=os.path.basename(xml_path),
                investigation_id=investigation_id,
                evidence_type="nse_xml",
                content_type="application/xml"
            )
        else:
            evidence_meta = {}

        return {
            "status": "COMPLETED" if result.returncode == 0 else "PARTIAL",
            "target": target,
            "executed_scripts": approved_scripts,
            "rejected_scripts": rejected_scripts,
            "script_results_count": len(script_results),
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "script_results": script_results,
            "evidence": evidence_meta,
            "raw_xml_path": xml_path
        }

    def _parse_nse_xml(
        self,
        xml_path: str,
        target_ip: str,
        investigation_id: str,
        scan_id: Optional[str]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        findings = []
        script_results = []

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall("host"):
                # Extract ports and scripts
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port_elem in ports_elem.findall("port"):
                        port_id = int(port_elem.get("portid", 0))
                        protocol = port_elem.get("protocol", "tcp")
                        service_elem = port_elem.find("service")
                        service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                        service_product = service_elem.get("product", "") if service_elem is not None else ""
                        service_version = service_elem.get("version", "") if service_elem is not None else ""

                        for script_elem in port_elem.findall("script"):
                            script_id = script_elem.get("id", "")
                            script_output = script_elem.get("output", "")

                            script_record = {
                                "script_id": script_id,
                                "port": port_id,
                                "protocol": protocol,
                                "service": service_name,
                                "output": script_output
                            }
                            script_results.append(script_record)

                            # Check if script indicates a vulnerability
                            meta = APPROVED_NSE_SCRIPTS.get(script_id, {})
                            is_vuln = meta.get("category") == "vuln" or "VULNERABLE" in script_output.upper() or "BACKDOOR" in script_output.upper()

                            if is_vuln:
                                cve = meta.get("cve")
                                cvss = meta.get("cvss", 7.5)
                                severity = meta.get("severity", "High")
                                title = meta.get("description", f"NSE Finding: {script_id}")

                                fid = f"NSE-{target_ip.replace('.', '_')}-{port_id}-{script_id}"
                                finding = {
                                    "finding_id": fid,
                                    "investigation_id": investigation_id,
                                    "scan_id": scan_id,
                                    "target_ip": target_ip,
                                    "port": port_id,
                                    "protocol": protocol,
                                    "service": service_name,
                                    "service_version": f"{service_product} {service_version}".strip(),
                                    "title": title,
                                    "description": script_output,
                                    "cve_identifiers": cve,
                                    "cvss_score": cvss,
                                    "severity": severity,
                                    "confidence": 0.95,
                                    "detection_source": "nse",
                                    "scanner_vt_id": script_id,
                                    "remediation": "Update or reconfigure affected service.",
                                    "evidence_reference": f"nse_script:{script_id}",
                                    "verification_status": "verified" if "VULNERABLE" in script_output.upper() or "BACKDOOR" in script_output.upper() else "unverified"
                                }
                                findings.append(finding)

                # Hostscript level (SMB, etc.)
                hostscript_elem = host.find("hostscript")
                if hostscript_elem is not None:
                    for script_elem in hostscript_elem.findall("script"):
                        script_id = script_elem.get("id", "")
                        script_output = script_elem.get("output", "")
                        script_results.append({
                            "script_id": script_id,
                            "port": None,
                            "protocol": "ip",
                            "service": "host",
                            "output": script_output
                        })
                        meta = APPROVED_NSE_SCRIPTS.get(script_id, {})
                        if meta.get("category") == "vuln" or "VULNERABLE" in script_output.upper():
                            findings.append({
                                "finding_id": f"NSE-{target_ip.replace('.', '_')}-host-{script_id}",
                                "investigation_id": investigation_id,
                                "scan_id": scan_id,
                                "target_ip": target_ip,
                                "port": 445 if "smb" in script_id else None,
                                "protocol": "tcp",
                                "service": "smb" if "smb" in script_id else "host",
                                "title": meta.get("description", f"NSE Host Finding: {script_id}"),
                                "description": script_output,
                                "cve_identifiers": meta.get("cve"),
                                "cvss_score": meta.get("cvss", 7.5),
                                "severity": meta.get("severity", "High"),
                                "confidence": 0.90,
                                "detection_source": "nse",
                                "scanner_vt_id": script_id,
                                "remediation": "Apply vendor security patch.",
                                "verification_status": "verified"
                            })

        except Exception as e:
            logger.error(f"Error parsing NSE XML: {e}")

        return findings, script_results
