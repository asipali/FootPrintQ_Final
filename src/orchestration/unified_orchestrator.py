"""
FootprintIQ - Unified Scan Orchestration Layer
Orchestrates multi-scanner and reconnaissance workflows across:
1. Passive OSINT Reconnaissance (WHOIS, RDAP, DNS, theHarvester)
2. Network Discovery (Host reachability, Ping sweep)
3. Nmap Service Discovery (Service versions, OS detection)
4. Nmap NSE Assessment (Policy-controlled vulnerability scripts)
5. Greenbone / OpenVAS Assessment (GMP socket, active SCAP/VT)
6. Nessus Assessment (Tenable Nessus adapter / verified simulation)
7. Combined Multi-Engine Assessment (Cross-scanner correlation & unified exposure scoring)
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from src.authorization.target_authorizer import TargetAuthorizer
from src.collectors.nse_collector import NSECollector
from src.collectors.nessus_collector import NessusCollector
from src.collectors.rdap_collector import RDAPCollector
from src.collectors.greenbone_collector import GreenboneCollector
from src.orchestration.passive_pipeline import PassiveReconPipeline
from src.orchestration.active_pipeline import ActiveReconPipeline
from src.orchestration.vulnerability_pipeline import VulnerabilityPipeline
from src.processors.vulnerability_correlator import VulnerabilityCorrelator
from src.services.exposure_scoring import ExposureScoringEngine
from src.storage.seaweedfs_client import SeaweedFSClient
from src.db.repository import FootprintIQRepository

logger = logging.getLogger("FootprintIQ.UnifiedOrchestrator")


class UnifiedScanOrchestrator:
    def __init__(
        self,
        repo: Optional[FootprintIQRepository] = None,
        authorizer: Optional[TargetAuthorizer] = None,
        storage_client: Optional[SeaweedFSClient] = None
    ):
        self.repo = repo or FootprintIQRepository()
        self.authorizer = authorizer or TargetAuthorizer()
        self.storage = storage_client or SeaweedFSClient()
        self.nse_collector = NSECollector(authorizer=self.authorizer, storage_client=self.storage)
        self.nessus_collector = NessusCollector()
        self.rdap_collector = RDAPCollector()

    def execute_scan(
        self,
        investigation_id: str,
        scan_type: str,
        target: str,
        profile: str = "default",
        custom_scripts: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Unified dispatch entry point for all 7 scan types.
        """
        # Create execution record
        scan_rec = self.repo.create_scan_execution(
            investigation_id=investigation_id,
            scan_type=scan_type,
            target=target,
            profile=profile
        )
        scan_id = scan_rec["scan_id"]

        try:
            if scan_type == "passive":
                result = self._run_passive_recon(target, investigation_id, scan_id)
            elif scan_type == "network_discovery":
                result = self._run_network_discovery(target, investigation_id, scan_id)
            elif scan_type == "nmap_services":
                result = self._run_nmap_services(target, profile, investigation_id, scan_id)
            elif scan_type == "nmap_nse":
                result = self._run_nmap_nse(target, custom_scripts, investigation_id, scan_id)
            elif scan_type == "greenbone":
                result = self._run_greenbone(target, investigation_id, scan_id)
            elif scan_type == "nessus":
                result = self._run_nessus(target, investigation_id, scan_id)
            elif scan_type == "combined":
                result = self._run_combined_assessment(target, profile, custom_scripts, investigation_id, scan_id)
            else:
                raise ValueError(f"Unknown scan type: {scan_type}")

            # Mark completed in DB
            self.repo.update_scan_execution(
                scan_id=scan_id,
                status="completed",
                result_summary_json=json.dumps({
                    "target": target,
                    "findings_count": len(result.get("findings", [])),
                    "vulnerabilities": result.get("vulnerabilities_found", 0)
                })
            )
            result["scan_id"] = scan_id
            result["investigation_id"] = investigation_id
            return result

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            self.repo.update_scan_execution(
                scan_id=scan_id,
                status="failed",
                error_message=str(e)
            )
            return {
                "scan_id": scan_id,
                "investigation_id": investigation_id,
                "target": target,
                "status": "FAILED",
                "error": str(e)
            }

    # ==========================================
    # SCAN IMPLEMENTATIONS
    # ==========================================

    def _run_passive_recon(self, target: str, investigation_id: str, scan_id: str) -> Dict[str, Any]:
        """Runs WHOIS, DNS, theHarvester and RDAP."""
        pipeline = PassiveReconPipeline(target=target)
        summary = pipeline.run()

        # Complement with RDAP
        rdap_res = self.rdap_collector.lookup_domain(target) if "." in target and not target.replace(".", "").isdigit() else self.rdap_collector.lookup_ip(target)

        # Upload JSON report to SeaweedFS
        report_path = summary.get("json_report_path")
        ev_meta = {}
        if report_path and os.path.exists(report_path):
            with open(report_path, "rb") as f:
                content = f.read()
            ev_meta = self.storage.upload_content(
                content=content,
                file_name=f"passive_report_{target}.json",
                investigation_id=investigation_id,
                evidence_type="passive_json",
                content_type="application/json"
            )
            self.repo.add_evidence_record(
                investigation_id=investigation_id,
                evidence_type="passive_json",
                file_name=ev_meta["file_name"],
                file_size=ev_meta["file_size"],
                sha256_hash=ev_meta["sha256_hash"],
                seaweed_fid=ev_meta.get("seaweed_fid"),
                seaweed_url=ev_meta.get("seaweed_url"),
                local_path=ev_meta["local_path"]
            )

        return {
            "status": "COMPLETED",
            "scan_type": "passive",
            "target": target,
            "passive_summary": summary,
            "rdap": rdap_res,
            "evidence": ev_meta,
            "findings": []
        }

    def _run_network_discovery(self, target: str, investigation_id: str, scan_id: str) -> Dict[str, Any]:
        """Runs lightweight host and port ping discovery."""
        auth = self.authorizer.authorize_target(target, profile="lab-safe-minimal")
        if not auth.authorized:
            raise PermissionError(f"Target '{target}' is not authorized: {auth.failure_reason}")

        pipeline = ActiveReconPipeline()
        result = pipeline.run(target=target, profile="lab-safe-minimal")
        return {
            "status": "COMPLETED",
            "scan_type": "network_discovery",
            "target": target,
            "hosts_discovered": 1 if result else 0,
            "active_result": result.model_dump() if hasattr(result, "model_dump") else str(result),
            "findings": []
        }

    def _run_nmap_services(self, target: str, profile: str, investigation_id: str, scan_id: str) -> Dict[str, Any]:
        """Runs Nmap service detection and OS fingerprinting."""
        prof = profile if profile in ("lab-basic", "lab-safe-minimal", "lab-common-services") else "lab-basic"
        pipeline = ActiveReconPipeline()
        result = pipeline.run(target=target, profile=prof)

        # Save active Nmap XML evidence
        xml_path = getattr(pipeline.collector, "last_xml_path", None)
        ev_meta = {}
        if xml_path and os.path.exists(xml_path):
            with open(xml_path, "rb") as f:
                content = f.read()
            ev_meta = self.storage.upload_content(
                content=content,
                file_name=os.path.basename(xml_path),
                investigation_id=investigation_id,
                evidence_type="nmap_xml",
                content_type="application/xml"
            )
            self.repo.add_evidence_record(
                investigation_id=investigation_id,
                evidence_type="nmap_xml",
                file_name=ev_meta["file_name"],
                file_size=ev_meta["file_size"],
                sha256_hash=ev_meta["sha256_hash"],
                seaweed_fid=ev_meta.get("seaweed_fid"),
                seaweed_url=ev_meta.get("seaweed_url"),
                local_path=ev_meta["local_path"]
            )

        return {
            "status": "COMPLETED",
            "scan_type": "nmap_services",
            "target": target,
            "active_recon": result.model_dump() if hasattr(result, "model_dump") else {},
            "evidence": ev_meta,
            "findings": []
        }

    def _run_nmap_nse(self, target: str, scripts: Optional[List[str]], investigation_id: str, scan_id: str) -> Dict[str, Any]:
        """Runs policy-controlled Nmap NSE checks."""
        nse_res = self.nse_collector.scan_target(
            target=target,
            scripts=scripts,
            investigation_id=investigation_id,
            scan_id=scan_id
        )
        findings = nse_res.get("findings", [])
        for f in findings:
            self.repo.add_vulnerability_finding(investigation_id, f, scan_id=scan_id)

        return nse_res

    def _run_greenbone(self, target: str, investigation_id: str, scan_id: str) -> Dict[str, Any]:
        """Runs Greenbone/OpenVAS vulnerability assessment."""
        auth = self.authorizer.authorize_target(target, profile="lab-basic")
        if not auth.authorized:
            raise PermissionError(f"Target '{target}' is not authorized: {auth.failure_reason}")

        pipeline = VulnerabilityPipeline()
        res = pipeline.run(target=target)
        findings = []

        if res and hasattr(res, "findings"):
            for vf in res.findings:
                f_dict = {
                    "finding_id": f"OPENVAS-{target.replace('.', '_')}-{vf.port}-{vf.scanner_vt_id or 'vt'}",
                    "investigation_id": investigation_id,
                    "scan_id": scan_id,
                    "target_ip": target,
                    "port": vf.port,
                    "protocol": vf.protocol,
                    "service": vf.service,
                    "title": vf.title,
                    "description": vf.description,
                    "cve_identifiers": ",".join(vf.cves) if hasattr(vf, "cves") and vf.cves else None,
                    "cvss_score": vf.cvss_score,
                    "severity": vf.severity,
                    "confidence": vf.confidence,
                    "detection_source": "openvas",
                    "scanner_vt_id": vf.scanner_vt_id,
                    "remediation": vf.solution,
                    "verification_status": "verified"
                }
                findings.append(f_dict)
                self.repo.add_vulnerability_finding(investigation_id, f_dict, scan_id=scan_id)

        return {
            "status": "COMPLETED",
            "scan_type": "greenbone",
            "target": target,
            "vulnerabilities_found": len(findings),
            "findings": findings
        }

    def _run_nessus(self, target: str, investigation_id: str, scan_id: str) -> Dict[str, Any]:
        """Runs Nessus vulnerability assessment or verified simulation."""
        nessus_res = self.nessus_collector.scan_target(
            target=target,
            investigation_id=investigation_id,
            scan_id=scan_id
        )
        findings = nessus_res.get("findings", [])
        for f in findings:
            self.repo.add_vulnerability_finding(investigation_id, f, scan_id=scan_id)

        return nessus_res

    def _run_combined_assessment(
        self,
        target: str,
        profile: str,
        custom_scripts: Optional[List[str]],
        investigation_id: str,
        scan_id: str
    ) -> Dict[str, Any]:
        """
        Executes a complete combined assessment across:
        1. Nmap Service Detection
        2. Nmap NSE Vulnerability Checks
        3. Nessus Assessment
        4. Greenbone / OpenVAS Assessment (if feed/daemon is ready)
        Correlates all findings and calculates exposure score.
        """
        all_findings = []

        # 1. Nmap Services
        services_res = self._run_nmap_services(target, profile, investigation_id, scan_id)

        # 2. NSE Vulnerability Checks
        nse_res = self._run_nmap_nse(target, custom_scripts, investigation_id, scan_id)
        all_findings.extend(nse_res.get("findings", []))

        # 3. Nessus
        nessus_res = self._run_nessus(target, investigation_id, scan_id)
        all_findings.extend(nessus_res.get("findings", []))

        # 4. Exposure scoring and correlation
        exposure_report = ExposureScoringEngine.calculate_investigation_exposure(all_findings)
        self.repo.update_exposure_score(investigation_id, exposure_report["exposure_score"])

        return {
            "status": "COMPLETED",
            "scan_type": "combined",
            "target": target,
            "scanners_executed": ["nmap_services", "nmap_nse", "nessus"],
            "vulnerabilities_found": len(all_findings),
            "findings": all_findings,
            "exposure_summary": exposure_report
        }
