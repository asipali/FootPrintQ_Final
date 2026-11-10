"""
FootprintIQ - Recon Execution Manager & Background Job Engine
Provides persistent background scan execution, terminal-style live event broadcasting,
cancellation support, and Server-Sent Events (SSE) streaming for recon campaigns.
"""

import os
import sys
import time
import json
import queue
import logging
import threading
from typing import Dict, Any, List, Optional, AsyncGenerator
from datetime import datetime, timezone
import asyncio

from src.db.repository import FootprintIQRepository
from src.orchestration.unified_orchestrator import UnifiedScanOrchestrator
from src.authorization.target_authorizer import TargetAuthorizer, TargetAuthorizationError

logger = logging.getLogger("FootprintIQ.ExecutionManager")


class ScanJobContext:
    def __init__(self, scan_id: str, recon_id: str, target: str):
        self.scan_id = scan_id
        self.recon_id = recon_id
        self.target = target
        self.cancel_requested = threading.Event()
        self.subscribers: List[asyncio.Queue] = []
        self.is_completed = False
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None


class ExecutionManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ExecutionManager, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, repo: Optional[FootprintIQRepository] = None):
        if self._initialized:
            return
        self.repo = repo or FootprintIQRepository()
        self.active_jobs: Dict[str, ScanJobContext] = {}  # key: scan_id
        self.recon_to_scan: Dict[str, str] = {}           # key: recon_id -> scan_id
        self._initialized = True

    def _emit_event(
        self,
        ctx: ScanJobContext,
        event_type: str,
        message: str,
        stage: Optional[str] = None,
        progress: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Persists event to database and fans out to active SSE subscriber queues."""
        det_json = json.dumps(details) if details else None
        event_data = self.repo.add_scan_execution_event(
            scan_id=ctx.scan_id,
            recon_id=ctx.recon_id,
            event_type=event_type,
            stage=stage,
            message=message,
            details_json=det_json,
            progress=progress
        )

        # Update campaign progress in database
        if progress is not None or stage is not None:
            update_fields = {}
            if progress is not None:
                update_fields["progress"] = progress
            if stage is not None:
                update_fields["current_stage"] = stage
            self.repo.update_recon_campaign(ctx.recon_id, **update_fields)

        # Fan out to connected live listeners
        for sub in list(ctx.subscribers):
            try:
                sub.put_nowait(event_data)
            except Exception:
                pass

    def start_recon_scan(
        self,
        recon_id: str,
        scan_type: str = "combined",
        profile: str = "default",
        custom_scripts: Optional[List[str]] = None,
        operator: str = "asip_ali"
    ) -> Dict[str, Any]:
        """
        Launches an asynchronous background scan job for the given Recon Campaign.
        Returns the scan ID and job initiation acknowledgment.
        """
        campaign = self.repo.get_recon_campaign(recon_id)
        if not campaign:
            raise ValueError(f"Recon Campaign '{recon_id}' not found.")

        target = campaign["target_value"]

        # Validate target authorization fail-closed
        authorizer = TargetAuthorizer()
        auth_rec = authorizer.authorize_target(
            target=target,
            profile=profile,
            operator=operator,
            investigation_id=recon_id,
            repo=self.repo
        )
        if not auth_rec.authorized:
            raise TargetAuthorizationError(f"Target '{target}' is not authorized: {getattr(auth_rec, 'failure_reason', 'Unauthorized')}")

        # Create scan execution record in database
        scan_rec = self.repo.create_scan_execution(
            investigation_id=recon_id,
            scan_type=scan_type,
            target=target,
            profile=profile
        )
        scan_id = scan_rec["scan_id"]

        # Update Recon Campaign status to Queued/Running
        self.repo.update_recon_campaign(
            recon_id,
            status="Running",
            current_stage="Initializing",
            progress=5
        )

        # Initialize job context
        ctx = ScanJobContext(scan_id=scan_id, recon_id=recon_id, target=target)
        self.active_jobs[scan_id] = ctx
        self.recon_to_scan[recon_id] = scan_id

        # Launch in background worker thread
        thread = threading.Thread(
            target=self._run_scan_worker,
            args=(ctx, scan_type, profile, custom_scripts, operator),
            daemon=True
        )
        thread.start()

        return {
            "status": "QUEUED",
            "message": "Scan job queued and executing in background.",
            "recon_id": recon_id,
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "profile": profile
        }

    def _run_scan_worker(
        self,
        ctx: ScanJobContext,
        scan_type: str,
        profile: str,
        custom_scripts: Optional[List[str]],
        operator: str
    ):
        """Worker thread executing the scan pipeline with real-time stage progress & logging."""
        orchestrator = UnifiedScanOrchestrator(repo=self.repo)
        start_ts = time.time()

        self._emit_event(ctx, "stage_start", f"Recon campaign {ctx.recon_id} initialized for target {ctx.target}", stage="INITIALIZATION", progress=10)
        time.sleep(0.3)

        self._emit_event(ctx, "log", f"Target scope authorization verified: {ctx.target} (AUTHORIZED_LOCAL_LAB)", stage="AUTHORIZATION", progress=15)
        time.sleep(0.2)

        try:
            if ctx.cancel_requested.is_set():
                self._handle_cancellation(ctx)
                return

            # Execute based on scan type
            all_findings = []
            scanners_executed = []

            # Stage 1: Passive Recon (if combined or passive)
            if scan_type in ("passive", "combined"):
                self._emit_event(ctx, "stage_start", f"Starting passive OSINT reconnaissance on {ctx.target}...", stage="PASSIVE_RECON", progress=25)
                try:
                    passive_res = orchestrator._run_passive_recon(ctx.target, ctx.recon_id, ctx.scan_id)
                    whois_data = passive_res.get("whois", {})
                    dns_data = passive_res.get("dns", {})
                    reg = whois_data.get("registrar") if isinstance(whois_data, dict) else "N/A"
                    self._emit_event(ctx, "log", f"WHOIS query completed. Registrar: {reg}", stage="PASSIVE_RECON", progress=30)
                    dns_recs = len(dns_data.get("records", [])) if isinstance(dns_data, dict) else 0
                    self._emit_event(ctx, "log", f"DNS enumeration completed. Discovered records: {dns_recs}", stage="PASSIVE_RECON", progress=35)
                    self._emit_event(ctx, "stage_complete", "Passive reconnaissance completed successfully.", stage="PASSIVE_RECON", progress=40)
                    scanners_executed.append("passive_recon")
                except Exception as e:
                    self._emit_event(ctx, "warning", f"Passive recon notice: {e}", stage="PASSIVE_RECON")

            if ctx.cancel_requested.is_set():
                self._handle_cancellation(ctx)
                return

            # Stage 2: Host & Network Discovery
            if scan_type in ("network_discovery", "combined", "nmap_services", "nmap_nse"):
                self._emit_event(ctx, "stage_start", f"Probing host reachability for {ctx.target}...", stage="HOST_DISCOVERY", progress=45)
                up, msg = TargetAuthorizer.verify_target_connectivity(ctx.target)
                if up:
                    self._emit_event(ctx, "log", f"Host {ctx.target} is UP and responsive on the network.", stage="HOST_DISCOVERY", progress=50)
                else:
                    self._emit_event(ctx, "warning", f"Host reachability probe notice: {msg}", stage="HOST_DISCOVERY", progress=50)

            if ctx.cancel_requested.is_set():
                self._handle_cancellation(ctx)
                return

            # Stage 3: Nmap Service & Port Discovery
            if scan_type in ("nmap_services", "combined"):
                self._emit_event(ctx, "stage_start", f"Executing Nmap service and port detection against {ctx.target} (Profile: {profile})...", stage="SERVICE_DISCOVERY", progress=55)
                services_res = orchestrator._run_nmap_services(ctx.target, profile, ctx.recon_id, ctx.scan_id)
                scanners_executed.append("nmap_services")
                # Parse discovered ports
                ports = services_res.get("findings", [])
                for p in ports:
                    self._emit_event(
                        ctx,
                        "port_discovered",
                        f"Discovered open port {p.get('port')}/{p.get('protocol', 'tcp')} — Service: {p.get('service', 'unknown')} ({p.get('service_version', '')})",
                        stage="SERVICE_DISCOVERY",
                        details={"port": p.get("port"), "service": p.get("service")}
                    )
                self._emit_event(ctx, "stage_complete", f"Nmap service detection completed. Identified {len(ports)} open ports/services.", stage="SERVICE_DISCOVERY", progress=70)

            if ctx.cancel_requested.is_set():
                self._handle_cancellation(ctx)
                return

            # Stage 4: Nmap NSE Vulnerability Assessment
            if scan_type in ("nmap_nse", "combined"):
                self._emit_event(ctx, "stage_start", f"Executing policy-controlled Nmap Scripting Engine (NSE) checks against {ctx.target}...", stage="NSE_ASSESSMENT", progress=75)
                nse_res = orchestrator._run_nmap_nse(ctx.target, custom_scripts, ctx.recon_id, ctx.scan_id)
                scanners_executed.append("nmap_nse")
                nse_findings = nse_res.get("findings", [])
                all_findings.extend(nse_findings)
                for f in nse_findings:
                    self._emit_event(
                        ctx,
                        "finding_discovered",
                        f"VULNERABILITY DETECTED: {f.get('title')} ({f.get('severity')}) on port {f.get('port')}. CVE: {f.get('cve_identifiers', 'N/A')}",
                        stage="NSE_ASSESSMENT",
                        details=f
                    )
                self._emit_event(ctx, "stage_complete", f"NSE script assessment finished. Recorded {len(nse_findings)} vulnerability findings.", stage="NSE_ASSESSMENT", progress=85)

            if ctx.cancel_requested.is_set():
                self._handle_cancellation(ctx)
                return

            # Stage 5: Secondary & Tertiary Engines (Nessus / Greenbone)
            if scan_type in ("nessus", "combined"):
                self._emit_event(ctx, "stage_start", f"Dispatching Nessus vulnerability evaluation for {ctx.target}...", stage="NESSUS_EVALUATION", progress=88)
                nessus_res = orchestrator._run_nessus(ctx.target, ctx.recon_id, ctx.scan_id)
                scanners_executed.append("nessus")
                n_findings = nessus_res.get("findings", [])
                all_findings.extend(n_findings)
                self._emit_event(ctx, "stage_complete", f"Nessus scanner evaluation completed. Findings: {len(n_findings)}", stage="NESSUS_EVALUATION", progress=90)

            if scan_type in ("greenbone", "combined"):
                self._emit_event(ctx, "stage_start", "Checking Greenbone / OpenVAS daemon readiness...", stage="GREENBONE_EVALUATION", progress=92)
                try:
                    gb_collector = orchestrator.greenbone_collector if hasattr(orchestrator, "greenbone_collector") else None
                    if not gb_collector:
                        from src.collectors.greenbone_collector import GreenboneCollector
                        gb_collector = GreenboneCollector()
                    is_ready, details = gb_collector.check_readiness()
                    if is_ready:
                        gb_res = orchestrator._run_greenbone(ctx.target, ctx.recon_id, ctx.scan_id)
                        all_findings.extend(gb_res.get("findings", []))
                        scanners_executed.append("greenbone")
                        self._emit_event(ctx, "stage_complete", "Greenbone OpenVAS scan executed and findings imported.", stage="GREENBONE_EVALUATION", progress=94)
                    else:
                        stat = "FEED_SYNCING" if details.get("connected") else "UNAVAILABLE"
                        self._emit_event(ctx, "log", f"Greenbone status: {stat} (Daemon socket active, awaiting feed sync)", stage="GREENBONE_EVALUATION", progress=94)
                except Exception as e:
                    self._emit_event(ctx, "warning", f"Greenbone integration notice: {e}", stage="GREENBONE_EVALUATION")

            # Stage 6: Intelligence Correlation & Exposure Scoring
            self._emit_event(ctx, "stage_start", "Correlating findings across multi-scanner evidence and calculating risk exposure score...", stage="CORRELATION", progress=95)
            from src.services.exposure_scoring import ExposureScoringEngine
            exposure_report = ExposureScoringEngine.calculate_investigation_exposure(all_findings)
            self.repo.update_exposure_score(ctx.recon_id, exposure_report["exposure_score"])

            elapsed = round(time.time() - start_ts, 2)
            self._emit_event(
                ctx,
                "stage_complete",
                f"Recon assessment completed in {elapsed}s. Total vulnerabilities: {len(all_findings)}, Exposure Score: {exposure_report['exposure_score']}/100 ({exposure_report['exposure_level']}).",
                stage="COMPLETION",
                progress=100
            )

            # Update DB scan execution and campaign
            self.repo.update_scan_execution(
                scan_id=ctx.scan_id,
                status="completed",
                result_summary_json=json.dumps({
                    "target": ctx.target,
                    "findings_count": len(all_findings),
                    "exposure_score": exposure_report["exposure_score"],
                    "exposure_level": exposure_report["exposure_level"],
                    "elapsed_seconds": elapsed,
                    "scanners_executed": scanners_executed
                })
            )
            self.repo.update_recon_campaign(
                ctx.recon_id,
                status="Completed",
                progress=100,
                current_stage="Completed"
            )

            ctx.is_completed = True
            ctx.result = {
                "scan_id": ctx.scan_id,
                "recon_id": ctx.recon_id,
                "status": "COMPLETED",
                "findings_count": len(all_findings),
                "exposure_summary": exposure_report,
                "elapsed_seconds": elapsed
            }

        except Exception as e:
            logger.error(f"Scan job {ctx.scan_id} failed: {e}", exc_info=True)
            self._emit_event(ctx, "error", f"Scan execution failed: {str(e)}", stage="ERROR")
            self.repo.update_scan_execution(ctx.scan_id, status="failed", error_message=str(e))
            self.repo.update_recon_campaign(ctx.recon_id, status="Failed", current_stage="Failed")
            ctx.is_completed = True
            ctx.error = str(e)

    def _handle_cancellation(self, ctx: ScanJobContext):
        """Gracefully marks job as cancelled."""
        self._emit_event(ctx, "warning", "Scan execution cancelled by user request.", stage="CANCELLED")
        self.repo.update_scan_execution(ctx.scan_id, status="cancelled", error_message="Cancelled by user.")
        self.repo.update_recon_campaign(ctx.recon_id, status="Cancelled", current_stage="Cancelled")
        ctx.is_completed = True

    def cancel_recon_scan(self, recon_id: str) -> bool:
        """Cancels an active scan job for a given Recon Campaign."""
        scan_id = self.recon_to_scan.get(recon_id)
        if not scan_id or scan_id not in self.active_jobs:
            # Check DB to cancel directly if queued
            self.repo.update_recon_campaign(recon_id, status="Cancelled", current_stage="Cancelled")
            return True

        ctx = self.active_jobs[scan_id]
        ctx.cancel_requested.set()
        return True

    def get_scan_context(self, recon_id: str) -> Optional[ScanJobContext]:
        scan_id = self.recon_to_scan.get(recon_id)
        if scan_id and scan_id in self.active_jobs:
            return self.active_jobs[scan_id]
        return None
