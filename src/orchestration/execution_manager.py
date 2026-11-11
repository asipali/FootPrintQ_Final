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
        self.start_time_utc = datetime.now(timezone.utc).isoformat()
        self.scan_categories: List[str] = []
        self.current_scanner: str = "Initializing"
        self.completed_checks: int = 0
        self.planned_checks: int = 1
        self.services_count: int = 0
        self.findings_count: int = 0
        self.cancel_requested = threading.Event()
        self.subscribers: List[asyncio.Queue] = []
        self.is_completed = False
        self.elapsed_seconds: Optional[float] = None
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
        details: Optional[Dict[str, Any]] = None,
        component: Optional[str] = None
    ):
        """Persists event to database and fans out to active SSE subscriber queues."""
        det = dict(details or {})
        det.setdefault("target", ctx.target)
        if component:
            det["component"] = component
            ctx.current_scanner = component
        elif stage:
            ctx.current_scanner = stage

        if event_type == "port_discovered":
            ctx.services_count += 1
        elif event_type == "finding_discovered":
            ctx.findings_count += 1
        elif (event_type == "stage_complete" and stage != "COMPLETION") or event_type == "passive_result":
            ctx.completed_checks += 1

        det.setdefault("current_scanner", ctx.current_scanner)
        det.setdefault("start_time_utc", ctx.start_time_utc)
        det.setdefault("completed_checks", ctx.completed_checks)
        det.setdefault("pending_checks", max(0, ctx.planned_checks - ctx.completed_checks))
        det.setdefault("services_count", ctx.services_count)
        det_json = json.dumps(det)
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
        raw_cfg = campaign.get("scan_config_json") or "{}"
        try:
            scan_config = json.loads(raw_cfg) if isinstance(raw_cfg, str) else (raw_cfg or {})
        except Exception:
            scan_config = {}

        selected_categories = [str(c).lower() for c in (scan_config.get("selected_categories") or [])]
        targets_list = scan_config.get("targets") or [t.strip() for t in str(target).split(",") if t.strip()]
        scope_mode = "passive" if selected_categories == ["passive"] or scan_type == "passive" else "combined"

        # Validate target authorization fail-closed
        authorizer = TargetAuthorizer()
        if scope_mode == "passive":
            authorizer.authorize_campaign_targets(
                targets=targets_list,
                scope_mode="passive",
                excluded_targets=campaign.get("excluded_targets"),
                explicit_authorization=True,
                operator=operator
            )
        else:
            for tgt in targets_list:
                auth_rec = authorizer.authorize_target(
                    target=tgt,
                    profile=profile,
                    operator=operator,
                    investigation_id=recon_id,
                    repo=self.repo
                )
                if not auth_rec.authorized:
                    raise TargetAuthorizationError(f"Target '{tgt}' is not authorized: {getattr(auth_rec, 'failure_reason', 'Unauthorized')}")

        # Atomically claim campaign and create scan execution record (prevents double-launch race condition)
        job_claim = self.repo.claim_and_start_recon_scan(
            recon_id=recon_id,
            scan_type=scan_type,
            profile=profile,
            operator=operator
        )
        scan_id = job_claim["scan_id"]

        # Initialize job context
        ctx = ScanJobContext(scan_id=scan_id, recon_id=recon_id, target=target)
        self.active_jobs[scan_id] = ctx
        self.recon_to_scan[recon_id] = scan_id

        # Launch in background worker thread with independent session
        thread = threading.Thread(
            target=self._run_scan_worker,
            args=(ctx, scan_type, profile, custom_scripts, operator, scan_config),
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
        operator: str,
        scan_config: Optional[Dict[str, Any]] = None
    ):
        """Worker thread executing configured recon stages with short-lived ACID DB transactions."""
        worker_repo = FootprintIQRepository()
        orchestrator = UnifiedScanOrchestrator(repo=worker_repo)
        start_ts = time.time()

        cfg = scan_config if isinstance(scan_config, dict) else {}
        selected_categories = [str(c).lower() for c in (cfg.get("selected_categories") or [])]
        targets_list = [str(t).strip() for t in (cfg.get("targets") or ctx.target.split(",")) if str(t).strip()]
        if not targets_list:
            targets_list = [ctx.target]

        passive_cfg = cfg.get("passive") or {}
        active_cfg = cfg.get("active") or {}
        vuln_cfg = cfg.get("vulnerability") or {}

        run_passive = ("passive" in selected_categories) or (not selected_categories and scan_type in ("passive", "combined"))
        run_active = ("active" in selected_categories) or (not selected_categories and scan_type in ("network_discovery", "nmap_services", "combined"))
        run_vuln = ("vulnerability" in selected_categories) or (not selected_categories and scan_type in ("nmap_nse", "nessus", "greenbone", "combined"))

        ctx.scan_categories = [c.title() for c in selected_categories] if selected_categories else [
            lbl for flag, lbl in ((run_passive, "Passive"), (run_active, "Active"), (run_vuln, "Vulnerability")) if flag
        ]
        ctx.planned_checks = max(1, (int(run_passive) + int(run_active) + int(run_vuln)) * len(targets_list))

        self._emit_event(
            ctx,
            "stage_start",
            f"Campaign {ctx.recon_id} initialized across {len(targets_list)} target(s).",
            stage="INITIALIZATION",
            progress=5,
            component="Campaign"
        )
        self._emit_event(
            ctx,
            "log",
            f"Scope verification passed for: {', '.join(targets_list)}",
            stage="AUTHORIZATION",
            progress=10,
            component="Authorization"
        )

        all_findings: List[Dict[str, Any]] = []
        passive_results: List[Dict[str, Any]] = []
        active_hosts: List[Dict[str, Any]] = []
        discovered_ports: List[Dict[str, Any]] = []
        scanner_statuses: List[Dict[str, Any]] = []
        scanners_executed: List[str] = []
        succeeded_stages = 0
        failed_stages = 0
        failed_stage_names: List[str] = []

        try:
            if ctx.cancel_requested.is_set():
                self._handle_cancellation(ctx, worker_repo)
                return

            total_targets = max(1, len(targets_list))

            for idx, tgt in enumerate(targets_list):
                if ctx.cancel_requested.is_set():
                    self._handle_cancellation(ctx, worker_repo)
                    return

                base_prog = int(12 + (idx / total_targets) * 78)

                # ==========================================
                # CATEGORY 1: PASSIVE RECONNAISSANCE
                # ==========================================
                if run_passive:
                    checks = passive_cfg.get("selected_checks") or [
                        "whois_lookup", "rdap_lookup", "dns_records", "asn_ip_hosting", "reverse_dns"
                    ]
                    allow_contact = bool(passive_cfg.get("allow_target_contact", False))
                    self._emit_event(
                        ctx,
                        "stage_start",
                        f"Executing passive reconnaissance checks on {tgt} ({len(checks)} modules)...",
                        stage="PASSIVE_RECON",
                        progress=min(35, base_prog + 5),
                        component="Passive Recon"
                    )
                    try:
                        p_res = orchestrator._run_passive_intel(
                            target=tgt,
                            selected_checks=checks,
                            allow_target_contact=allow_contact,
                            investigation_id=ctx.recon_id,
                            scan_id=ctx.scan_id,
                            progress_cb=lambda m: self._emit_event(ctx, "log", m, stage="PASSIVE_RECON", component="Passive Recon")
                        )
                        passive_results.append(p_res)
                        scanners_executed.append("passive_recon")
                        succeeded_stages += 1

                        dom_subs = len((p_res.get("domain_intel") or {}).get("subdomains") or [])
                        dns_count = sum(len(v) for v in ((p_res.get("domain_intel") or {}).get("dns_records") or {}).values() if isinstance(v, list))
                        emails_count = len((p_res.get("osint_intel") or {}).get("emails") or [])
                        unavail = p_res.get("unavailable_checks") or []

                        scanner_statuses.append({
                            "scanner": "Passive Intelligence",
                            "target": tgt,
                            "status": "COMPLETED",
                            "detail": f"DNS records: {dns_count}, Subdomains: {dom_subs}, Emails: {emails_count}"
                        })
                        if unavail:
                            for u in unavail:
                                self._emit_event(ctx, "warning", f"Passive check notice ({u.get('id')}): {u.get('reason')}", stage="PASSIVE_RECON", component="Passive Recon")

                        self._emit_event(
                            ctx,
                            "passive_result",
                            f"Passive intelligence finished for {tgt}: {dns_count} DNS records, {dom_subs} subdomains, {emails_count} contacts.",
                            stage="PASSIVE_RECON",
                            progress=min(40, base_prog + 18),
                            component="Passive Recon",
                            details={"passive_summary": p_res}
                        )
                    except Exception as pe:
                        failed_stages += 1
                        failed_stage_names.append(f"Passive Recon ({tgt})")
                        scanner_statuses.append({"scanner": "Passive Intelligence", "target": tgt, "status": "FAILED", "detail": str(pe)})
                        self._emit_event(ctx, "error", f"Passive reconnaissance failed for {tgt}: {pe}", stage="PASSIVE_RECON", component="Passive Recon")

                if ctx.cancel_requested.is_set():
                    self._handle_cancellation(ctx, worker_repo)
                    return

                # ==========================================
                # CATEGORY 2: ACTIVE RECONNAISSANCE
                # ==========================================
                if run_active:
                    if scan_type == "network_discovery" and not selected_categories:
                        effective_active_opts = {"host_discovery": "ping_only", "timing": "T4"}
                    elif active_cfg:
                        effective_active_opts = active_cfg
                    else:
                        effective_active_opts = None

                    self._emit_event(
                        ctx,
                        "stage_start",
                        f"Executing active host, port, and service discovery against {tgt}...",
                        stage="ACTIVE_RECON",
                        progress=min(62, base_prog + 25),
                        component="Active Recon"
                    )
                    try:
                        services_res = orchestrator._run_nmap_services(
                            target=tgt,
                            profile=profile,
                            investigation_id=ctx.recon_id,
                            scan_id=ctx.scan_id,
                            custom_active_options=effective_active_opts,
                            use_db_scope=True
                        )
                        stage_stat = services_res.get("status", "COMPLETED")
                        hosts_found = services_res.get("hosts", [])
                        ports_found = services_res.get("ports", [])
                        errs = services_res.get("errors", [])

                        if stage_stat in ("FAILED", "BLOCKED") and not hosts_found:
                            failed_stages += 1
                            failed_stage_names.append(f"Active Recon ({tgt})")
                            err_text = "; ".join(errs) or f"Active scan {stage_stat.lower()} for {tgt}"
                            scanner_statuses.append({"scanner": "Active Port & Service Scan", "target": tgt, "status": stage_stat, "detail": err_text})
                            self._emit_event(ctx, "error", f"Active scan error for {tgt}: {err_text}", stage="ACTIVE_RECON", component="Active Recon")
                        else:
                            succeeded_stages += 1
                            scanners_executed.append("nmap_services")
                            active_hosts.extend(hosts_found)
                            discovered_ports.extend(ports_found)
                            scanner_statuses.append({
                                "scanner": "Active Port & Service Scan",
                                "target": tgt,
                                "status": "COMPLETED",
                                "detail": f"Hosts UP: {len(hosts_found)}, Open ports: {len(ports_found)}"
                            })
                            for h in hosts_found:
                                self._emit_event(
                                    ctx,
                                    "host_discovered",
                                    f"Host {h.get('ip')} status: {h.get('status')} ({h.get('open_ports_count', 0)} open ports)",
                                    stage="ACTIVE_RECON",
                                    component="Active Recon",
                                    details=h
                                )
                            for p in ports_found:
                                self._emit_event(
                                    ctx,
                                    "port_discovered",
                                    f"Open port {p.get('port')}/{p.get('protocol', 'tcp')} — {p.get('service', 'unknown')} {p.get('service_version', '')}".strip(),
                                    stage="ACTIVE_RECON",
                                    component="Active Recon",
                                    details=p
                                )
                            self._emit_event(
                                ctx,
                                "stage_complete",
                                f"Active service discovery completed for {tgt}: {len(ports_found)} open port(s) identified.",
                                stage="ACTIVE_RECON",
                                progress=min(68, base_prog + 40),
                                component="Active Recon"
                            )

                        # Run targeted safe Service Enumeration NSE scripts if selected under Active D
                        svc_checks = active_cfg.get("service_checks") or []
                        service_map = {
                            "ssh_enum": ["ssh2-enum-algos"],
                            "web_enum": ["http-title", "http-headers", "http-methods", "http-security-headers"],
                            "smb_enum": ["smb-os-discovery", "smb-security-mode"],
                            "ftp_enum": ["ftp-anon"],
                            "db_enum": ["mysql-info", "postgresql-info"],
                            "dns_enum": ["dns-nsid", "dns-recursion"],
                            "ssl_enum": ["ssl-cert", "ssl-enum-ciphers"]
                        }
                        enum_scripts: List[str] = []
                        for sc in svc_checks:
                            enum_scripts.extend(service_map.get(sc, []))
                        if enum_scripts and stage_stat not in ("FAILED", "BLOCKED"):
                            enum_scripts = list(dict.fromkeys(enum_scripts))
                            self._emit_event(ctx, "log", f"Running targeted service enumeration scripts ({len(enum_scripts)}) on {tgt}...", stage="ACTIVE_RECON", component="Service Enum")
                            nse_enum_res = orchestrator._run_nmap_nse(tgt, enum_scripts, ctx.recon_id, ctx.scan_id)
                            for f in nse_enum_res.get("findings", []):
                                all_findings.append(f)
                                self._emit_event(ctx, "finding_discovered", f"Service Check: {f.get('title')} on port {f.get('port')}", stage="ACTIVE_RECON", component="Service Enum", details=f)
                    except Exception as ae:
                        failed_stages += 1
                        failed_stage_names.append(f"Active Recon ({tgt})")
                        scanner_statuses.append({"scanner": "Active Port & Service Scan", "target": tgt, "status": "FAILED", "detail": str(ae)})
                        self._emit_event(ctx, "error", f"Active reconnaissance exception for {tgt}: {ae}", stage="ACTIVE_RECON", component="Active Recon")

                if ctx.cancel_requested.is_set():
                    self._handle_cancellation(ctx, worker_repo)
                    return

                # ==========================================
                # CATEGORY 3: VULNERABILITY ASSESSMENT
                # ==========================================
                if run_vuln:
                    vuln_engine = str(vuln_cfg.get("engine") or "").lower()
                    vuln_engines = [str(e).lower() for e in (vuln_cfg.get("engines") or []) if str(e).strip()]
                    if not selected_categories:
                        # Legacy scan_type dispatch mapping
                        want_nse = scan_type in ("nmap_nse", "combined")
                        want_nessus = scan_type in ("nessus", "combined")
                        want_greenbone = scan_type in ("greenbone", "combined")
                        explicit_greenbone = (scan_type == "greenbone")
                    elif vuln_engines:
                        want_nse = ("nse" in vuln_engines) or bool(vuln_cfg.get("nse_scripts"))
                        want_nessus = "nessus" in vuln_engines
                        want_greenbone = "greenbone" in vuln_engines
                        explicit_greenbone = "greenbone" in vuln_engines
                    else:
                        want_nse = vuln_engine in ("nse", "all") or bool(vuln_cfg.get("nse_scripts"))
                        want_nessus = vuln_engine in ("nessus", "combined_nessus_greenbone", "combined", "all")
                        want_greenbone = vuln_engine in ("greenbone", "combined_nessus_greenbone", "all")
                        explicit_greenbone = vuln_engine in ("greenbone", "combined_nessus_greenbone")

                    # A. Allowlisted Nmap NSE Assessment
                    if want_nse:
                        req_scripts = vuln_cfg.get("nse_scripts") or custom_scripts
                        self._emit_event(ctx, "stage_start", f"Running allowlisted vulnerability checks against {tgt}...", stage="VULN_NSE", progress=min(78, base_prog + 50), component="NSE Scanner")
                        try:
                            nse_res = orchestrator._run_nmap_nse(tgt, req_scripts, ctx.recon_id, ctx.scan_id)
                            if nse_res.get("status") == "FAILED":
                                failed_stages += 1
                                failed_stage_names.append(f"NSE Check ({tgt})")
                                err_txt = "; ".join(nse_res.get("errors", [])) or "NSE scan failed"
                                scanner_statuses.append({"scanner": "Nmap NSE Assessment", "target": tgt, "status": "FAILED", "detail": err_txt})
                                self._emit_event(ctx, "error", f"NSE vulnerability check failed for {tgt}: {err_txt}", stage="VULN_NSE", component="NSE Scanner")
                            else:
                                succeeded_stages += 1
                                scanners_executed.append("nmap_nse")
                                nse_findings = nse_res.get("findings", [])
                                all_findings.extend(nse_findings)
                                scanner_statuses.append({"scanner": "Nmap NSE Assessment", "target": tgt, "status": "COMPLETED", "detail": f"Findings: {len(nse_findings)}"})
                                for f in nse_findings:
                                    self._emit_event(ctx, "finding_discovered", f"Detected: {f.get('title')} ({f.get('severity')}) on port {f.get('port')}", stage="VULN_NSE", component="NSE Scanner", details=f)
                                self._emit_event(ctx, "stage_complete", f"NSE checks completed for {tgt} ({len(nse_findings)} finding(s)).", stage="VULN_NSE", progress=min(82, base_prog + 55), component="NSE Scanner")
                        except Exception as ne:
                            failed_stages += 1
                            failed_stage_names.append(f"NSE Check ({tgt})")
                            scanner_statuses.append({"scanner": "Nmap NSE Assessment", "target": tgt, "status": "FAILED", "detail": str(ne)})
                            self._emit_event(ctx, "error", f"NSE assessment error on {tgt}: {ne}", stage="VULN_NSE", component="NSE Scanner")

                    if ctx.cancel_requested.is_set():
                        self._handle_cancellation(ctx, worker_repo)
                        return

                    # B. Tenable Nessus Live Assessment (No simulation fallback in manual workflows)
                    if want_nessus:
                        self._emit_event(ctx, "stage_start", f"Starting Tenable Nessus vulnerability scan on {tgt}...", stage="VULN_NESSUS", progress=84, component="Tenable Nessus")
                        try:
                            def nessus_cb(status_data):
                                st_text = status_data.get("status", "running")
                                prog = status_data.get("progress")
                                prog_str = f" ({prog}%)" if prog is not None else ""
                                self._emit_event(
                                    ctx,
                                    "log",
                                    f"Nessus scan status: {st_text}{prog_str}",
                                    stage="VULN_NESSUS",
                                    progress=84 if prog is None else min(91, 84 + int(prog * 0.07)),
                                    component="Tenable Nessus",
                                    details=status_data
                                )

                            nessus_res = orchestrator.nessus_collector.scan_target(
                                target=tgt,
                                investigation_id=ctx.recon_id,
                                scan_id=ctx.scan_id,
                                template_uuid=vuln_cfg.get("nessus_template_uuid"),
                                status_callback=nessus_cb,
                                allow_simulation=False,
                                cancel_event=ctx.cancel_requested
                            )
                            n_status = nessus_res.get("status", "UNKNOWN")
                            if ctx.cancel_requested.is_set() or n_status == "CANCELED":
                                self._handle_cancellation(ctx, worker_repo)
                                return

                            if n_status == "FAILED":
                                failed_stages += 1
                                failed_stage_names.append(f"Tenable Nessus ({tgt})")
                                err_msg = nessus_res.get("error") or "Nessus assessment failed or unavailable."
                                scanner_statuses.append({"scanner": "Tenable Nessus", "target": tgt, "status": "FAILED", "detail": err_msg})
                                self._emit_event(ctx, "error", f"Tenable Nessus failed on {tgt}: {err_msg}", stage="VULN_NESSUS", component="Tenable Nessus")
                            else:
                                succeeded_stages += 1
                                scanners_executed.append("nessus")
                                n_findings = nessus_res.get("findings", [])
                                all_findings.extend(n_findings)
                                for f in n_findings:
                                    worker_repo.add_vulnerability_finding(ctx.recon_id, f, scan_id=ctx.scan_id)
                                    self._emit_event(
                                        ctx,
                                        "finding_discovered",
                                        f"Nessus: {f.get('title')} ({f.get('severity')}) on port {f.get('port')}",
                                        stage="VULN_NESSUS",
                                        component="Tenable Nessus",
                                        details=f
                                    )
                                rep_bytes = nessus_res.get("report_bytes")
                                if rep_bytes:
                                    try:
                                        ev = orchestrator.storage.upload_content(
                                            content=rep_bytes,
                                            file_name=f"nessus_{tgt}_{ctx.scan_id}.nessus",
                                            investigation_id=ctx.recon_id,
                                            evidence_type="nessus_export",
                                            content_type="application/xml"
                                        )
                                        worker_repo.add_evidence_record(
                                            investigation_id=ctx.recon_id,
                                            evidence_type="nessus_export",
                                            file_name=ev["file_name"],
                                            file_size=ev["file_size"],
                                            sha256_hash=ev["sha256_hash"],
                                            seaweed_fid=ev.get("seaweed_fid"),
                                            seaweed_url=ev.get("seaweed_url"),
                                            local_path=ev.get("local_path"),
                                            scan_id=ctx.scan_id
                                        )
                                    except Exception as e_ev:
                                        logger.warning(f"Evidence archival notice for Nessus export: {e_ev}")

                                scanner_statuses.append({"scanner": "Tenable Nessus", "target": tgt, "status": "COMPLETED", "detail": f"Findings: {len(n_findings)}"})
                                self._emit_event(ctx, "stage_complete", f"Tenable Nessus completed for {tgt} ({len(n_findings)} findings).", stage="VULN_NESSUS", progress=91, component="Tenable Nessus")
                        except Exception as n_err:
                            failed_stages += 1
                            failed_stage_names.append(f"Tenable Nessus ({tgt})")
                            scanner_statuses.append({"scanner": "Tenable Nessus", "target": tgt, "status": "FAILED", "detail": str(n_err)})
                            self._emit_event(ctx, "error", f"Tenable Nessus execution error on {tgt}: {n_err}", stage="VULN_NESSUS", component="Tenable Nessus")

                    if ctx.cancel_requested.is_set():
                        self._handle_cancellation(ctx, worker_repo)
                        return

                    # C. Greenbone / OpenVAS Assessment (Strict Readiness — Never Fake Operational)
                    if want_greenbone:
                        self._emit_event(ctx, "stage_start", "Verifying Greenbone / OpenVAS readiness...", stage="VULN_GREENBONE", progress=92, component="Greenbone")
                        try:
                            from src.collectors.greenbone_collector import GreenboneCollector
                            gb_collector = GreenboneCollector()
                            readiness = GreenboneCollector.normalize_readiness(gb_collector.check_readiness())
                            if readiness.get("ready"):
                                gb_res = orchestrator._run_greenbone(tgt, ctx.recon_id, ctx.scan_id)
                                g_findings = gb_res.get("findings", [])
                                all_findings.extend(g_findings)
                                scanners_executed.append("greenbone")
                                succeeded_stages += 1
                                scanner_statuses.append({"scanner": "Greenbone / OpenVAS", "target": tgt, "status": "COMPLETED", "detail": f"Findings: {len(g_findings)}"})
                                self._emit_event(ctx, "stage_complete", f"Greenbone scan completed for {tgt} ({len(g_findings)} findings).", stage="VULN_GREENBONE", progress=94, component="Greenbone")
                            else:
                                err_reason = "; ".join(readiness.get("errors", [])) or "Greenbone manager, scanner, or vulnerability feeds are not ready."
                                scanner_statuses.append({"scanner": "Greenbone / OpenVAS", "target": tgt, "status": "UNAVAILABLE", "detail": err_reason})
                                if explicit_greenbone:
                                    failed_stages += 1
                                    failed_stage_names.append(f"Greenbone ({tgt})")
                                    self._emit_event(ctx, "error", f"Greenbone scan could not start: {err_reason}", stage="VULN_GREENBONE", progress=94, component="Greenbone")
                                else:
                                    self._emit_event(ctx, "warning", f"Greenbone unavailable: {err_reason}", stage="VULN_GREENBONE", progress=94, component="Greenbone")
                        except Exception as g_err:
                            scanner_statuses.append({"scanner": "Greenbone / OpenVAS", "target": tgt, "status": "FAILED", "detail": str(g_err)})
                            if explicit_greenbone:
                                failed_stages += 1
                                failed_stage_names.append(f"Greenbone ({tgt})")
                            self._emit_event(ctx, "error", f"Greenbone error: {g_err}", stage="VULN_GREENBONE", component="Greenbone")

            if ctx.cancel_requested.is_set():
                self._handle_cancellation(ctx, worker_repo)
                return

            # Stage: Exposure Scoring & Result Archival
            self._emit_event(ctx, "stage_start", "Correlating collected findings and calculating risk exposure score...", stage="CORRELATION", progress=96, component="Exposure Engine")
            from src.services.exposure_scoring import ExposureScoringEngine
            exposure_report = ExposureScoringEngine.calculate_investigation_exposure(all_findings)
            worker_repo.update_exposure_score(ctx.recon_id, exposure_report["exposure_score"])

            elapsed = round(time.time() - start_ts, 2)
            ctx.elapsed_seconds = elapsed
            # Determine truthful campaign & scan completion status
            if failed_stages > 0 and succeeded_stages == 0:
                camp_status = "Failed"
                scan_status = "failed"
                final_msg = f"Campaign failed in {elapsed}s: {', '.join(failed_stage_names)} could not complete."
                final_evt_type = "error"
            elif failed_stages > 0:
                camp_status = "Partially Completed"
                scan_status = "partially_completed"
                final_msg = f"Campaign partially completed in {elapsed}s ({failed_stages} stage failure/unavailability: {', '.join(failed_stage_names)})."
                final_evt_type = "warning"
            else:
                camp_status = "Completed"
                scan_status = "completed"
                final_msg = f"Assessment completed in {elapsed}s. Findings: {len(all_findings)}, Open Ports: {len(discovered_ports)}, Risk Score: {exposure_report['exposure_score']}/100 ({exposure_report['exposure_level']})."
                final_evt_type = "stage_complete"

            summary_bundle = {
                "target": ctx.target,
                "targets": targets_list,
                "status": camp_status,
                "findings_count": len(all_findings),
                "exposure_score": exposure_report["exposure_score"],
                "exposure_level": exposure_report["exposure_level"],
                "elapsed_seconds": elapsed,
                "scanners_executed": list(dict.fromkeys(scanners_executed)),
                "scanner_statuses": scanner_statuses,
                "failed_stages": failed_stage_names,
                "passive_results": passive_results,
                "active_hosts": active_hosts,
                "discovered_ports": discovered_ports
            }

            # Archive structured recon_results_json into evidence storage cleanly
            try:
                res_bytes = json.dumps(summary_bundle, indent=2).encode("utf-8")
                ev_res = orchestrator.storage.upload_content(
                    content=res_bytes,
                    file_name=f"recon_results_{ctx.recon_id}_{ctx.scan_id}.json",
                    investigation_id=ctx.recon_id,
                    evidence_type="recon_results_json",
                    content_type="application/json"
                )
                worker_repo.add_evidence_record(
                    investigation_id=ctx.recon_id,
                    evidence_type="recon_results_json",
                    file_name=ev_res["file_name"],
                    file_size=ev_res["file_size"],
                    sha256_hash=ev_res["sha256_hash"],
                    seaweed_fid=ev_res.get("seaweed_fid"),
                    seaweed_url=ev_res.get("seaweed_url"),
                    local_path=ev_res.get("local_path"),
                    scan_id=ctx.scan_id
                )
            except Exception as ev_err:
                logger.warning(f"Results archival notice: {ev_err}")

            self._emit_event(
                ctx,
                final_evt_type,
                final_msg,
                stage="COMPLETION",
                progress=100,
                component="FootprintIQ",
                details={"status": camp_status, "failed_stages": failed_stage_names}
            )

            worker_repo.update_scan_execution(
                scan_id=ctx.scan_id,
                status=scan_status,
                error_message="; ".join(failed_stage_names) if failed_stage_names else None,
                result_summary_json=json.dumps(summary_bundle)
            )
            worker_repo.update_recon_campaign(
                ctx.recon_id,
                status=camp_status,
                progress=100,
                current_stage=camp_status
            )

            ctx.is_completed = True
            ctx.result = {
                "scan_id": ctx.scan_id,
                "recon_id": ctx.recon_id,
                "status": camp_status.upper(),
                "findings_count": len(all_findings),
                "exposure_summary": exposure_report,
                "elapsed_seconds": elapsed
            }

        except Exception as e:
            logger.error(f"Scan job {ctx.scan_id} failed: {e}", exc_info=True)
            self._emit_event(ctx, "error", f"Scan execution failed: {str(e)}", stage="ERROR", component="FootprintIQ")
            worker_repo.update_scan_execution(ctx.scan_id, status="failed", error_message=str(e))
            worker_repo.update_recon_campaign(ctx.recon_id, status="Failed", current_stage="Failed")
            ctx.is_completed = True
            ctx.error = str(e)

    def _handle_cancellation(self, ctx: ScanJobContext, worker_repo: Optional[FootprintIQRepository] = None):
        """Gracefully marks job as cancelled."""
        repo = worker_repo or self.repo
        self._emit_event(ctx, "warning", "Scan execution cancelled by user request.", stage="CANCELLED", component="FootprintIQ")
        repo.update_scan_execution(ctx.scan_id, status="cancelled", error_message="Cancelled by user.")
        repo.update_recon_campaign(ctx.recon_id, status="Cancelled", current_stage="Cancelled")
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

    def build_live_snapshot(
        self,
        recon_id: str,
        campaign: Optional[Dict[str, Any]],
        scans: Optional[List[Dict[str, Any]]],
        bundle: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Builds a unified live telemetry snapshot from memory context or persisted scan bundle."""
        ctx_obj = self.get_scan_context(recon_id)
        latest_scan = scans[0] if scans else None
        camp = campaign or {}
        elapsed_seconds = getattr(ctx_obj, "elapsed_seconds", None) if ctx_obj else None
        if elapsed_seconds is None and latest_scan and latest_scan.get("result_summary_json"):
            try:
                raw_sum = latest_scan["result_summary_json"]
                parsed = json.loads(raw_sum) if isinstance(raw_sum, str) else raw_sum
                if isinstance(parsed, dict) and parsed.get("elapsed_seconds") is not None:
                    elapsed_seconds = parsed.get("elapsed_seconds")
            except Exception:
                pass

        is_terminal = str(camp.get("status") or "").lower() in (
            "completed", "failed", "cancelled", "partially completed"
        )
        completed_checks = (
            ctx_obj.completed_checks
            if ctx_obj is not None
            else len(bundle.get("scanner_statuses") or [])
        )
        if ctx_obj is not None and not ctx_obj.is_completed and not is_terminal:
            pending_checks = max(0, ctx_obj.planned_checks - ctx_obj.completed_checks)
        else:
            pending_checks = 0

        return {
            "start_time_utc": (
                getattr(ctx_obj, "start_time_utc", None)
                or (latest_scan.get("started_at") if latest_scan else None)
                or camp.get("updated_at")
            ),
            "current_scanner": (
                getattr(ctx_obj, "current_scanner", None)
                or camp.get("current_stage")
                or "Pending"
            ),
            "completed_checks": completed_checks,
            "pending_checks": pending_checks,
            "services_count": len(bundle.get("discovered_ports") or []),
            "elapsed_seconds": elapsed_seconds,
        }

