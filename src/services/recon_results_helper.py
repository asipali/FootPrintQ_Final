"""
FootprintIQ - Recon Results & Bundle Hydration Helper
Extracts structured passive results, active hosts, discovered ports,
scanner statuses, and plain-language finding explanations for campaigns.
"""

import os
import json
from typing import Dict, Any, List, Optional

from src.db.repository import FootprintIQRepository
from src.services.finding_translator import explain_finding_plain_language


def load_campaign_results_bundle(recon_id: str, repo: FootprintIQRepository) -> Dict[str, Any]:
    """
    Hydrates passive_results, active_hosts, discovered_ports, scanner_statuses,
    and failed_stages from persisted scan summaries, evidence cache, or execution events.
    """
    bundle: Dict[str, Any] = {
        "passive_results": [],
        "active_hosts": [],
        "discovered_ports": [],
        "scanner_statuses": [],
        "failed_stages": [],
        "scanners_executed": []
    }

    scans = repo.list_scans(investigation_id=recon_id)
    for sc in scans:
        raw_sum = sc.get("result_summary_json")
        if raw_sum:
            try:
                parsed = json.loads(raw_sum) if isinstance(raw_sum, str) else raw_sum
                if isinstance(parsed, dict):
                    bundle["passive_results"].extend(parsed.get("passive_results") or [])
                    bundle["active_hosts"].extend(parsed.get("active_hosts") or [])
                    bundle["discovered_ports"].extend(parsed.get("discovered_ports") or [])
                    bundle["scanner_statuses"].extend(parsed.get("scanner_statuses") or [])
                    bundle["failed_stages"].extend(parsed.get("failed_stages") or [])
                    bundle["scanners_executed"].extend(parsed.get("scanners_executed") or [])
                    if any([bundle["passive_results"], bundle["active_hosts"], bundle["discovered_ports"], bundle["scanner_statuses"]]):
                        break
            except Exception:
                pass

    # Fallback: check evidence artifacts (recon_results_json / passive_intel_json)
    evidence_list = repo.list_evidence(investigation_id=recon_id)
    if not bundle["scanner_statuses"]:
        for ev in evidence_list:
            if ev.get("evidence_type") == "recon_results_json" and ev.get("local_path") and os.path.exists(ev["local_path"]):
                try:
                    with open(ev["local_path"], "r", encoding="utf-8") as f:
                        parsed = json.load(f)
                    bundle["passive_results"] = parsed.get("passive_results") or []
                    bundle["active_hosts"] = parsed.get("active_hosts") or []
                    bundle["discovered_ports"] = parsed.get("discovered_ports") or []
                    bundle["scanner_statuses"] = parsed.get("scanner_statuses") or []
                    bundle["failed_stages"] = parsed.get("failed_stages") or []
                    bundle["scanners_executed"] = parsed.get("scanners_executed") or []
                    break
                except Exception:
                    pass

    # Live incremental fallback while scan is still running: read persisted events
    events: List[Dict[str, Any]] = []
    if scans:
        events = repo.list_scan_execution_events(scans[0]["scan_id"])

    if not bundle["passive_results"] and events:
        for ev in events:
            if ev.get("event_type") == "passive_result" and ev.get("details_json"):
                try:
                    det = json.loads(ev["details_json"])
                    if "passive_summary" in det:
                        bundle["passive_results"].append(det["passive_summary"])
                except Exception:
                    pass

    if not bundle["active_hosts"] and events:
        seen_hosts = {}
        seen_ports = []
        for ev in events:
            et = ev.get("event_type")
            if et == "host_discovered" and ev.get("details_json"):
                try:
                    det = json.loads(ev["details_json"])
                    ip_key = det.get("ip") or det.get("target")
                    if ip_key:
                        seen_hosts[ip_key] = det
                except Exception:
                    pass
            elif et == "port_discovered" and ev.get("details_json"):
                try:
                    det = json.loads(ev["details_json"])
                    if det.get("port"):
                        seen_ports.append(det)
                except Exception:
                    pass
        if seen_hosts:
            bundle["active_hosts"] = list(seen_hosts.values())
        if seen_ports:
            bundle["discovered_ports"] = seen_ports

    # Deduplicate discovered_ports cleanly
    unique_ports = []
    seen_port_keys = set()
    for p in bundle["discovered_ports"]:
        key = (p.get("target_ip"), str(p.get("port")), str(p.get("protocol", "tcp")))
        if key not in seen_port_keys:
            seen_port_keys.add(key)
            unique_ports.append(p)
    bundle["discovered_ports"] = unique_ports
    bundle["events"] = events
    return bundle


def enrich_findings_with_explanations(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attaches non-fabricated plain-language explanations to each finding copy."""
    enriched = []
    for f in findings:
        copy = dict(f)
        copy["plain_language"] = explain_finding_plain_language(copy)
        enriched.append(copy)
    return enriched

