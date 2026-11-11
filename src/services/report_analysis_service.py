"""
FootprintIQ - Integrated Report Analysis Engine
Synthesizes factual, non-fabricated Executive Analysis, Vulnerability Analysis,
Risk Interpretation, Remediation Analysis, and Assessment Limitations directly from
persisted campaign data, vulnerability findings, exposure scores, scan execution logs,
and collected evidence records.
"""

import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.db.repository import FootprintIQRepository
from src.services.exposure_scoring import ExposureScoringEngine
from src.services.finding_translator import (
    build_dynamic_remediation_roadmap,
    classify_confidence,
    explain_finding_plain_language,
)
from src.services.recon_results_helper import load_campaign_results_bundle

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")


def extract_report_file_metadata(filename: str) -> Dict[str, str]:
    """Extracts report format and investigation/campaign ID from standard PDF names."""
    m = re.search(r"FootprintIQ_(?:(Executive|Technical)_)?Report_([A-Za-z0-9_-]+)_\d+", filename or "")
    if m:
        return {
            "report_format": (m.group(1) or "Executive").lower(),
            "investigation_id": m.group(2),
        }
    return {"report_format": "executive", "investigation_id": "UNKNOWN"}


def resolve_report_record(
    report_identifier: str,
    repo: FootprintIQRepository,
    reports_dir: str = REPORTS_DIR,
) -> Optional[Dict[str, Any]]:
    """
    Resolves a report by REP-... ID or PDF file name, merging database metadata
    with filesystem artifact details cleanly.
    """
    clean_id = os.path.basename((report_identifier or "").strip())
    if not clean_id:
        return None

    db_rec = repo.get_report_record(clean_id)
    if not db_rec and not clean_id.endswith(".pdf") and not clean_id.startswith("REP-"):
        db_rec = repo.get_report_record(clean_id + ".pdf")

    file_name = db_rec.get("file_name") if db_rec else (clean_id if clean_id.endswith(".pdf") else f"{clean_id}.pdf")
    full_path = os.path.join(reports_dir, file_name)
    file_exists = os.path.isfile(full_path)

    if not db_rec and not file_exists:
        return None

    meta = extract_report_file_metadata(file_name)
    inv_id = (
        (db_rec.get("recon_id") if db_rec else None)
        or (db_rec.get("investigation_id") if db_rec else None)
        or meta["investigation_id"]
    )
    stat_size = os.path.getsize(full_path) if file_exists else 0
    created_iso = (
        (db_rec.get("generated_at") if db_rec else None)
        or (datetime.fromtimestamp(os.path.getctime(full_path), tz=timezone.utc).isoformat() if file_exists else None)
    )

    return {
        "report_id": db_rec.get("report_id") if db_rec else file_name,
        "db_report_id": db_rec.get("report_id") if db_rec else None,
        "file_name": file_name,
        "file_exists": file_exists,
        "file_path": full_path if file_exists else None,
        "investigation_id": inv_id,
        "recon_id": inv_id,
        "report_format": ((db_rec.get("report_type") if db_rec else None) or meta["report_format"]).lower(),
        "file_size": db_rec.get("file_size") if (db_rec and db_rec.get("file_size")) else stat_size,
        "sha256_hash": db_rec.get("sha256_hash") if db_rec else None,
        "seaweed_fid": db_rec.get("seaweed_fid") if db_rec else None,
        "generated_by_user_id": db_rec.get("generated_by_user_id") if db_rec else None,
        "generated_by_username": db_rec.get("generated_by_username") if db_rec else None,
        "generated_at": created_iso,
        "download_url": f"/api/v1/reports/{file_name}/download?investigation_id={inv_id}",
    }


def build_report_analysis(
    investigation_id: str,
    repo: FootprintIQRepository,
    *,
    report_meta: Optional[Dict[str, Any]] = None,
    findings_override: Optional[List[Dict[str, Any]]] = None,
    targets_override: Optional[List[Dict[str, Any]]] = None,
    evidence_override: Optional[List[Dict[str, Any]]] = None,
    results_bundle_override: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Produces complete factual Report Analysis across all 5 analytical dimensions:
      1. Executive analysis
      2. Vulnerability analysis
      3. Risk interpretation
      4. Remediation analysis
      5. Assessment limitations
    """
    camp = repo.get_recon_campaign(investigation_id) or {}
    inv = repo.get_investigation(investigation_id) or {}
    campaign_name = camp.get("name") or inv.get("title") or investigation_id
    campaign_status = camp.get("status") or inv.get("status") or "Unknown"
    target_value = camp.get("target_value") or "Scoped targets"

    targets = targets_override if targets_override is not None else repo.list_authorized_targets(investigation_id)
    findings = findings_override if findings_override is not None else repo.list_findings(investigation_id)
    evidence = evidence_override if evidence_override is not None else repo.list_evidence(investigation_id)
    scans = repo.list_scans(investigation_id)
    bundle = results_bundle_override if results_bundle_override is not None else load_campaign_results_bundle(investigation_id, repo)

    exposure = ExposureScoringEngine.calculate_investigation_exposure(findings)
    sev_counts = exposure["severity_counts"]
    score = exposure["exposure_score"]
    level = exposure["exposure_level"]

    discovered_ports = bundle.get("discovered_ports") or []
    scanner_statuses = bundle.get("scanner_statuses") or []
    passive_results = bundle.get("passive_results") or []
    failed_stages = list(bundle.get("failed_stages") or [])

    # 1. Confidence & Remediation Status Breakdown
    confidence_counts: Dict[str, int] = defaultdict(int)
    remediation_counts: Dict[str, int] = defaultdict(int)
    cve_set = set()
    host_map: Dict[str, Dict[str, Any]] = {}

    enriched_findings: List[Dict[str, Any]] = []
    for f in findings:
        conf_label = classify_confidence(f)
        confidence_counts[conf_label] += 1
        rem_status = str(f.get("remediation_status") or f.get("finding_status") or "open").lower()
        remediation_counts[rem_status] += 1

        raw_cve = str(f.get("cve_identifiers") or "").strip()
        f_cves = [c.strip() for c in raw_cve.split(",") if c.strip() and c.strip() not in ("N/A", "None", "—")]
        cve_set.update(f_cves)

        ip_key = str(f.get("target_ip") or target_value or "Target")
        if ip_key not in host_map:
            host_map[ip_key] = {
                "host": ip_key,
                "finding_count": 0,
                "critical_high_count": 0,
                "ports": set(),
                "services": set(),
                "cves": set(),
            }
        host_map[ip_key]["finding_count"] += 1
        if str(f.get("severity") or "").lower() in ("critical", "high"):
            host_map[ip_key]["critical_high_count"] += 1
        if f.get("port"):
            host_map[ip_key]["ports"].add(int(f["port"]))
        if f.get("service"):
            host_map[ip_key]["services"].add(str(f["service"]))
        host_map[ip_key]["cves"].update(f_cves)

        plain = explain_finding_plain_language(f)
        enriched_findings.append({
            **f,
            "confidence_label": conf_label,
            "remediation_status": rem_status,
            "plain_language": plain,
        })

    # Include active discovered ports in host summaries even when no CVE findings exist on them
    for dp in discovered_ports:
        ip_key = str(dp.get("target_ip") or target_value or "Target")
        if ip_key not in host_map:
            host_map[ip_key] = {
                "host": ip_key,
                "finding_count": 0,
                "critical_high_count": 0,
                "ports": set(),
                "services": set(),
                "cves": set(),
            }
        if dp.get("port"):
            host_map[ip_key]["ports"].add(int(dp["port"]))
        if dp.get("service"):
            host_map[ip_key]["services"].add(str(dp["service"]))

    sev_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Info": 1}
    sorted_findings = sorted(
        enriched_findings,
        key=lambda item: (
            sev_rank.get(str(item.get("severity") or "Informational"), 0),
            float(item.get("cvss_score") or 0.0),
        ),
        reverse=True,
    )

    affected_hosts = [
        {
            "host": h["host"],
            "finding_count": h["finding_count"],
            "critical_high_count": h["critical_high_count"],
            "ports": sorted(h["ports"]),
            "services": sorted(h["services"]),
            "cves": sorted(h["cves"]),
        }
        for h in sorted(host_map.values(), key=lambda x: (x["critical_high_count"], x["finding_count"]), reverse=True)
    ]

    # 2. Honest Coverage & Limitations Evaluation
    coverage_gaps: List[str] = []
    for st in failed_stages:
        coverage_gaps.append(f"Stage '{st}' failed or exited incomplete; findings from this stage may be missing.")
    for ss in scanner_statuses:
        s_status = str(ss.get("status") or "").upper()
        if s_status in ("FAILED", "UNAVAILABLE", "READ_ONLY_LICENSE", "BLOCKED", "CANCELLED"):
            coverage_gaps.append(
                f"{ss.get('scanner') or 'Scanner'} ({s_status}): {ss.get('detail') or 'Engine unavailable or did not finish.'}"
            )
    for sc in scans:
        sc_status = str(sc.get("status") or "").lower()
        if sc_status in ("failed", "cancelled", "interrupted", "partially_completed"):
            coverage_gaps.append(
                f"Scan {sc.get('scan_id')} ({sc.get('scan_type')}) ended with status '{sc_status}'."
            )
    for pr in passive_results:
        for uc in (pr.get("unavailable_checks") or []):
            coverage_gaps.append(f"Passive check '{uc.get('id')}' unavailable: {uc.get('reason')}")

    # Deduplicate gaps cleanly preserving order
    dedup_gaps = list(dict.fromkeys(coverage_gaps))
    is_incomplete_campaign = campaign_status in (
        "Draft", "Pending Authorization", "Authorized", "Queued", "Running",
        "Failed", "Partially Completed", "Cancelled", "Interrupted"
    )
    has_incomplete_coverage = bool(dedup_gaps or is_incomplete_campaign)

    # 3. Executive Analysis
    key_takeaways: List[str] = []
    if sev_counts["Critical"] or sev_counts["High"]:
        key_takeaways.append(
            f"Identified {sev_counts['Critical']} Critical and {sev_counts['High']} High severity findings contributing to a {score}/100 ({level}) exposure score."
        )
    elif findings:
        key_takeaways.append(
            f"Recorded {len(findings)} lower-severity or informational finding(s) with no Critical or High vulnerabilities in completed modules (Exposure Score: {score}/100)."
        )
    elif has_incomplete_coverage:
        key_takeaways.append(
            f"No findings were persisted, but coverage is INCOMPLETE ({campaign_status}). Zero recorded findings cannot be interpreted as a clean bill of health."
        )
    else:
        key_takeaways.append(
            "Zero vulnerabilities were detected across all completed assessment modules for the configured scope."
        )

    if discovered_ports:
        port_sample = ", ".join([f"{p.get('port')}/{p.get('service') or p.get('protocol', 'tcp')}" for p in discovered_ports[:6]])
        key_takeaways.append(f"Observed {len(discovered_ports)} exposed service port(s), including {port_sample}.")
    if cve_set:
        key_takeaways.append(f"Correlated {len(cve_set)} distinct CVE identifier(s): {', '.join(sorted(cve_set)[:6])}.")
    if confidence_counts.get("Confirmed Vulnerability"):
        key_takeaways.append(f"{confidence_counts['Confirmed Vulnerability']} finding(s) carry Confirmed confidence from verified evidence.")
    if confidence_counts.get("Potential Vulnerability"):
        key_takeaways.append(f"{confidence_counts['Potential Vulnerability']} finding(s) are classified as Potential vulnerabilities pending manual validation.")

    overall_posture = (
        f"Campaign '{campaign_name}' ({investigation_id}) assessed target '{target_value}' with current outcome '{campaign_status}'. "
        f"Calculated risk posture is {level} ({score}/100) across {len(findings)} recorded finding(s) and {len(discovered_ports)} discovered port(s)."
    )
    if has_incomplete_coverage:
        overall_posture += " Incomplete or failed scan modules limit completeness; affected modules must be re-run before concluding target security."

    # 4. Risk Interpretation (non-fabricated, driven by observed evidence)
    risk_drivers: List[str] = []
    confirmed_count = confidence_counts.get("Confirmed Vulnerability", 0)
    potential_count = confidence_counts.get("Potential Vulnerability", 0)
    high_cvss = [f for f in sorted_findings if (f.get("cvss_score") or 0) >= 7.0]
    if high_cvss:
        risk_drivers.append(
            f"{len(high_cvss)} finding(s) carry CVSS scores >= 7.0 (highest: {high_cvss[0].get('cvss_score')} on '{high_cvss[0].get('title')}'), indicating elevated exploitation potential."
        )
    exposed_services = {str(p.get("service") or "").lower() for p in discovered_ports if p.get("service")}
    legacy_or_admin = sorted(exposed_services & {"ftp", "telnet", "smb", "microsoft-ds", "netbios-ssn", "ssh", "rdp", "ms-wbt-server", "vnc", "http"})
    if legacy_or_admin:
        risk_drivers.append(
            f"Exposed remote administration or cleartext/web services detected ({', '.join(legacy_or_admin)}); review authentication hardening and network segmentation."
        )
    if potential_count and not confirmed_count:
        risk_drivers.append(
            "Findings rely primarily on automated version/signature indicators (Potential); analyst validation is recommended to confirm exploitability."
        )
    if not risk_drivers and findings:
        risk_drivers.append(
            "Observed items are primarily moderate/informational configuration exposures without confirmed critical remote exploitation paths in scanned scope."
        )
    if not risk_drivers and not findings:
        risk_drivers.append(
            "No exploit paths recorded in completed stages."
            if not has_incomplete_coverage
            else "Risk remains indeterminate for incomplete or failed scanner stages until those checks complete cleanly."
        )

    risk_interpretation = {
        "exposure_score": score,
        "exposure_level": level,
        "confirmed_findings": confirmed_count,
        "potential_findings": potential_count,
        "informational_findings": confidence_counts.get("Informational Observation", 0) + confidence_counts.get("Unverified / Informational", 0),
        "drivers": risk_drivers,
        "confidence_summary": (
            f"{confirmed_count} confirmed, {potential_count} potential, "
            f"{confidence_counts.get('Marked False Positive', 0)} false positive"
        ),
    }

    # 5. Remediation Analysis
    roadmap = build_dynamic_remediation_roadmap(findings, failed_scanners=failed_stages)
    action_items: List[Dict[str, Any]] = []
    for f in sorted_findings[:12]:
        rem_text = str(f.get("remediation") or f.get("plain_language", {}).get("recommended_action") or "").strip()
        if not rem_text:
            continue
        action_items.append({
            "finding_id": f.get("finding_id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "target": f"{f.get('target_ip')}:{f.get('port')}" if f.get("port") else f.get("target_ip"),
            "status": f.get("remediation_status"),
            "action": rem_text,
        })

    # 6. Scope Limitations
    scope_constraints = {
        "authorized_targets_count": len(targets),
        "primary_target": target_value,
        "excluded_targets": camp.get("excluded_targets") or "None recorded",
        "excluded_ports": camp.get("excluded_ports") or "None recorded",
        "selected_scan_types": camp.get("selected_scan_types") or "Not specified",
    }

    return {
        "report_metadata": report_meta or {
            "investigation_id": investigation_id,
            "recon_id": investigation_id,
            "campaign_name": campaign_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "campaign": {
            "investigation_id": investigation_id,
            "name": campaign_name,
            "status": campaign_status,
            "target_value": target_value,
            "purpose": camp.get("purpose") or inv.get("description") or "Security Assessment",
            "creator_id": camp.get("creator_id") or inv.get("creator_id"),
            "authorized_by": camp.get("authorized_by"),
        },
        "executive_analysis": {
            "overall_posture": overall_posture,
            "exposure_score": score,
            "exposure_level": level,
            "affected_target_count": len(affected_hosts) or len(targets) or 1,
            "findings_count": len(findings),
            "open_ports_count": len(discovered_ports),
            "evidence_count": len(evidence),
            "key_takeaways": key_takeaways,
        },
        "vulnerability_analysis": {
            "severity_distribution": sev_counts,
            "confidence_breakdown": dict(confidence_counts),
            "affected_hosts": affected_hosts,
            "discovered_ports": discovered_ports,
            "cve_inventory": sorted(cve_set),
            "scanner_coverage": scanner_statuses,
            "top_findings": sorted_findings[:25],
        },
        "risk_interpretation": risk_interpretation,
        "remediation_analysis": {
            "roadmap": roadmap,
            "remediation_status_counts": dict(remediation_counts),
            "prioritized_actions": action_items,
            "verification_guidance": (
                "Re-execute targeted validation scans after applying patches/hardening and update each finding's remediation status with verification notes."
            ),
        },
        "assessment_limitations": {
            "campaign_status": campaign_status,
            "is_complete": not has_incomplete_coverage,
            "incomplete_warning": (
                "Assessment has incomplete, cancelled, failed, or unavailable scanner stages. Absence of findings in incomplete stages is NOT clean."
                if has_incomplete_coverage
                else None
            ),
            "coverage_gaps": dedup_gaps,
            "failed_stages": failed_stages,
            "scope_constraints": scope_constraints,
        },
        "evidence_references": evidence[:50],
    }
