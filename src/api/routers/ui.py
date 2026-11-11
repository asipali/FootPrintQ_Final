"""
FootprintIQ - UI Web Dashboard Router
Renders RBAC-scoped Jinja2 HTML templates with server-side ownership enforcement:
- / (Main Dashboard)
- /recon, /recon/new, /recon/{recon_id}/workspace, /recon/{recon_id}/live, /recon/{recon_id}/results, /recon/{recon_id}/pdf
- /investigations, /scans, /findings, /evidence
- /reports, /reports/{report_id} (Integrated Report Details & Analyse Report)
- /settings, /login
- /admin/users, /admin/scanners, /admin/system, /admin/audit-logs
"""

import os
import re
import json
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any, List, Set

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse

from src.db.repository import FootprintIQRepository
from src.services.exposure_scoring import ExposureScoringEngine
from src.services.scan_options_service import ScanOptionsService
from src.services.recon_results_helper import load_campaign_results_bundle, enrich_findings_with_explanations
from src.services.report_analysis_service import (
    REPORTS_DIR as ANALYSIS_REPORTS_DIR,
    build_report_analysis,
    extract_report_file_metadata,
    resolve_report_record,
)
from src.services.rbac_service import (
    ROLE_ADMIN,
    ROLE_INVESTIGATOR,
    enforce_investigation_access,
    filter_accessible_investigation_ids,
    is_admin_user,
    is_investigator_user,
    normalize_role,
    record_security_audit,
)
from src.authorization.target_authorizer import TargetAuthorizer
from src.orchestration.execution_manager import ExecutionManager
from src.api.dependencies import (
    CSRF_COOKIE_NAME,
    UIAccessDeniedException,
    get_current_user_ui,
    get_optional_current_user,
    get_repository,
    require_admin_ui,
    require_investigator_ui,
)

TEMPLATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "templates"))
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
REPORTS_DIR = ANALYSIS_REPORTS_DIR
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(include_in_schema=False)


def _filter_scoped_list(
    items: List[Dict[str, Any]],
    accessible_ids: Optional[Set[str]],
    *id_keys: str,
) -> List[Dict[str, Any]]:
    """Filters list of records against allowed investigation/recon IDs (None = Admin unfiltered)."""
    if accessible_ids is None:
        return items
    keys = id_keys or ("investigation_id", "recon_id")
    filtered: List[Dict[str, Any]] = []
    for item in items:
        if any(item.get(k) in accessible_ids for k in keys if item.get(k)):
            filtered.append(item)
    return filtered


def _enforce_ui_investigation_access(
    repo: FootprintIQRepository,
    current_user: Dict[str, Any],
    investigation_id: str,
    request: Request,
    *,
    require_execution: bool = False,
    action_label: str = "UI_INVESTIGATION_VIEW",
) -> Dict[str, Any]:
    """Converts RBAC 403 HTTPExceptions into branded HTML Access Denied responses for browser UI."""
    try:
        return enforce_investigation_access(
            repo,
            current_user,
            investigation_id,
            require_execution=require_execution,
            request=request,
            action_label=action_label,
        )
    except HTTPException as exc:
        if exc.status_code == 403:
            raise UIAccessDeniedException(str(exc.detail), user=current_user)
        raise


def _get_existing_reports(
    repo: Optional[FootprintIQRepository] = None,
    accessible_ids: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    db_by_file: Dict[str, Dict[str, Any]] = {}
    if repo is not None:
        try:
            for r in repo.list_report_records():
                db_by_file[r["file_name"]] = r
        except Exception:
            pass

    reports: List[Dict[str, Any]] = []
    if os.path.exists(REPORTS_DIR):
        for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
            if not f.endswith(".pdf"):
                continue
            full_path = os.path.join(REPORTS_DIR, f)
            if not os.path.isfile(full_path):
                continue
            stat = os.stat(full_path)
            meta = extract_report_file_metadata(f)
            db_rec = db_by_file.get(f)
            fmt = (db_rec.get("report_type") if db_rec else None) or meta["report_format"]
            inv_id = (
                (db_rec.get("recon_id") if db_rec else None)
                or (db_rec.get("investigation_id") if db_rec else None)
                or meta["investigation_id"]
            )
            if accessible_ids is not None and inv_id not in accessible_ids:
                continue
            report_key = (db_rec.get("report_id") if db_rec else None) or f
            reports.append({
                "report_id": db_rec.get("report_id") if db_rec else None,
                "report_key": report_key,
                "file_name": f,
                "investigation_id": inv_id,
                "report_format": fmt.lower(),
                "file_size": stat.st_size,
                "generated_by_username": db_rec.get("generated_by_username") if db_rec else None,
                "created_at": (db_rec.get("generated_at") if db_rec else None) or datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                "analysis_url": f"/reports/{report_key}",
                "download_url": f"/api/v1/reports/{f}/download?investigation_id={inv_id}",
            })
    return reports


def _ui_ctx(
    active_page: str,
    current_user: Optional[Dict[str, Any]],
    request: Optional[Request] = None,
    **extra,
) -> Dict[str, Any]:
    role = normalize_role((current_user or {}).get("role"))
    csrf_token = (
        (request.cookies.get(CSRF_COOKIE_NAME) if request else None)
        or (current_user or {}).get("csrf_token")
        or ""
    )
    return {
        "active_page": active_page,
        "current_user": current_user,
        "is_admin": role == ROLE_ADMIN,
        "is_investigator": role == ROLE_INVESTIGATOR,
        "csrf_token": csrf_token,
        **extra,
    }


@router.get("/", response_class=HTMLResponse)
def view_dashboard(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    investigations = _filter_scoped_list(repo.list_investigations(), accessible, "investigation_id")
    scans = _filter_scoped_list(repo.list_scans(), accessible, "investigation_id", "recon_id")
    findings = _filter_scoped_list(repo.list_findings(), accessible, "investigation_id", "recon_id")
    evidence = _filter_scoped_list(repo.list_evidence(), accessible, "investigation_id", "recon_id")
    targets = _filter_scoped_list(repo.list_authorized_targets(), accessible, "investigation_id", "recon_id")
    recon_campaigns = _filter_scoped_list(repo.list_recon_campaigns(), accessible, "recon_id", "investigation_id")
    options_catalog = ScanOptionsService.get_full_catalog()

    exposure_summary = ExposureScoringEngine.calculate_investigation_exposure(findings)

    running_campaigns = [c for c in recon_campaigns if c.get("status") in ("Running", "in_progress", "Queued")]
    completed_campaigns = [c for c in recon_campaigns if c.get("status") in ("Completed", "completed")]
    failed_campaigns = [c for c in recon_campaigns if c.get("status") in ("Failed", "failed", "Partially Completed")]

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context=_ui_ctx(
            "dashboard",
            current_user,
            request=request,
            exposure=exposure_summary,
            options_catalog=options_catalog,
            total_investigations=len(investigations),
            total_scans=len(scans),
            total_findings=len(findings),
            total_evidence=len(evidence),
            total_targets=len(targets),
            total_campaigns=len(recon_campaigns),
            running_campaigns_count=len(running_campaigns),
            completed_campaigns_count=len(completed_campaigns),
            failed_campaigns_count=len(failed_campaigns),
            investigations=investigations,
            recon_campaigns=recon_campaigns,
            targets=targets,
            findings=findings,
            scans=list(reversed(scans)),
        ),
    )


# =========================================================================
# RECONNAISSANCE CAMPAIGN PLATFORM UI ROUTES
# =========================================================================

@router.get("/recon", response_class=HTMLResponse)
def view_recon_campaigns(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    campaigns = _filter_scoped_list(repo.list_recon_campaigns(), accessible, "recon_id", "investigation_id")
    targets = _filter_scoped_list(repo.list_authorized_targets(), accessible, "investigation_id", "recon_id")
    findings = _filter_scoped_list(repo.list_findings(), accessible, "investigation_id", "recon_id")
    all_reports = _get_existing_reports(repo, accessible_ids=accessible)
    reports_by_recon: Dict[str, Any] = {}
    for rep in all_reports:
        rid = rep.get("investigation_id")
        if rid and rid not in reports_by_recon:
            reports_by_recon[rid] = rep

    total = len(campaigns)
    running = sum(1 for c in campaigns if c.get("status") in ("Running", "in_progress", "Queued"))
    completed = sum(1 for c in campaigns if c.get("status") in ("Completed", "completed"))
    failed = sum(1 for c in campaigns if c.get("status") in ("Failed", "failed", "Partially Completed"))

    return templates.TemplateResponse(
        request=request,
        name="recon_list.html",
        context=_ui_ctx(
            "recon_list",
            current_user,
            request=request,
            campaigns=campaigns,
            reports_by_recon=reports_by_recon,
            total_campaigns=total,
            running_count=running,
            completed_count=completed,
            failed_count=failed,
            total_targets=len(targets),
            total_findings=len(findings),
        ),
    )


@router.get("/recon/new", response_class=HTMLResponse)
def view_recon_create(
    request: Request,
    edit: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_investigator_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    if edit:
        edit_campaign = _enforce_ui_investigation_access(
            repo, current_user, edit, request, require_execution=True, action_label="UI_RECON_EDIT"
        )
        if not repo.get_recon_campaign(edit):
            raise HTTPException(status_code=404, detail=f"Recon Campaign '{edit}' not found.")
        profiles = repo.list_saved_scan_profiles()
        options_catalog = ScanOptionsService.get_full_catalog()
        return templates.TemplateResponse(
            request=request,
            name="recon_workspace.html",
            context=_ui_ctx(
                "recon_new",
                current_user,
                request=request,
                campaign=edit_campaign,
                recon_id=edit,
                profiles=profiles,
                options_catalog=options_catalog,
                created=False,
            ),
        )

    return templates.TemplateResponse(
        request=request,
        name="recon_create.html",
        context=_ui_ctx(
            "recon_new",
            current_user,
            request=request,
            default_target="",
        ),
    )


@router.get("/recon/{recon_id}/workspace", response_class=HTMLResponse)
def view_recon_workspace(
    recon_id: str,
    request: Request,
    created: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_investigator_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    campaign = _enforce_ui_investigation_access(
        repo, current_user, recon_id, request, require_execution=True, action_label="UI_RECON_WORKSPACE"
    )
    if not repo.get_recon_campaign(recon_id):
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    profiles = repo.list_saved_scan_profiles()
    options_catalog = ScanOptionsService.get_full_catalog()
    return templates.TemplateResponse(
        request=request,
        name="recon_workspace.html",
        context=_ui_ctx(
            "recon_list",
            current_user,
            request=request,
            campaign=campaign,
            recon_id=recon_id,
            profiles=profiles,
            options_catalog=options_catalog,
            created=(created == "1" or created == "true"),
        ),
    )


@router.get("/recon/{recon_id}", response_class=HTMLResponse)
def view_recon_detail(
    recon_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    campaign = _enforce_ui_investigation_access(repo, current_user, recon_id, request)
    if not repo.get_recon_campaign(recon_id):
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    if campaign.get("status") in ("Running", "in_progress", "Queued"):
        return RedirectResponse(url=f"/recon/{recon_id}/live", status_code=303)
    if campaign.get("status") in ("Draft", "Authorized", "Pending"):
        if is_investigator_user(current_user):
            return RedirectResponse(url=f"/recon/{recon_id}/workspace", status_code=303)
        return RedirectResponse(url=f"/recon/{recon_id}/results", status_code=303)
    return RedirectResponse(url=f"/recon/{recon_id}/results", status_code=303)


@router.get("/recon/{recon_id}/live", response_class=HTMLResponse)
def view_recon_live(
    recon_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    campaign = _enforce_ui_investigation_access(repo, current_user, recon_id, request)
    if not repo.get_recon_campaign(recon_id):
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    scans = repo.list_scans(investigation_id=recon_id)
    findings = repo.list_findings(investigation_id=recon_id)
    latest_scan = scans[0] if scans else None
    bundle = load_campaign_results_bundle(recon_id, repo)
    evidence = repo.list_evidence(investigation_id=recon_id)

    nessus_status = "Unavailable"
    try:
        from src.collectors.nessus_collector import NessusCollector
        n_res = NessusCollector().test_connection()
        if n_res.get("connected") and n_res.get("scan_api_enabled", True):
            nessus_status = "Operational"
        elif n_res.get("connected"):
            nessus_status = "Connected (Read-Only)"
        else:
            nessus_status = n_res.get("status") or "Unavailable"
    except Exception:
        pass

    nuclei_status = "Unavailable"
    try:
        from src.collectors.nuclei_collector import NucleiCollector
        nuc_res = NucleiCollector().check_readiness()
        nuclei_status = "Operational" if nuc_res.get("ready") else "Unavailable"
    except Exception:
        pass

    live_ctx = ExecutionManager(repo=repo).build_live_snapshot(recon_id, campaign, scans, bundle)
    try:
        parsed_cfg = json.loads(campaign.get("scan_config_json") or "{}")
    except Exception:
        parsed_cfg = {}
    selected_cats = parsed_cfg.get("selected_categories") or ([campaign.get("selected_scan_types")] if campaign.get("selected_scan_types") else [])

    return templates.TemplateResponse(
        request=request,
        name="recon_live.html",
        context=_ui_ctx(
            "recon_list",
            current_user,
            request=request,
            campaign=campaign,
            recon_id=recon_id,
            scans=scans,
            latest_scan=latest_scan,
            findings=findings,
            findings_count=len(findings),
            initial_events=bundle["events"],
            passive_results=bundle["passive_results"],
            active_hosts=bundle["active_hosts"],
            discovered_ports=bundle["discovered_ports"],
            scanner_statuses=bundle["scanner_statuses"],
            evidence=evidence,
            nessus_status=nessus_status,
            nuclei_status=nuclei_status,
            scan_categories=selected_cats,
            live_ctx=live_ctx,
        ),
    )


@router.get("/recon/{recon_id}/results", response_class=HTMLResponse)
def view_recon_results(
    recon_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    campaign = _enforce_ui_investigation_access(repo, current_user, recon_id, request)
    if not repo.get_recon_campaign(recon_id):
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    accessible = filter_accessible_investigation_ids(repo, current_user)
    findings = repo.list_findings(investigation_id=recon_id)
    explained_findings = enrich_findings_with_explanations(findings)
    exposure_summary = ExposureScoringEngine.calculate_investigation_exposure(findings)
    all_campaigns = _filter_scoped_list(repo.list_recon_campaigns(), accessible, "recon_id", "investigation_id")
    scans = repo.list_scans(investigation_id=recon_id)
    bundle = load_campaign_results_bundle(recon_id, repo)
    campaign_reports = _get_existing_reports(repo, accessible_ids={recon_id})

    return templates.TemplateResponse(
        request=request,
        name="recon_results.html",
        context=_ui_ctx(
            "recon_list",
            current_user,
            request=request,
            campaign=campaign,
            recon_id=recon_id,
            findings=findings,
            explained_findings=explained_findings,
            scans=scans,
            exposure=exposure_summary,
            all_campaigns=all_campaigns,
            passive_results=bundle["passive_results"],
            active_hosts=bundle["active_hosts"],
            discovered_ports=bundle["discovered_ports"],
            scanner_statuses=bundle["scanner_statuses"],
            failed_stages=bundle["failed_stages"],
            reports=campaign_reports,
        ),
    )


@router.get("/recon/{recon_id}/pdf")
def download_recon_pdf(
    recon_id: str,
    request: Request,
    format: str = "technical",
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    """
    One-click download for Executive/Technical PDFs.
    - Investigators (owner/shared): compile & persist fresh PDF with integrated Report Analysis.
    - Administrators (read-only): download latest existing PDF for the campaign if present; blocked (403) from generating new ones.
    """
    from src.reporting.unified_report import UnifiedReportGenerator

    campaign = _enforce_ui_investigation_access(
        repo,
        current_user,
        recon_id,
        request,
        require_execution=False,
        action_label="UI_REPORT_PDF",
    )
    if not repo.get_recon_campaign(recon_id):
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    if is_admin_user(current_user):
        existing = _get_existing_reports(repo, accessible_ids={recon_id})
        req_fmt = (format or "technical").lower()
        fmt_matches = [r for r in existing if (r.get("report_format") or "").lower() == req_fmt]
        target_rec = fmt_matches[0] if fmt_matches else (existing[0] if existing else None)
        if not target_rec:
            record_security_audit(
                repo,
                user=current_user,
                action="PERMISSION_DENIED",
                target_resource=recon_id,
                details={"reason": "admin_report_generation_blocked"},
                outcome="DENIED",
                request=request,
            )
            raise UIAccessDeniedException(
                "Administrators cannot generate new PDF reports. Download an existing investigator-generated report from the Reports archive once available.",
                user=current_user,
            )
        pdf_path = os.path.realpath(os.path.join(REPORTS_DIR, os.path.basename(target_rec["file_name"])))
        real_dir = os.path.realpath(REPORTS_DIR)
        if not pdf_path.startswith(real_dir + os.sep) or not os.path.isfile(pdf_path):
            raise HTTPException(status_code=404, detail="Existing report file not found.")
        record_security_audit(
            repo,
            user=current_user,
            action="REPORT_DOWNLOADED",
            target_resource=str(target_rec.get("report_id") or target_rec["file_name"]),
            details={"investigation_id": recon_id},
            outcome="SUCCESS",
            request=request,
        )
        return FileResponse(path=pdf_path, media_type="application/pdf", filename=os.path.basename(pdf_path))

    # Investigator execution path
    inv = {
        "investigation_id": campaign["recon_id"],
        "recon_id": campaign["recon_id"],
        "title": campaign["name"],
        "name": campaign["name"],
        "purpose": campaign.get("purpose", "Security Assessment"),
        "description": campaign.get("description", ""),
        "status": campaign.get("status", "Completed"),
        "target_value": campaign.get("target_value", ""),
        "target_type": campaign.get("target_type", "ipv4"),
        "scope_description": campaign.get("scope_description", ""),
        "excluded_targets": campaign.get("excluded_targets", ""),
        "selected_scan_types": campaign.get("selected_scan_types", ""),
        "scan_config_json": campaign.get("scan_config_json", "{}"),
        "created_at": campaign.get("created_at"),
    }
    targets = repo.list_authorized_targets(recon_id)
    if not targets:
        targets = [{
            "target": campaign["target_value"],
            "target_type": campaign.get("target_type", "ipv4"),
            "name": campaign["name"],
            "scope": campaign.get("scope_description") or "Authorized Scope",
            "permitted_profiles": "lab-basic",
        }]
    findings = repo.list_findings(recon_id)
    evidence = repo.list_evidence(recon_id)
    bundle = load_campaign_results_bundle(recon_id, repo)
    analysis = build_report_analysis(
        recon_id,
        repo,
        findings_override=findings,
        targets_override=targets,
        evidence_override=evidence,
        results_bundle_override=bundle,
    )

    generator = UnifiedReportGenerator()
    pdf_path = generator.generate_pdf_report(
        investigation=inv,
        targets=targets,
        findings=findings,
        evidence=evidence,
        report_format=format,
        results_bundle=bundle,
        analysis=analysis,
        generated_by=current_user.get("username"),
    )

    try:
        fsize = os.path.getsize(pdf_path)
        with open(pdf_path, "rb") as pf:
            sha = hashlib.sha256(pf.read()).hexdigest()
        rec = repo.add_report_record(
            investigation_id=recon_id,
            recon_id=recon_id,
            file_name=os.path.basename(pdf_path),
            file_size=fsize,
            sha256_hash=sha,
            report_type=format.lower(),
            generated_by_user_id=current_user.get("id"),
            generated_by_username=current_user.get("username"),
        )
        record_security_audit(
            repo,
            user=current_user,
            action="REPORT_GENERATED",
            target_resource=str(rec.get("report_id") or os.path.basename(pdf_path)),
            details={"investigation_id": recon_id, "report_format": format.lower()},
            outcome="SUCCESS",
            request=request,
        )
    except Exception:
        pass

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=os.path.basename(pdf_path),
    )


@router.get("/investigations", response_class=HTMLResponse)
def view_investigations(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    investigations = _filter_scoped_list(repo.list_investigations(), accessible, "investigation_id")
    targets = _filter_scoped_list(repo.list_authorized_targets(), accessible, "investigation_id", "recon_id")
    return templates.TemplateResponse(
        request=request,
        name="investigations.html",
        context=_ui_ctx(
            "investigations",
            current_user,
            request=request,
            investigations=list(reversed(investigations)),
            targets=targets,
        ),
    )


@router.get("/scans", response_class=HTMLResponse)
def view_scans(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    scans = _filter_scoped_list(repo.list_scans(), accessible, "investigation_id", "recon_id")
    investigations = _filter_scoped_list(repo.list_investigations(), accessible, "investigation_id")
    targets = _filter_scoped_list(repo.list_authorized_targets(), accessible, "investigation_id", "recon_id")
    return templates.TemplateResponse(
        request=request,
        name="scans.html",
        context=_ui_ctx(
            "scans",
            current_user,
            request=request,
            scans=list(reversed(scans)),
            investigations=investigations,
            targets=targets,
        ),
    )


@router.get("/findings", response_class=HTMLResponse)
def view_findings(
    request: Request,
    severity: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    findings = _filter_scoped_list(repo.list_findings(severity=severity), accessible, "investigation_id", "recon_id")
    all_findings = _filter_scoped_list(repo.list_findings(), accessible, "investigation_id", "recon_id")
    exposure_summary = ExposureScoringEngine.calculate_investigation_exposure(all_findings)
    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context=_ui_ctx(
            "findings",
            current_user,
            request=request,
            findings=findings,
            total_findings=len(all_findings),
            exposure=exposure_summary,
            selected_severity=severity,
        ),
    )


@router.get("/evidence", response_class=HTMLResponse)
def view_evidence(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    evidence = _filter_scoped_list(repo.list_evidence(), accessible, "investigation_id", "recon_id")
    return templates.TemplateResponse(
        request=request,
        name="evidence.html",
        context=_ui_ctx(
            "evidence",
            current_user,
            request=request,
            evidence=list(reversed(evidence)),
            total_evidence=len(evidence),
        ),
    )


@router.get("/reports", response_class=HTMLResponse)
def view_reports(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    investigations = _filter_scoped_list(repo.list_investigations(), accessible, "investigation_id")
    campaigns = _filter_scoped_list(repo.list_recon_campaigns(), accessible, "recon_id", "investigation_id")
    reports = _get_existing_reports(repo, accessible_ids=accessible)
    findings = _filter_scoped_list(repo.list_findings(), accessible, "investigation_id", "recon_id")
    return templates.TemplateResponse(
        request=request,
        name="reports.html",
        context=_ui_ctx(
            "reports",
            current_user,
            request=request,
            investigations=investigations,
            campaigns=campaigns,
            reports=reports,
            total_findings=len(findings),
        ),
    )


@router.get("/reports/{report_id}", response_class=HTMLResponse)
def view_report_detail_analysis(
    report_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    """Integrated Report Details & Analyse Report view (RBAC & ownership enforced)."""
    report_meta = resolve_report_record(report_id, repo)
    if not report_meta:
        raise HTTPException(status_code=404, detail=f"Report '{os.path.basename(report_id)}' not found.")

    inv_id = report_meta.get("investigation_id")
    if inv_id and inv_id != "UNKNOWN":
        _enforce_ui_investigation_access(repo, current_user, inv_id, request, action_label="UI_REPORT_ANALYZE")
    elif not is_admin_user(current_user):
        raise UIAccessDeniedException("Access denied to legacy unowned report.", user=current_user)

    analysis = build_report_analysis(inv_id, repo, report_meta=report_meta)
    record_security_audit(
        repo,
        user=current_user,
        action="REPORT_ANALYZED",
        target_resource=str(report_meta.get("report_id") or report_meta.get("file_name")),
        details={"investigation_id": inv_id, "source": "ui"},
        outcome="SUCCESS",
        request=request,
    )

    return templates.TemplateResponse(
        request=request,
        name="report_detail.html",
        context=_ui_ctx(
            "reports",
            current_user,
            request=request,
            report=report_meta,
            analysis=analysis,
        ),
    )


@router.get("/login", response_class=HTMLResponse)
def view_login(
    request: Request,
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_current_user),
):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context=_ui_ctx("login", current_user, request=request),
    )


@router.get("/settings", response_class=HTMLResponse)
def view_settings(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    raw_scope = TargetAuthorizer().get_scope_summary()
    sanitized_scope = {
        "policy_mode": "Fail-Closed Scope Enforcement",
        "authorized_targets_count": len(raw_scope.get("authorized_targets") or []),
        "approved_ranges_count": len(raw_scope.get("approved_lab_ranges") or []),
        "authorized_domains_count": len(raw_scope.get("authorized_domains") or []),
        "public_ips_restricted": not raw_scope.get("allow_public_ips", False),
    }
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context=_ui_ctx("settings", current_user, request=request, scope_summary=sanitized_scope),
    )


@router.get("/admin/users", response_class=HTMLResponse)
def view_admin_users(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_admin_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    users = [{k: v for k, v in u.items() if k != "hashed_password"} for u in repo.list_users()]
    investigations = repo.list_recon_campaigns()
    return templates.TemplateResponse(
        request=request,
        name="admin_users.html",
        context=_ui_ctx("admin_users", current_user, request=request, users=users, campaigns=investigations),
    )


@router.get("/admin/scanners", response_class=HTMLResponse)
def view_admin_scanners(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_admin_ui),
):
    catalog = ScanOptionsService.get_full_catalog()
    return templates.TemplateResponse(
        request=request,
        name="admin_scanners.html",
        context=_ui_ctx("admin_scanners", current_user, request=request, catalog=catalog),
    )


@router.get("/admin/system", response_class=HTMLResponse)
def view_admin_system(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_admin_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    from src.storage.seaweedfs_client import SeaweedFSClient
    scope = TargetAuthorizer().get_scope_summary()
    storage = SeaweedFSClient().check_health()
    db_ok = getattr(repo, "db", None) is not None
    docs_enabled = os.getenv("ENABLE_PUBLIC_API_DOCS", "false").lower() == "true"
    return templates.TemplateResponse(
        request=request,
        name="admin_system.html",
        context=_ui_ctx(
            "admin_system",
            current_user,
            request=request,
            scope_summary=scope,
            storage=storage,
            db_available=db_ok,
            docs_enabled=docs_enabled,
        ),
    )


@router.get("/admin/audit-logs", response_class=HTMLResponse)
def view_admin_audit_logs(
    request: Request,
    action: Optional[str] = None,
    outcome: Optional[str] = None,
    limit: int = 200,
    current_user: Dict[str, Any] = Depends(require_admin_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    safe_limit = max(1, min(int(limit), 500))
    logs = repo.list_audit_logs(limit=safe_limit, action=action or None, outcome=outcome or None)
    return templates.TemplateResponse(
        request=request,
        name="admin_audit_logs.html",
        context=_ui_ctx(
            "admin_audit_logs",
            current_user,
            request=request,
            audit_logs=logs,
            filter_action=action or "",
            filter_outcome=outcome or "",
        ),
    )
