"""
FootprintIQ - UI Web Dashboard Router
Renders Jinja2 HTML templates for:
- / (Main Dashboard)
- /investigations (Investigation management)
- /scans (Reconnaissance and vulnerability assessment launch)
- /findings (Vulnerability correlation table)
- /evidence (SeaweedFS evidence catalog)
- /reports (PDF report generation and download)
"""

import os
import re
from datetime import datetime
from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from typing import Optional

from src.db.repository import FootprintIQRepository
from src.services.exposure_scoring import ExposureScoringEngine
from src.api.dependencies import get_repository

TEMPLATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "templates"))
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(include_in_schema=False)


def _get_existing_reports():
    reports = []
    if os.path.exists(REPORTS_DIR):
        for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
            if f.endswith(".pdf"):
                full_path = os.path.join(REPORTS_DIR, f)
                stat = os.stat(full_path)
                match = re.search(r"FootprintIQ_Report_([A-Za-z0-9_-]+)_\d+", f)
                inv_id = match.group(1) if match else "UNKNOWN"
                reports.append({
                    "file_name": f,
                    "investigation_id": inv_id,
                    "file_size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                    "download_url": f"/api/v1/reports/{f}/download"
                })
    return reports


@router.get("/", response_class=HTMLResponse)
def view_dashboard(request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    investigations = repo.list_investigations()
    scans = repo.list_scans()
    findings = repo.list_findings()
    evidence = repo.list_evidence()
    targets = repo.list_authorized_targets()
    recon_campaigns = repo.list_recon_campaigns()

    exposure_summary = ExposureScoringEngine.calculate_investigation_exposure(findings)

    running_campaigns = [c for c in recon_campaigns if c.get("status") in ("Running", "in_progress")]
    completed_campaigns = [c for c in recon_campaigns if c.get("status") in ("Completed", "completed")]
    failed_campaigns = [c for c in recon_campaigns if c.get("status") in ("Failed", "failed")]

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "active_page": "dashboard",
            "exposure": exposure_summary,
            "total_investigations": len(investigations),
            "total_scans": len(scans),
            "total_findings": len(findings),
            "total_evidence": len(evidence),
            "total_targets": len(targets),
            "total_campaigns": len(recon_campaigns),
            "running_campaigns_count": len(running_campaigns),
            "completed_campaigns_count": len(completed_campaigns),
            "failed_campaigns_count": len(failed_campaigns),
            "investigations": investigations,
            "recon_campaigns": recon_campaigns,
            "targets": targets,
            "findings": findings,
            "scans": list(reversed(scans))
        }
    )


# =========================================================================
# RECONNAISSANCE CAMPAIGN PLATFORM UI ROUTES
# =========================================================================

@router.get("/recon", response_class=HTMLResponse)
def view_recon_campaigns(request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    campaigns = repo.list_recon_campaigns()
    targets = repo.list_authorized_targets()
    findings = repo.list_findings()
    
    total = len(campaigns)
    running = sum(1 for c in campaigns if c.get("status") in ("Running", "in_progress"))
    completed = sum(1 for c in campaigns if c.get("status") in ("Completed", "completed"))
    failed = sum(1 for c in campaigns if c.get("status") in ("Failed", "failed"))

    return templates.TemplateResponse(
        request=request,
        name="recon_list.html",
        context={
            "active_page": "recon",
            "campaigns": campaigns,
            "total_campaigns": total,
            "running_count": running,
            "completed_count": completed,
            "failed_count": failed,
            "total_targets": len(targets),
            "total_findings": len(findings)
        }
    )


@router.get("/recon/new", response_class=HTMLResponse)
def view_recon_create(request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    profiles = repo.list_saved_scan_profiles()
    targets = repo.list_authorized_targets()
    return templates.TemplateResponse(
        request=request,
        name="recon_create.html",
        context={
            "active_page": "recon",
            "profiles": profiles,
            "targets": targets,
            "default_target": "192.168.56.111"
        }
    )


@router.get("/recon/{recon_id}", response_class=HTMLResponse)
def view_recon_detail(recon_id: str, request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    campaign = repo.get_recon_campaign(recon_id)
    if not campaign:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")
    
    # If running, direct user to live terminal view; otherwise results
    if campaign.get("status") in ("Running", "in_progress"):
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=f"/recon/{recon_id}/live", status_code=303)
    
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/recon/{recon_id}/results", status_code=303)


@router.get("/recon/{recon_id}/live", response_class=HTMLResponse)
def view_recon_live(recon_id: str, request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    campaign = repo.get_recon_campaign(recon_id)
    if not campaign:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    scans = repo.list_scans(investigation_id=recon_id)
    findings = repo.list_findings(investigation_id=recon_id)

    return templates.TemplateResponse(
        request=request,
        name="recon_live.html",
        context={
            "active_page": "recon",
            "campaign": campaign,
            "recon_id": recon_id,
            "scans": scans,
            "findings_count": len(findings)
        }
    )


@router.get("/recon/{recon_id}/results", response_class=HTMLResponse)
def view_recon_results(recon_id: str, request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    campaign = repo.get_recon_campaign(recon_id)
    if not campaign:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    findings = repo.list_findings(investigation_id=recon_id)
    exposure_summary = ExposureScoringEngine.calculate_investigation_exposure(findings)
    all_campaigns = repo.list_recon_campaigns()
    scans = repo.list_scans(investigation_id=recon_id)

    return templates.TemplateResponse(
        request=request,
        name="recon_results.html",
        context={
            "active_page": "recon",
            "campaign": campaign,
            "recon_id": recon_id,
            "findings": findings,
            "scans": scans,
            "exposure": exposure_summary,
            "all_campaigns": all_campaigns
        }
    )


@router.get("/investigations", response_class=HTMLResponse)
def view_investigations(request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    investigations = repo.list_investigations()
    targets = repo.list_authorized_targets()
    return templates.TemplateResponse(
        request=request,
        name="investigations.html",
        context={
            "active_page": "investigations",
            "investigations": list(reversed(investigations)),
            "targets": targets
        }
    )


@router.get("/scans", response_class=HTMLResponse)
def view_scans(request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    scans = repo.list_scans()
    investigations = repo.list_investigations()
    targets = repo.list_authorized_targets()
    return templates.TemplateResponse(
        request=request,
        name="scans.html",
        context={
            "active_page": "scans",
            "scans": list(reversed(scans)),
            "investigations": investigations,
            "targets": targets
        }
    )


@router.get("/findings", response_class=HTMLResponse)
def view_findings(
    request: Request,
    severity: Optional[str] = None,
    repo: FootprintIQRepository = Depends(get_repository)
):
    findings = repo.list_findings(severity=severity)
    all_findings = repo.list_findings()
    exposure_summary = ExposureScoringEngine.calculate_investigation_exposure(all_findings)
    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={
            "active_page": "findings",
            "findings": findings,
            "total_findings": len(all_findings),
            "exposure": exposure_summary,
            "selected_severity": severity
        }
    )


@router.get("/evidence", response_class=HTMLResponse)
def view_evidence(request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    evidence = repo.list_evidence()
    return templates.TemplateResponse(
        request=request,
        name="evidence.html",
        context={
            "active_page": "evidence",
            "evidence": list(reversed(evidence)),
            "total_evidence": len(evidence)
        }
    )


@router.get("/reports", response_class=HTMLResponse)
def view_reports(request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    investigations = repo.list_investigations()
    reports = _get_existing_reports()
    findings = repo.list_findings()
    return templates.TemplateResponse(
        request=request,
        name="reports.html",
        context={
            "active_page": "reports",
            "investigations": investigations,
            "reports": reports,
            "total_findings": len(findings)
        }
    )
