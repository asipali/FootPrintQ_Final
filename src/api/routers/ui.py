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

    exposure_summary = ExposureScoringEngine.calculate_investigation_exposure(findings)

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
            "investigations": investigations,
            "targets": targets,
            "findings": findings,
            "scans": list(reversed(scans))
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
