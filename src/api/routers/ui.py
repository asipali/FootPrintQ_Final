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
from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from typing import Optional

from src.db.repository import FootprintIQRepository
from src.services.exposure_scoring import ExposureScoringEngine
from src.api.dependencies import get_repository

TEMPLATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "templates"))
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(include_in_schema=False)


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
            "findings": findings,
            "scans": list(reversed(scans))
        }
    )


@router.get("/investigations", response_class=HTMLResponse)
def view_investigations(request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    investigations = repo.list_investigations()
    return templates.TemplateResponse(
        request=request,
        name="investigations.html",
        context={
            "active_page": "investigations",
            "investigations": list(reversed(investigations))
        }
    )


@router.get("/scans", response_class=HTMLResponse)
def view_scans(request: Request, repo: FootprintIQRepository = Depends(get_repository)):
    scans = repo.list_scans()
    return templates.TemplateResponse(
        request=request,
        name="scans.html",
        context={
            "active_page": "scans",
            "scans": list(reversed(scans))
        }
    )


@router.get("/findings", response_class=HTMLResponse)
def view_findings(
    request: Request,
    severity: Optional[str] = None,
    repo: FootprintIQRepository = Depends(get_repository)
):
    findings = repo.list_findings(severity=severity)
    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={
            "active_page": "findings",
            "findings": findings,
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
            "evidence": list(reversed(evidence))
        }
    )


@router.get("/reports", response_class=HTMLResponse)
def view_reports(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="reports.html",
        context={
            "active_page": "reports"
        }
    )
