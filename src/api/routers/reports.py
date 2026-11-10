"""
FootprintIQ - Reports Router
Endpoints:
- GET  /api/v1/reports (List all generated reports)
- POST /api/v1/reports/generate (Generate PDF & JSON investigation report)
- GET  /api/v1/reports/download (Download report by investigation_id or latest)
- GET  /api/v1/reports/{report_id}/download (Download specific report file)
"""

import os
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Response
from pydantic import BaseModel, Field

from src.db.repository import FootprintIQRepository
from src.reporting.unified_report import UnifiedReportGenerator
from src.api.dependencies import get_repository

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")


class GenerateReportRequest(BaseModel):
    investigation_id: str = Field(..., example="INV-20261110-001")
    report_format: Optional[str] = Field("executive", example="executive", description="'executive' or 'technical'")


def _sanitize_filename(filename: str) -> str:
    """Ensure filename has no path traversal components."""
    clean = os.path.basename(filename)
    if ".." in clean or "/" in clean or "\\" in clean:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report filename.")
    return clean


def _safe_resolve_report(filepath: str) -> str:
    """Ensure resolved file path is strictly within the reports directory."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    real_reports = os.path.realpath(REPORTS_DIR)
    real_file = os.path.realpath(filepath)
    if not (real_file == real_reports or real_file.startswith(real_reports + os.sep)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: path traversal attempt.")
    if not os.path.isfile(real_file):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found.")
    return real_file


@router.get("")
@router.get("/", include_in_schema=False)
def list_reports(investigation_id: Optional[str] = None):
    """Lists all generated PDF reports with metadata."""
    if not os.path.exists(REPORTS_DIR):
        return []

    reports = []
    for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if f.endswith(".pdf"):
            full_path = os.path.join(REPORTS_DIR, f)
            stat = os.stat(full_path)
            # Try extracting investigation ID from filename pattern FootprintIQ_Report_INV-XXXXXX_...
            match = re.search(r"FootprintIQ_Report_([A-Za-z0-9_-]+)_\d+", f)
            inv_id = match.group(1) if match else "UNKNOWN"
            if investigation_id and inv_id != investigation_id:
                continue

            reports.append({
                "file_name": f,
                "investigation_id": inv_id,
                "file_size": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "download_url": f"/api/v1/reports/{f}/download"
            })
    return reports


@router.post("/generate", status_code=status.HTTP_201_CREATED)
def generate_report(
    req: GenerateReportRequest,
    repo: FootprintIQRepository = Depends(get_repository)
):
    inv = repo.get_investigation(req.investigation_id)
    if not inv:
        # Check if it is a recon campaign ID
        camp = repo.get_recon_campaign(req.investigation_id)
        if camp:
            inv = {
                "investigation_id": camp["recon_id"],
                "recon_id": camp["recon_id"],
                "title": camp["name"],
                "name": camp["name"],
                "description": camp["description"]
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation or Recon Campaign '{req.investigation_id}' not found. Cannot generate report."
            )

    targets = repo.list_authorized_targets(req.investigation_id)
    findings = repo.list_findings(req.investigation_id)
    evidence = repo.list_evidence(req.investigation_id)

    generator = UnifiedReportGenerator()
    pdf_path = generator.generate_pdf_report(
        investigation=inv,
        targets=targets,
        findings=findings,
        evidence=evidence,
        report_format=req.report_format or "executive"
    )

    return {
        "status": "SUCCESS",
        "investigation_id": req.investigation_id,
        "report_format": req.report_format or "executive",
        "pdf_report_path": pdf_path,
        "file_name": os.path.basename(pdf_path),
        "download_url": f"/api/v1/reports/{os.path.basename(pdf_path)}/download",
        "findings_included": len(findings),
        "evidence_included": len(evidence)
    }


@router.get("/download")
def download_latest_report(investigation_id: Optional[str] = None):
    if not os.path.exists(REPORTS_DIR):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No reports available.")

    files = [os.path.join(REPORTS_DIR, f) for f in os.listdir(REPORTS_DIR) if f.endswith(".pdf")]
    if not files:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No PDF report has been generated yet.")

    if investigation_id:
        filtered = [f for f in files if f"_{investigation_id}_" in os.path.basename(f) or f"_{investigation_id}." in os.path.basename(f)]
        if filtered:
            files = filtered
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No PDF report found for investigation '{investigation_id}'.")

    latest_file = max(files, key=os.path.getctime)
    safe_path = _safe_resolve_report(latest_file)

    with open(safe_path, "rb") as f:
        content = f.read()

    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(safe_path)}"'}
    )


@router.get("/{report_id}/download")
def download_specific_report(report_id: str):
    clean_id = _sanitize_filename(report_id)
    if not clean_id.endswith(".pdf"):
        clean_id += ".pdf"

    target_file = os.path.join(REPORTS_DIR, clean_id)
    safe_path = _safe_resolve_report(target_file)

    with open(safe_path, "rb") as f:
        content = f.read()

    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(safe_path)}"'}
    )

