"""
FootprintIQ - Reports Router
Endpoints:
- POST /api/v1/reports/generate (Generate PDF & JSON investigation report)
- GET  /api/v1/reports/{report_id}/download (Download report file)
"""

from fastapi import APIRouter, Depends, HTTPException, status, Response
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import os

from src.db.repository import FootprintIQRepository
from src.reporting.unified_report import UnifiedReportGenerator
from src.api.dependencies import get_repository

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


class GenerateReportRequest(BaseModel):
    investigation_id: str = Field(..., example="INV-20261110-001")


@router.post("/generate", status_code=status.HTTP_201_CREATED)
def generate_report(
    req: GenerateReportRequest,
    repo: FootprintIQRepository = Depends(get_repository)
):
    inv = repo.get_investigation(req.investigation_id)
    if not inv:
        # Create lightweight placeholder if not present
        inv = repo.create_investigation(title="FootprintIQ Security Audit")

    targets = repo.list_authorized_targets(req.investigation_id)
    findings = repo.list_findings(req.investigation_id)
    evidence = repo.list_evidence(req.investigation_id)

    generator = UnifiedReportGenerator()
    pdf_path = generator.generate_pdf_report(
        investigation=inv,
        targets=targets,
        findings=findings,
        evidence=evidence
    )

    return {
        "status": "SUCCESS",
        "investigation_id": req.investigation_id,
        "pdf_report_path": pdf_path,
        "file_name": os.path.basename(pdf_path),
        "findings_included": len(findings),
        "evidence_included": len(evidence)
    }


@router.get("/download")
def download_latest_report(investigation_id: Optional[str] = None):
    reports_dir = os.path.abspath("reports")
    if not os.path.exists(reports_dir):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No reports available.")

    files = [os.path.join(reports_dir, f) for f in os.listdir(reports_dir) if f.endswith(".pdf")]
    if not files:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No PDF report has been generated yet.")

    latest_file = max(files, key=os.path.getctime)
    with open(latest_file, "rb") as f:
        content = f.read()

    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(latest_file)}"'}
    )

