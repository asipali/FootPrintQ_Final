"""
FootprintIQ - Vulnerability Findings Router
Endpoints:
- GET /api/v1/findings (Filtered findings list)
- GET /api/v1/findings/{finding_id} (Finding details)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any, List, Optional
from src.db.repository import FootprintIQRepository
from src.services.exposure_scoring import ExposureScoringEngine
from src.api.dependencies import get_repository

router = APIRouter(prefix="/api/v1/findings", tags=["Vulnerability Findings"])


@router.get("")
@router.get("/", include_in_schema=False)
def list_findings(
    investigation_id: Optional[str] = None,
    severity: Optional[str] = None,
    target_ip: Optional[str] = None,
    detection_source: Optional[str] = None,
    repo: FootprintIQRepository = Depends(get_repository)
):
    findings = repo.list_findings(
        investigation_id=investigation_id,
        severity=severity,
        target_ip=target_ip
    )
    if detection_source:
        findings = [f for f in findings if f.get("detection_source") == detection_source]

    # Attach risk score to each finding
    enriched = []
    for f in findings:
        risk_info = ExposureScoringEngine.calculate_finding_risk(f)
        enriched.append({**f, "risk_calculation": risk_info})

    return enriched


@router.get("/{finding_id}")
def get_finding(finding_id: str, repo: FootprintIQRepository = Depends(get_repository)):
    findings = repo.list_findings()
    for f in findings:
        if f.get("finding_id") == finding_id:
            risk_info = ExposureScoringEngine.calculate_finding_risk(f)
            return {**f, "risk_calculation": risk_info}

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{finding_id}' not found.")
