"""
FootprintIQ - Investigations Router
Endpoints:
- POST /api/v1/investigations (Create new investigation)
- GET  /api/v1/investigations (List all investigations)
- GET  /api/v1/investigations/{id} (Retrieve investigation details & exposure summary)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from src.db.repository import FootprintIQRepository
from src.api.dependencies import get_repository, get_current_user

router = APIRouter(prefix="/api/v1/investigations", tags=["Investigations"])


class CreateInvestigationRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200, example="Quarterly Lab VM Vulnerability Audit")
    description: Optional[str] = Field("", example="Comprehensive OSINT & Vulnerability Assessment of Metasploitable2 VM")


@router.post("", status_code=status.HTTP_201_CREATED)
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def create_investigation(
    req: CreateInvestigationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    inv = repo.create_investigation(
        title=req.title,
        description=req.description or "",
        creator_id=current_user.get("user_id", 1)
    )
    repo.log_audit(
        user_id=current_user.get("user_id", 1),
        action="INVESTIGATION_CREATED",
        target_resource=inv["investigation_id"],
        details_json=f'{{"title": "{inv["title"]}"}}'
    )
    return inv


@router.get("")
@router.get("/", include_in_schema=False)
def list_investigations(repo: FootprintIQRepository = Depends(get_repository)):
    return repo.list_investigations()


@router.get("/{investigation_id}")
def get_investigation(investigation_id: str, repo: FootprintIQRepository = Depends(get_repository)):
    inv = repo.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation '{investigation_id}' not found.")

    # Attach related stats
    targets = repo.list_authorized_targets(investigation_id)
    scans = repo.list_scans(investigation_id)
    findings = repo.list_findings(investigation_id)
    evidence = repo.list_evidence(investigation_id)

    return {
        **inv,
        "targets_count": len(targets),
        "scans_count": len(scans),
        "findings_count": len(findings),
        "evidence_count": len(evidence)
    }
