"""
FootprintIQ - Authorized Targets Router
Endpoints:
- POST /api/v1/targets (Register authorized scope target)
- GET  /api/v1/targets (List authorized scope targets)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from src.db.repository import FootprintIQRepository
from src.api.dependencies import get_repository, get_current_user

router = APIRouter(prefix="/api/v1/targets", tags=["Authorized Targets"])


class AddTargetRequest(BaseModel):
    investigation_id: str = Field(..., example="INV-20261110-001")
    target: str = Field(..., example="192.168.56.111")
    name: str = Field(..., example="Metasploitable2 Lab VM")
    scope: str = Field(..., example="Host-Only Adapter 192.168.56.0/24")
    permitted_profiles: str = Field("lab-basic,lab-safe-minimal", example="lab-basic")
    allowed_ports: str = Field("1-65535", example="1-65535")


@router.post("", status_code=status.HTTP_201_CREATED)
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def add_authorized_target(
    req: AddTargetRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    target_rec = repo.add_authorized_target(
        investigation_id=req.investigation_id,
        target=req.target,
        name=req.name,
        scope=req.scope,
        permitted_profiles=req.permitted_profiles,
        allowed_ports=req.allowed_ports,
        authorized_by=current_user.get("username", "asip_ali")
    )
    repo.log_audit(
        user_id=current_user.get("user_id", 1),
        action="TARGET_AUTHORIZED",
        target_resource=req.target,
        details_json=f'{{"investigation_id": "{req.investigation_id}", "scope": "{req.scope}"}}'
    )
    return target_rec


@router.get("")
@router.get("/", include_in_schema=False)
def list_targets(
    investigation_id: Optional[str] = None,
    repo: FootprintIQRepository = Depends(get_repository)
):
    return repo.list_authorized_targets(investigation_id=investigation_id)
