"""
FootprintIQ - Scans Execution Router
Endpoints:
- POST /api/v1/scans (Launch authorized scan execution)
- GET  /api/v1/scans (List all scans)
- GET  /api/v1/scans/{scan_id} (Scan execution details & status)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from src.db.repository import FootprintIQRepository
from src.orchestration.unified_orchestrator import UnifiedScanOrchestrator
from src.api.dependencies import get_repository, get_current_user

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


class LaunchScanRequest(BaseModel):
    investigation_id: str = Field(..., example="INV-20261110-001")
    scan_type: str = Field(
        ...,
        example="combined",
        description="One of: 'passive', 'network_discovery', 'nmap_services', 'nmap_nse', 'greenbone', 'nessus', 'combined'"
    )
    target: str = Field(..., example="192.168.56.111")
    profile: Optional[str] = Field("lab-basic", example="lab-basic")
    custom_scripts: Optional[List[str]] = Field(None, example=["ftp-vsftpd-backdoor", "http-title"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
@router.post("/", status_code=status.HTTP_202_ACCEPTED, include_in_schema=False)
def launch_scan(
    req: LaunchScanRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    orchestrator = UnifiedScanOrchestrator(repo=repo)
    # Validate authorization upfront
    if req.scan_type in ("network_discovery", "nmap_services", "nmap_nse", "greenbone", "nessus", "combined"):
        try:
            auth_rec = orchestrator.authorizer.authorize_target(req.target, profile=req.profile or "lab-basic")
            if not auth_rec.authorized:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Target '{req.target}' is unauthorized: {auth_rec.failure_reason}")
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    try:
        result = orchestrator.execute_scan(
            investigation_id=req.investigation_id,
            scan_type=req.scan_type,
            target=req.target,
            profile=req.profile or "default",
            custom_scripts=req.custom_scripts
        )
        if result.get("status") == "FAILED":
            err_msg = result.get("error", "Scan execution failed")
            if "strictly prohibited" in err_msg or "unauthorized" in err_msg.lower():
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=err_msg)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)

        repo.log_audit(
            user_id=current_user.get("user_id", 1),
            action="SCAN_EXECUTED",
            target_resource=req.target,
            details_json=f'{{"scan_type": "{req.scan_type}", "status": "{result.get("status")}"}}'
        )
        return result
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("")
@router.get("/", include_in_schema=False)
def list_scans(
    investigation_id: Optional[str] = None,
    repo: FootprintIQRepository = Depends(get_repository)
):
    return repo.list_scans(investigation_id=investigation_id)


@router.get("/{scan_id}")
def get_scan(scan_id: str, repo: FootprintIQRepository = Depends(get_repository)):
    scans = repo.list_scans()
    for s in scans:
        if s.get("scan_id") == scan_id:
            findings = [f for f in repo.list_findings() if f.get("scan_id") == scan_id]
            return {**s, "findings": findings, "findings_count": len(findings)}

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")
