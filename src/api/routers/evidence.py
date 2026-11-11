"""
FootprintIQ - SeaweedFS Evidence Management Router
Endpoints:
- GET /api/v1/evidence (List evidence items - Role & ownership scoped)
- GET /api/v1/evidence/{evidence_id}/download (Retrieve raw evidence payload)
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status, Response
from typing import Dict, Any, Optional
from src.db.repository import FootprintIQRepository
from src.storage.seaweedfs_client import SeaweedFSClient
from src.api.dependencies import get_repository, get_current_user
from src.services.rbac_service import (
    enforce_investigation_access,
    filter_accessible_investigation_ids,
    record_security_audit,
)

router = APIRouter(prefix="/api/v1/evidence", tags=["Evidence Management"])


@router.get("")
@router.get("/", include_in_schema=False)
def list_evidence(
    request: Request,
    investigation_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    if investigation_id:
        enforce_investigation_access(repo, current_user, investigation_id, request=request, action_label="EVIDENCE_LIST")
        return repo.list_evidence(investigation_id=investigation_id)

    items = repo.list_evidence()
    accessible = filter_accessible_investigation_ids(repo, current_user)
    if accessible is None:
        return items
    return [e for e in items if e.get("investigation_id") in accessible]


@router.get("/{evidence_id}/download")
def download_evidence(
    evidence_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    target_ev = repo.get_evidence(evidence_id)
    if not target_ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence '{evidence_id}' not found.")

    inv_id = target_ev.get("investigation_id")
    if inv_id:
        enforce_investigation_access(repo, current_user, inv_id, request=request, action_label="EVIDENCE_DOWNLOAD")
    elif current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    storage_client = SeaweedFSClient()
    content = storage_client.download_content(
        seaweed_fid=target_ev.get("seaweed_fid"),
        local_path=target_ev.get("local_path")
    )

    if content is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence content could not be retrieved from Evidence Vault.")

    record_security_audit(
        repo,
        user=current_user,
        action="EVIDENCE_DOWNLOADED",
        target_resource=evidence_id,
        details={"investigation_id": inv_id, "file_name": target_ev.get("file_name")},
        outcome="SUCCESS",
        request=request,
    )

    content_type = target_ev.get("content_type", "application/octet-stream")
    file_name = target_ev.get("file_name", "evidence.bin")

    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'}
    )
