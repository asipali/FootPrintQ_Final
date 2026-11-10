"""
FootprintIQ - SeaweedFS Evidence Management Router
Endpoints:
- GET /api/v1/evidence (List evidence items)
- GET /api/v1/evidence/{evidence_id}/download (Retrieve raw evidence payload)
"""

from fastapi import APIRouter, Depends, HTTPException, status, Response
from typing import Dict, Any, List, Optional
from src.db.repository import FootprintIQRepository
from src.storage.seaweedfs_client import SeaweedFSClient
from src.api.dependencies import get_repository

router = APIRouter(prefix="/api/v1/evidence", tags=["Evidence Management"])


@router.get("")
@router.get("/", include_in_schema=False)
def list_evidence(
    investigation_id: Optional[str] = None,
    repo: FootprintIQRepository = Depends(get_repository)
):
    return repo.list_evidence(investigation_id=investigation_id)


@router.get("/{evidence_id}/download")
def download_evidence(
    evidence_id: str,
    repo: FootprintIQRepository = Depends(get_repository)
):
    evidence_items = repo.list_evidence()
    target_ev = None
    for ev in evidence_items:
        if ev.get("evidence_id") == evidence_id:
            target_ev = ev
            break

    if not target_ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence '{evidence_id}' not found.")

    storage_client = SeaweedFSClient()
    content = storage_client.download_content(
        seaweed_fid=target_ev.get("seaweed_fid"),
        local_path=target_ev.get("local_path")
    )

    if content is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence content could not be retrieved from SeaweedFS.")

    content_type = target_ev.get("content_type", "application/octet-stream")
    file_name = target_ev.get("file_name", "evidence.bin")

    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'}
    )
