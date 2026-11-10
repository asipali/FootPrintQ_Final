"""
FootprintIQ - Reconnaissance Campaign Platform API Router
Endpoints:
- POST /api/v1/recon (Create Recon Campaign)
- GET  /api/v1/recon (List all Recon Campaigns)
- GET  /api/v1/recon/profiles (List saved scan profiles)
- POST /api/v1/recon/profiles (Create custom scan profile)
- GET  /api/v1/recon/{recon_id} (Campaign details)
- POST /api/v1/recon/{recon_id}/targets (Add target to campaign)
- POST /api/v1/recon/{recon_id}/start (Launch background scan execution)
- POST /api/v1/recon/{recon_id}/cancel (Cancel active scan)
- GET  /api/v1/recon/{recon_id}/events (Get persisted terminal-style events)
- GET  /api/v1/recon/{recon_id}/stream (SSE live terminal log stream)
- GET  /api/v1/recon/{recon_id}/findings (List campaign findings)
- POST /api/v1/recon/{recon_id}/remediation (Update finding remediation status)
- GET  /api/v1/recon/{recon_id}/compare/{other_recon_id} (Compare two campaigns)
"""

import os
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from src.db.repository import FootprintIQRepository
from src.orchestration.execution_manager import ExecutionManager
from src.authorization.target_authorizer import TargetAuthorizer, TargetAuthorizationError
from src.api.dependencies import get_repository, get_current_user

router = APIRouter(prefix="/api/v1/recon", tags=["Recon Campaigns"])


class CreateReconRequest(BaseModel):
    name: str = Field(..., example="Perimeter Reconnaissance 2026")
    target_value: str = Field(..., example="192.168.56.111")
    target_type: str = Field("ipv4", example="ipv4", description="'ipv4', 'range', 'domain'")
    description: Optional[str] = Field("", example="Comprehensive active & passive perimeter audit")
    purpose: Optional[str] = Field("Security Audit", example="Security Audit")
    scope_description: Optional[str] = Field("", example="192.168.56.111 Metasploitable2 Lab VM")
    excluded_targets: Optional[str] = Field("", example="192.168.56.1")
    excluded_ports: Optional[str] = Field("", example="25,135")
    allowed_methods: Optional[str] = Field("all", example="all")
    allowed_ports: Optional[str] = Field("1-65535", example="1-65535")
    selected_scan_types: Optional[str] = Field("combined", example="combined")
    scan_config_json: Optional[str] = Field("{}", example="{}")


class StartReconRequest(BaseModel):
    scan_type: Optional[str] = Field("combined", example="combined")
    profile: Optional[str] = Field("lab-basic", example="lab-basic")
    custom_scripts: Optional[List[str]] = Field(None, example=["ftp-vsftpd-backdoor", "http-title"])


class RemediationUpdateRequest(BaseModel):
    finding_id: str = Field(..., example="VULN-20261110-001")
    status: str = Field(..., example="resolved", description="'open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive'")
    notes: Optional[str] = Field("", example="Backdoor FTP daemon replaced with patched vsftpd 3.0.5")


class SaveProfileRequest(BaseModel):
    name: str = Field(..., example="Fast Web Audit")
    description: Optional[str] = Field("", example="Quick web ports and HTTP scripts")
    category: Optional[str] = Field("web", example="web")
    config_json: str = Field(..., example='{"ports": "80,443,8080", "service_detection": true}')


@router.post("", status_code=status.HTTP_201_CREATED)
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def create_recon_campaign(
    req: CreateReconRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    # Validate target syntax & global scope upfront
    authorizer = TargetAuthorizer()
    try:
        clean_target, _ = authorizer.validate_target_syntax(req.target_value)
    except TargetAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    campaign = repo.create_recon_campaign(
        name=req.name,
        target_value=clean_target,
        target_type=req.target_type,
        description=req.description or "",
        purpose=req.purpose or "Security Audit",
        scope_description=req.scope_description or "",
        excluded_targets=req.excluded_targets or "",
        excluded_ports=req.excluded_ports or "",
        allowed_methods=req.allowed_methods or "all",
        allowed_ports=req.allowed_ports or "1-65535",
        authorized_by=current_user.get("username", "asip_ali"),
        creator_id=current_user.get("user_id", 1),
        selected_scan_types=req.selected_scan_types or "combined",
        scan_config_json=req.scan_config_json or "{}"
    )

    repo.log_audit(
        user_id=current_user.get("user_id", 1),
        action="RECON_CAMPAIGN_CREATED",
        target_resource=clean_target,
        details_json=json.dumps({"recon_id": campaign["recon_id"], "name": req.name})
    )

    return campaign


@router.get("")
@router.get("/", include_in_schema=False)
def list_recon_campaigns(repo: FootprintIQRepository = Depends(get_repository)):
    return repo.list_recon_campaigns()


@router.get("/profiles")
def list_profiles(repo: FootprintIQRepository = Depends(get_repository)):
    return repo.list_saved_scan_profiles()


@router.post("/profiles", status_code=status.HTTP_201_CREATED)
def create_profile(
    req: SaveProfileRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    prof = {
        "name": req.name,
        "description": req.description,
        "category": req.category,
        "config_json": req.config_json,
        "is_builtin": False,
        "created_by": current_user.get("username", "asip_ali"),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    repo._mem_profiles[req.name] = prof
    return prof


@router.get("/{recon_id}")
def get_recon_campaign(recon_id: str, repo: FootprintIQRepository = Depends(get_repository)):
    campaign = repo.get_recon_campaign(recon_id)
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recon Campaign '{recon_id}' not found.")

    targets = repo.list_authorized_targets(investigation_id=recon_id)
    scans = repo.list_scans(investigation_id=recon_id)
    findings = repo.list_findings(investigation_id=recon_id)
    evidence = repo.list_evidence(investigation_id=recon_id)

    return {
        **campaign,
        "targets": targets,
        "scans": scans,
        "findings_count": len(findings),
        "evidence_count": len(evidence),
        "findings": findings
    }


@router.post("/{recon_id}/start")
def start_recon_scan(
    recon_id: str,
    req: StartReconRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    campaign = repo.get_recon_campaign(recon_id)
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recon Campaign '{recon_id}' not found.")

    manager = ExecutionManager(repo=repo)
    try:
        job = manager.start_recon_scan(
            recon_id=recon_id,
            scan_type=req.scan_type or campaign.get("selected_scan_types") or "combined",
            profile=req.profile or "lab-basic",
            custom_scripts=req.custom_scripts,
            operator=current_user.get("username", "asip_ali")
        )

        repo.log_audit(
            user_id=current_user.get("user_id", 1),
            action="RECON_SCAN_STARTED",
            target_resource=campaign["target_value"],
            details_json=json.dumps({"recon_id": recon_id, "scan_id": job["scan_id"]})
        )
        return job
    except TargetAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{recon_id}/cancel")
def cancel_recon_scan(
    recon_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    manager = ExecutionManager(repo=repo)
    success = manager.cancel_recon_scan(recon_id)
    repo.log_audit(
        user_id=current_user.get("user_id", 1),
        action="RECON_SCAN_CANCELLED",
        target_resource=recon_id
    )
    return {"status": "SUCCESS", "message": f"Scan for {recon_id} cancellation signaled."}


@router.get("/{recon_id}/events")
def get_recon_events(recon_id: str, repo: FootprintIQRepository = Depends(get_repository)):
    campaign = repo.get_recon_campaign(recon_id)
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recon Campaign '{recon_id}' not found.")

    # Find matching scan
    scans = repo.list_scans(investigation_id=recon_id)
    if not scans:
        return []

    latest_scan = scans[0]
    return repo.list_scan_execution_events(latest_scan["scan_id"])


@router.get("/{recon_id}/stream")
async def stream_recon_events(recon_id: str, repo: FootprintIQRepository = Depends(get_repository)):
    """Server-Sent Events (SSE) live execution stream for terminal output."""
    campaign = repo.get_recon_campaign(recon_id)
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recon Campaign '{recon_id}' not found.")

    manager = ExecutionManager(repo=repo)
    ctx = manager.get_scan_context(recon_id)

    async def event_generator():
        # 1. First yield all historical events from database
        scans = repo.list_scans(investigation_id=recon_id)
        sent_messages = set()

        if scans:
            latest_scan_id = scans[0]["scan_id"]
            db_events = repo.list_scan_execution_events(latest_scan_id)
            for ev in db_events:
                msg_key = f"{ev.get('timestamp')}:{ev.get('message')}"
                sent_messages.add(msg_key)
                yield f"data: {json.dumps(ev)}\n\n"

        # 2. If no active running context, close stream
        if not ctx or ctx.is_completed:
            camp = repo.get_recon_campaign(recon_id)
            final_status = camp.get("status", "Completed") if camp else "Completed"
            yield f"data: {json.dumps({'event_type': 'done', 'status': final_status, 'progress': 100})}\n\n"
            return

        # 3. Stream live events as they occur
        queue = asyncio.Queue()
        ctx.subscribers.append(queue)

        try:
            while not ctx.is_completed:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    msg_key = f"{event.get('timestamp')}:{event.get('message')}"
                    if msg_key not in sent_messages:
                        sent_messages.add(msg_key)
                        yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Send keep-alive heartbeat
                    yield f": heartbeat\n\n"

            # Final completion event
            yield f"data: {json.dumps({'event_type': 'done', 'status': 'Completed', 'progress': 100})}\n\n"
        finally:
            if queue in ctx.subscribers:
                ctx.subscribers.remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/{recon_id}/findings")
def get_recon_findings(recon_id: str, repo: FootprintIQRepository = Depends(get_repository)):
    return repo.list_findings(investigation_id=recon_id)


@router.post("/{recon_id}/remediation")
def update_remediation(
    recon_id: str,
    req: RemediationUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    success = repo.update_finding_remediation_status(
        finding_id=req.finding_id,
        new_status=req.status,
        changed_by=current_user.get("username", "asip_ali"),
        notes=req.notes or ""
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{req.finding_id}' not found.")

    repo.log_audit(
        user_id=current_user.get("user_id", 1),
        action="REMEDIATION_STATUS_UPDATED",
        target_resource=req.finding_id,
        details_json=json.dumps({"status": req.status, "notes": req.notes})
    )
    return {"status": "SUCCESS", "finding_id": req.finding_id, "new_status": req.status}


@router.get("/{recon_id}/compare/{other_recon_id}")
def compare_recon_campaigns(
    recon_id: str,
    other_recon_id: str,
    repo: FootprintIQRepository = Depends(get_repository)
):
    """Compares two reconnaissance campaigns to identify delta findings and port exposure."""
    from src.services.exposure_scoring import ExposureScoringEngine

    c1 = repo.get_recon_campaign(recon_id)
    c2 = repo.get_recon_campaign(other_recon_id)
    if not c1 or not c2:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both Recon Campaigns not found.")

    f1 = repo.list_findings(investigation_id=recon_id)
    f2 = repo.list_findings(investigation_id=other_recon_id)

    f1_titles = {f["title"]: f for f in f1}
    f2_titles = {f["title"]: f for f in f2}

    # f1 is current scan, f2 is baseline
    new_findings = [f for t, f in f1_titles.items() if t not in f2_titles]
    resolved_findings = [f for t, f in f2_titles.items() if t not in f1_titles]
    persistent_findings = [f for t, f in f1_titles.items() if t in f2_titles]

    f1_ports = {f.get("port") for f in f1 if f.get("port")}
    f2_ports = {f.get("port") for f in f2 if f.get("port")}

    exp1 = ExposureScoringEngine.calculate_investigation_exposure(f1)["exposure_score"]
    exp2 = ExposureScoringEngine.calculate_investigation_exposure(f2)["exposure_score"]
    score_delta = round(exp1 - exp2, 1)

    return {
        "base_recon_id": recon_id,
        "compare_recon_id": other_recon_id,
        "target": c1.get("target_value"),
        "exposure_score_delta": score_delta,
        "metrics": {
            "exposure_score_delta": score_delta,
            "new_findings_count": len(new_findings),
            "resolved_findings_count": len(resolved_findings),
            "persistent_findings_count": len(persistent_findings),
            "newly_opened_ports": list(f1_ports - f2_ports),
            "closed_ports": list(f2_ports - f1_ports)
        },
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "persistent_findings": persistent_findings
    }
