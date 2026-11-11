"""
FootprintIQ - Reports & Integrated Analysis Router
Endpoints:
- GET  /api/v1/reports (List generated reports - Admin all, Investigator owner/shared)
- GET  /api/v1/reports/{report_id}/analysis (Detailed non-fabricated report analysis - Admin & permitted Investigator)
- POST /api/v1/reports/generate (Generate Executive/Technical PDF - Investigator owner/shared only)
- GET  /api/v1/reports/download (Download latest accessible report or scoped by investigation_id)
- GET  /api/v1/reports/{report_id}/download (Download specific report file cleanly with ownership & traversal check)
"""

import hashlib
import os
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from src.db.repository import FootprintIQRepository
from src.reporting.unified_report import UnifiedReportGenerator
from src.services.recon_results_helper import load_campaign_results_bundle
from src.services.report_analysis_service import (
    REPORTS_DIR,
    build_report_analysis,
    extract_report_file_metadata,
    resolve_report_record,
)
from src.services.rbac_service import (
    enforce_investigation_access,
    filter_accessible_investigation_ids,
    is_admin_user,
    record_security_audit,
)
from src.api.dependencies import get_repository, get_current_user, require_investigator

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


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


def _collect_scoped_reports(
    repo: FootprintIQRepository,
    current_user: Dict[str, Any],
    investigation_id: Optional[str] = None,
) -> list:
    db_reports = repo.list_report_records(investigation_id=investigation_id)
    db_by_file = {r["file_name"]: r for r in db_reports}
    accessible = filter_accessible_investigation_ids(repo, current_user)

    reports = []
    if os.path.exists(REPORTS_DIR):
        for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
            if not f.endswith(".pdf"):
                continue
            full_path = os.path.join(REPORTS_DIR, f)
            stat = os.stat(full_path)
            meta = extract_report_file_metadata(f)
            db_rec = db_by_file.get(f)
            inv_id = (db_rec.get("recon_id") if db_rec else None) or meta["investigation_id"]
            if investigation_id and inv_id != investigation_id:
                continue
            if accessible is not None and inv_id not in accessible:
                continue

            rid = (db_rec.get("report_id") if db_rec else None) or f
            reports.append({
                "report_id": db_rec.get("report_id") if db_rec else None,
                "report_key": rid,
                "file_name": f,
                "investigation_id": inv_id,
                "recon_id": inv_id,
                "report_format": (db_rec.get("report_type") if db_rec else None) or meta["report_format"],
                "file_size": stat.st_size,
                "sha256_hash": db_rec.get("sha256_hash") if db_rec else None,
                "generated_by_username": db_rec.get("generated_by_username") if db_rec else None,
                "created_at": (db_rec.get("generated_at") if db_rec else None) or datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "analysis_url": f"/reports/{rid}",
                "download_url": f"/api/v1/reports/{f}/download?investigation_id={inv_id}"
            })
    return reports


@router.get("")
@router.get("/", include_in_schema=False)
def list_reports(
    request: Request,
    investigation_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    """Lists generated PDF reports with strict RBAC & investigation ownership isolation."""
    if investigation_id:
        enforce_investigation_access(repo, current_user, investigation_id, request=request, action_label="REPORTS_LIST")
    return _collect_scoped_reports(repo, current_user, investigation_id=investigation_id)


@router.get("/{report_id}/analysis")
def get_report_analysis(
    report_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    """Returns integrated multi-section analytical breakdown for a permitted report."""
    clean_id = _sanitize_filename(report_id)
    report_meta = resolve_report_record(clean_id, repo)
    if not report_meta:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{clean_id}' not found.")

    inv_id = report_meta.get("investigation_id")
    if inv_id and inv_id != "UNKNOWN":
        enforce_investigation_access(repo, current_user, inv_id, request=request, action_label="REPORT_ANALYZE")
    elif not is_admin_user(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to legacy unowned report.")

    analysis = build_report_analysis(inv_id, repo, report_meta=report_meta)
    record_security_audit(
        repo,
        user=current_user,
        action="REPORT_ANALYZED",
        target_resource=str(report_meta.get("report_id") or report_meta.get("file_name")),
        details={"investigation_id": inv_id},
        outcome="SUCCESS",
        request=request,
    )
    return analysis


@router.post("/generate", status_code=status.HTTP_201_CREATED)
def generate_report(
    req: GenerateReportRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    enforce_investigation_access(
        repo,
        current_user,
        req.investigation_id,
        require_execution=True,
        request=request,
        action_label="REPORT_GENERATE",
    )
    inv = repo.get_investigation(req.investigation_id)
    camp = repo.get_recon_campaign(req.investigation_id)
    if camp:
        inv = {
            "investigation_id": camp["recon_id"],
            "recon_id": camp["recon_id"],
            "title": camp["name"],
            "name": camp["name"],
            "description": camp.get("description", ""),
            "purpose": camp.get("purpose", ""),
            "status": camp.get("status", "Completed"),
            "target_value": camp.get("target_value", ""),
            "target_type": camp.get("target_type", "ipv4"),
            "scope_description": camp.get("scope_description", ""),
            "excluded_targets": camp.get("excluded_targets", ""),
            "selected_scan_types": camp.get("selected_scan_types", ""),
            "scan_config_json": camp.get("scan_config_json", "{}"),
            "created_at": camp.get("created_at", "")
        }
    elif not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation or Recon Campaign '{req.investigation_id}' not found. Cannot generate report."
        )

    targets = repo.list_authorized_targets(req.investigation_id)
    findings = repo.list_findings(req.investigation_id)
    evidence = repo.list_evidence(req.investigation_id)
    results_bundle = load_campaign_results_bundle(req.investigation_id, repo)
    analysis = build_report_analysis(
        req.investigation_id,
        repo,
        findings_override=findings,
        targets_override=targets,
        evidence_override=evidence,
        results_bundle_override=results_bundle,
    )

    generator = UnifiedReportGenerator()
    pdf_path = generator.generate_pdf_report(
        investigation=inv,
        targets=targets,
        findings=findings,
        evidence=evidence,
        report_format=req.report_format or "executive",
        results_bundle=results_bundle,
        analysis=analysis,
        generated_by=current_user.get("username"),
    )

    file_size = os.path.getsize(pdf_path) if os.path.exists(pdf_path) else 0
    sha256 = ""
    if os.path.exists(pdf_path):
        with open(pdf_path, "rb") as pf:
            sha256 = hashlib.sha256(pf.read()).hexdigest()

    rec = repo.add_report_record(
        investigation_id=req.investigation_id,
        recon_id=req.investigation_id,
        file_name=os.path.basename(pdf_path),
        file_size=file_size,
        sha256_hash=sha256,
        report_type=(req.report_format or "executive").lower(),
        generated_by_user_id=current_user.get("id"),
        generated_by_username=current_user.get("username"),
    )

    record_security_audit(
        repo,
        user=current_user,
        action="REPORT_GENERATED",
        target_resource=str(rec.get("report_id") or os.path.basename(pdf_path)),
        details={
            "investigation_id": req.investigation_id,
            "report_format": (req.report_format or "executive").lower(),
            "file_name": os.path.basename(pdf_path),
        },
        outcome="SUCCESS",
        request=request,
    )

    fname = os.path.basename(pdf_path)
    rid = rec.get("report_id") or fname
    return {
        "status": "SUCCESS",
        "report_id": rec.get("report_id"),
        "investigation_id": req.investigation_id,
        "recon_id": req.investigation_id,
        "report_format": (req.report_format or "executive").lower(),
        "pdf_report_path": pdf_path,
        "file_name": fname,
        "analysis_url": f"/reports/{rid}",
        "download_url": f"/api/v1/reports/{fname}/download?investigation_id={req.investigation_id}",
        "findings_included": len(findings),
        "evidence_included": len(evidence)
    }


@router.get("/download")
def download_latest_report(
    request: Request,
    investigation_id: Optional[str] = None,
    report_format: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository),
):
    if investigation_id:
        enforce_investigation_access(repo, current_user, investigation_id, request=request, action_label="REPORT_DOWNLOAD")

    scoped = _collect_scoped_reports(repo, current_user, investigation_id=investigation_id)
    if report_format:
        rf = report_format.lower()
        fmt_filtered = [r for r in scoped if (r.get("report_format") or "").lower() == rf]
        if fmt_filtered:
            scoped = fmt_filtered

    if not scoped:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No accessible PDF report found{f' for {investigation_id}' if investigation_id else ''}."
        )

    latest_rec = max(scoped, key=lambda r: os.path.getctime(os.path.join(REPORTS_DIR, r["file_name"])))
    safe_path = _safe_resolve_report(os.path.join(REPORTS_DIR, latest_rec["file_name"]))

    with open(safe_path, "rb") as f:
        content = f.read()

    record_security_audit(
        repo,
        user=current_user,
        action="REPORT_DOWNLOADED",
        target_resource=latest_rec.get("report_id") or latest_rec["file_name"],
        details={"investigation_id": latest_rec.get("investigation_id")},
        outcome="SUCCESS",
        request=request,
    )

    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(safe_path)}"'}
    )


@router.get("/{report_id}/download")
def download_specific_report(
    report_id: str,
    request: Request,
    investigation_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    clean_id = _sanitize_filename(report_id)
    if clean_id.startswith("REP-"):
        all_recs = repo.list_report_records(investigation_id=investigation_id)
        match_rec = next((r for r in all_recs if r.get("report_id") == clean_id), None)
        if not match_rec:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{clean_id}' not found in requested campaign scope.")
        clean_id = match_rec["file_name"]

    if not clean_id.endswith(".pdf"):
        clean_id += ".pdf"

    # Cross-campaign isolation enforcement
    meta_inv = extract_report_file_metadata(clean_id)["investigation_id"]
    db_rec = repo.get_report_record(clean_id)
    owner_inv = (db_rec.get("recon_id") if db_rec else None) or (db_rec.get("investigation_id") if db_rec else None) or meta_inv

    if investigation_id:
        db_recs = repo.list_report_records(investigation_id=investigation_id)
        db_match = any(r.get("file_name") == clean_id for r in db_recs)
        if meta_inv != investigation_id and not db_match:
            record_security_audit(
                repo,
                user=current_user,
                action="PERMISSION_DENIED",
                target_resource=clean_id,
                details={"reason": "cross_campaign_report_download", "requested_inv": investigation_id, "owner_inv": owner_inv},
                outcome="DENIED",
                request=request,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Report '{clean_id}' does not belong to campaign '{investigation_id}'."
            )

    if owner_inv and owner_inv != "UNKNOWN":
        enforce_investigation_access(repo, current_user, owner_inv, request=request, action_label="REPORT_DOWNLOAD")
    elif not is_admin_user(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to legacy unowned report.")

    target_file = os.path.join(REPORTS_DIR, clean_id)
    safe_path = _safe_resolve_report(target_file)

    with open(safe_path, "rb") as f:
        content = f.read()

    record_security_audit(
        repo,
        user=current_user,
        action="REPORT_DOWNLOADED",
        target_resource=(db_rec.get("report_id") if db_rec else None) or clean_id,
        details={"investigation_id": owner_inv},
        outcome="SUCCESS",
        request=request,
    )

    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(safe_path)}"'}
    )
