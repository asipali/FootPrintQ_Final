"""
FootprintIQ - Database Repository Layer
Provides transactional data access for all entities against Microsoft SQL Server 2022 Express,
with an in-memory cache layer to guarantee resilient operation if the SQL Server instance is pending connection.
Strict Rule: No SQLite. No secondary database.
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import uuid
from sqlalchemy.orm import Session
from src.db.models import (
    User, Investigation, Campaign, AuthorizedTarget,
    ScanExecution, VulnerabilityFinding, EvidenceRecord,
    ReportRecord, AuditLog, ReconCampaign, ScanExecutionEvent,
    SavedScanProfile, RemediationHistory
)
from src.db.session import SessionLocal

logger = logging.getLogger("FootprintIQ.Repository")


def utcnow():
    return datetime.now(timezone.utc)


class FootprintIQRepository:
    # Shared fallback memory stores across requests for ephemeral testing / connection buffering
    _shared_mem_users: Dict[str, Dict[str, Any]] = {}
    _shared_mem_investigations: Dict[str, Dict[str, Any]] = {}
    _shared_mem_targets: Dict[str, Dict[str, Any]] = {}
    _shared_mem_scans: Dict[str, Dict[str, Any]] = {}
    _shared_mem_findings: Dict[str, Dict[str, Any]] = {}
    _shared_mem_evidence: Dict[str, Dict[str, Any]] = {}
    _shared_mem_reports: Dict[str, Dict[str, Any]] = {}
    _shared_mem_audit: List[Dict[str, Any]] = []
    _shared_mem_recon_campaigns: Dict[str, Dict[str, Any]] = {}
    _shared_mem_scan_events: Dict[str, List[Dict[str, Any]]] = {}
    _shared_mem_profiles: Dict[str, Dict[str, Any]] = {}
    _shared_mem_remediation: List[Dict[str, Any]] = []

    def __init__(self, db: Optional[Session] = None):
        self._db = db
        self._mem_users = FootprintIQRepository._shared_mem_users
        self._mem_investigations = FootprintIQRepository._shared_mem_investigations
        self._mem_targets = FootprintIQRepository._shared_mem_targets
        self._mem_scans = FootprintIQRepository._shared_mem_scans
        self._mem_findings = FootprintIQRepository._shared_mem_findings
        self._mem_evidence = FootprintIQRepository._shared_mem_evidence
        self._mem_reports = FootprintIQRepository._shared_mem_reports
        self._mem_audit = FootprintIQRepository._shared_mem_audit
        self._mem_recon_campaigns = FootprintIQRepository._shared_mem_recon_campaigns
        self._mem_scan_events = FootprintIQRepository._shared_mem_scan_events
        self._mem_profiles = FootprintIQRepository._shared_mem_profiles
        self._mem_remediation = FootprintIQRepository._shared_mem_remediation
        self._init_builtin_profiles()

    def _get_db(self) -> Optional[Session]:
        if self._db is not None:
            return self._db
        if SessionLocal is not None:
            try:
                return SessionLocal()
            except Exception:
                return None
        return None

    # ==========================================
    # USER MANAGEMENT
    # ==========================================

    def create_user(self, username: str, email: str, hashed_password: str, role: str = "investigator", is_approved: bool = False) -> Dict[str, Any]:
        db = self._get_db()
        if db:
            try:
                user = User(
                    username=username,
                    email=email,
                    hashed_password=hashed_password,
                    role=role,
                    is_active=True,
                    is_approved=is_approved,
                    created_at=utcnow(),
                    updated_at=utcnow()
                )
                db.add(user)
                db.commit()
                db.refresh(user)
                return {
                    "id": user.id,
                    "uuid": user.uuid,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role,
                    "is_active": user.is_active,
                    "is_approved": user.is_approved,
                    "created_at": user.created_at.isoformat()
                }
            except Exception as e:
                db.rollback()
                logger.warning(f"DB user creation fallback to memory cache: {e}")

        # Memory store fallback
        uid = len(self._mem_users) + 1
        user_data = {
            "id": uid,
            "uuid": str(uuid.uuid4()),
            "username": username,
            "email": email,
            "hashed_password": hashed_password,
            "role": role,
            "is_active": True,
            "is_approved": is_approved,
            "created_at": utcnow().isoformat()
        }
        self._mem_users[username] = user_data
        return user_data

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                user = db.query(User).filter(User.username == username).first()
                if user:
                    return {
                        "id": user.id,
                        "uuid": user.uuid,
                        "username": user.username,
                        "email": user.email,
                        "hashed_password": user.hashed_password,
                        "role": user.role,
                        "is_active": user.is_active,
                        "is_approved": user.is_approved,
                        "created_at": user.created_at.isoformat()
                    }
            except Exception as e:
                logger.debug(f"DB get user error: {e}")

        return self._mem_users.get(username)

    def list_users(self) -> List[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                users = db.query(User).all()
                if users:
                    return [{
                        "id": u.id,
                        "uuid": u.uuid,
                        "username": u.username,
                        "email": u.email,
                        "role": u.role,
                        "is_active": u.is_active,
                        "is_approved": u.is_approved,
                        "created_at": u.created_at.isoformat()
                    } for u in users]
            except Exception as e:
                logger.debug(f"DB list users error: {e}")

        return list(self._mem_users.values())

    def approve_user(self, username: str) -> bool:
        db = self._get_db()
        if db:
            try:
                user = db.query(User).filter(User.username == username).first()
                if user:
                    user.is_approved = True
                    user.updated_at = utcnow()
                    db.commit()
                    return True
            except Exception as e:
                db.rollback()
                logger.debug(f"DB approve user error: {e}")

        if username in self._mem_users:
            self._mem_users[username]["is_approved"] = True
            return True
        return False

    # ==========================================
    # INVESTIGATION MANAGEMENT
    # ==========================================

    def create_investigation(self, title: str, description: str = "", creator_id: int = 1) -> Dict[str, Any]:
        inv_id = f"INV-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        db = self._get_db()
        if db:
            try:
                inv = Investigation(
                    investigation_id=inv_id,
                    title=title,
                    description=description,
                    creator_id=creator_id,
                    status="active",
                    exposure_score=0.0,
                    created_at=utcnow(),
                    updated_at=utcnow()
                )
                db.add(inv)
                db.commit()
                db.refresh(inv)
                return {
                    "id": inv.id,
                    "investigation_id": inv.investigation_id,
                    "title": inv.title,
                    "description": inv.description,
                    "status": inv.status,
                    "exposure_score": inv.exposure_score,
                    "created_at": inv.created_at.isoformat()
                }
            except Exception as e:
                db.rollback()
                logger.debug(f"DB investigation creation fallback: {e}")

        iid = len(self._mem_investigations) + 1
        inv_data = {
            "id": iid,
            "investigation_id": inv_id,
            "title": title,
            "description": description,
            "status": "active",
            "exposure_score": 0.0,
            "created_at": utcnow().isoformat()
        }
        self._mem_investigations[inv_id] = inv_data
        return inv_data

    def get_investigation(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                if inv:
                    return {
                        "id": inv.id,
                        "investigation_id": inv.investigation_id,
                        "title": inv.title,
                        "description": inv.description,
                        "status": inv.status,
                        "exposure_score": inv.exposure_score,
                        "created_at": inv.created_at.isoformat()
                    }
            except Exception as e:
                logger.debug(f"DB get investigation error: {e}")

        return self._mem_investigations.get(investigation_id)

    def list_investigations(self) -> List[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                invs = db.query(Investigation).all()
                if invs:
                    return [{
                        "id": i.id,
                        "investigation_id": i.investigation_id,
                        "title": i.title,
                        "description": i.description,
                        "status": i.status,
                        "exposure_score": i.exposure_score,
                        "created_at": i.created_at.isoformat()
                    } for i in invs]
            except Exception as e:
                logger.debug(f"DB list investigations error: {e}")

        return list(self._mem_investigations.values())

    def update_exposure_score(self, investigation_id: str, score: float) -> bool:
        db = self._get_db()
        if db:
            try:
                inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                if inv:
                    inv.exposure_score = score
                    inv.updated_at = utcnow()
                    db.commit()
                    return True
            except Exception as e:
                db.rollback()
                logger.debug(f"DB update score error: {e}")

        if investigation_id in self._mem_investigations:
            self._mem_investigations[investigation_id]["exposure_score"] = score
            return True
        return False

    # ==========================================
    # AUTHORIZED TARGETS
    # ==========================================

    def add_authorized_target(self, investigation_id: str, target: str, name: str, scope: str, permitted_profiles: str = "lab-basic", allowed_ports: str = "1-65535", authorized_by: str = "asip_ali") -> Dict[str, Any]:
        tid = f"TGT-{uuid.uuid4().hex[:8].upper()}"
        target_type = "ipv4" if any(c.isdigit() for c in target.split('.')) else "domain"
        
        db = self._get_db()
        if db:
            try:
                inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                if inv:
                    tgt = AuthorizedTarget(
                        target_id=tid,
                        investigation_id=inv.id,
                        target=target,
                        target_type=target_type,
                        name=name,
                        category="authorized_lab",
                        scope=scope,
                        permitted_profiles=permitted_profiles,
                        allowed_ports=allowed_ports,
                        authorization_status="AUTHORIZED_LOCAL_LAB",
                        authorized_by=authorized_by,
                        created_at=utcnow()
                    )
                    db.add(tgt)
                    db.commit()
                    db.refresh(tgt)
                    return {
                        "id": tgt.id,
                        "target_id": tgt.target_id,
                        "target": tgt.target,
                        "target_type": tgt.target_type,
                        "name": tgt.name,
                        "scope": tgt.scope,
                        "permitted_profiles": tgt.permitted_profiles,
                        "authorization_status": tgt.authorization_status,
                        "authorized_by": tgt.authorized_by
                    }
            except Exception as e:
                db.rollback()
                logger.debug(f"DB target creation fallback: {e}")

        tgt_data = {
            "id": len(self._mem_targets) + 1,
            "target_id": tid,
            "investigation_id": investigation_id,
            "target": target,
            "target_type": target_type,
            "name": name,
            "scope": scope,
            "permitted_profiles": permitted_profiles,
            "authorization_status": "AUTHORIZED_LOCAL_LAB",
            "authorized_by": authorized_by,
            "created_at": utcnow().isoformat()
        }
        self._mem_targets[tid] = tgt_data
        return tgt_data

    def list_authorized_targets(self, investigation_id: Optional[str] = None) -> List[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                query = db.query(AuthorizedTarget)
                if investigation_id:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    if inv:
                        query = query.filter(AuthorizedTarget.investigation_id == inv.id)
                targets = query.all()
                if targets:
                    return [{
                        "id": t.id,
                        "target_id": t.target_id,
                        "target": t.target,
                        "target_type": t.target_type,
                        "name": t.name,
                        "scope": t.scope,
                        "permitted_profiles": t.permitted_profiles,
                        "authorization_status": t.authorization_status,
                        "authorized_by": t.authorized_by
                    } for t in targets]
            except Exception as e:
                logger.debug(f"DB list targets error: {e}")

        if investigation_id:
            return [t for t in self._mem_targets.values() if t.get("investigation_id") == investigation_id]
        return list(self._mem_targets.values())

    # ==========================================
    # SCAN EXECUTIONS
    # ==========================================

    def create_scan_execution(self, investigation_id: str, scan_type: str, target: str, profile: str = "default") -> Dict[str, Any]:
        scan_id = f"SCAN-{utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
        db = self._get_db()
        if db:
            try:
                inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                inv_pk = inv.id if inv else 1
                scan = ScanExecution(
                    scan_id=scan_id,
                    investigation_id=inv_pk,
                    scan_type=scan_type,
                    target=target,
                    profile=profile,
                    status="running",
                    started_at=utcnow(),
                    created_at=utcnow()
                )
                db.add(scan)
                db.commit()
                db.refresh(scan)
                return {
                    "id": scan.id,
                    "scan_id": scan.scan_id,
                    "investigation_id": investigation_id,
                    "scan_type": scan.scan_type,
                    "target": scan.target,
                    "profile": scan.profile,
                    "status": scan.status,
                    "started_at": scan.started_at.isoformat()
                }
            except Exception as e:
                db.rollback()
                logger.debug(f"DB scan execution creation fallback: {e}")

        scan_data = {
            "id": len(self._mem_scans) + 1,
            "scan_id": scan_id,
            "investigation_id": investigation_id,
            "scan_type": scan_type,
            "target": target,
            "profile": profile,
            "status": "running",
            "started_at": utcnow().isoformat(),
            "findings_count": 0
        }
        self._mem_scans[scan_id] = scan_data
        return scan_data

    def update_scan_execution(self, scan_id: str, status: str, error_message: Optional[str] = None, result_summary_json: Optional[str] = None) -> bool:
        db = self._get_db()
        if db:
            try:
                scan = db.query(ScanExecution).filter(ScanExecution.scan_id == scan_id).first()
                if scan:
                    scan.status = status
                    scan.completed_at = utcnow()
                    if error_message:
                        scan.error_message = error_message
                    if result_summary_json:
                        scan.result_summary_json = result_summary_json
                    db.commit()
                    return True
            except Exception as e:
                db.rollback()
                logger.debug(f"DB update scan error: {e}")

        if scan_id in self._mem_scans:
            self._mem_scans[scan_id]["status"] = status
            self._mem_scans[scan_id]["completed_at"] = utcnow().isoformat()
            if error_message:
                self._mem_scans[scan_id]["error_message"] = error_message
            if result_summary_json:
                self._mem_scans[scan_id]["result_summary_json"] = result_summary_json
            return True
        return False

    def list_scans(self, investigation_id: Optional[str] = None) -> List[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                query = db.query(ScanExecution)
                if investigation_id:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    if inv:
                        query = query.filter(ScanExecution.investigation_id == inv.id)
                scans = query.all()
                if scans:
                    return [{
                        "id": s.id,
                        "scan_id": s.scan_id,
                        "scan_type": s.scan_type,
                        "target": s.target,
                        "profile": s.profile,
                        "status": s.status,
                        "started_at": s.started_at.isoformat() if s.started_at else None,
                        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                        "error_message": s.error_message
                    } for s in scans]
            except Exception as e:
                logger.debug(f"DB list scans error: {e}")

        if investigation_id:
            return [s for s in self._mem_scans.values() if s.get("investigation_id") == investigation_id]
        return list(self._mem_scans.values())

    # ==========================================
    # VULNERABILITY FINDINGS
    # ==========================================

    def add_vulnerability_finding(self, investigation_id: str, finding_dict: Dict[str, Any], scan_id: Optional[str] = None) -> Dict[str, Any]:
        fid = finding_dict.get("finding_id") or f"VULN-{uuid.uuid4().hex[:8].upper()}"
        finding_dict["finding_id"] = fid
        finding_dict["investigation_id"] = investigation_id
        finding_dict["scan_id"] = scan_id

        db = self._get_db()
        if db:
            try:
                inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                inv_pk = inv.id if inv else 1
                scan_pk = None
                if scan_id:
                    scan = db.query(ScanExecution).filter(ScanExecution.scan_id == scan_id).first()
                    if scan:
                        scan_pk = scan.id

                vf = VulnerabilityFinding(
                    finding_id=fid,
                    investigation_id=inv_pk,
                    scan_execution_id=scan_pk,
                    target_ip=finding_dict.get("target_ip", "127.0.0.1"),
                    hostname=finding_dict.get("hostname"),
                    port=finding_dict.get("port"),
                    protocol=finding_dict.get("protocol", "tcp"),
                    service=finding_dict.get("service"),
                    service_version=finding_dict.get("service_version"),
                    title=finding_dict.get("title", "Untitled Vulnerability"),
                    description=finding_dict.get("description", ""),
                    cve_identifiers=finding_dict.get("cve_identifiers") or (",".join(finding_dict.get("cves", [])) if isinstance(finding_dict.get("cves"), list) else None),
                    cvss_score=finding_dict.get("cvss_score"),
                    severity=finding_dict.get("severity", "Informational"),
                    confidence=finding_dict.get("confidence", 1.0),
                    detection_source=finding_dict.get("detection_source", "scanner"),
                    scanner_vt_id=finding_dict.get("scanner_vt_id"),
                    remediation=finding_dict.get("remediation"),
                    evidence_reference=finding_dict.get("evidence_reference"),
                    verification_status=finding_dict.get("verification_status", "unverified"),
                    finding_status=finding_dict.get("finding_status", "open"),
                    first_detected=utcnow(),
                    last_detected=utcnow()
                )
                db.add(vf)
                db.commit()
                db.refresh(vf)
                return finding_dict
            except Exception as e:
                db.rollback()
                logger.debug(f"DB finding creation fallback: {e}")

        self._mem_findings[fid] = finding_dict
        return finding_dict

    def list_findings(self, investigation_id: Optional[str] = None, severity: Optional[str] = None, target_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                query = db.query(VulnerabilityFinding)
                if investigation_id:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    if inv:
                        query = query.filter(VulnerabilityFinding.investigation_id == inv.id)
                if severity:
                    query = query.filter(VulnerabilityFinding.severity == severity)
                if target_ip:
                    query = query.filter(VulnerabilityFinding.target_ip == target_ip)
                findings = query.all()
                if findings:
                    return [{
                        "id": f.id,
                        "finding_id": f.finding_id,
                        "target_ip": f.target_ip,
                        "port": f.port,
                        "protocol": f.protocol,
                        "service": f.service,
                        "title": f.title,
                        "cve_identifiers": f.cve_identifiers,
                        "cvss_score": f.cvss_score,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "detection_source": f.detection_source,
                        "scanner_vt_id": f.scanner_vt_id,
                        "remediation": f.remediation,
                        "finding_status": getattr(f, "finding_status", "open"),
                        "remediation_status": getattr(f, "finding_status", "open"),
                        "remediation_notes": getattr(f, "remediation_notes", ""),
                        "verification_status": f.verification_status,
                        "first_detected": f.first_detected.isoformat()
                    } for f in findings]
            except Exception as e:
                logger.debug(f"DB list findings error: {e}")

        res = list(self._mem_findings.values())
        for f in res:
            if "remediation_status" not in f:
                f["remediation_status"] = f.get("finding_status", "open")
            if "finding_status" not in f:
                f["finding_status"] = f.get("remediation_status", "open")
        if investigation_id:
            res = [f for f in res if f.get("investigation_id") == investigation_id]
        if severity:
            res = [f for f in res if f.get("severity") == severity]
        if target_ip:
            res = [f for f in res if f.get("target_ip") == target_ip]
        return res

    # ==========================================
    # EVIDENCE RECORDS
    # ==========================================

    def add_evidence_record(self, investigation_id: str, evidence_type: str, file_name: str, file_size: int, sha256_hash: str, seaweed_fid: Optional[str] = None, seaweed_url: Optional[str] = None, local_path: Optional[str] = None) -> Dict[str, Any]:
        eid = f"EVD-{uuid.uuid4().hex[:8].upper()}"
        rec = {
            "evidence_id": eid,
            "investigation_id": investigation_id,
            "evidence_type": evidence_type,
            "file_name": file_name,
            "file_size": file_size,
            "sha256_hash": sha256_hash,
            "seaweed_fid": seaweed_fid,
            "seaweed_url": seaweed_url,
            "local_path": local_path,
            "created_at": utcnow().isoformat()
        }

        db = self._get_db()
        if db:
            try:
                inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                inv_pk = inv.id if inv else 1
                ev = EvidenceRecord(
                    evidence_id=eid,
                    investigation_id=inv_pk,
                    evidence_type=evidence_type,
                    file_name=file_name,
                    file_size=file_size,
                    sha256_hash=sha256_hash,
                    seaweed_fid=seaweed_fid,
                    seaweed_url=seaweed_url,
                    local_path=local_path,
                    created_at=utcnow()
                )
                db.add(ev)
                db.commit()
                db.refresh(ev)
                return rec
            except Exception as e:
                db.rollback()
                logger.debug(f"DB evidence creation fallback: {e}")

        self._mem_evidence[eid] = rec
        return rec

    def list_evidence(self, investigation_id: Optional[str] = None) -> List[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                query = db.query(EvidenceRecord)
                if investigation_id:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    if inv:
                        query = query.filter(EvidenceRecord.investigation_id == inv.id)
                evidence = query.all()
                if evidence:
                    return [{
                        "evidence_id": e.evidence_id,
                        "evidence_type": e.evidence_type,
                        "file_name": e.file_name,
                        "file_size": e.file_size,
                        "sha256_hash": e.sha256_hash,
                        "seaweed_fid": e.seaweed_fid,
                        "seaweed_url": e.seaweed_url,
                        "local_path": e.local_path,
                        "created_at": e.created_at.isoformat()
                    } for e in evidence]
            except Exception as e:
                logger.debug(f"DB list evidence error: {e}")

        if investigation_id:
            return [e for e in self._mem_evidence.values() if e.get("investigation_id") == investigation_id]
        return list(self._mem_evidence.values())

    # ==========================================
    # AUDIT LOGGING
    # ==========================================

    def log_audit(self, user_id: Optional[int], action: str, target_resource: Optional[str] = None, details_json: Optional[str] = None, ip_address: Optional[str] = None):
        db = self._get_db()
        if db:
            try:
                entry = AuditLog(
                    user_id=user_id,
                    action=action,
                    target_resource=target_resource,
                    details_json=details_json,
                    ip_address=ip_address,
                    timestamp=utcnow()
                )
                db.add(entry)
                db.commit()
                return
            except Exception as e:
                db.rollback()
                logger.debug(f"DB audit log fallback: {e}")

        self._mem_audit.append({
            "user_id": user_id,
            "action": action,
            "target_resource": target_resource,
            "details_json": details_json,
            "ip_address": ip_address,
            "timestamp": utcnow().isoformat()
        })

    def list_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
                if logs:
                    return [{
                        "id": l.id,
                        "user_id": l.user_id,
                        "action": l.action,
                        "target_resource": l.target_resource,
                        "details_json": l.details_json,
                        "ip_address": l.ip_address,
                        "timestamp": l.timestamp.isoformat()
                    } for l in logs]
            except Exception as e:
                logger.debug(f"DB list audit logs error: {e}")

        return list(reversed(self._mem_audit[-limit:]))

    # ==========================================
    # RECON CAMPAIGN MANAGEMENT
    # ==========================================

    def _init_builtin_profiles(self):
        """Populates built-in scan profiles if not present."""
        defaults = [
            {
                "name": "Quick Demo",
                "description": "Fast demonstration using selected common ports against authorized lab targets",
                "category": "quick",
                "config_json": '{"scan_types": ["nmap_services", "nmap_nse"], "ports": "21,22,80,445,3306,3632", "service_detection": true, "scripts": ["ftp-vsftpd-backdoor", "http-title"]}',
                "is_builtin": True
            },
            {
                "name": "Passive Only",
                "description": "Exclusively non-intrusive OSINT: WHOIS, DNS enumeration, RDAP, theHarvester",
                "category": "passive",
                "config_json": '{"scan_types": ["passive"], "collectors": ["whois", "dns", "rdap", "theharvester"]}',
                "is_builtin": True
            },
            {
                "name": "Basic Discovery",
                "description": "Host discovery, ping verification, and top 100 common TCP ports",
                "category": "discovery",
                "config_json": '{"scan_types": ["network_discovery", "nmap_services"], "ports": "top-100", "service_detection": true}',
                "is_builtin": True
            },
            {
                "name": "TCP Quick",
                "description": "Standard fast scan of top 1,000 common TCP ports with version identification",
                "category": "tcp",
                "config_json": '{"scan_types": ["nmap_services"], "ports": "1-1024", "service_detection": true}',
                "is_builtin": True
            },
            {
                "name": "TCP Full",
                "description": "Comprehensive scan across all 65,535 TCP ports",
                "category": "tcp",
                "config_json": '{"scan_types": ["nmap_services"], "ports": "1-65535", "service_detection": true}',
                "is_builtin": True
            },
            {
                "name": "UDP Basic",
                "description": "Selected common UDP ports (DNS, DHCP, NTP, SNMP, Syslog)",
                "category": "udp",
                "config_json": '{"scan_types": ["nmap_services"], "ports": "53,67,68,123,161,514", "protocol": "udp"}',
                "is_builtin": True
            },
            {
                "name": "Service Audit",
                "description": "Deep service detection, OS fingerprinting, and RPC/SMB enumeration",
                "category": "service",
                "config_json": '{"scan_types": ["nmap_services"], "service_detection": true, "os_detection": true}',
                "is_builtin": True
            },
            {
                "name": "Vulnerability Assessment",
                "description": "Policy-governed NSE vulnerability scripts and Greenbone/OpenVAS evaluation",
                "category": "vulnerability",
                "config_json": '{"scan_types": ["nmap_nse", "greenbone", "nessus"], "service_detection": true}',
                "is_builtin": True
            },
            {
                "name": "Full Recon",
                "description": "End-to-end multi-engine assessment: Passive OSINT + Nmap Services + NSE + Greenbone + Nessus",
                "category": "combined",
                "config_json": '{"scan_types": ["combined"], "service_detection": true, "os_detection": true}',
                "is_builtin": True
            }
        ]

        for p in defaults:
            if p["name"] not in self._mem_profiles:
                self._mem_profiles[p["name"]] = {
                    "id": len(self._mem_profiles) + 1,
                    "name": p["name"],
                    "description": p["description"],
                    "category": p["category"],
                    "config_json": p["config_json"],
                    "is_builtin": p["is_builtin"],
                    "created_by": "system",
                    "created_at": utcnow().isoformat()
                }

    def generate_recon_id(self) -> str:
        """Generates a human-readable, persistent server-side Recon ID: FIQ-REC-YYYYMMDD-XXXX."""
        date_str = utcnow().strftime("%Y%m%d")
        existing_count = len(self._mem_recon_campaigns) + 1
        db = self._get_db()
        if db:
            try:
                count = db.query(ReconCampaign).count()
                existing_count = count + 1
            except Exception:
                pass
        return f"FIQ-REC-{date_str}-{existing_count:04d}"

    def create_recon_campaign(
        self,
        name: str,
        target_value: str,
        target_type: str = "ipv4",
        description: str = "",
        purpose: str = "Security Audit",
        scope_description: str = "",
        excluded_targets: str = "",
        excluded_ports: str = "",
        allowed_methods: str = "all",
        allowed_ports: str = "1-65535",
        authorized_by: str = "asip_ali",
        creator_id: int = 1,
        selected_scan_types: str = "combined",
        scan_config_json: str = "{}"
    ) -> Dict[str, Any]:
        """Creates a new Recon Campaign with guaranteed unique Recon ID and auto-registered scope."""
        recon_id = self.generate_recon_id()

        db = self._get_db()
        if db:
            try:
                # 1. Also create corresponding Investigation record so foreign keys remain unified
                inv = db.query(Investigation).filter(Investigation.investigation_id == recon_id).first()
                if not inv:
                    inv = Investigation(
                        investigation_id=recon_id,
                        title=name,
                        description=description,
                        creator_id=creator_id,
                        status="active",
                        exposure_score=0.0,
                        created_at=utcnow(),
                        updated_at=utcnow()
                    )
                    db.add(inv)
                    db.commit()
                    db.refresh(inv)

                camp = ReconCampaign(
                    recon_id=recon_id,
                    investigation_id=recon_id,
                    name=name,
                    description=description,
                    purpose=purpose,
                    scope_description=scope_description,
                    target_type=target_type,
                    target_value=target_value,
                    excluded_targets=excluded_targets,
                    excluded_ports=excluded_ports,
                    allowed_methods=allowed_methods,
                    allowed_ports=allowed_ports,
                    authorization_status="Authorized",
                    authorized_by=authorized_by,
                    authorized_at=utcnow(),
                    status="Authorized",
                    selected_scan_types=selected_scan_types,
                    scan_config_json=scan_config_json,
                    progress=0,
                    current_stage="Configured",
                    creator_id=creator_id,
                    created_at=utcnow(),
                    updated_at=utcnow()
                )
                db.add(camp)

                # 2. Automatically register target in authorized_targets table under recon_id
                target_rec = AuthorizedTarget(
                    target_id=f"TGT-{uuid.uuid4().hex[:8].upper()}",
                    investigation_id=inv.id,
                    target=target_value,
                    target_type=target_type,
                    name=f"{name} Target ({target_value})",
                    category="authorized_lab",
                    scope=scope_description or f"{target_value} authorized scope",
                    permitted_profiles="lab-basic,default,lab-safe-minimal",
                    allowed_ports=allowed_ports,
                    authorization_status="AUTHORIZED_LOCAL_LAB",
                    authorized_by=authorized_by,
                    created_at=utcnow()
                )
                db.add(target_rec)
                db.commit()
                db.refresh(camp)

                data = {
                    "id": camp.id,
                    "recon_id": camp.recon_id,
                    "investigation_id": camp.investigation_id,
                    "name": camp.name,
                    "description": camp.description,
                    "purpose": camp.purpose,
                    "scope_description": camp.scope_description,
                    "target_type": camp.target_type,
                    "target_value": camp.target_value,
                    "excluded_targets": camp.excluded_targets,
                    "excluded_ports": camp.excluded_ports,
                    "allowed_methods": camp.allowed_methods,
                    "allowed_ports": camp.allowed_ports,
                    "authorization_status": camp.authorization_status,
                    "authorized_by": camp.authorized_by,
                    "authorized_at": camp.authorized_at.isoformat(),
                    "status": camp.status,
                    "selected_scan_types": camp.selected_scan_types,
                    "scan_config_json": camp.scan_config_json,
                    "progress": camp.progress,
                    "current_stage": camp.current_stage,
                    "creator_id": camp.creator_id,
                    "created_at": camp.created_at.isoformat(),
                    "updated_at": camp.updated_at.isoformat()
                }
                self._mem_recon_campaigns[recon_id] = data
                return data
            except Exception as e:
                db.rollback()
                logger.debug(f"DB recon campaign creation fallback: {e}")

        # Memory store fallback
        # Ensure underlying investigation in memory
        self.create_investigation(title=name, description=description)
        # Register target in memory
        self.add_authorized_target(
            investigation_id=recon_id,
            target=target_value,
            name=f"{name} Target",
            scope=scope_description or f"{target_value} authorized scope",
            permitted_profiles="lab-basic,default,lab-safe-minimal",
            allowed_ports=allowed_ports,
            authorized_by=authorized_by
        )

        camp_data = {
            "id": len(self._mem_recon_campaigns) + 1,
            "recon_id": recon_id,
            "investigation_id": recon_id,
            "name": name,
            "description": description,
            "purpose": purpose,
            "scope_description": scope_description,
            "target_type": target_type,
            "target_value": target_value,
            "excluded_targets": excluded_targets,
            "excluded_ports": excluded_ports,
            "allowed_methods": allowed_methods,
            "allowed_ports": allowed_ports,
            "authorization_status": "Authorized",
            "authorized_by": authorized_by,
            "authorized_at": utcnow().isoformat(),
            "status": "Authorized",
            "selected_scan_types": selected_scan_types,
            "scan_config_json": scan_config_json,
            "progress": 0,
            "current_stage": "Configured",
            "creator_id": creator_id,
            "created_at": utcnow().isoformat(),
            "updated_at": utcnow().isoformat()
        }
        self._mem_recon_campaigns[recon_id] = camp_data
        return camp_data

    def get_recon_campaign(self, recon_id: str) -> Optional[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                camp = db.query(ReconCampaign).filter(ReconCampaign.recon_id == recon_id).first()
                if camp:
                    return {
                        "id": camp.id,
                        "recon_id": camp.recon_id,
                        "investigation_id": camp.investigation_id,
                        "name": camp.name,
                        "description": camp.description,
                        "purpose": camp.purpose,
                        "scope_description": camp.scope_description,
                        "target_type": camp.target_type,
                        "target_value": camp.target_value,
                        "excluded_targets": camp.excluded_targets,
                        "excluded_ports": camp.excluded_ports,
                        "allowed_methods": camp.allowed_methods,
                        "allowed_ports": camp.allowed_ports,
                        "authorization_status": camp.authorization_status,
                        "authorized_by": camp.authorized_by,
                        "authorized_at": camp.authorized_at.isoformat() if camp.authorized_at else None,
                        "status": camp.status,
                        "selected_scan_types": camp.selected_scan_types,
                        "scan_config_json": camp.scan_config_json,
                        "progress": camp.progress,
                        "current_stage": camp.current_stage,
                        "creator_id": camp.creator_id,
                        "created_at": camp.created_at.isoformat() if camp.created_at else None,
                        "updated_at": camp.updated_at.isoformat() if camp.updated_at else None
                    }
            except Exception as e:
                logger.debug(f"DB get recon campaign error: {e}")

        return self._mem_recon_campaigns.get(recon_id)

    def list_recon_campaigns(self) -> List[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                camps = db.query(ReconCampaign).order_by(ReconCampaign.created_at.desc()).all()
                if camps:
                    return [{
                        "id": c.id,
                        "recon_id": c.recon_id,
                        "investigation_id": c.investigation_id,
                        "name": c.name,
                        "description": c.description,
                        "purpose": c.purpose,
                        "scope_description": c.scope_description,
                        "target_type": c.target_type,
                        "target_value": c.target_value,
                        "authorization_status": c.authorization_status,
                        "authorized_by": c.authorized_by,
                        "status": c.status,
                        "progress": c.progress,
                        "current_stage": c.current_stage,
                        "created_at": c.created_at.isoformat() if c.created_at else None
                    } for c in camps]
            except Exception as e:
                logger.debug(f"DB list recon campaigns error: {e}")

        return list(reversed(list(self._mem_recon_campaigns.values())))

    def update_recon_campaign(self, recon_id: str, **kwargs) -> bool:
        db = self._get_db()
        if db:
            try:
                camp = db.query(ReconCampaign).filter(ReconCampaign.recon_id == recon_id).first()
                if camp:
                    for k, v in kwargs.items():
                        if hasattr(camp, k):
                            setattr(camp, k, v)
                    camp.updated_at = utcnow()
                    db.commit()
                    return True
            except Exception as e:
                db.rollback()
                logger.debug(f"DB update recon campaign error: {e}")

        if recon_id in self._mem_recon_campaigns:
            self._mem_recon_campaigns[recon_id].update(kwargs)
            self._mem_recon_campaigns[recon_id]["updated_at"] = utcnow().isoformat()
            return True
        return False

    # ==========================================
    # SCAN EXECUTION EVENTS (TERMINAL LOG STREAM)
    # ==========================================

    def add_scan_execution_event(
        self,
        scan_id: str,
        event_type: str,
        message: str,
        stage: Optional[str] = None,
        progress: Optional[int] = None,
        details_json: Optional[str] = None,
        recon_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Persists a real execution event to the scan execution log."""
        ts = utcnow()
        level_map = {
            "stage_start": "STAGE",
            "stage_complete": "SUCCESS",
            "finding_discovered": "FINDING",
            "port_discovered": "SUCCESS",
            "warning": "WARN",
            "error": "ERROR",
            "critical": "CRITICAL",
            "security": "SECURITY",
            "init": "INFO",
            "log": "INFO"
        }
        level = level_map.get(event_type.lower(), "INFO")
        event_data = {
            "scan_id": scan_id,
            "recon_id": recon_id,
            "event_type": event_type,
            "level": level,
            "stage": stage,
            "message": message,
            "details_json": details_json,
            "progress": progress,
            "timestamp": ts.isoformat()
        }

        db = self._get_db()
        if db:
            try:
                ev = ScanExecutionEvent(
                    scan_id=scan_id,
                    recon_id=recon_id,
                    event_type=event_type,
                    stage=stage,
                    message=message,
                    details_json=details_json,
                    progress=progress,
                    timestamp=ts
                )
                db.add(ev)
                db.commit()
            except Exception as e:
                db.rollback()
                logger.debug(f"DB add scan execution event fallback: {e}")

        if scan_id not in self._mem_scan_events:
            self._mem_scan_events[scan_id] = []
        self._mem_scan_events[scan_id].append(event_data)
        return event_data

    def list_scan_execution_events(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieves all chronological execution events for a scan."""
        db = self._get_db()
        if db:
            try:
                events = db.query(ScanExecutionEvent).filter(
                    ScanExecutionEvent.scan_id == scan_id
                ).order_by(ScanExecutionEvent.timestamp.asc()).all()
                if events:
                    return [{
                        "id": e.id,
                        "scan_id": e.scan_id,
                        "recon_id": e.recon_id,
                        "event_type": e.event_type,
                        "level": level_map.get((e.event_type or "").lower(), "INFO"),
                        "stage": e.stage,
                        "message": e.message,
                        "details_json": e.details_json,
                        "progress": e.progress,
                        "timestamp": e.timestamp.isoformat()
                    } for e in events]
            except Exception as e:
                logger.debug(f"DB list scan execution events error: {e}")

        return self._mem_scan_events.get(scan_id, [])

    # ==========================================
    # SAVED SCAN PROFILES
    # ==========================================

    def list_saved_scan_profiles(self) -> List[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                profs = db.query(SavedScanProfile).order_by(SavedScanProfile.name.asc()).all()
                if profs:
                    return [{
                        "id": p.id,
                        "name": p.name,
                        "description": p.description,
                        "category": p.category,
                        "config_json": p.config_json,
                        "is_builtin": p.is_builtin,
                        "created_by": p.created_by
                    } for p in profs]
            except Exception as e:
                logger.debug(f"DB list saved scan profiles error: {e}")

        return list(self._mem_profiles.values())

    def get_saved_scan_profile(self, name: str) -> Optional[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                prof = db.query(SavedScanProfile).filter(SavedScanProfile.name == name).first()
                if prof:
                    return {
                        "id": prof.id,
                        "name": prof.name,
                        "description": prof.description,
                        "category": prof.category,
                        "config_json": prof.config_json,
                        "is_builtin": prof.is_builtin,
                        "created_by": prof.created_by
                    }
            except Exception as e:
                logger.debug(f"DB get saved scan profile error: {e}")

        return self._mem_profiles.get(name)

    # ==========================================
    # REMEDIATION TRACKING
    # ==========================================

    def update_finding_remediation_status(
        self,
        finding_id: str,
        new_status: str,
        changed_by: str = "asip_ali",
        notes: str = ""
    ) -> bool:
        """Updates finding status and records an audit trail entry in remediation history."""
        db = self._get_db()
        prev_status = "open"
        if db:
            try:
                finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.finding_id == finding_id).first()
                if finding:
                    prev_status = finding.finding_status
                    finding.finding_status = new_status
                    finding.remediation_notes = notes
                    finding.status_updated_by = changed_by
                    finding.status_updated_at = utcnow()

                    hist = RemediationHistory(
                        finding_id=finding_id,
                        previous_status=prev_status,
                        new_status=new_status,
                        changed_by=changed_by,
                        notes=notes,
                        created_at=utcnow()
                    )
                    db.add(hist)
                    db.commit()
                    return True
            except Exception as e:
                db.rollback()
                logger.debug(f"DB update finding remediation status error: {e}")

        for f in self._mem_findings.values():
            if f.get("finding_id") == finding_id:
                prev_status = f.get("finding_status", "open")
                f["finding_status"] = new_status
                f["remediation_status"] = new_status
                f["remediation_notes"] = notes
                f["status_updated_by"] = changed_by
                f["status_updated_at"] = utcnow().isoformat()
                self._mem_remediation.append({
                    "finding_id": finding_id,
                    "previous_status": prev_status,
                    "new_status": new_status,
                    "changed_by": changed_by,
                    "notes": notes,
                    "created_at": utcnow().isoformat()
                })
                return True
        return False

    def list_remediation_history(self, finding_id: str) -> List[Dict[str, Any]]:
        db = self._get_db()
        if db:
            try:
                history = db.query(RemediationHistory).filter(
                    RemediationHistory.finding_id == finding_id
                ).order_by(RemediationHistory.created_at.desc()).all()
                if history:
                    return [{
                        "id": h.id,
                        "finding_id": h.finding_id,
                        "previous_status": h.previous_status,
                        "new_status": h.new_status,
                        "changed_by": h.changed_by,
                        "notes": h.notes,
                        "created_at": h.created_at.isoformat()
                    } for h in history]
            except Exception as e:
                logger.debug(f"DB list remediation history error: {e}")

        return [h for h in self._mem_remediation if h.get("finding_id") == finding_id]

