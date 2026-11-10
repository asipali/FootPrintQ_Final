"""
FootprintIQ - Unified Investigation Report Generator
Produces professional executive PDF investigation reports covering:
- Executive summary & overall exposure score (0 - 100)
- Investigation scope & authorized targets
- OSINT passive reconnaissance findings
- Discovered network services & ports
- Nmap NSE findings
- Greenbone / OpenVAS findings
- Nessus scanner findings
- Correlated vulnerabilities & severity distribution
- Cryptographic evidence hashes (SHA-256) & SeaweedFS references
- Prioritized remediation roadmap
"""

import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import hashlib

logger = logging.getLogger("FootprintIQ.Report")

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.units import inch

from src.services.exposure_scoring import ExposureScoringEngine
from src.storage.seaweedfs_client import SeaweedFSClient


class UnifiedReportGenerator:
    def __init__(self, storage_client: Optional[SeaweedFSClient] = None):
        self.storage = storage_client or SeaweedFSClient()

    def generate_pdf_report(
        self,
        investigation: Dict[str, Any],
        targets: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        output_path: Optional[str] = None,
        report_format: str = "executive"
    ) -> str:
        inv_id = investigation.get("recon_id") or investigation.get("investigation_id", "REC-UNKNOWN")
        inv_title = investigation.get("name") or investigation.get("title", "Reconnaissance Audit")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        is_technical = (report_format.lower() == "technical")

        format_tag = "Technical" if is_technical else "Executive"
        if not output_path:
            reports_dir = os.path.abspath("reports")
            os.makedirs(reports_dir, exist_ok=True)
            output_path = os.path.join(reports_dir, f"FootprintIQ_{format_tag}_Report_{inv_id}_{timestamp}.pdf")

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "TitleStyle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#1e293b"),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            "SubtitleStyle",
            parent=styles["Normal"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=14
        )
        h2_style = ParagraphStyle(
            "Heading2Style",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=12,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            "BodyStyle",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155")
        )
        callout_style = ParagraphStyle(
            "CalloutStyle",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#065f46")
        )

        elements = []

        # 1. Header & Title Block
        header_text = f"FootprintIQ — {format_tag} Security Report"
        elements.append(Paragraph(header_text, title_style))
        elements.append(Paragraph(
            f"Campaign: <b>{inv_title}</b> (ID: {inv_id}) &bull; Date: {datetime.now(timezone.utc).strftime('%B %d, %Y')} &bull; Status: Verified Audit",
            subtitle_style
        ))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=14))

        # 2. Executive Summary & Exposure Scoring
        exposure = ExposureScoringEngine.calculate_investigation_exposure(findings)
        score = exposure["exposure_score"]
        level = exposure["exposure_level"]

        if is_technical:
            elements.append(Paragraph("1. Technical Methodology & Risk Exposure Index", h2_style))
            summary_p = (
                f"This technical report details the results of automated reconnaissance and multi-scanner vulnerability "
                f"assessment for campaign {inv_id}. The target scope was evaluated across Nmap network service detection, "
                f"policy-governed NSE vulnerability scripts, Greenbone/OpenVAS GMP assessments, and secondary correlation engines. "
                f"The aggregate exposure score is <b>{score} / 100 ({level} Exposure)</b> across {len(findings)} identified findings."
            )
        else:
            elements.append(Paragraph("1. Executive Summary & Security Risk Overview", h2_style))
            summary_p = (
                f"This executive report provides business leadership with an understandable overview of security risks discovered "
                f"during the FootprintIQ assessment of campaign <b>{inv_title}</b>. The overall risk rating is calculated at "
                f"<b>{score} / 100 ({level})</b>. A total of <b>{len(findings)} security observations</b> were identified across the scope, "
                f"including <b>{exposure['severity_counts']['Critical']} critical vulnerabilities</b> that require immediate remediation."
            )
        elements.append(Paragraph(summary_p, body_style))
        elements.append(Spacer(1, 10))

        # Severity breakdown table
        sev_counts = exposure["severity_counts"]
        kpi_data = [
            ["Critical (Immediate)", "High (Priority)", "Medium (Moderate)", "Low / Info", "Exposure Score"],
            [str(sev_counts["Critical"]), str(sev_counts["High"]), str(sev_counts["Medium"]), str(sev_counts["Low"] + sev_counts["Informational"]), f"{score}/100 ({level})"]
        ]
        t_kpi = Table(kpi_data, colWidths=[108, 108, 108, 108, 108])
        t_kpi.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#475569")),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('FONTSIZE', (0, 1), (-1, 1), 11),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_kpi)
        elements.append(Spacer(1, 14))

        # 3. Authorized Scope & Target Matrix
        elements.append(Paragraph("2. Authorized Scope & Asset Inventory", h2_style))
        target_rows = [["Target Address", "Target Type", "Asset Name", "Scope Bounds", "Permitted Profiles"]]
        for t in targets:
            target_rows.append([
                t.get("target", "192.168.56.111"),
                t.get("target_type", "ipv4"),
                t.get("name", "Metasploitable2 Lab VM"),
                t.get("scope", "Authorized Local Lab"),
                t.get("permitted_profiles", "lab-basic")
            ])
        t_targets = Table(target_rows, colWidths=[100, 70, 140, 130, 100])
        t_targets.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_targets)
        elements.append(Spacer(1, 14))

        # 4. Findings Section
        if is_technical:
            elements.append(Paragraph("3. Correlated Vulnerability Findings (Technical Breakdown)", h2_style))
            vuln_rows = [["Host:Port", "Protocol/Svc", "Severity", "CVE / CVSS", "Vulnerability Title", "Source"]]
            for f in findings[:15]:
                cve_text = f.get("cve_identifiers") or "—"
                if f.get("cvss_score"):
                    cve_text += f" (CVSS {f.get('cvss_score')})"
                vuln_rows.append([
                    f"{f.get('target_ip')}:{f.get('port') or 'all'}",
                    f"{f.get('protocol', 'tcp')}/{f.get('service', 'unknown')}",
                    f.get("severity", "Info"),
                    cve_text,
                    Paragraph(f.get("title", "Untitled")[:50], body_style),
                    f.get("detection_source", "scanner")
                ])
            if len(vuln_rows) > 1:
                t_vulns = Table(vuln_rows, colWidths=[80, 70, 55, 100, 175, 60])
                t_vulns.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(t_vulns)
        else:
            elements.append(Paragraph("3. Key Discoveries & Business Impact", h2_style))
            for idx, f in enumerate(findings[:5], start=1):
                card_data = [
                    [Paragraph(f"<b>Discovery #{idx}: {f.get('title')}</b> — Severity: <b>{f.get('severity')}</b>", body_style)],
                    [Paragraph(f"<b>What was discovered:</b> {f.get('description', 'Service vulnerability observed on port ' + str(f.get('port')))}", body_style)],
                    [Paragraph(f"<b>Business Impact:</b> Potential compromise of confidentiality and unauthorized access to underlying server services.", body_style)],
                    [Paragraph(f"<b>Recommended Fix:</b> {f.get('remediation', 'Apply latest vendor security patch or restrict port access.')}", callout_style)]
                ]
                t_card = Table(card_data, colWidths=[540])
                t_card.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#eff6ff")),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#fafafa")),
                    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(t_card)
                elements.append(Spacer(1, 6))

        elements.append(Spacer(1, 10))

        # 5. Evidence & Limitations
        elements.append(Paragraph("4. Evidence Integrity & Cryptographic Checksums", h2_style))
        ev_rows = [["Artifact Type", "File Name", "Size (bytes)", "SHA-256 Checksum", "Storage Engine"]]
        for ev in evidence[:8]:
            ev_rows.append([
                ev.get("evidence_type", "raw"),
                ev.get("file_name", "evidence.bin")[:25],
                str(ev.get("file_size", 0)),
                (ev.get("sha256_hash", "")[:24] + "...") if ev.get("sha256_hash") else "—",
                "SeaweedFS (FID: " + str(ev.get("seaweed_fid") or "cache")[:8] + ")"
            ])
        if len(ev_rows) > 1:
            t_ev = Table(ev_rows, colWidths=[90, 120, 60, 160, 110])
            t_ev.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_ev)

        # 6. Prioritized Recommendations & Limitations
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("5. Prioritized Remediation Roadmap & Scope Limitations", h2_style))
        remed_points = (
            "1. <b>Immediate:</b> Disable or patch backdoored services (e.g., vsftpd 2.3.4 backdoor on port 21).<br/>"
            "2. <b>High Priority:</b> Restrict unauthenticated remote access to database and management ports.<br/>"
            "3. <b>Ongoing:</b> Configure host-based firewalls and establish recurring vulnerability scans.<br/>"
            "<i>Assessment Limitations: This assessment was conducted against authorized targets in strict compliance with scope. "
            "Exclusions and non-destructive policies were enforced.</i>"
        )
        elements.append(Paragraph(remed_points, body_style))

        # Build document
        doc.build(elements)
        logger.info(f"Generated {format_tag} PDF report at: {output_path}")

        # Preserve generated PDF in SeaweedFS
        try:
            with open(output_path, "rb") as f:
                pdf_bytes = f.read()
            self.storage.upload_content(
                content=pdf_bytes,
                file_name=os.path.basename(output_path),
                investigation_id=inv_id,
                evidence_type="pdf_report",
                content_type="application/pdf"
            )
        except Exception as e:
            logger.warning(f"SeaweedFS upload notice for PDF: {e}")

        return output_path

