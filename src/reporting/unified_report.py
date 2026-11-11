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
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import hashlib
from xml.sax.saxutils import escape as _xml_escape

logger = logging.getLogger("FootprintIQ.Report")

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.units import inch

from src.services.exposure_scoring import ExposureScoringEngine
from src.services.finding_translator import (
    explain_finding_plain_language,
    classify_confidence,
    build_dynamic_remediation_roadmap,
)
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
        report_format: str = "executive",
        results_bundle: Optional[Dict[str, Any]] = None,
        analysis: Optional[Dict[str, Any]] = None,
        generated_by: Optional[str] = None,
    ) -> str:
        inv_id = investigation.get("recon_id") or investigation.get("investigation_id", "REC-UNKNOWN")
        inv_title = investigation.get("name") or investigation.get("title", "Reconnaissance Audit")
        camp_status = investigation.get("status", "Completed")
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
            fontSize=21,
            leading=25,
            textColor=colors.HexColor("#1e293b"),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            "SubtitleStyle",
            parent=styles["Normal"],
            fontSize=10.5,
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
        warn_style = ParagraphStyle(
            "WarnStyle",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#991b1b")
        )

        elements = []
        bundle = results_bundle or {}
        passive_results = bundle.get("passive_results") or []
        active_hosts = bundle.get("active_hosts") or []
        discovered_ports = bundle.get("discovered_ports") or []
        scanner_statuses = bundle.get("scanner_statuses") or []
        failed_stages = bundle.get("failed_stages") or []

        # 1. Header & Title Block
        inv_purpose = _xml_escape(str(investigation.get("purpose") or "Security Assessment"))
        assess_date = str(investigation.get("created_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
        try:
            scan_cfg = json.loads(investigation.get("scan_config_json") or "{}") if isinstance(investigation.get("scan_config_json"), str) else (investigation.get("scan_config_json") or {})
        except Exception:
            scan_cfg = {}

        header_text = f"FootprintIQ — {format_tag} Security Assessment Report"
        elements.append(Paragraph(header_text, title_style))
        actor_line = f" &bull; Generated By: <b>{_xml_escape(str(generated_by))}</b>" if generated_by else ""
        elements.append(Paragraph(
            f"Campaign: <b>{_xml_escape(str(inv_title))}</b> &bull; Recon ID: <b>{_xml_escape(str(inv_id))}</b> &bull; "
            f"Purpose: <b>{inv_purpose}</b> &bull; Assessment Date: {_xml_escape(assess_date[:19])} &bull; "
            f"Generated: {datetime.now(timezone.utc).strftime('%B %d, %Y %H:%M UTC')}{actor_line} &bull; Outcome: <b>{_xml_escape(str(camp_status))}</b>",
            subtitle_style
        ))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=12))

        if camp_status in ("Failed", "Partially Completed", "Cancelled", "Interrupted") or failed_stages:
            elements.append(Paragraph(
                f"<b>Assessment Coverage Notice:</b> Campaign status is <b>{_xml_escape(str(camp_status))}</b>. "
                + (f"Incomplete or failed modules: {_xml_escape(', '.join(failed_stages))}. " if failed_stages else "")
                + "Absence of findings in incomplete modules must not be interpreted as clean security status.",
                warn_style
            ))
            elements.append(Spacer(1, 10))

        # 2. Executive Summary & Exposure Scoring
        exposure = ExposureScoringEngine.calculate_investigation_exposure(findings)
        score = exposure["exposure_score"]
        level = exposure["exposure_level"]

        if is_technical:
            elements.append(Paragraph("1. Technical Methodology & Exposure Summary", h2_style))
            summary_p = (
                f"This technical deliverable documents the verified reconnaissance and vulnerability assessment executed under "
                f"Campaign <b>{_xml_escape(str(inv_id))}</b>. Results combine executed modules across passive intelligence, active port/service discovery, "
                f"and enabled vulnerability assessment engines. "
                f"Aggregate risk index: <b>{score} / 100 ({level} Exposure)</b> across <b>{len(findings)} security finding(s)</b> and <b>{len(discovered_ports)} open port(s)</b>."
            )
        else:
            elements.append(Paragraph("1. Executive Overview & Security Posture", h2_style))
            summary_p = (
                f"This executive report summarizes security exposures identified during Campaign <b>{_xml_escape(str(inv_title))}</b> ({_xml_escape(str(inv_id))}). "
                f"The overall calculated risk rating is <b>{score} / 100 ({level})</b> across <b>{len(targets) or 1} scoped asset(s)</b>, "
                f"<b>{len(discovered_ports)} exposed service port(s)</b>, and <b>{len(findings)} security finding(s)</b>, "
                f"including <b>{exposure['severity_counts']['Critical']} Critical</b> and <b>{exposure['severity_counts']['High']} High</b> severity items."
            )
        elements.append(Paragraph(summary_p, body_style))
        elements.append(Spacer(1, 10))

        sev_counts = exposure["severity_counts"]
        kpi_data = [
            ["Critical", "High", "Medium", "Low", "Informational", "Open Ports", "Risk Score"],
            [
                str(sev_counts["Critical"]),
                str(sev_counts["High"]),
                str(sev_counts["Medium"]),
                str(sev_counts["Low"]),
                str(sev_counts["Informational"]),
                str(len(discovered_ports)),
                f"{score}/100 ({level})"
            ]
        ]
        t_kpi = Table(kpi_data, colWidths=[68, 65, 68, 62, 85, 78, 114])
        t_kpi.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#475569")),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('FONTSIZE', (0, 1), (-1, 1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_kpi)
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(
            f"<b>Severity Distribution:</b> Critical: {sev_counts['Critical']} | High: {sev_counts['High']} | "
            f"Medium: {sev_counts['Medium']} | Low: {sev_counts['Low']} | Informational: {sev_counts['Informational']}",
            body_style
        ))
        elements.append(Spacer(1, 12))

        # 2B. Selected Scan Methods Summary
        sel_cats = [str(c).title() for c in (scan_cfg.get("selected_categories") or [])]
        if not sel_cats and investigation.get("selected_scan_types"):
            sel_cats = [str(investigation.get("selected_scan_types")).title()]
        p_checks = (scan_cfg.get("passive") or {}).get("selected_checks") or []
        a_cfg = scan_cfg.get("active") or {}
        v_cfg = scan_cfg.get("vulnerability") or {}
        v_engines = v_cfg.get("engines") or ([v_cfg.get("engine")] if v_cfg.get("engine") else [])
        methods_text = (
            f"<b>Selected Categories:</b> {_xml_escape(', '.join(sel_cats) or 'Standard')} &bull; "
            f"<b>Passive Modules:</b> {_xml_escape(', '.join(p_checks[:12]) if p_checks else 'None')} &bull; "
            f"<b>Active Options:</b> {_xml_escape(str(a_cfg.get('port_mode', 'N/A')) if a_cfg else 'None')} &bull; "
            f"<b>Vulnerability Engines:</b> {_xml_escape(', '.join(str(e).upper() for e in v_engines if e) or 'None')}"
        )
        elements.append(Paragraph("2. Selected Scan Methods & Assessment Scope", h2_style))
        elements.append(Paragraph(methods_text, body_style))
        elements.append(Spacer(1, 8))
        target_rows = [["Target", "Type", "Description", "Scope Basis", "Exclusions"]]
        for t in (targets or [{"target": investigation.get("target_value", "N/A"), "target_type": investigation.get("target_type", "ipv4"), "name": inv_title, "scope": investigation.get("scope_description") or "Authorized Campaign Scope"}]):
            target_rows.append([
                Paragraph(str(t.get("target", "N/A")), body_style),
                str(t.get("target_type", "ipv4")),
                Paragraph(str(t.get("name", inv_title))[:45], body_style),
                Paragraph(str(t.get("scope", "Authorized Scope"))[:45], body_style),
                Paragraph(str(investigation.get("excluded_targets") or "None")[:30], body_style)
            ])
        t_targets = Table(target_rows, colWidths=[110, 55, 145, 140, 90])
        t_targets.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_targets)
        elements.append(Spacer(1, 10))

        # Scanner Execution Coverage
        if scanner_statuses:
            elements.append(Paragraph("3. Executed Assessment Modules & Coverage", h2_style))
            sc_rows = [["Module / Scanner", "Target", "Status", "Details"]]
            for ss in scanner_statuses:
                sc_rows.append([
                    Paragraph(str(ss.get("scanner", "Module")), body_style),
                    str(ss.get("target", "")),
                    str(ss.get("status", "")),
                    Paragraph(str(ss.get("detail", ""))[:80], body_style)
                ])
            t_sc = Table(sc_rows, colWidths=[130, 100, 80, 230])
            t_sc.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_sc)
            elements.append(Spacer(1, 10))

        # 4. Passive & Active Recon Results Summary
        if passive_results or discovered_ports:
            elements.append(Paragraph("4. Reconnaissance Observations (Passive & Active)", h2_style))
            if passive_results:
                for pr in passive_results:
                    p_tgt = pr.get("target", "")
                    dom = pr.get("domain_intel") or {}
                    osint = pr.get("osint_intel") or {}
                    infra = pr.get("infrastructure_intel") or {}
                    whois_org = ((dom.get("whois") or {}).get("organization") or (dom.get("whois") or {}).get("registrar") or "Not disclosed")
                    subs = dom.get("subdomains") or []
                    ips = infra.get("resolved_ips") or []
                    emails = osint.get("emails") or []
                    sec_post = dom.get("dns_security") or {}
                    spf_ok = "Configured" if sec_post.get("spf_configured") else "Not detected"
                    dmarc_ok = "Configured" if sec_post.get("dmarc_configured") else "Not detected"
                    elements.append(Paragraph(
                        f"<b>Passive Intelligence ({p_tgt}):</b> Registrar/Org: {whois_org} &bull; Resolved IPs: {', '.join(ips[:5]) or 'None'} &bull; "
                        f"Subdomains Discovered: {len(subs)} &bull; Public Contacts: {len(emails)} &bull; SPF: {spf_ok} &bull; DMARC: {dmarc_ok}",
                        body_style
                    ))
                    elements.append(Spacer(1, 4))

            if discovered_ports:
                port_rows = [["Host IP", "Port / Proto", "State", "Service", "Detected Version"]]
                for p in discovered_ports[:60]:
                    port_rows.append([
                        str(p.get("target_ip", "")),
                        f"{p.get('port')}/{p.get('protocol', 'tcp')}",
                        str(p.get("state", "open")),
                        str(p.get("service", "unknown")),
                        Paragraph(str(p.get("service_version") or "—")[:55], body_style)
                    ])
                t_ports = Table(port_rows, colWidths=[105, 75, 55, 100, 205])
                t_ports.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                ]))
                elements.append(t_ports)
                elements.append(Spacer(1, 10))

        # 5. Findings Section (Full Non-Truncated Breakdown)
        if is_technical:
            elements.append(Paragraph("5. Detailed Vulnerability Findings (Technical Breakdown)", h2_style))
            vuln_rows = [["Host:Port", "Svc", "Severity", "Classification", "CVE / CVSS", "Title", "Source"]]
            for f in findings:
                cve_text = f.get("cve_identifiers") or "—"
                if f.get("cvss_score"):
                    cve_text += f" ({f.get('cvss_score')})"
                vuln_rows.append([
                    f"{f.get('target_ip')}:{f.get('port') or 'all'}",
                    str(f.get("service") or "—")[:14],
                    str(f.get("severity", "Info")),
                    classify_confidence(f).replace(" Vulnerability", ""),
                    Paragraph(cve_text[:28], body_style),
                    Paragraph(str(f.get("title", "Untitled"))[:65], body_style),
                    str(f.get("detection_source", "scanner"))
                ])
            if len(vuln_rows) > 1:
                t_vulns = Table(vuln_rows, colWidths=[75, 50, 50, 75, 80, 155, 55])
                t_vulns.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                ]))
                elements.append(t_vulns)
            else:
                elements.append(Paragraph("No vulnerability findings recorded in this campaign.", body_style))
        else:
            elements.append(Paragraph("5. Key Findings & Plain-Language Risk Explanations", h2_style))
            if findings:
                for idx, f in enumerate(findings[:25], start=1):
                    exp = explain_finding_plain_language(f)
                    card_data = [
                        [Paragraph(f"<b>#{idx}: {f.get('title')}</b> — <b>{exp['seriousness']}</b> ({exp['confidence_label']})", body_style)],
                        [Paragraph(f"<b>What was discovered:</b> {exp['what_discovered']}", body_style)],
                        [Paragraph(f"<b>Why it matters:</b> {exp['why_important']}", body_style)],
                        [Paragraph(f"<b>Potential impact:</b> {exp['potential_impact']}", body_style)],
                        [Paragraph(f"<b>Recommended action:</b> {exp['recommended_action']}", callout_style)]
                    ]
                    t_card = Table(card_data, colWidths=[540])
                    t_card.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#eff6ff")),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#fafafa")),
                        ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd5e1")),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ]))
                    elements.append(KeepTogether([t_card, Spacer(1, 6)]))
            else:
                elements.append(Paragraph("No security vulnerabilities were recorded in the completed scan modules.", body_style))

        elements.append(Spacer(1, 10))

        # 6. Evidence & Integrity
        elements.append(Paragraph("6. Collected Evidence References & Integrity Verification", h2_style))
        if evidence:
            ev_rows = [["Type", "File Name", "Size (bytes)", "SHA-256 Digest", "Storage Ref"]]
            for ev in evidence[:20]:
                ev_rows.append([
                    str(ev.get("evidence_type", "artifact")),
                    Paragraph(_xml_escape(str(ev.get("file_name", "evidence.bin"))[:30]), body_style),
                    str(ev.get("file_size", 0)),
                    (ev.get("sha256_hash", "")[:24] + "...") if ev.get("sha256_hash") else "—",
                    "Archived (" + (str(ev.get("seaweed_fid") or "local")[:10]) + ")"
                ])
            t_ev = Table(ev_rows, colWidths=[85, 140, 60, 155, 100])
            t_ev.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_ev)
        else:
            elements.append(Paragraph("No external binary or raw XML evidence artifacts were attached for this campaign run.", body_style))
        elements.append(Spacer(1, 10))

        # 7. Dynamic Prioritized Recommendations & Integrated Report Analysis
        elements.append(Paragraph("7. Integrated Report Analysis, Risk Interpretation & Remediation", h2_style))
        roadmap = build_dynamic_remediation_roadmap(findings, failed_scanners=failed_stages)
        roadmap_html = "<br/>".join([f"{i}. {_xml_escape(str(item))}" for i, item in enumerate(roadmap, start=1)])

        if analysis:
            ri = analysis.get("risk_interpretation") or {}
            va = analysis.get("vulnerability_analysis") or {}
            al = analysis.get("assessment_limitations") or {}
            drivers = ri.get("drivers") or []
            driver_lines = "<br/>".join([f"&bull; {_xml_escape(str(d))}" for d in drivers])
            conf_summary = _xml_escape(str(ri.get("confidence_summary") or ""))
            cves = va.get("cve_inventory") or []
            cve_line = _xml_escape(", ".join(cves[:12])) if cves else "None recorded"
            roadmap_html = (
                f"<b>Risk Interpretation ({_xml_escape(str(ri.get('exposure_level', level)))} — {score}/100):</b><br/>"
                f"Confidence Profile: {conf_summary} &bull; CVEs Referenced: {cve_line}<br/>"
                f"{driver_lines}<br/><br/>"
                f"<b>Prioritized Remediation Roadmap:</b><br/>{roadmap_html}"
            )
            extra_gaps = al.get("coverage_gaps") or []
        else:
            extra_gaps = []

        unavail_notes = list(extra_gaps)
        for pr in passive_results:
            for uc in (pr.get("unavailable_checks") or []):
                note = f"{uc.get('id')}: {uc.get('reason')}"
                if note not in unavail_notes:
                    unavail_notes.append(note)
        for ss in scanner_statuses:
            if ss.get("status") in ("FAILED", "UNAVAILABLE", "READ_ONLY_LICENSE", "BLOCKED"):
                note = f"{ss.get('scanner')}: {ss.get('detail')}"
                if note not in unavail_notes:
                    unavail_notes.append(note)
        limitations_text = "; ".join(unavail_notes[:10]) if unavail_notes else "All enabled modules executed cleanly within authorized scope."

        roadmap_html += (
            f"<br/><br/><b>Assessment Limitations &amp; Coverage Verification:</b> {_xml_escape(limitations_text)}<br/>"
            "<i>Scope Notice: Findings strictly reflect the authorized targets, selected modules, and host permissions active at execution time.</i>"
        )
        elements.append(Paragraph(roadmap_html, body_style))

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

