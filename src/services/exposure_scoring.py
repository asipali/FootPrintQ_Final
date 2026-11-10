"""
FootprintIQ - Exposure Scoring and Risk Prioritization Engine
Implements a transparent, deterministic risk-scoring methodology combining:
- CVSS v3.x base scores
- Scanner confidence and verification status
- Multi-scanner corroboration
- Network service exposure
- Severity category distribution
"""

import math
from typing import List, Dict, Any

SEVERITY_WEIGHTS = {
    "Critical": 10.0,
    "High": 7.5,
    "Medium": 5.0,
    "Low": 2.5,
    "Informational": 0.5
}


class ExposureScoringEngine:
    @staticmethod
    def calculate_finding_risk(finding: Dict[str, Any], corroborated: bool = False) -> Dict[str, Any]:
        """
        Calculates individual finding risk score (0 - 100).
        """
        cvss = finding.get("cvss_score")
        severity = finding.get("severity", "Informational")
        confidence = float(finding.get("confidence", 0.8))
        is_verified = finding.get("verification_status") == "verified"

        # Determine base score
        if cvss is not None and isinstance(cvss, (int, float)) and cvss > 0:
            base_score = float(cvss) * 10.0
            score_source = f"CVSS {cvss}"
        else:
            base_score = SEVERITY_WEIGHTS.get(severity, 2.5) * 10.0
            score_source = f"Severity mapping ({severity})"

        # Multipliers
        verif_factor = 1.0 if is_verified else 0.85
        conf_factor = max(0.5, min(1.0, confidence))
        corroboration_factor = 1.15 if corroborated else 1.0

        raw_score = base_score * verif_factor * conf_factor * corroboration_factor
        final_score = round(min(100.0, max(0.0, raw_score)), 1)

        return {
            "finding_id": finding.get("finding_id"),
            "risk_score": final_score,
            "base_score": base_score,
            "score_source": score_source,
            "corroborated": corroborated,
            "verification_factor": verif_factor,
            "confidence_factor": conf_factor
        }

    @classmethod
    def calculate_investigation_exposure(cls, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculates aggregate target and investigation exposure score (0 - 100)
        and severity distribution.
        """
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0
        }

        if not findings:
            return {
                "exposure_score": 0.0,
                "exposure_level": "Minimal",
                "total_findings": 0,
                "severity_counts": severity_counts,
                "prioritized_findings": [],
                "scoring_methodology": "No vulnerabilities detected. Exposure level is minimal."
            }

        # Check for multi-scanner corroboration by CVE or Port+Service
        cve_map: Dict[str, set] = {}
        for f in findings:
            cves = f.get("cve_identifiers")
            src = f.get("detection_source", "unknown")
            if cves:
                for cve in str(cves).split(","):
                    cve_clean = cve.strip().upper()
                    if cve_clean:
                        cve_map.setdefault(cve_clean, set()).add(src)

        finding_risks = []
        total_risk_sum = 0.0

        for f in findings:
            sev = f.get("severity", "Informational")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Check if this finding was detected across multiple engines
            cves = str(f.get("cve_identifiers", "")).split(",")
            corroborated = False
            for cve in cves:
                cve_clean = cve.strip().upper()
                if cve_clean in cve_map and len(cve_map[cve_clean]) > 1:
                    corroborated = True
                    break

            risk_meta = cls.calculate_finding_risk(f, corroborated=corroborated)
            f_score = risk_meta["risk_score"]
            total_risk_sum += f_score

            finding_risks.append({
                **f,
                "calculated_risk_score": f_score,
                "corroborated": corroborated
            })

        # Calculate aggregate score using asymptotic curve: 100 * (1 - e^(-total_risk / 150))
        exposure_score = round(100.0 * (1.0 - math.exp(-total_risk_sum / 150.0)), 1)
        exposure_score = min(100.0, max(0.0, exposure_score))

        # Qualitative level
        if exposure_score >= 80.0:
            level = "Critical"
        elif exposure_score >= 60.0:
            level = "High"
        elif exposure_score >= 40.0:
            level = "Medium"
        elif exposure_score >= 20.0:
            level = "Low"
        else:
            level = "Informational"

        # Prioritize top findings
        prioritized = sorted(finding_risks, key=lambda x: x.get("calculated_risk_score", 0), reverse=True)

        return {
            "exposure_score": exposure_score,
            "exposure_level": level,
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "prioritized_findings": prioritized,
            "scoring_formula": "Exposure = 100 * (1 - exp(-Sum(Risk_i) / 150)) where Risk_i = CVSS * Verification * Confidence * MultiScannerBoost"
        }

