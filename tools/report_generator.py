"""
SMP Report Generator — V9.5
Produces professional Markdown/PDF and JSON VAPT reports with cryptographic authenticity.

Output formats:
  - Markdown (.md) — renders to PDF via weasyprint
  - JSON (.json)   — machine-readable, CI-pipeline ready

Report sections:
  1. Cover Page
  2. Executive Summary
  3. Scope & Methodology
  4. Security Findings (per-finding detail)
  5. Asset & Service Inventory
  6. Appendix (intel provenance, evidence hashes, attestation)
"""

import json
import hashlib
import uuid
import datetime
from typing import List, Dict, Any, Optional

# CVSS v3.1 severity bands
CVSS_SEVERITY_MAP = {
    "Critical": {"range": "9.0–10.0", "color": "🔴", "priority": 1},
    "High":     {"range": "7.0–8.9",  "color": "🟠", "priority": 2},
    "Medium":   {"range": "4.0–6.9",  "color": "🟡", "priority": 3},
    "Low":      {"range": "0.1–3.9",  "color": "🟢", "priority": 4},
    "Info":     {"range": "0.0",      "color": "⚪", "priority": 5},
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


class ReportGenerator:
    """
    Professional VAPT report generator for SMP V9.5.
    
    Usage:
        rg = ReportGenerator(version="V9.5")
        json_report = rg.generate_json_report(engagement_id, findings, evidence_hashes, intel_version, scanner_versions)
        markdown_report = rg.generate_markdown_report(json_report, metadata)
        pdf_bytes = rg.render_pdf(markdown_report)  # requires weasyprint
    """

    def __init__(self, version: str = "V9.5"):
        self.version = version
        self.generated_at = datetime.datetime.now(datetime.timezone.utc)

    # ─────────────────────────────────────────────────────────────────────────
    # Authenticity
    # ─────────────────────────────────────────────────────────────────────────

    def _compute_authenticity_hash(self, report_data: Dict) -> str:
        """SHA-256 of the canonical JSON representation of report data (excluding the hash field itself)."""
        sanitized = {k: v for k, v in report_data.items() if k != "authenticity_hash"}
        canonical = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # ─────────────────────────────────────────────────────────────────────────
    # JSON Report
    # ─────────────────────────────────────────────────────────────────────────

    def generate_json_report(
        self,
        engagement_id: str,
        findings: List[Dict],
        evidence_hashes: List[str],
        intel_version: str,
        scanner_versions: Dict[str, str],
        target: Optional[str] = None,
        operator: Optional[str] = None,
        assets: Optional[List[Dict]] = None,
        services: Optional[List[Dict]] = None,
    ) -> Dict:
        """
        Generate a machine-readable JSON report with authenticity hash.
        
        Returns:
            dict: Complete report payload suitable for storage/transmission.
        """
        # Sort findings by severity priority
        sorted_findings = sorted(
            findings,
            key=lambda f: CVSS_SEVERITY_MAP.get(f.get("severity", "Info"), {}).get("priority", 99),
        )

        report = {
            "schema_version": "1.0",
            "report_id": str(uuid.uuid4()),
            "engagement_id": engagement_id,
            "target": target or "Not specified",
            "operator": operator or "Unknown",
            "generated_at": self.generated_at.isoformat(),
            "report_generator_version": self.version,
            "intelligence_version": intel_version,
            "scanner_versions": scanner_versions,
            "findings": sorted_findings,
            "assets": assets or [],
            "services": services or [],
            "evidence_hashes": evidence_hashes,
            "statistics": self._compute_statistics(sorted_findings),
        }

        report["authenticity_hash"] = self._compute_authenticity_hash(report)
        return report

    def _compute_statistics(self, findings: List[Dict]) -> Dict:
        """Compute severity statistics from findings list."""
        stats = {sev: 0 for sev in SEVERITY_ORDER}
        confirmed_cves = set()
        kev_count = 0

        for f in findings:
            sev = f.get("severity", "Info")
            if sev in stats:
                stats[sev] += 1
            cve_ids = f.get("cve_id", [])
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            confirmed_cves.update([c for c in cve_ids if c])
            if f.get("provenance", {}) and f["provenance"].get("kev", False):
                kev_count += 1

        return {
            "total_findings": len(findings),
            "by_severity": stats,
            "unique_cves": len(confirmed_cves),
            "kev_findings": kev_count,
            "risk_rating": self._overall_risk_rating(stats),
        }

    def _overall_risk_rating(self, stats: Dict) -> str:
        """Derive overall engagement risk rating."""
        if stats.get("Critical", 0) > 0:
            return "CRITICAL"
        elif stats.get("High", 0) > 0:
            return "HIGH"
        elif stats.get("Medium", 0) > 0:
            return "MEDIUM"
        elif stats.get("Low", 0) > 0:
            return "LOW"
        return "INFORMATIONAL"

    # ─────────────────────────────────────────────────────────────────────────
    # Markdown Report
    # ─────────────────────────────────────────────────────────────────────────

    def generate_markdown_report(
        self,
        json_report: Dict,
        metadata: Optional[Dict] = None,
    ) -> str:
        """
        Generate a full professional VAPT report in Markdown format.
        
        Args:
            json_report: Output of generate_json_report()
            metadata: Optional dict with extra engagement info (client_name, submitted_to, etc.)
            
        Returns:
            str: Markdown document
        """
        metadata = metadata or {}
        stats = json_report.get("statistics", {})
        findings = json_report.get("findings", [])
        assets = json_report.get("assets", [])
        services = json_report.get("services", [])
        risk_rating = stats.get("risk_rating", "UNKNOWN")

        sections = [
            self._render_cover_page(json_report, metadata, risk_rating),
            self._render_toc(),
            self._render_executive_summary(json_report, stats, risk_rating),
            self._render_scope_methodology(json_report),
            self._render_findings_section(findings),
            self._render_asset_inventory(assets, services),
            self._render_appendix(json_report),
        ]

        return "\n\n---\n\n".join(sections)

    def _render_cover_page(self, report: Dict, metadata: Dict, risk_rating: str) -> str:
        risk_color = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🟢", "INFORMATIONAL": "⚪", "UNKNOWN": "⚫",
        }.get(risk_rating, "⚫")

        return f"""# Vulnerability Assessment & Penetration Test Report

**Security Management Platform {self.version}**

---

| Field | Value |
|---|---|
| **Report ID** | `{report['report_id']}` |
| **Engagement ID** | `{report['engagement_id']}` |
| **Target** | `{report.get('target', 'Not specified')}` |
| **Client** | {metadata.get('client_name', 'Confidential')} |
| **Submitted To** | {metadata.get('submitted_to', '—')} |
| **Operator** | {report.get('operator', 'Unknown')} |
| **Generated** | {report['generated_at'][:19].replace('T', ' ')} UTC |
| **Overall Risk Rating** | {risk_color} **{risk_rating}** |
| **Authenticity Hash** | `{report['authenticity_hash'][:32]}...` |

> ⚠️ **CONFIDENTIAL — RESTRICTED DISTRIBUTION**
> This report contains sensitive security findings. Distribution is restricted to
> authorised personnel only. Do not reproduce or distribute without written consent.

> This assessment was conducted using SMP {self.version} with intelligence database
> version `{report.get('intelligence_version', 'N/A')}`. All findings are based on
> evidence captured during authorised testing only."""

    def _render_toc(self) -> str:
        return """## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope & Methodology](#scope--methodology)
3. [Security Findings](#security-findings)
4. [Asset & Service Inventory](#asset--service-inventory)
5. [Appendix](#appendix)"""

    def _render_executive_summary(self, report: Dict, stats: Dict, risk_rating: str) -> str:
        by_sev = stats.get("by_severity", {})
        total = stats.get("total_findings", 0)
        crit = by_sev.get("Critical", 0)
        high = by_sev.get("High", 0)
        med = by_sev.get("Medium", 0)
        low = by_sev.get("Low", 0)
        info = by_sev.get("Info", 0)
        unique_cves = stats.get("unique_cves", 0)
        kev = stats.get("kev_findings", 0)

        # Narrative
        if crit > 0:
            narrative = (
                f"This assessment identified **{crit} Critical** and **{high} High** severity "
                f"vulnerabilities that require immediate remediation. These findings represent "
                f"direct, exploitable attack paths that could lead to complete system compromise."
            )
        elif high > 0:
            narrative = (
                f"This assessment identified **{high} High** severity vulnerabilities that "
                f"require urgent attention. While no Critical findings were confirmed, the "
                f"identified issues represent significant security risks."
            )
        elif med > 0:
            narrative = (
                f"This assessment identified **{med} Medium** severity vulnerabilities. "
                f"No Critical or High severity findings were confirmed during this engagement. "
                f"The identified issues should be remediated as part of regular security maintenance."
            )
        else:
            narrative = (
                "No Critical, High, or Medium severity vulnerabilities were confirmed during "
                "this assessment. The assessed target demonstrates an acceptable security posture "
                "for the scope evaluated."
            )

        kev_note = ""
        if kev > 0:
            kev_note = f"\n\n> ⚠️ **{kev} finding(s) match CISA Known Exploited Vulnerabilities (KEV).** Immediate patching required."

        return f"""## Executive Summary

### Overall Risk Rating: {risk_rating}

{narrative}{kev_note}

### Finding Breakdown

| Severity | Count | CVSS Range |
|---|---|---|
| 🔴 Critical | {crit} | 9.0 – 10.0 |
| 🟠 High | {high} | 7.0 – 8.9 |
| 🟡 Medium | {med} | 4.0 – 6.9 |
| 🟢 Low | {low} | 0.1 – 3.9 |
| ⚪ Informational | {info} | 0.0 |
| **Total** | **{total}** | |

**Unique CVEs Referenced:** {unique_cves}
**CISA KEV Matches:** {kev}

### Key Recommendations

{"1. **IMMEDIATE ACTION REQUIRED** — Remediate all Critical findings within 24 hours." if crit > 0 else ""}
{"2. Remediate all High severity findings within 7 days." if high > 0 else ""}
{"3. Address Medium severity findings within 30 days." if med > 0 else ""}
{"4. Schedule Low severity findings in the next quarterly patch cycle." if low > 0 else ""}
5. Re-test all findings after remediation to verify effectiveness."""

    def _render_scope_methodology(self, report: Dict) -> str:
        scanner_rows = "\n".join(
            f"| `{name}` | `{ver}` |"
            for name, ver in report.get("scanner_versions", {}).items()
        )
        if not scanner_rows:
            scanner_rows = "| N/A | N/A |"

        return f"""## Scope & Methodology

### Target
```
{report.get('target', 'Not specified')}
```

### Assessment Type
Full-scope Vulnerability Assessment & Penetration Test (VAPT) using SMP {self.version}.
All scanning conducted using local, offline-capable security tooling with no exfiltration of target data.

### Testing Approach
- **Phase 1** — Asset & Service Discovery (Nmap)
- **Phase 2** — Technology Enumeration (HTTPx, WhatWeb, Nuclei)
- **Phase 3** — Vulnerability Scanning (Nuclei, Nikto, SQLMap, etc.)
- **Phase 4** — CVE Intelligence Correlation (NVD, CISA KEV, EPSS)
- **Phase 5** — Finding Deduplication & Risk Scoring
- **Phase 6** — Evidence Preservation & Report Generation

### Tools Used

| Tool | Version |
|---|---|
{scanner_rows}

### Intelligence Database
Version: `{report.get('intelligence_version', 'N/A')}`
Source: NVD CVE, CISA KEV, EPSS (FIRST.org)

### Authorisation
All testing was conducted under written authorisation. Results reflect only the scope
defined in the engagement agreement. Out-of-scope systems were not tested."""

    def _render_findings_section(self, findings: List[Dict]) -> str:
        if not findings:
            return "## Security Findings\n\nNo security findings were identified during this assessment."

        sections = ["## Security Findings"]

        # Summary table
        table_rows = []
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "Info")
            icon = CVSS_SEVERITY_MAP.get(sev, {}).get("color", "⚪")
            cves = f.get("cve_id", [])
            if isinstance(cves, str):
                cves = [cves]
            cve_str = ", ".join([f"`{c}`" for c in cves if c]) or "—"
            table_rows.append(
                f"| {i} | {icon} {sev} | {f.get('title', 'Unknown')} | {cve_str} | {f.get('status', 'open')} |"
            )

        table = "| # | Severity | Title | CVE | Status |\n|---|---|---|---|---|\n" + "\n".join(table_rows)
        sections.append(table)

        # Per-finding detail
        for i, f in enumerate(findings, 1):
            sections.append(self._render_single_finding(i, f))

        return "\n\n".join(sections)

    def _render_single_finding(self, idx: int, f: Dict) -> str:
        sev = f.get("severity", "Info")
        icon = CVSS_SEVERITY_MAP.get(sev, {}).get("color", "⚪")
        conf = f.get("confidence", 0.5)
        risk = f.get("risk_score")
        risk_str = f"{risk:.1f}/100" if risk is not None else "Not calculated"

        cves = f.get("cve_id", [])
        if isinstance(cves, str):
            cves = [cves]
        cve_str = ", ".join([f"`{c}`" for c in cves if c]) or "None confirmed"

        sources = f.get("scanner_sources", [])
        if isinstance(sources, set):
            sources = list(sources)
        source_str = ", ".join([f"`{s}`" for s in sources]) if sources else "Unknown"

        obs_ids = f.get("affected_observations", [])
        obs_str = "\n".join([f"  - `{o}`" for o in obs_ids[:5]])
        if len(obs_ids) > 5:
            obs_str += f"\n  - _...and {len(obs_ids) - 5} more_"

        return f"""### Finding {idx:02d}: {f.get('title', 'Unknown')}

| Field | Value |
|---|---|
| **Finding ID** | `{f.get('finding_id', 'N/A')}` |
| **Severity** | {icon} {sev} |
| **Confidence** | {conf * 100:.0f}% |
| **Risk Score** | {risk_str} |
| **CVE Reference** | {cve_str} |
| **CWE** | {f.get('cwe_id') or '—'} |
| **Status** | {f.get('status', 'open')} |
| **Vulnerability Class** | {f.get('vulnerability_class') or '—'} |
| **Asset** | {f.get('asset_id') or '—'} |
| **Endpoint** | {f.get('endpoint') or '—'} |
| **Parameter** | {f.get('parameter') or '—'} |
| **First Observed** | {str(f.get('first_observed_at', '—'))[:19]} |
| **Occurrence Count** | {f.get('occurrence_count', 1)} |
| **Scanner Sources** | {source_str} |

#### Description

{f.get('description') or f.get('title', 'No description provided.')}

#### Evidence

The following {len(obs_ids)} observation(s) support this finding:

{obs_str or "  - No observations linked"}

#### Remediation

{f.get('remediation') or "Refer to the CVE advisory for vendor-specific remediation guidance. Apply available patches and verify using the steps below."}

#### Validation Steps

{f.get('validation') or "Re-test this finding after applying the recommended remediation. Use the same scanner set to confirm the vulnerability is no longer present."}"""

    def _render_asset_inventory(self, assets: List[Dict], services: List[Dict]) -> str:
        asset_rows = "\n".join(
            f"| `{a.get('asset_value', '—')}` | {a.get('asset_type', '—')} | {a.get('source_scanner', '—')} | {a.get('confidence', 1.0) * 100:.0f}% |"
            for a in assets
        ) or "| No assets recorded | — | — | — |"

        service_rows = "\n".join(
            f"| {s.get('port', '—')} | {s.get('protocol', '—').upper()} | {s.get('state', '—')} | {s.get('product') or s.get('service_name') or '—'} | {s.get('version') or '—'} |"
            for s in services
        ) or "| No services recorded | — | — | — | — |"

        return f"""## Asset & Service Inventory

### Discovered Assets

| Address | Type | Source | Confidence |
|---|---|---|---|
{asset_rows}

### Open Services

| Port | Protocol | State | Product | Version |
|---|---|---|---|---|
{service_rows}"""

    def _render_appendix(self, report: Dict) -> str:
        hash_rows = "\n".join(
            f"| `{h}` |" for h in report.get("evidence_hashes", [])
        ) or "| No evidence recorded |"

        scanner_rows = "\n".join(
            f"| `{k}` | `{v}` |"
            for k, v in report.get("scanner_versions", {}).items()
        ) or "| N/A | N/A |"

        return f"""## Appendix

### A. Intelligence Provenance

| Field | Value |
|---|---|
| **NVD CVE Version** | {report.get('intelligence_version', 'N/A')} |
| **Report Generator** | SMP {report.get('report_generator_version', 'N/A')} |
| **Generated At** | {report.get('generated_at', 'N/A')} |

### B. Evidence Hashes

| SHA-256 / Evidence Reference |
|---|
{hash_rows}

### C. Tool Version Manifest

| Tool | Version |
|---|---|
{scanner_rows}

### D. Report Integrity Attestation

This report was generated by the Security Management Platform (SMP) {report.get('report_generator_version', 'N/A')}.
The authenticity hash below was computed over the canonical JSON representation of all report
data (excluding the hash field itself) using SHA-256.

```
REPORT-ID:    {report.get('report_id', 'N/A')}
ENGAGEMENT:   {report.get('engagement_id', 'N/A')}
GENERATED-AT: {report.get('generated_at', 'N/A')}
SHA-256:      {report.get('authenticity_hash', 'N/A')}
```

To verify this report has not been tampered with:
```bash
python3 tools/verify_report.py <report_file.json>
```

*Use only against systems for which you have written authorisation to test.*
*© SMP — Licensed under the MIT License.*"""

    # ─────────────────────────────────────────────────────────────────────────
    # Executive Summary (text)
    # ─────────────────────────────────────────────────────────────────────────

    def generate_executive_summary(self, json_report: Dict) -> str:
        """
        Generate a plain-text executive summary for quick terminal output.
        Backward-compatible with the previous interface.
        """
        stats = json_report.get("statistics", self._compute_statistics(json_report.get("findings", [])))
        by_sev = stats.get("by_severity", {})

        return (
            f"Executive Summary\n"
            f"=================\n"
            f"Report ID:          {json_report.get('report_id', 'N/A')}\n"
            f"Engagement ID:      {json_report.get('engagement_id', 'N/A')}\n"
            f"Target:             {json_report.get('target', 'N/A')}\n"
            f"Generated:          {json_report.get('generated_at', 'N/A')[:19]} UTC\n"
            f"Overall Risk:       {stats.get('risk_rating', 'UNKNOWN')}\n"
            f"Authenticity Hash:  {json_report.get('authenticity_hash', 'N/A')}\n"
            f"\n"
            f"Vulnerability Breakdown:\n"
            f"  Critical:  {by_sev.get('Critical', 0)}\n"
            f"  High:      {by_sev.get('High', 0)}\n"
            f"  Medium:    {by_sev.get('Medium', 0)}\n"
            f"  Low:       {by_sev.get('Low', 0)}\n"
            f"  Info:      {by_sev.get('Info', 0)}\n"
            f"  Total:     {stats.get('total_findings', 0)}\n"
            f"\n"
            f"Unique CVEs:        {stats.get('unique_cves', 0)}\n"
            f"CISA KEV Matches:   {stats.get('kev_findings', 0)}\n"
            f"Intelligence DB:    {json_report.get('intelligence_version', 'N/A')}\n"
        )

    # ─────────────────────────────────────────────────────────────────────────
    # PDF Rendering (optional weasyprint)
    # ─────────────────────────────────────────────────────────────────────────

    def render_pdf(self, markdown_content: str, output_path: str) -> bool:
        """
        Render Markdown to PDF using weasyprint (if available).
        Falls back gracefully if weasyprint is not installed.
        
        Returns:
            bool: True if PDF was written, False if fell back to Markdown.
        """
        try:
            import markdown as md_lib
            from weasyprint import HTML, CSS

            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SMP VAPT Report</title>
<style>
  body {{ font-family: "Helvetica Neue", Arial, sans-serif; margin: 40px; color: #1a1a1a; line-height: 1.6; }}
  h1 {{ color: #000; border-bottom: 3px solid #C0392B; padding-bottom: 10px; }}
  h2 {{ color: #1a1a1a; border-bottom: 1px solid #ccc; padding-bottom: 6px; margin-top: 40px; }}
  h3 {{ color: #333; margin-top: 28px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
  th {{ background: #f0f0f0; padding: 8px 12px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #e0e0e0; font-size: 13px; }}
  code {{ background: #f5f5f5; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
  pre {{ background: #f5f5f5; padding: 16px; border-radius: 6px; overflow: auto; font-size: 12px; }}
  blockquote {{ border-left: 4px solid #C0392B; margin: 0; padding: 12px 20px; background: #fdf0f0; }}
  hr {{ border: none; border-top: 1px solid #e0e0e0; margin: 32px 0; }}
  @page {{ margin: 2cm; }}
</style>
</head>
<body>
{md_lib.markdown(markdown_content, extensions=['tables', 'fenced_code'])}
</body>
</html>"""

            HTML(string=html_content).write_pdf(output_path)
            return True

        except ImportError:
            # Fall back: write as .md if weasyprint/markdown not available
            md_path = output_path.replace(".pdf", ".md")
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            return False
