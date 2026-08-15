"""
SMP V9.5 — Data Exporter
Exports engagement data in multiple formats for  ticketing system integration.
All exports require explicit legal gate confirmation — the caller MUST pass gate_confirmed=True.
"""

import os
import sys
import json
import csv
import hashlib
import zipfile
import datetime
import io
import uuid
from typing import Optional, Dict, Any, List
from enum import Enum
from dataclasses import dataclass

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

class ExportFormat(Enum):
    JIRA_JSON = "JIRA_JSON"
    SERVICENOW_CSV = "SERVICENOW_CSV"
    DEFECTDOJO_JSON = "DEFECTDOJO_JSON"
    GENERIC_JSON = "GENERIC_JSON"
    MARKDOWN_ZIP = "MARKDOWN_ZIP"
    SARIF = "SARIF"

PLAINTEXT_WARNING_HEADER = """═══ SMP PLAINTEXT EXPORT — UNENCRYPTED DATA ═══
  This file is NOT encrypted. Secure immediately.
═══════════════════════════════════════════════════"""

@dataclass
class ExportAuditRecord:
    export_id: str
    timestamp: str
    operator: str
    engagement_id: str
    export_format: str
    output_path: str
    sha256_hash: str
    gate_confirmed_at: str

class DataExporter:
    def __init__(self, db_manager_module=None):
        self.db_manager = db_manager_module

    def _build_jira_json(self, findings: list, engagement_meta: dict) -> dict:
        issues = []
        for f in findings:
            issue = {
                "summary": f.get("title", "Untitled Finding"),
                "issuetype": {"name": f.get("severity", "Bug")},
                "priority": f.get("severity", "Medium"),
                "description": PLAINTEXT_WARNING_HEADER + "\n" + f.get("description", ""),
                "labels": ["SMP-Export", f.get("cve_id", "NO-CVE")],
                "customfield_cvss": f.get("cvss_score", 0.0)
            }
            issues.append(issue)
        return {"issues": issues, "engagement": engagement_meta}

    def _build_servicenow_csv(self, findings: list, engagement_meta: dict) -> str:
        output = io.StringIO()
        output.write(PLAINTEXT_WARNING_HEADER + "\n")
        writer = csv.writer(output)
        writer.writerow(["number", "category", "priority", "short_description", "description", "assignment_group", "state", "severity", "cmdb_ci", "work_notes"])
        for i, f in enumerate(findings):
            writer.writerow([
                f"INC{i+1000}",
                "Security",
                f.get("severity", "Medium"),
                f.get("title", "Untitled"),
                f.get("description", ""),
                "Security-Ops",
                "New",
                f.get("severity", "Medium"),
                f.get("asset", "Unknown"),
                "Exported from SMP V9.5"
            ])
        return output.getvalue()

    def _build_defectdojo_json(self, findings: list, assets: list, engagement_meta: dict) -> dict:
        return {
            "warning": PLAINTEXT_WARNING_HEADER.strip(),
            "engagement": engagement_meta,
            "test": {"title": "SMP Exported Test", "type": "SMP"},
            "findings": findings,
            "assets": assets
        }

    def _build_sarif(self, findings: list, engagement_meta: dict) -> dict:
        results = []
        for f in findings:
            results.append({
                "ruleId": f.get("cve_id", "SMP-RULE"),
                "message": {"text": f.get("description", "")},
                "level": f.get("severity", "none").lower()
            })
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "warning": PLAINTEXT_WARNING_HEADER.strip(),
            "runs": [{
                "tool": {"driver": {"name": "SMP V9.5 Exporter"}},
                "results": results
            }]
        }

    def _build_generic_json(self, findings: list, assets: list, services: list, scan_timeline: list, engagement_meta: dict) -> dict:
        return {
            "warning": PLAINTEXT_WARNING_HEADER.strip(),
            "engagement_meta": engagement_meta,
            "findings": findings,
            "assets": assets,
            "services": services,
            "scan_timeline": scan_timeline
        }

    def _build_markdown_report(self, findings: list, assets: list, engagement_meta: dict) -> str:
        md = PLAINTEXT_WARNING_HEADER + "\n"
        md += f"# Engagement Report: {engagement_meta.get('name', 'N/A')}\n\n"
        md += f"**ID:** {engagement_meta.get('id', 'N/A')}\n\n"
        md += "## Findings\n"
        for f in findings:
            md += f"### {f.get('title', 'Untitled')} ({f.get('severity', 'Unknown')})\n"
            md += f"{f.get('description', '')}\n\n"
        return md

    def _compute_sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _write_audit_record(self, record: ExportAuditRecord):
        if self.db_manager:
            try:
                # Mocked DB write
                pass
            except Exception as e:
                print(f"Warning: Failed to write audit record. {e}")
        else:
            print(f"Audit record generated but no DB manager available: {record}")

    def export(self, engagement_id: str, export_format: ExportFormat, output_dir: str, operator: str, gate_confirmed: bool = False, gate_confirmed_at: str = None) -> dict:
        if not gate_confirmed:
            raise ValueError('SMP-4050: Export gate not confirmed. User must type I AGREE before export.')
        
        # Mocking data fetch
        engagement_meta = {"id": engagement_id, "name": f"Engagement {engagement_id}"}
        findings = [{"title": "Test SQLi", "severity": "High", "description": "SQL injection in login.", "cve_id": "CVE-2023-1234", "cvss_score": 8.5}]
        assets = [{"id": "A1", "ip": "10.0.0.1"}]
        services = []
        scan_timeline = []

        output_path = ""
        output_data = b""

        os.makedirs(output_dir, exist_ok=True)
        export_id = str(uuid.uuid4())
        
        if export_format == ExportFormat.JIRA_JSON:
            res = self._build_jira_json(findings, engagement_meta)
            output_path = os.path.join(output_dir, f"{export_id}_jira.json")
            output_data = json.dumps(res, indent=2).encode('utf-8')
            with open(output_path, "wb") as f:
                f.write(output_data)
        
        elif export_format == ExportFormat.SERVICENOW_CSV:
            res = self._build_servicenow_csv(findings, engagement_meta)
            output_path = os.path.join(output_dir, f"{export_id}_servicenow.csv")
            output_data = res.encode('utf-8')
            with open(output_path, "wb") as f:
                f.write(output_data)

        elif export_format == ExportFormat.DEFECTDOJO_JSON:
            res = self._build_defectdojo_json(findings, assets, engagement_meta)
            output_path = os.path.join(output_dir, f"{export_id}_defectdojo.json")
            output_data = json.dumps(res, indent=2).encode('utf-8')
            with open(output_path, "wb") as f:
                f.write(output_data)

        elif export_format == ExportFormat.SARIF:
            res = self._build_sarif(findings, engagement_meta)
            output_path = os.path.join(output_dir, f"{export_id}_sarif.json")
            output_data = json.dumps(res, indent=2).encode('utf-8')
            with open(output_path, "wb") as f:
                f.write(output_data)

        elif export_format == ExportFormat.GENERIC_JSON:
            res = self._build_generic_json(findings, assets, services, scan_timeline, engagement_meta)
            output_path = os.path.join(output_dir, f"{export_id}_generic.json")
            output_data = json.dumps(res, indent=2).encode('utf-8')
            with open(output_path, "wb") as f:
                f.write(output_data)

        elif export_format == ExportFormat.MARKDOWN_ZIP:
            output_path = os.path.join(output_dir, f"{export_id}_markdown.zip")
            mem_zip = io.BytesIO()
            with zipfile.ZipFile(mem_zip, "w") as zf:
                md_content = self._build_markdown_report(findings, assets, engagement_meta)
                zf.writestr("report.md", md_content)
                
                csv_content = PLAINTEXT_WARNING_HEADER + "\ntitle,severity,description\n"
                for f in findings:
                    csv_content += f"{f.get('title')},{f.get('severity')},{f.get('description')}\n"
                zf.writestr("findings.csv", csv_content)
                
                json_assets = json.dumps({"warning": PLAINTEXT_WARNING_HEADER.strip(), "assets": assets}, indent=2)
                zf.writestr("assets.json", json_assets)
                zf.writestr("PLAINTEXT_WARNING.txt", PLAINTEXT_WARNING_HEADER)
                
            output_data = mem_zip.getvalue()
            with open(output_path, "wb") as f:
                f.write(output_data)

        sha256_hash = self._compute_sha256(output_data)
        
        record = ExportAuditRecord(
            export_id=export_id,
            timestamp=datetime.datetime.utcnow().isoformat(),
            operator=operator,
            engagement_id=engagement_id,
            export_format=export_format.name,
            output_path=output_path,
            sha256_hash=sha256_hash,
            gate_confirmed_at=gate_confirmed_at or datetime.datetime.utcnow().isoformat()
        )
        self._write_audit_record(record)

        return {
            "success": True,
            "output_path": output_path,
            "sha256": sha256_hash,
            "export_id": export_id,
            "record_count": len(findings)
        }

if __name__ == "__main__":
    exporter = DataExporter()
    try:
        res = exporter.export(
            engagement_id="ENG-001",
            export_format=ExportFormat.MARKDOWN_ZIP,
            output_dir="./exports",
            operator="admin",
            gate_confirmed=True
        )
        print("Export successful:", res)
    except Exception as e:
        print("Export failed:", e)
