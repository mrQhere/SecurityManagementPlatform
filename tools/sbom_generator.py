"""
SBOM Generator V7.0.1
====================
Generates a CycloneDX JSON Software Bill of Materials from technology
fingerprinting data collected during a scan.

Fallback chain:
  1. CycloneDX JSON (preferred — industry standard)
  2. SPDX tag-value format (if cyclonedx-python-lib not installed)
  3. Simple CSV (last resort — always works)

Usage:
    from tools.sbom_generator import generate_sbom_for_scan
    sbom_path = generate_sbom_for_scan(scan_id, target_url)
"""
import os
import json
import logging
from datetime import datetime

logger = logging.getLogger("smp")


def _generate_cyclonedx(scan_id: int, target_url: str, technologies: list, output_path: str) -> bool:
    """Generate CycloneDX JSON SBOM."""
    try:
        components = []
        for tech in technologies:
            name    = tech.get("tech_name", "unknown")
            version = tech.get("version", "")
            comp = {
                "type": "library",
                "name": name,
                "version": version if version else "unknown",
                "description": f"Detected on {target_url} during security scan",
                "properties": [
                    {"name": "smp:scan_id", "value": str(scan_id)},
                    {"name": "smp:confidence", "value": str(tech.get("confidence", 50))},
                    {"name": "smp:detected_by", "value": tech.get("source", "SMP")},
                ]
            }
            # Add CPE if available
            if tech.get("cpe"):
                comp["cpe"] = tech["cpe"]
            components.append(comp)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:smp-{scan_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [{
                    "vendor": "mrQhere",
                    "name": "Security Management Platform",
                    "version": "V7.0.1"
                }],
                "component": {
                    "type": "application",
                    "name": target_url,
                    "description": f"Target scanned by SMP V7.0.1 on {datetime.now().strftime('%Y-%m-%d')}"
                }
            },
            "components": components
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2)
        logger.info(f"[SBOM] CycloneDX SBOM written: {output_path} ({len(components)} components)")
        return True
    except Exception as e:
        logger.warning(f"[SBOM] CycloneDX generation failed: {e}")
        return False


def _generate_spdx(scan_id: int, target_url: str, technologies: list, output_path: str) -> bool:
    """Fallback: generate SPDX tag-value SBOM."""
    try:
        lines = [
            "SPDXVersion: SPDX-2.3",
            "DataLicense: CC0-1.0",
            f"SPDXID: SPDXRef-DOCUMENT",
            f"DocumentName: SMP-Scan-{scan_id}",
            f"DocumentNamespace: https://smp/sbom/{scan_id}",
            "",
            f"## Detected components on {target_url}",
            "",
        ]
        for i, tech in enumerate(technologies):
            name    = tech.get("tech_name", "unknown")
            version = tech.get("version", "NOASSERTION")
            lines += [
                f"PackageName: {name}",
                f"SPDXID: SPDXRef-Package-{i}",
                f"PackageVersion: {version}",
                f"PackageDownloadLocation: NOASSERTION",
                f"FilesAnalyzed: false",
                "",
            ]

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        logger.info(f"[SBOM] SPDX SBOM written: {output_path}")
        return True
    except Exception as e:
        logger.warning(f"[SBOM] SPDX generation failed: {e}")
        return False


def _generate_csv(technologies: list, output_path: str) -> bool:
    """Last resort: CSV output."""
    try:
        import csv
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["tech_name", "version", "confidence", "source"])
            writer.writeheader()
            for tech in technologies:
                writer.writerow({
                    "tech_name": tech.get("tech_name", ""),
                    "version": tech.get("version", ""),
                    "confidence": tech.get("confidence", ""),
                    "source": tech.get("source", ""),
                })
        logger.info(f"[SBOM] CSV SBOM written: {output_path}")
        return True
    except Exception as e:
        logger.error(f"[SBOM] CSV generation also failed: {e}")
        return False


def generate_sbom_for_scan(scan_id: int, target_url: str, output_dir: str = None) -> str:
    """
    Generate SBOM for a completed scan.
    
    Returns path to generated SBOM file, or empty string on failure.
    """
    if not output_dir:
        from tools.config_manager import BASE_DIR
        output_dir = os.path.join(BASE_DIR, "reports", "sbom")
    os.makedirs(output_dir, exist_ok=True)

    # Get technologies from DB
    technologies = []
    try:
        from tools.db_manager import get_technologies_for_scan
        technologies = list(get_technologies_for_scan(scan_id))
    except Exception as e:
        logger.warning(f"[SBOM] Could not load technologies from DB: {e}")

    if not technologies:
        logger.info(f"[SBOM] No technologies found for scan {scan_id} — skipping SBOM generation.")
        return ""

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url  = target_url.replace("://", "_").replace("/", "_").replace(":", "_")[:40]

    # Try CycloneDX (JSON) first
    cdx_path = os.path.join(output_dir, f"sbom_{safe_url}_{timestamp}.cdx.json")
    if _generate_cyclonedx(scan_id, target_url, technologies, cdx_path):
        return cdx_path

    # Fallback: SPDX
    spdx_path = os.path.join(output_dir, f"sbom_{safe_url}_{timestamp}.spdx")
    if _generate_spdx(scan_id, target_url, technologies, spdx_path):
        return spdx_path

    # Last resort: CSV
    csv_path = os.path.join(output_dir, f"sbom_{safe_url}_{timestamp}.csv")
    _generate_csv(technologies, csv_path)
    return csv_path
