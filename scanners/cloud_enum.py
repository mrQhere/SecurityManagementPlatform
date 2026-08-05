from scanners.core.registry import register_scanner
"""
Cloud Enum — Cloud Asset Enumeration
======================================
cloud_enum enumerates public cloud assets (AWS S3, Azure Blob, GCP Storage,
Azure Websites, etc.) associated with a target keyword. Discovers exposed
cloud storage, functions, and services that may be publicly accessible.

Install: pip install cloud-enum
"""
import subprocess
import re
import logging
from urllib.parse import urlparse
from tools.config_manager import load_settings
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

CLOUDENUM_TIMEOUT = 240


@register_scanner(name="Cloud Enum", step_name="Running Cloud Enum", depends_on=['ParamSpider'], binary_name="cloud_enum", needs_binary=True, confidence=85)
def run_cloud_enum_scan(url):
    """
    Runs cloud_enum to discover public cloud assets for the target domain/keyword.

    Returns list of finding dicts, [] if none found, None if binary missing.
    """
    settings = load_settings()
    bin_path = settings.get("cloud_enum_path", "cloud_enum")

    import shutil
    if not shutil.which(bin_path):
        logger.warning(f"Cloud Enum not found at '{bin_path}'. Skipping.")
        add_log_entry("WARNING", f"Cloud Enum not installed ('{bin_path}' not found). Skipping.")
        return None

    parsed = urlparse(url)
    domain = parsed.hostname or url.replace("https://", "").replace("http://", "").split("/")[0]

    # ── V7.0.3 — Custom Keyword List ──────────────────────────────────────────
    # Derive base keyword from domain (e.g. company name from sub.company.com → company)
    parts = domain.split(".")
    base_keyword = parts[-2] if len(parts) >= 2 else parts[0]
    
    # Check if custom keywords are defined in settings
    custom_keywords_str = settings.get("cloud_enum_keywords", "")
    keywords = [k.strip() for k in custom_keywords_str.split(",") if k.strip()]
    if not keywords:
        keywords = [base_keyword]

    logger.info(f"Cloud Enum Started: Cloud asset discovery for keywords {keywords}")
    add_log_entry("INFO", f"Cloud Enum Started: Enumerating cloud assets for {domain} (keywords: {keywords})")

    cmd = [
        bin_path,
        "--quickscan",
        "-t", "10",    # 10 threads
        "--disable-azure",  # comment out if Azure coverage is needed
    ]
    
    for kw in keywords:
        cmd.extend(["-k", kw])

    findings = []
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        try:
            stdout, stderr = process.communicate(timeout=CLOUDENUM_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            logger.warning(f"Cloud Enum timed out after {CLOUDENUM_TIMEOUT}s for {keywords}")
            add_log_entry("WARNING", f"Cloud Enum timed out for {keywords}")
            return []

        combined = stdout + "\n" + stderr

        # Parse results — cloud_enum outputs one URL/resource per line
        s3_buckets = re.findall(r"(https?://[a-z0-9\-\.]+\.s3[a-z\-]*\.amazonaws\.com[^\s]*)", combined, re.IGNORECASE)
        gcs_buckets = re.findall(r"(https?://storage\.googleapis\.com/[^\s]+)", combined, re.IGNORECASE)
        azure_blobs = re.findall(r"(https?://[a-z0-9\-]+\.blob\.core\.windows\.net[^\s]*)", combined, re.IGNORECASE)
        azure_sites = re.findall(r"(https?://[a-z0-9\-]+\.azurewebsites\.net[^\s]*)", combined, re.IGNORECASE)

        # Check for public/open indicators in output
        open_pattern = re.compile(r"(OPEN|PUBLIC|Accessible|200|ListBucketResult)", re.IGNORECASE)

        for bucket_url in s3_buckets:
            is_open = bool(open_pattern.search(combined[combined.find(bucket_url):combined.find(bucket_url)+200]))
            severity = "Critical" if is_open else "Medium"
            findings.append({
                "severity": severity,
                "title": f"{'Public' if is_open else 'Exposed'} AWS S3 Bucket: {bucket_url.split('amazonaws.com')[0].split('//')[1]}",
                "description": (
                    f"Domain: {domain}\n"
                    f"S3 Bucket URL: {bucket_url}\n"
                    f"Status: {'PUBLICLY ACCESSIBLE — DATA EXPOSED' if is_open else 'Accessible URL found'}\n\n"
                    f"Cloud storage exposed to the internet may contain sensitive data, backups, or source code.\n\n"
                    f"Remediation: Enforce private bucket ACLs and enable S3 Block Public Access."
                ),
                "template_id": "CLOUDENUM-S3-BUCKET",
            })

        for bucket_url in gcs_buckets:
            findings.append({
                "severity": "High",
                "title": f"GCP Storage Bucket Discovered: {bucket_url[:80]}",
                "description": (
                    f"Domain: {domain}\n"
                    f"GCS URL: {bucket_url}\n\n"
                    f"A Google Cloud Storage bucket associated with this organisation was discovered.\n"
                    f"Verify bucket permissions and ensure it is not publicly readable or writable."
                ),
                "template_id": "CLOUDENUM-GCS-BUCKET",
            })

        for blob_url in azure_blobs:
            findings.append({
                "severity": "High",
                "title": f"Azure Blob Storage Discovered: {blob_url[:80]}",
                "description": (
                    f"Domain: {domain}\n"
                    f"Azure Blob URL: {blob_url}\n\n"
                    f"An Azure Blob Storage container associated with this organisation was discovered.\n"
                    f"Ensure containers are not set to 'Blob' or 'Container' public access level."
                ),
                "template_id": "CLOUDENUM-AZURE-BLOB",
            })

        for site_url in azure_sites:
            findings.append({
                "severity": "Info",
                "title": f"Azure Web App Discovered: {site_url[:80]}",
                "description": (
                    f"Domain: {domain}\n"
                    f"Azure Web App: {site_url}\n\n"
                    f"An Azure Web App associated with this organisation was discovered. "
                    f"Verify it is not a staging or test environment with sensitive data."
                ),
                "template_id": "CLOUDENUM-AZURE-WEBAPP",
            })

        if not findings and not (s3_buckets or gcs_buckets or azure_blobs or azure_sites):
            logger.info(f"Cloud Enum Completed: No cloud assets found for '{keywords}'.")
            add_log_entry("INFO", f"Cloud Enum Completed: No cloud assets found.")
            return []

        logger.info(f"Cloud Enum Completed: {len(findings)} cloud asset findings.")
        add_log_entry("INFO", f"Cloud Enum Completed: {len(findings)} cloud assets found.")
        return findings

    except FileNotFoundError:
        logger.warning(f"cloud_enum not found at '{bin_path}'. Skipping.")
        add_log_entry("WARNING", f"cloud_enum not installed ('{bin_path}' not found). Skipping.")
        return None
    except Exception as e:
        logger.error(f"Cloud Enum Failed: {e}")
        add_log_entry("ERROR", f"Cloud Enum Failed: {e}")
        return None
