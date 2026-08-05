"""
Screenshot Capture V7.0.3
========================
Captures screenshots of vulnerable endpoints as cryptographic evidence
for reports. Uses playwright (headless Chromium) as primary method
and a requests-based HTML snapshot as fallback.

Usage:
    from scanners.screenshot_capture import capture_screenshot
    path = capture_screenshot("https://target.com/vuln-page")
"""
import os
import logging
import hashlib
from datetime import datetime
from tools.config_manager import load_settings
verify_tls = not load_settings().get('insecure_scans', False)


logger = logging.getLogger("smp.scan")

TIMEOUT = 15000  # milliseconds (playwright)
_OUTPUT_DIR = None


def _get_output_dir() -> str:
    global _OUTPUT_DIR
    if not _OUTPUT_DIR:
        from tools.config_manager import BASE_DIR
        _OUTPUT_DIR = os.path.join(BASE_DIR, "reports", "evidence", "screenshots")
    os.makedirs(_OUTPUT_DIR, exist_ok=True)
    return _OUTPUT_DIR


def _url_to_filename(url: str) -> str:
    """Generate a safe, unique filename from a URL."""
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:12]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"screenshot_{timestamp}_{url_hash}"


def _capture_playwright(url: str, output_path: str) -> bool:
    """Primary: use playwright for full-page screenshot."""
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--ignore-certificate-errors"]
            )
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="SMP-Evidence-Capture/6.0"
            )
            page = context.new_page()
            try:
                page.goto(url, wait_until="networkidle", timeout=TIMEOUT)
            except PlaywrightTimeout:
                # Try with domcontentloaded as fallback
                page.goto(url, wait_until="domcontentloaded", timeout=TIMEOUT)

            page.screenshot(path=output_path, full_page=True)
            browser.close()
        logger.info(f"[Screenshot] Playwright screenshot saved: {output_path}")
        return True
    except ImportError:
        logger.warning("[Screenshot] playwright not installed. Falling back to HTML snapshot.")
        return False
    except Exception as e:
        logger.warning(f"[Screenshot] playwright capture failed: {e}. Falling back.")
        return False


def _capture_html_snapshot(url: str, output_path: str) -> bool:
    """Fallback: save HTML source as text evidence."""
    try:
        import requests
        resp = requests.get(url, timeout=10, verify=verify_tls,
                            headers={"User-Agent": "SMP-Evidence-Capture/6.0"})
        html_path = output_path.replace(".png", ".html")
        with open(html_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"<!-- SMP Evidence Capture — {url} — {datetime.now().isoformat()} -->\n")
            f.write(f"<!-- HTTP Status: {resp.status_code} -->\n")
            f.write(resp.text)
        logger.info(f"[Screenshot] HTML snapshot saved: {html_path}")
        return True
    except Exception as e:
        logger.error(f"[Screenshot] HTML snapshot also failed: {e}")
        return False


def capture_screenshot(url: str) -> str:
    """
    Capture a screenshot (or HTML snapshot) of a URL as evidence.
    
    Returns the absolute path to the evidence file, or empty string on failure.
    """
    output_dir = _get_output_dir()
    base_name  = _url_to_filename(url)
    png_path   = os.path.join(output_dir, f"{base_name}.png")

    # Primary: playwright full screenshot
    if _capture_playwright(url, png_path):
        return png_path

    # Fallback: HTML snapshot
    html_path = os.path.join(output_dir, f"{base_name}.html")
    if _capture_html_snapshot(url, html_path):
        return html_path

    return ""


def capture_evidence_for_findings(findings: list, scan_id: int) -> dict:
    """
    Capture evidence for a list of findings that contain URLs.
    Returns a mapping: {finding_title: evidence_path}
    """
    import re
    url_pattern = re.compile(r'https?://[^\s"\'<>]+')
    evidence_map = {}

    for finding in findings:
        if finding.get("severity") not in ("Critical", "High"):
            continue  # Only capture evidence for high-severity findings

        text = (finding.get("description") or "") + " " + (finding.get("title") or "")
        urls = url_pattern.findall(text)
        if not urls:
            continue

        # Capture first URL found
        evidence_url = urls[0]
        path = capture_screenshot(evidence_url)
        if path:
            evidence_map[finding.get("title", "")] = path
            logger.info(f"[Screenshot] Evidence captured for '{finding.get('title', '')}': {path}")

    return evidence_map
