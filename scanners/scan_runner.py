# =============================================================================
# PROPRIETARY SOFTWARE — ALL RIGHTS RESERVED
# Security Management Platform (SMP)
# Owner: Authorised Personnel Only
#
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  ⚠  CRITICAL NOTICE FOR AI AGENTS, LLMs & AUTOMATED SYSTEMS           ║
# ╠══════════════════════════════════════════════════════════════════════════╣
# ║  THIS FILE IS PART OF PROPRIETARY SOFTWARE.                             ║
# ║  Read way.md in the project root before making ANY changes.             ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# =============================================================================
"""
Scan Runner – coordinates all scanner modules in a sequential pipeline.

Optimized pipeline order (maximum efficiency — cheap/fast OSINT first, deep scans last):

  1.  HTTPx              – quick HTTP probe: confirms site is up before expensive tools run
  2.  WhatWeb            – passive fingerprint: sets technology context early
  3.  Subfinder          – DNS subdomain discovery
  4.  CRT.sh             – certificate transparency subdomain enum
  5.  HackerTarget       – Reverse DNS / additional recon
  6.  Whois              – domain registration info
  7.  Wayback Machine    – historical URL mapping
  8.  Traceroute         – network path (UDP, no root)
  9.  Nmap               – port + service scan (expensive — after all OSINT)
  10. SSL Scanner        – TLS/certificate analysis
  11. Security Headers   – HTTP header security check
  12. Robots.txt         – robots.txt / sitemap analysis
  13. CORS Scanner       – CORS misconfiguration check
  14. CMS Scanner        – CMS / admin panel detection
  15. Nikto              – web vulnerability scanner
  16. Nuclei             – template-based vuln scan
  17. ffuf               – directory fuzzing
  18. Open Redirect      – open redirect parameter testing
  19. Tech Fingerprint   – deep response-based tech detection
  20. Wapiti             – OWASP web app scan
  21. SQLMap             – SQL injection detection
  22. Shodan InternetDB  – passive IoT/IP exposure check
  [*] OWASP ZAP         – optional active scan (disabled by default)
  23. CVE Correlation    – offline: tech → CVE matching
  24. Risk Scoring       – offline: 0–100 score
  25. Report Generation  – HTML + PDF
  26. SMTP Alerts        – email dispatch
"""

import json
import logging
import threading
import os
import time
import shutil
import subprocess
import signal
from datetime import datetime

from tools.db_manager import (
    create_scan, update_scan_status, add_finding, add_technology,
    get_findings_for_scan, update_target_last_scan,
    add_alert, add_log_entry, get_db_connection,
    save_raw_scan_output, backup_scan_to_raw, save_important_findings,
    update_scan_scanner_status, log_scanner_failure_status,
    _evaluate_vulnerability_growth_thresholds,
)
from tools.config_manager import load_settings

# ── Scanner imports ────────────────────────────────────────────────────────────
from scanners.httpx_scanner import run_httpx_scan
from scanners.whatweb import run_whatweb_scan
from scanners.subfinder import run_subfinder_scan
from scanners.crtsh import run_crtsh_scan
from scanners.hackertarget import run_hackertarget_scan
from scanners.whois_scanner import run_whois_scan
from scanners.wayback import run_wayback_scan
from scanners.traceroute import run_traceroute
from scanners.nmap import run_nmap_scan
from scanners.ssl_scanner import run_ssl_scan
from scanners.headers_scanner import run_headers_scan
from scanners.robots_scanner import run_robots_scan
from scanners.cors_scanner import run_cors_scan
from scanners.cms_scanner import run_cms_scan
from scanners.nikto import run_nikto_scan
from scanners.nuclei import run_nuclei_scan
from scanners.ffuf import run_ffuf_scan
from scanners.open_redirect import run_open_redirect_scan
from scanners.tech_fingerprint import run_tech_fingerprint
from scanners.wapiti import run_wapiti_scan
from scanners.sqlmap import run_sqlmap_scan
from scanners.shodan_idb import run_shodan_idb_scan
from scanners.zap import run_zap_scan
from tools.report_generator import generate_scan_reports

logger = logging.getLogger("smp.scan")


def get_cooling_delay():
    """Improvement 6: Shifts worker thread cooling delays based on system resource metrics to prevent overheating."""
    try:
        # Load average over last 1 minute
        load1, _, _ = os.getloadavg()
        num_cpus = os.cpu_count() or 1
        load_ratio = load1 / num_cpus
        if load_ratio > 1.0:
            return 5.0  # High load, cool down more
        elif load_ratio > 0.5:
            return 3.0  # Moderate load
        else:
            return 1.5  # Low load, fast cooling
    except Exception:
        return 2.5      # Fallback default


def run_with_resilience(scan_id, step_name, scan_func, url, binary_name, needs_binary=True, attempt=1):
    """
    Executes a scan function with execution guards, process group tracking,
    adaptive timeouts, and failure tracking.
    """
    settings = load_settings()
    
    # 1. Binary availability guard
    if needs_binary:
        bin_path = settings.get(f"{binary_name}_path", binary_name)
        if not shutil.which(bin_path):
            logger.warning(f"[{step_name}] Tool binary '{bin_path}' missing from system PATH. Recording failure.")
            log_scanner_failure_status(scan_id, step_name, "Missing Binary Dependency")
            return None, False  # (result, success)
            
    # 2. Dynamic Adaptive Timeout Scaling
    # Scale timeout constant of the target module if on retry attempt
    module_name = scan_func.__module__
    import sys
    module = sys.modules.get(module_name)
    orig_timeout = None
    timeout_var_name = None
    if module:
        for attr in dir(module):
            if attr.endswith("_TIMEOUT") or attr == "TIMEOUT":
                orig_timeout = getattr(module, attr)
                timeout_var_name = attr
                break
        if timeout_var_name and orig_timeout:
            if attempt == 1:
                max_initial = settings.get("scanner_timeout_seconds", 180)
                if orig_timeout > max_initial:
                    setattr(module, timeout_var_name, max_initial)
                    logger.info(f"[{step_name}] Capped timeout {timeout_var_name} to {max_initial}s for initial run.")
                else:
                    setattr(module, timeout_var_name, orig_timeout)
            else:
                scale = 1.5
                setattr(module, timeout_var_name, orig_timeout * scale)
                logger.info(f"[{step_name}] Restored timeout {timeout_var_name} to {orig_timeout * scale}s (attempt {attempt})")

    # 3. Subprocess monkeypatching for process group isolation and termination (Improvement 7)
    original_popen = subprocess.Popen
    
    class ResilientPopen(original_popen):
        def __init__(self, args, *kargs, **kwargs):
            if os.name != 'nt' and 'preexec_fn' not in kwargs:
                kwargs['preexec_fn'] = os.setsid
            super().__init__(args, *kargs, **kwargs)

        def kill(self):
            if os.name != 'nt':
                try:
                    os.killpg(os.getpgid(self.pid), signal.SIGKILL)
                except Exception:
                    super().kill()
            else:
                super().kill()

        def terminate(self):
            if os.name != 'nt':
                try:
                    os.killpg(os.getpgid(self.pid), signal.SIGTERM)
                except Exception:
                    super().terminate()
            else:
                super().terminate()

    subprocess.Popen = ResilientPopen
    
    result = None
    success = False
    try:
        result = scan_func(url)
        if result is not None:
            success = True
            log_scanner_failure_status(scan_id, step_name, "Success")
        else:
            log_scanner_failure_status(scan_id, step_name, "Soft Crash")
    except Exception as e:
        logger.error(f"[{step_name}] Execution exception: {e}")
        log_scanner_failure_status(scan_id, step_name, f"Exception: {str(e)}")
    finally:
        # Restore original popen
        subprocess.Popen = original_popen
        # Restore original timeout
        if module and timeout_var_name and orig_timeout:
            setattr(module, timeout_var_name, orig_timeout)

    # 4. Tailored cooling delay
    cooling_sleep = get_cooling_delay()
    logger.info(f"[{step_name}] Cooling down for {cooling_sleep:.1f}s...")
    time.sleep(cooling_sleep)

    return result, success

# Active scan tracking – prevents duplicate concurrent scans on the same target
_active_scans = {}       # target_id → thread
_active_urls = set()     # URL set for URL-level dedup
_lock = threading.Lock()

# Thread-local storage to pass sudo password securely
thread_local = threading.local()

def get_sudo_password():
    """Retrieve the sudo password configured for the current scan thread."""
    return getattr(thread_local, "sudo_password", None)

# Ordered list of all step names (must match db_manager.ALL_ACTIVE_STATUSES)
_PIPELINE_STEPS = [
    "Running HTTPx", "Running WhatWeb", "Running Subfinder", "Running CRT.sh",
    "Running HackerTarget", "Running Whois", "Running Wayback Machine",
    "Running Traceroute", "Running Nmap", "Running SSL Scan",
    "Running Security Headers", "Running Robots.txt", "Running CORS",
    "Running CMS Scanner", "Running Nikto", "Running Nuclei", "Running ffuf",
    "Running Open Redirect", "Running Tech Fingerprint",
    "Running Wapiti", "Running SQLMap", "Running Shodan",
    "Running ZAP",
    "Correlating CVEs", "Report Pending",
]


# ── Public API ─────────────────────────────────────────────────────────────────

def start_scan_for_target(target, sudo_password=None):
    """Start a background scan for *target* if one isn't already running."""
    target_id = target["id"]
    url = target["url"]

    with _lock:
        if target_id in _active_scans:
            logger.warning(f"Scan already running for target ID {target_id}: {url}")
            return False

        if url in _active_urls:
            logger.warning(f"Scan already running for URL: {url}")
            return False

        if len(_active_scans) >= 3:
            logger.warning(f"Global active scan limit (3) reached. Cannot start scan for: {url}")
            return False

        thread = threading.Thread(
            target=_run_scan_sequence,
            args=(target, None, None, sudo_password),
            daemon=True,
            name=f"ScanThread_{target_id}",
        )
        _active_scans[target_id] = thread
        _active_urls.add(url)
        thread.start()
        return True


def is_target_scanning(target_id):
    with _lock:
        return target_id in _active_scans


# ── Internal helpers ───────────────────────────────────────────────────────────

def _should_run_step(step_name, resume_status):
    """Returns True if this step should execute (not yet completed before interruption)."""
    if not resume_status:
        return True
    if step_name not in _PIPELINE_STEPS:
        return True
    if resume_status not in _PIPELINE_STEPS:
        return True
    return _PIPELINE_STEPS.index(step_name) >= _PIPELINE_STEPS.index(resume_status)


def _save_findings(scan_id, results, source_tool, severity_override=None, confidence=50):
    """Bulk-save a list of finding dicts to the DB."""
    if not results:
        return
    for item in results:
        sev = severity_override or item.get("severity", "Info")
        desc = item.get("description", "")
        template = item.get("template_id", "")
        if template:
            desc = f"Reference: {template}\n\n{desc}"
        item_conf = item.get("confidence", confidence)
        add_finding(
            scan_id=scan_id,
            severity=sev,
            title=item.get("title", "Unknown Finding"),
            description=desc,
            source_tool=source_tool,
            confidence=item_conf,
        )


def _save_nmap_findings(scan_id, nmap_results):
    if not nmap_results:
        return
    for port in nmap_results:
        port_num = port.get('port', 'N/A')
        proto = port.get('protocol', 'tcp')
        service = port.get('service', 'unknown')
        version = port.get('version', '')
        state = port.get('state', 'open')
        
        title = f"Open Port {port_num}/{proto} ({service})"
        desc = (
            f"Service: {service}\n"
            f"Version: {version}\n"
            f"State:   {state}"
        )
        add_finding(scan_id=scan_id, severity="Info", title=title,
                    description=desc, source_tool="Nmap", confidence=95)


def _save_technologies(scan_id, tech_list, source_tool):
    """Persist detected technologies."""
    if not tech_list:
        return
    for t in tech_list:
        add_technology(
            scan_id=scan_id,
            name=t.get("name", ""),
            version=t.get("version", ""),
            category=t.get("category", ""),
            confidence=t.get("confidence", 0),
            source_tool=source_tool,
        )


def _determine_site_up(*scanner_results):
    """Returns True if at least one scanner returned a non-None result."""
    return any(r is not None for r in scanner_results)


def _get_previous_completed_scan(target_id, current_scan_id):
    """Return the most recent completed scan for a target before the current one."""
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE target_id = ? AND status = 'Completed' AND id < ? "
            "ORDER BY id DESC LIMIT 1",
            (target_id, current_scan_id),
        ).fetchone()
        return dict(row) if row else None
    except Exception:
        return None
    finally:
        conn.close()


def _diff_findings(current_findings, previous_scan):
    """Compare current findings with previous scan."""
    new_findings_detected = False
    severity_escalated = False
    escalated_details = []

    severity_rank = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    if previous_scan:
        prev_findings = get_findings_for_scan(previous_scan["id"])
        prev_map = {f["title"]: f["severity"] for f in prev_findings}

        for cur in current_findings:
            title = cur["title"]
            cur_sev = cur["severity"]
            if title not in prev_map:
                if cur_sev in ("Low", "Medium", "High", "Critical"):
                    new_findings_detected = True
            else:
                prev_sev = prev_map[title]
                if severity_rank.get(cur_sev, 0) > severity_rank.get(prev_sev, 0):
                    severity_escalated = True
                    escalated_details.append(f"'{title}' escalated {prev_sev} → {cur_sev}")
    else:
        if any(f["severity"] in ("Low", "Medium", "High", "Critical") for f in current_findings):
            new_findings_detected = True

    return new_findings_detected, severity_escalated, escalated_details


def _max_severity(findings):
    sevs = {f["severity"] for f in findings}
    for s in ("Critical", "High", "Medium", "Low", "Info"):
        if s in sevs:
            return s
    return "Info"


def _log_raw(scan_id, tool_name, result_list):
    """Save stringified result to raw output DB."""
    try:
        raw_str = json.dumps(result_list, default=str) if result_list is not None else "null"
        save_raw_scan_output(scan_id, tool_name, raw_str, "")
    except Exception:
        pass


# ── Main scan pipeline ─────────────────────────────────────────────────────────

def _run_scan_sequence(target, resume_scan_id=None, resume_status=None, sudo_password=None):
    # Store sudo password in thread-local storage for this execution thread
    thread_local.sudo_password = sudo_password
    
    target_id = target["id"]
    url = target["url"]
    settings = load_settings()

    logger.info(f"Scan Started: {url}")
    add_log_entry("INFO", f"Scan Started: {url}")

    # Initialize result holders
    httpx_result = whatweb_results = subfinder_results = crtsh_results = None
    ht_results = whois_results = wayback_results = trace_result = None
    nmap_results = ssl_results = headers_results = robots_results = None
    cors_results = cms_results = nikto_results = nuclei_results = None
    ffuf_results = redirect_results = tech_results = None
    wapiti_results = sqlmap_results = shodan_results = zap_results = None
    current_findings = []

    if resume_scan_id:
        from tools.db_manager import get_scan
        if get_scan(resume_scan_id):
            scan_id = resume_scan_id
            logger.info(f"Resuming Scan for: {url} from step: {resume_status}")
            add_log_entry("INFO", f"Resuming Scan for: {url} from step: {resume_status}")
        else:
            logger.warning(f"Scan ID {resume_scan_id} not found in DB. Creating new scan.")
            scan_id = create_scan(target_id)
            resume_status = None
    else:
        scan_id = create_scan(target_id)

    deferred_retry_queue = []

    # ── Result processing local nested helpers ──────────────────────────
    def _process_httpx_results(res):
        nonlocal httpx_result
        httpx_result = res
        if isinstance(res, dict) and res:
            for f in res.get("findings", []):
                add_finding(scan_id=scan_id, severity=f["severity"],
                            title=f["title"], description=f["description"],
                            source_tool="HTTPx", confidence=80)
            tech_list = [
                {"name": t, "version": "", "category": "Web Technology", "confidence": 75}
                for t in res.get("tech", [])
            ]
            _save_technologies(scan_id, tech_list, "HTTPx")

    def _process_whatweb_results(res):
        nonlocal whatweb_results
        whatweb_results = res
        if res:
            _save_technologies(scan_id, res, "WhatWeb")
        if res is None:
            add_log_entry("WARNING", f"WhatWeb failed or not installed for {url}")

    def _process_subfinder_results(res):
        nonlocal subfinder_results
        subfinder_results = res
        if res:
            for sub in res:
                if sub.get("host"):
                    add_finding(
                        scan_id=scan_id, severity="Info",
                        title=f"Subdomain Discovered: {sub['host']}",
                        description=(
                            f"Subdomain: {sub['host']}\n"
                            f"IP: {sub.get('ip', 'N/A')}\n"
                            f"Source: {sub.get('source', 'subfinder')}"
                        ),
                        source_tool="Subfinder", confidence=90,
                    )

    def _process_crtsh_results(res):
        nonlocal crtsh_results
        crtsh_results = res
        _save_findings(scan_id, res or [], "CRT.sh", confidence=85)

    def _process_ht_results(res):
        nonlocal ht_results
        ht_results = res
        _save_findings(scan_id, res or [], "HackerTarget", confidence=80)

    def _process_whois_results(res):
        nonlocal whois_results
        whois_results = res
        _save_findings(scan_id, res or [], "Whois", confidence=95)

    def _process_wayback_results(res):
        nonlocal wayback_results
        wayback_results = res
        _save_findings(scan_id, res or [], "Wayback Machine", confidence=80)

    def _process_trace_results(res):
        nonlocal trace_result
        trace_result = res
        _save_findings(scan_id, res or [], "Traceroute", confidence=85)
        if res is None:
            add_log_entry("WARNING", f"Traceroute failed or not installed for {url}")

    def _process_nmap_results(res):
        nonlocal nmap_results
        nmap_results = res
        _save_nmap_findings(scan_id, res or [])
        if res is None:
            add_log_entry("WARNING", f"Nmap failed or not installed for {url}")

    def _process_ssl_results(res):
        nonlocal ssl_results
        ssl_results = res
        _save_findings(scan_id, res or [], "SSL", confidence=90)
        if res is None:
            add_log_entry("WARNING", f"SSL scan failed for {url}")

    def _process_headers_results(res):
        nonlocal headers_results
        headers_results = res
        _save_findings(scan_id, res or [], "Security Headers")

    def _process_robots_results(res):
        nonlocal robots_results
        robots_results = res
        _save_findings(scan_id, res or [], "Robots.txt")

    def _process_cors_results(res):
        nonlocal cors_results
        cors_results = res
        _save_findings(scan_id, res or [], "CORS")

    def _process_cms_results(res):
        nonlocal cms_results
        cms_results = res
        _save_findings(scan_id, res or [], "CMS Scanner")

    def _process_nikto_results(res):
        nonlocal nikto_results
        nikto_results = res
        _save_findings(scan_id, res or [], "Nikto")
        if res is None:
            add_log_entry("WARNING", f"Nikto failed or not installed for {url}")

    def _process_nuclei_results(res):
        nonlocal nuclei_results
        nuclei_results = res
        _save_findings(scan_id, res or [], "Nuclei")
        if res is None:
            add_log_entry("WARNING", f"Nuclei failed or not installed for {url}")

    def _process_ffuf_results(res):
        nonlocal ffuf_results
        ffuf_results = res
        _save_findings(scan_id, res or [], "ffuf", confidence=75)
        if res is None:
            add_log_entry("WARNING", f"ffuf failed or not installed for {url}")

    def _process_redirect_results(res):
        nonlocal redirect_results
        redirect_results = res
        _save_findings(scan_id, res or [], "Open Redirect")

    def _process_tech_results(res):
        nonlocal tech_results
        tech_results = res
        if res:
            for f in res:
                add_technology(
                    scan_id=scan_id,
                    name=f.get("title", "").replace("Technology Detected: ", "").split()[0],
                    version=f.get("title", "").split()[-1] if len(f.get("title","").split()) > 2 else "",
                    category="Web Technology",
                    confidence=f.get("confidence", 70),
                    source_tool="Tech Fingerprint",
                )
            _save_findings(scan_id, res, "Tech Fingerprint")

    def _process_wapiti_results(res):
        nonlocal wapiti_results
        wapiti_results = res
        _save_findings(scan_id, res or [], "Wapiti")
        if res is None:
            add_log_entry("WARNING", f"Wapiti failed or not installed for {url}")

    def _process_sqlmap_results(res):
        nonlocal sqlmap_results
        sqlmap_results = res
        _save_findings(scan_id, res or [], "SQLMap")
        if res is None:
            add_log_entry("WARNING", f"SQLMap failed or not installed for {url}")

    def _process_shodan_results(res):
        nonlocal shodan_results
        shodan_results = res
        _save_findings(scan_id, res or [], "Shodan", confidence=80)

    def _process_zap_results(res):
        nonlocal zap_results
        zap_results = res
        _save_findings(scan_id, res or [], "ZAP")

    try:
        # ── Step 1: HTTPx ─────────────────────────────────────────────────
        if _should_run_step("Running HTTPx", resume_status):
            update_scan_status(scan_id, "Running HTTPx")
            logger.info(f"[1/22] HTTPx probe – {url}")
            res, success = run_with_resilience(scan_id, "Running HTTPx", run_httpx_scan, url, "httpx")
            if success:
                _process_httpx_results(res)
            else:
                deferred_retry_queue.append(("Running HTTPx", run_httpx_scan, "httpx", _process_httpx_results))
            _log_raw(scan_id, "HTTPx", res)

        # ── Step 2: WhatWeb ───────────────────────────────────────────────
        if _should_run_step("Running WhatWeb", resume_status):
            update_scan_status(scan_id, "Running WhatWeb")
            logger.info(f"[2/22] WhatWeb fingerprinting – {url}")
            res, success = run_with_resilience(scan_id, "Running WhatWeb", run_whatweb_scan, url, "whatweb")
            if success:
                _process_whatweb_results(res)
            else:
                deferred_retry_queue.append(("Running WhatWeb", run_whatweb_scan, "whatweb", _process_whatweb_results))
            _log_raw(scan_id, "WhatWeb", res)

        # ── Step 3: Subfinder ─────────────────────────────────────────────
        if _should_run_step("Running Subfinder", resume_status):
            update_scan_status(scan_id, "Running Subfinder")
            logger.info(f"[3/22] Subfinder – {url}")
            res, success = run_with_resilience(scan_id, "Running Subfinder", run_subfinder_scan, url, "subfinder")
            if success:
                _process_subfinder_results(res)
            else:
                deferred_retry_queue.append(("Running Subfinder", run_subfinder_scan, "subfinder", _process_subfinder_results))
            _log_raw(scan_id, "Subfinder", res)

        # ── Step 4: CRT.sh ────────────────────────────────────────────────
        if _should_run_step("Running CRT.sh", resume_status):
            update_scan_status(scan_id, "Running CRT.sh")
            logger.info(f"[4/22] CRT.sh subdomain enum – {url}")
            res, success = run_with_resilience(scan_id, "Running CRT.sh", run_crtsh_scan, url, "", needs_binary=False)
            if success:
                _process_crtsh_results(res)
            else:
                deferred_retry_queue.append(("Running CRT.sh", run_crtsh_scan, "", _process_crtsh_results))
            _log_raw(scan_id, "CRT.sh", res)

        # ── Step 5: HackerTarget ──────────────────────────────────────────
        if _should_run_step("Running HackerTarget", resume_status):
            update_scan_status(scan_id, "Running HackerTarget")
            logger.info(f"[5/22] HackerTarget Reverse DNS – {url}")
            res, success = run_with_resilience(scan_id, "Running HackerTarget", run_hackertarget_scan, url, "", needs_binary=False)
            if success:
                _process_ht_results(res)
            else:
                deferred_retry_queue.append(("Running HackerTarget", run_hackertarget_scan, "", _process_ht_results))
            _log_raw(scan_id, "HackerTarget", res)

        # ── Step 6: Whois ─────────────────────────────────────────────────
        if _should_run_step("Running Whois", resume_status):
            update_scan_status(scan_id, "Running Whois")
            logger.info(f"[6/22] Whois Registry Info – {url}")
            res, success = run_with_resilience(scan_id, "Running Whois", run_whois_scan, url, "whois")
            if success:
                _process_whois_results(res)
            else:
                deferred_retry_queue.append(("Running Whois", run_whois_scan, "whois", _process_whois_results))
            _log_raw(scan_id, "Whois", res)

        # ── Step 7: Wayback Machine ───────────────────────────────────────
        if _should_run_step("Running Wayback Machine", resume_status):
            update_scan_status(scan_id, "Running Wayback Machine")
            logger.info(f"[7/22] Wayback Machine mapping – {url}")
            res, success = run_with_resilience(scan_id, "Running Wayback Machine", run_wayback_scan, url, "", needs_binary=False)
            if success:
                _process_wayback_results(res)
            else:
                deferred_retry_queue.append(("Running Wayback Machine", run_wayback_scan, "", _process_wayback_results))
            _log_raw(scan_id, "Wayback Machine", res)

        # ── Step 8: Traceroute ────────────────────────────────────────────
        if _should_run_step("Running Traceroute", resume_status):
            update_scan_status(scan_id, "Running Traceroute")
            logger.info(f"[8/22] Network Traceroute – {url}")
            res, success = run_with_resilience(scan_id, "Running Traceroute", run_traceroute, url, "traceroute")
            if success:
                _process_trace_results(res)
            else:
                deferred_retry_queue.append(("Running Traceroute", run_traceroute, "traceroute", _process_trace_results))
            _log_raw(scan_id, "Traceroute", res)

        # ── Step 9: Nmap ──────────────────────────────────────────────────
        if _should_run_step("Running Nmap", resume_status):
            update_scan_status(scan_id, "Running Nmap")
            logger.info(f"[9/22] Nmap port scan – {url}")
            res, success = run_with_resilience(scan_id, "Running Nmap", run_nmap_scan, url, "nmap")
            if success:
                _process_nmap_results(res)
            else:
                deferred_retry_queue.append(("Running Nmap", run_nmap_scan, "nmap", _process_nmap_results))
            _log_raw(scan_id, "Nmap", res)

        # ── Step 10: SSL Scanner ──────────────────────────────────────────
        if _should_run_step("Running SSL Scan", resume_status):
            update_scan_status(scan_id, "Running SSL Scan")
            logger.info(f"[10/22] SSL/TLS scan – {url}")
            res, success = run_with_resilience(scan_id, "Running SSL Scan", run_ssl_scan, url, "", needs_binary=False)
            if success:
                _process_ssl_results(res)
            else:
                deferred_retry_queue.append(("Running SSL Scan", run_ssl_scan, "", _process_ssl_results))
            _log_raw(scan_id, "SSL", res)

        # ── Step 11: Security Headers ─────────────────────────────────────
        if _should_run_step("Running Security Headers", resume_status):
            update_scan_status(scan_id, "Running Security Headers")
            logger.info(f"[11/22] Security Headers scan – {url}")
            res, success = run_with_resilience(scan_id, "Running Security Headers", run_headers_scan, url, "", needs_binary=False)
            if success:
                _process_headers_results(res)
            else:
                deferred_retry_queue.append(("Running Security Headers", run_headers_scan, "", _process_headers_results))
            _log_raw(scan_id, "Security Headers", res)

        # ── Step 12: Robots.txt ───────────────────────────────────────────
        if _should_run_step("Running Robots.txt", resume_status):
            update_scan_status(scan_id, "Running Robots.txt")
            logger.info(f"[12/22] Robots.txt / Sitemap scan – {url}")
            res, success = run_with_resilience(scan_id, "Running Robots.txt", run_robots_scan, url, "", needs_binary=False)
            if success:
                _process_robots_results(res)
            else:
                deferred_retry_queue.append(("Running Robots.txt", run_robots_scan, "", _process_robots_results))
            _log_raw(scan_id, "Robots.txt", res)

        # ── Step 13: CORS Scanner ─────────────────────────────────────────
        if _should_run_step("Running CORS", resume_status):
            update_scan_status(scan_id, "Running CORS")
            logger.info(f"[13/22] CORS misconfiguration scan – {url}")
            res, success = run_with_resilience(scan_id, "Running CORS", run_cors_scan, url, "", needs_binary=False)
            if success:
                _process_cors_results(res)
            else:
                deferred_retry_queue.append(("Running CORS", run_cors_scan, "", _process_cors_results))
            _log_raw(scan_id, "CORS", res)

        # ── Step 14: CMS Scanner ──────────────────────────────────────────
        if _should_run_step("Running CMS Scanner", resume_status):
            update_scan_status(scan_id, "Running CMS Scanner")
            logger.info(f"[14/22] CMS detection scan – {url}")
            res, success = run_with_resilience(scan_id, "Running CMS Scanner", run_cms_scan, url, "", needs_binary=False)
            if success:
                _process_cms_results(res)
            else:
                deferred_retry_queue.append(("Running CMS Scanner", run_cms_scan, "", _process_cms_results))
            _log_raw(scan_id, "CMS Scanner", res)

        # ── Step 15: Nikto ────────────────────────────────────────────────
        if _should_run_step("Running Nikto", resume_status):
            update_scan_status(scan_id, "Running Nikto")
            logger.info(f"[15/22] Nikto web vuln scan – {url}")
            res, success = run_with_resilience(scan_id, "Running Nikto", run_nikto_scan, url, "nikto")
            if success:
                _process_nikto_results(res)
            else:
                deferred_retry_queue.append(("Running Nikto", run_nikto_scan, "nikto", _process_nikto_results))
            _log_raw(scan_id, "Nikto", res)

        # ── Step 16: Nuclei ───────────────────────────────────────────────
        if _should_run_step("Running Nuclei", resume_status):
            update_scan_status(scan_id, "Running Nuclei")
            logger.info(f"[16/22] Nuclei template scan – {url}")
            res, success = run_with_resilience(scan_id, "Running Nuclei", run_nuclei_scan, url, "nuclei")
            if success:
                _process_nuclei_results(res)
            else:
                deferred_retry_queue.append(("Running Nuclei", run_nuclei_scan, "nuclei", _process_nuclei_results))
            _log_raw(scan_id, "Nuclei", res)

        # ── Step 17: ffuf ─────────────────────────────────────────────────
        if _should_run_step("Running ffuf", resume_status):
            update_scan_status(scan_id, "Running ffuf")
            logger.info(f"[17/22] ffuf directory fuzzing – {url}")
            res, success = run_with_resilience(scan_id, "Running ffuf", run_ffuf_scan, url, "ffuf")
            if success:
                _process_ffuf_results(res)
            else:
                deferred_retry_queue.append(("Running ffuf", run_ffuf_scan, "ffuf", _process_ffuf_results))
            _log_raw(scan_id, "ffuf", res)

        # ── Step 18: Open Redirect ────────────────────────────────────────
        if _should_run_step("Running Open Redirect", resume_status):
            update_scan_status(scan_id, "Running Open Redirect")
            logger.info(f"[18/22] Open Redirect scan – {url}")
            res, success = run_with_resilience(scan_id, "Running Open Redirect", run_open_redirect_scan, url, "", needs_binary=False)
            if success:
                _process_redirect_results(res)
            else:
                deferred_retry_queue.append(("Running Open Redirect", run_open_redirect_scan, "", _process_redirect_results))
            _log_raw(scan_id, "Open Redirect", res)

        # ── Step 19: Tech Fingerprint ─────────────────────────────────────
        if _should_run_step("Running Tech Fingerprint", resume_status):
            update_scan_status(scan_id, "Running Tech Fingerprint")
            logger.info(f"[19/22] Deep Tech Fingerprint – {url}")
            res, success = run_with_resilience(scan_id, "Running Tech Fingerprint", run_tech_fingerprint, url, "", needs_binary=False)
            if success:
                _process_tech_results(res)
            else:
                deferred_retry_queue.append(("Running Tech Fingerprint", run_tech_fingerprint, "", _process_tech_results))
            _log_raw(scan_id, "Tech Fingerprint", res)

        # ── Step 20: Wapiti ───────────────────────────────────────────────
        if _should_run_step("Running Wapiti", resume_status):
            update_scan_status(scan_id, "Running Wapiti")
            logger.info(f"[20/22] Wapiti web vuln scan – {url}")
            res, success = run_with_resilience(scan_id, "Running Wapiti", run_wapiti_scan, url, "wapiti")
            if success:
                _process_wapiti_results(res)
            else:
                deferred_retry_queue.append(("Running Wapiti", run_wapiti_scan, "wapiti", _process_wapiti_results))
            _log_raw(scan_id, "Wapiti", res)

        # ── Step 21: SQLMap ───────────────────────────────────────────────
        if _should_run_step("Running SQLMap", resume_status):
            update_scan_status(scan_id, "Running SQLMap")
            logger.info(f"[21/22] SQLMap SQLi scan – {url}")
            res, success = run_with_resilience(scan_id, "Running SQLMap", run_sqlmap_scan, url, "sqlmap")
            if success:
                _process_sqlmap_results(res)
            else:
                deferred_retry_queue.append(("Running SQLMap", run_sqlmap_scan, "sqlmap", _process_sqlmap_results))
            _log_raw(scan_id, "SQLMap", res)

        # ── Step 22: Shodan InternetDB ────────────────────────────────────
        if _should_run_step("Running Shodan", resume_status):
            update_scan_status(scan_id, "Running Shodan")
            logger.info(f"[22/22] Shodan passive profiling – {url}")
            res, success = run_with_resilience(scan_id, "Running Shodan", run_shodan_idb_scan, url, "", needs_binary=False)
            if success:
                _process_shodan_results(res)
            else:
                deferred_retry_queue.append(("Running Shodan", run_shodan_idb_scan, "", _process_shodan_results))
            _log_raw(scan_id, "Shodan", res)

        # ── Optional: OWASP ZAP ───────────────────────────────────────────
        zap_results = []
        if _should_run_step("Running ZAP", resume_status):
            if settings.get("zap_enabled", False):
                update_scan_status(scan_id, "Running ZAP")
                logger.info(f"[ZAP] ZAP active scan – {url}")
                res, success = run_with_resilience(scan_id, "Running ZAP", run_zap_scan, url, "zap", needs_binary=False)
                if success:
                    _process_zap_results(res)
                else:
                    deferred_retry_queue.append(("Running ZAP", run_zap_scan, "zap", _process_zap_results))
                _log_raw(scan_id, "ZAP", res)
            else:
                logger.info("[ZAP] ZAP disabled in settings – skipping.")

        # ── Execute Deferred Retry Queue (Improvement 4 & 8) ──────────────
        if deferred_retry_queue:
            logger.info("\n[*] Initial sequence concluded. Re-attempting deferred failures with adaptive timeout balancing...")
            for step_name, scan_func, binary_name, process_fn in deferred_retry_queue:
                logger.info(f"[*] Retrying failed/timed out step: {step_name} with 1.5x timeout...")
                res, success = run_with_resilience(scan_id, step_name, scan_func, url, binary_name, attempt=2)
                if success:
                    process_fn(res)
                    logger.info(f"[✅ RECOVERY] Fallback execution succeeded for step: {step_name}")
                else:
                    log_scanner_failure_status(scan_id, step_name, "Persistent Execution Failure")

        # ── Site up determination ─────────────────────────────────────────
        is_site_up = _determine_site_up(
            httpx_result, whatweb_results, nmap_results,
            nikto_results, nuclei_results, ssl_results,
            headers_results, cors_results,
        )
        if not is_site_up:
            add_alert(target_id, "Website Unavailable / All Scanners Failed", "High")
            add_log_entry("WARNING", f"Website unavailable or all scanners failed for {url}")

        # ── CVE Correlation ────────────────────────────────────────────────
        if _should_run_step("Correlating CVEs", resume_status):
            update_scan_status(scan_id, "Correlating CVEs")
            logger.info(f"CVE Correlation – {url}")
            try:
                from intelligence.cve_correlator import correlate_cves_for_scan
                correlate_cves_for_scan(scan_id)
            except Exception as ce:
                logger.error(f"CVE Correlation error: {ce}")

        # ── Risk Scoring ───────────────────────────────────────────────────
        if _should_run_step("Report Pending", resume_status):
            update_scan_status(scan_id, "Report Pending")
        current_findings = get_findings_for_scan(scan_id)

        try:
            from tools.risk_scorer import calculate_and_store_risk_score
            risk = calculate_and_store_risk_score(scan_id, current_findings)
            logger.info(f"Risk Score: {risk['score']}/100 ({risk['rating']})")
        except Exception as re_:
            logger.error(f"Risk scoring error: {re_}")

        # Improvement 16: Check long-term stability and flag systemic vulnerability increases
        try:
            _evaluate_vulnerability_growth_thresholds()
        except Exception:
            pass

        # ── Differential analysis ─────────────────────────────────────────
        previous_scan = _get_previous_completed_scan(target_id, scan_id)
        new_findings_detected, severity_escalated, _ = _diff_findings(current_findings, previous_scan)

        if new_findings_detected:
            max_sev = _max_severity(current_findings)
            add_alert(target_id, "New Vulnerability Detected", max_sev)
        if severity_escalated:
            add_alert(target_id, "Severity Increased", "High")

        # ── Report Generation ──────────────────────────────────────────────
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_report, pdf_report = generate_scan_reports(
            scan_id, target, current_findings, previous_scan
        )
        add_log_entry("INFO", "Report Generated")

        # ── SMTP Alerts ────────────────────────────────────────────────────
        from tools.alert_engine import process_alerts_for_scan
        process_alerts_for_scan(
            target=target,
            findings=current_findings,
            new_findings_detected=new_findings_detected,
            severity_escalated=severity_escalated,
            is_site_up=is_site_up,
            html_report_path=html_report,
            pdf_report_path=pdf_report,
        )

        # ── Tech-matched CVE alerts (Improvement 9) ───────────────────────
        try:
            from tools.alert_engine import scan_and_alert_matched_technology_cves
            smtp_config = {
                "sender": settings.get("smtp_sender") or settings.get("smtp_user"),
                "receiver": settings.get("smtp_receiver"),
                "primary_host": settings.get("smtp_host"),
                "primary_port": int(settings.get("smtp_port", 587)),
                "backup_host": settings.get("smtp_backup_host") or settings.get("smtp_host"),
                "backup_port": int(settings.get("smtp_backup_port", 587)),
                "user": settings.get("smtp_user"),
                "pass": settings.get("smtp_pass")
            }
            if smtp_config["receiver"]:
                scan_and_alert_matched_technology_cves(url, scan_id, smtp_config)
        except Exception as alert_err:
            logger.error(f"Tech-matched alert engine error: {alert_err}")

        # ── Backup ────────────────────────────────────────────────────────
        try:
            backup_scan_to_raw(scan_id, url)
            save_important_findings(scan_id, url, current_findings, now_str)
        except Exception as be:
            logger.error(f"Backup error: {be}")

        update_target_last_scan(target_id, now_str)
        update_scan_status(scan_id, "Completed", end_time=now_str)
        logger.info(f"Scan Completed: {url}")
        add_log_entry("INFO", f"Scan Completed: {url}")

    except Exception as e:
        logger.error(f"Scan pipeline failed for {url}: {e}", exc_info=True)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        update_scan_status(scan_id, "Failed", end_time=now_str)
        add_log_entry("ERROR", f"Scanner Failure: {url} – {e}")
    finally:
        with _lock:
            _active_scans.pop(target_id, None)
            _active_urls.discard(url)


# ── Scan resumption ────────────────────────────────────────────────────────────

def resume_interrupted_scans():
    """Find scans that were running when the app was killed and resume them."""
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT scans.*, targets.url FROM scans "
            "JOIN targets ON scans.target_id = targets.id "
            "WHERE scans.status NOT IN ('Completed', 'Failed', 'Report Pending')"
        ).fetchall()
        conn.close()

        def _infer_resume_step(target_url, db_status):
            import os
            from tools.config_manager import BASE_DIR
            log_path = os.path.join(BASE_DIR, "logs", "scan.log")
            if not os.path.exists(log_path):
                return db_status

            step_map = {
                "[1/22]": "Running HTTPx",
                "[2/22]": "Running WhatWeb",
                "[3/22]": "Running Subfinder",
                "[4/22]": "Running CRT.sh",
                "[5/22]": "Running HackerTarget",
                "[6/22]": "Running Whois",
                "[7/22]": "Running Wayback Machine",
                "[8/22]": "Running Traceroute",
                "[9/22]": "Running Nmap",
                "[10/22]": "Running SSL Scan",
                "[11/22]": "Running Security Headers",
                "[12/22]": "Running Robots.txt",
                "[13/22]": "Running CORS",
                "[14/22]": "Running CMS Scanner",
                "[15/22]": "Running Nikto",
                "[16/22]": "Running Nuclei",
                "[17/22]": "Running ffuf",
                "[18/22]": "Running Open Redirect",
                "[19/22]": "Running Tech Fingerprint",
                "[20/22]": "Running Wapiti",
                "[21/22]": "Running SQLMap",
                "[22/22]": "Running Shodan",
            }
            last_status = db_status
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if target_url in line:
                            for prefix, status in step_map.items():
                                if prefix in line:
                                    last_status = status
            except Exception:
                pass
            return last_status

        for r in rows:
            scan = dict(r)
            target = {"id": scan["target_id"], "url": scan["url"]}
            target_id = target["id"]
            url = target["url"]

            with _lock:
                if target_id in _active_scans or url in _active_urls:
                    continue
                if len(_active_scans) >= 3:
                    logger.warning(f"Global scan limit reached. Cannot resume {url}")
                    continue

                resume_step = _infer_resume_step(url, scan["status"])

                thread = threading.Thread(
                    target=_run_scan_sequence,
                    args=(target, scan["id"], resume_step),
                    daemon=True,
                    name=f"ScanThread_{target_id}",
                )
                _active_scans[target_id] = thread
                _active_urls.add(url)
                thread.start()
                logger.info(f"Resumed scan {scan['id']} for {url} from '{resume_step}'")

    except Exception as e:
        logger.error(f"Error resuming scans: {e}")
