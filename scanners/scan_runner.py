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

import os
import json
import logging
import threading
import multiprocessing
import shutil
import subprocess
import signal
import time
from datetime import datetime

from tools.db_manager import (
    create_scan, update_scan_status, add_finding, add_technology,
    get_findings_for_scan, update_target_last_scan,
    add_alert, add_log_entry, get_db_connection,
    save_raw_scan_output, backup_scan_to_raw,
    update_scan_scanner_status, log_scanner_failure_status,
    _evaluate_vulnerability_growth_thresholds,
    clear_redundancy_db,
)
from tools.config_manager import load_settings

# ── Graceful-shutdown flag ─────────────────────────────────────────────────
# Set to True by main.py / dashboard.py before calling QApplication.quit().
# When True, the scan pipeline skips the redundancy-DB wipe so that any
# in-flight scan data is preserved for the next session's resume logic.
_APP_SHUTTING_DOWN: bool = False

def signal_app_shutdown():
    """Call this before closing the app to protect the redundancy DB."""
    global _APP_SHUTTING_DOWN
    _APP_SHUTTING_DOWN = True

from tools.tool_installer import install_single_tool

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
from scanners.theharvester import run_theharvester_scan
from scanners.gitleaks import run_gitleaks_scan
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
    
    # 1. Binary availability guard with self-healing
    if needs_binary:
        bin_path = settings.get(f"{binary_name}_path", binary_name)
        if not shutil.which(bin_path):
            logger.warning(f"[{step_name}] ⚠️  Binary '{bin_path}' not in PATH — triggering self-healing installer...")
            healed = install_single_tool(binary_name)
            if healed and shutil.which(bin_path):
                logger.info(f"[{step_name}] ✅ Self-heal succeeded — '{bin_path}' is now available. Proceeding.")
            else:
                logger.error(f"[{step_name}] ❌ Self-heal failed for '{bin_path}'. Skipping this step.")
                log_scanner_failure_status(scan_id, step_name, "Missing Binary Dependency (Self-Heal Failed)")
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
                max_initial = settings.get("scanner_timeout_seconds", 600)
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
    # ── Tier 1: Passive / OSINT (fast, no traffic) ─────────────────────────
    "Running HTTPx", "Running WhatWeb", "Running Subfinder", "Running Amass",
    "Running theHarvester", "Running SpiderFoot OSINT", "Running CRT.sh",
    "Running HackerTarget", "Running Whois", "Running Wayback Machine",
    # ── Tier 2: Network & Infrastructure ───────────────────────────────────
    "Running Traceroute", "Running Nmap", "Running Masscan", "Running DNSx",
    "Running SSL Scan", "Running HTTP Smuggling Scanner",
    # ── Tier 3: Web Surface Discovery ──────────────────────────────────────
    "Running Security Headers", "Running Robots.txt", "Running CORS",
    "Running CMS Scanner", "Running Katana", "Running ffuf",
    "Running Feroxbuster", "Running API Fuzzer", "Running GraphQL Scanner",
    "Running ParamSpider", "Running Arjun",
    # ── Tier 4: Vulnerability Scanning ─────────────────────────────────────
    "Running Nikto", "Running Nuclei", "Running ZAP",
    "Running Retire.js Scanner", "Running Tech Fingerprint",
    "Running Open Redirect", "Running CRLF Scanner",
    # ── Tier 5: Deep Exploitation Testing ──────────────────────────────────
    "Running Wapiti", "Running SQLMap", "Running Dalfox", "Running Commix",
    "Running SSRF Scanner", "Running XXE Scanner", "Running Path Traversal Scanner",
    "Running JWT Scanner", "Running WPScan",
    # ── Tier 6: Auth & Secrets ──────────────────────────────────────────────
    "Running Auth Brute-Force Test", "Running Cloud Enum",
    "Running Gitleaks", "Running TruffleHog",
    "Running Semgrep", "Running Trivy",
    # ── Tier 7: Passive Intelligence ───────────────────────────────────────
    "Running Shodan",
    # ── Terminal ────────────────────────────────────────────────────────────
    "Correlating CVEs", "Report Pending",
]


_cancel_events = {}

# ── Public API ─────────────────────────────────────────────────────────────────

def _process_waiter(target_id, url, process):
    """Waits for a scanner process to finish and cleans up the active state."""
    process.join()
    with _lock:
        _active_scans.pop(target_id, None)
        _active_urls.discard(url)
        _cancel_events.pop(target_id, None)
        
        if not _APP_SHUTTING_DOWN and len(_active_scans) == 0:
            try:
                clear_redundancy_db()
                logger.debug("Redundancy DB cleared after all scans completed.")
            except Exception as rdbe:
                logger.warning(f"Failed to clear redundancy DB post-scan: {rdbe}")


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

        
        resume_scan_id = None
        resume_status = None
        
        # Check if there is an interrupted scan for this target
        from tools.db_manager import get_scans_for_target
        recent_scans = get_scans_for_target(target_id, limit=1)
        if recent_scans:
            last_scan = recent_scans[0]
            if last_scan["status"] not in ("Completed", "Failed"):
                # It was interrupted or stuck in "Running ..." state
                resume_scan_id = last_scan["id"]
                resume_status = last_scan.get("scanner_status") or last_scan["status"]
                logger.info(f"Resuming interrupted scan {resume_scan_id} for target {url} from step {resume_status}")

        cancel_event = multiprocessing.Event()
        _cancel_events[target_id] = cancel_event

        process = multiprocessing.Process(
            target=_run_scan_sequence,
            args=(target, resume_scan_id, resume_status, sudo_password, cancel_event),
            daemon=True,
            name=f"ScanProcess_{target_id}",
        )
        _active_scans[target_id] = process
        _active_urls.add(url)
        process.start()

        waiter = threading.Thread(
            target=_process_waiter,
            args=(target_id, url, process),
            daemon=True
        )
        waiter.start()
        return True

def cancel_scan(target_id):
    """Signal an ongoing scan to cancel gracefully."""
    with _lock:
        if target_id in _cancel_events:
            _cancel_events[target_id].set()
            logger.info(f"Cancel signal sent to target_id: {target_id}")


def is_target_scanning(target_id):
    with _lock:
        return target_id in _active_scans


# ── Internal helpers ───────────────────────────────────────────────────────────

def _should_run_step(step_name, resume_status):
    """
    Returns True if this step should execute given the selected scan profile.

    Scan Profiles (V9.0.2)
    ────────────────────
    osint    — Purely passive, zero traffic to target. Safe for un-permissioned recon.
               Covers: OSINT APIs, certificate transparency, Whois, Wayback, Shodan.
    standard — Normal VAPT: OSINT + active network/web scanning. Recommended for engagements.
               Adds: Nmap, SSL, Headers, CMS, Nikto, Nuclei, ffuf, WPScan, DNSx, Katana.
    full     — Maximum coverage. Intrusive. Requires explicit written permission.
               Adds: All exploitation tools (SQLMap, Dalfox, Wapiti, Commix, Hydra, ZAP,
               SSRF, XXE, path traversal, JWT attacks, ParamSpider, Arjun, TruffleHog,
               Trivy, Semgrep, Feroxbuster, Masscan, GraphQL, API Fuzzer, etc.)
    """
    # ── 1. Load profile ──────────────────────────────────────────────────────
    settings = load_settings()
    profile = settings.get("scan_profile", "standard").lower()
    # Allow legacy 'fast' alias to resolve to 'osint'
    if profile == "fast":
        profile = "osint"

    # ── 2. Profile step allowlists ────────────────────────────────────────────

    # OSINT — Passive only, no active network requests to target
    _OSINT_STEPS = {
        "Running HTTPx",           # HTTP probe — minimal, just checks if site is up
        "Running WhatWeb",         # Passive fingerprint from public HTTP response
        "Running Subfinder",       # DNS-based subdomain enum (no target traffic)
        "Running Amass",           # Passive OSINT subdomain enum
        "Running theHarvester",    # Email/DNS OSINT (search engine queries)
        "Running SpiderFoot OSINT",# SpiderFoot passive mode
        "Running CRT.sh",          # Certificate transparency lookup
        "Running HackerTarget",    # Reverse DNS OSINT API
        "Running Whois",           # Domain registration lookup
        "Running Wayback Machine", # Historical URL archive lookup
        "Running Shodan",          # Shodan InternetDB (passive IP intelligence)
        "Running Cloud Enum",      # Cloud storage bucket enum (passive DNS)
        "Running Gitleaks",        # Git secret scanning (remote repo analysis)
        "Correlating CVEs",        # Offline CVE correlation
        "Report Pending",          # Report generation
    }

    # Standard — Active web/network scanning, typical VAPT engagement
    _STANDARD_STEPS = _OSINT_STEPS | {
        "Running Traceroute",      # Network path (UDP-based, no root needed)
        "Running Nmap",            # Port + service scan
        "Running DNSx",            # Active DNS resolution of found subdomains
        "Running SSL Scan",        # TLS/certificate analysis
        "Running Security Headers",# HTTP response header analysis
        "Running Robots.txt",      # robots.txt / sitemap analysis
        "Running CORS",            # CORS misconfiguration check
        "Running CMS Scanner",     # CMS detection and admin panels
        "Running Katana",          # Web crawler (follows discovered links)
        "Running Nikto",           # Classic web vulnerability scanner
        "Running Nuclei",          # Template-based vuln scan
        "Running ffuf",            # Directory fuzzing (standard wordlist)
        "Running Tech Fingerprint",# Deep response-based tech detection
        "Running Open Redirect",   # Open redirect parameter testing
        "Running CRLF Scanner",    # CRLF/header injection testing
        "Running Retire.js Scanner",# Outdated JS library detection
        "Running WPScan",          # WordPress vulnerability scan
        "Running JWT Scanner",     # JWT weakness detection
        "Running API Fuzzer",      # Swagger/OpenAPI endpoint detection
        "Running GraphQL Scanner", # GraphQL introspection check
    }

    # Full — Deep/intrusive exploitation testing. Requires explicit written permission.
    # All steps run in full mode (no allowlist restriction needed — return True always)
    _FULL_STEPS = _STANDARD_STEPS | {
        "Running Wapiti",          # OWASP web app scan (active)
        "Running SQLMap",          # SQL injection exploitation
        "Running Dalfox",          # XSS parameter scanning
        "Running Commix",          # Command injection testing
        "Running SSRF Scanner",    # Server-Side Request Forgery testing
        "Running XXE Scanner",     # XML External Entity injection
        "Running Path Traversal Scanner",  # LFI/path traversal testing
        "Running ParamSpider",     # Parameter discovery from Wayback URLs
        "Running Arjun",           # Hidden HTTP parameter discovery
        "Running Feroxbuster",     # Deep directory fuzzing
        "Running Masscan",         # High-speed port scanner
        "Running Auth Brute-Force Test",   # Auth brute force (Hydra)
        "Running HTTP Smuggling Scanner",  # HTTP request smuggling
        "Running TruffleHog",      # Secret scanning in history/repos
        "Running Trivy",           # Container/image vulnerability scan
        "Running Semgrep",         # Static analysis (source code mode)
        "Running ZAP",             # OWASP ZAP active scan
        "Running WPScan",          # (already in standard; run deeper in full)
    }

    # ── 3. Check profile gating ───────────────────────────────────────────────
    if profile == "osint":
        if step_name not in _OSINT_STEPS:
            return False
    elif profile == "standard":
        if step_name not in _STANDARD_STEPS:
            return False
    # 'full' — all steps run; no filtering needed

    # ── 4. Resume / skip-already-done logic ───────────────────────────────────
    if not resume_status:
        return True
    if step_name not in _PIPELINE_STEPS:
        return True
    if resume_status not in _PIPELINE_STEPS:
        return True
    return _PIPELINE_STEPS.index(step_name) >= _PIPELINE_STEPS.index(resume_status)



def _save_findings(scan_id, results, source_tool, severity_override=None, confidence=50):
    """Bulk-save a list of finding dicts to the DB, including all enterprise metadata."""
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
            url=item.get("url"),
            evidence=item.get("evidence"),
            recommendation=item.get("recommendation"),
            cvss_score=item.get("cvss_score"),
            cve_id=item.get("cve_id"),
            affected_component=item.get("affected_component"),
            owasp_category=item.get("owasp_category"),
            business_impact=item.get("business_impact"),
            reproduction_steps=item.get("reproduction_steps"),
            references_json=item.get("references_json"),
            remediation_code=item.get("remediation_code"),
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

def _filter_spa_ffuf_results(results):
    """
    Filter ffuf false positives caused by React/SPA catch-all 200 responses.
    If >= 80% of results share the same content-length, they are all SPA catch-alls.
    Removes those entries; keeps only results with unique content-lengths.
    """
    if not results or len(results) < 5:
        return results  # Too few results to apply heuristic

    # Count content-length occurrences
    from collections import Counter
    lengths = []
    for r in results:
        desc = r.get("description", "")
        for part in desc.split("\n"):
            if "Content-Length:" in part:
                try:
                    cl = int(part.split("Content-Length:")[1].split("|")[0].strip())
                    lengths.append(cl)
                except Exception:
                    lengths.append(-1)
                break
        else:
            lengths.append(-1)

    if not lengths:
        return results

    counter = Counter(lengths)
    most_common_len, most_common_count = counter.most_common(1)[0]
    ratio = most_common_count / len(lengths)

    if ratio >= 0.80 and most_common_len != -1:
        # SPA catch-all detected — remove all results with this content-length
        filtered = []
        for r, cl in zip(results, lengths):
            if cl != most_common_len:
                filtered.append(r)
        removed = len(results) - len(filtered)
        if removed > 0:
            logger.info(
                f"ffuf SPA Filter: Removed {removed} catch-all false positives "
                f"(content-length={most_common_len} appeared in {ratio*100:.0f}% of results)."
            )
        return filtered

    return results


def _run_scan_sequence(target, resume_scan_id=None, resume_status=None, sudo_password=None, cancel_event=None):
    # Store sudo password in thread-local storage for this execution thread
    thread_local.sudo_password = sudo_password

    target_id = target["id"]
    url = target["url"]
    settings = load_settings()

    # ── V9.0.2 — Global Proxy Configuration ────────────────────────────────────
    http_proxy = settings.get("http_proxy", "").strip()
    https_proxy = settings.get("https_proxy", "").strip()
    if http_proxy:
        os.environ["HTTP_PROXY"] = http_proxy
        os.environ["http_proxy"] = http_proxy
    if https_proxy:
        os.environ["HTTPS_PROXY"] = https_proxy
        os.environ["https_proxy"] = https_proxy

    # ── MAC Address Randomisation at scan start ───────────────────────────────
    mac_change_ok = False
    if settings.get("mac_changer_enabled", True):
        try:
            from tools.mac_changer import change_mac_address
            mac_ok, mac_msg = change_mac_address(sudo_password=sudo_password)
            mac_change_ok = mac_ok
            if mac_ok:
                logger.info(mac_msg)
            else:
                logger.warning(f"[MAC] {mac_msg}")
        except Exception as me:
            logger.warning(f"[MAC] MAC changer error (non-fatal): {me}")
    else:
        logger.debug("[MAC] mac_changer_enabled=false in settings — skipping.")
        mac_change_ok = True  # Treat as OK so scanners are not blocked

    logger.info(f"Scan Started: {url}")
    add_log_entry("INFO", f"Scan Started: {url}")

    # Initialize result holders
    httpx_result = whatweb_results = subfinder_results = crtsh_results = None
    ht_results = whois_results = wayback_results = trace_result = None
    nmap_results = ssl_results = headers_results = robots_results = None
    cors_results = cms_results = nikto_results = nuclei_results = None
    ffuf_results = redirect_results = tech_results = None
    wapiti_results = sqlmap_results = shodan_results = zap_results = None
    theharvester_results = gitleaks_results = None
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
        # Apply SPA false-positive filter before saving
        if res:
            res = _filter_spa_ffuf_results(res)
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

    def _process_theharvester_results(res):
        nonlocal theharvester_results
        theharvester_results = res
        _save_findings(scan_id, res or [], "theHarvester", confidence=90)

    def _process_gitleaks_results(res):
        nonlocal gitleaks_results
        gitleaks_results = res
        _save_findings(scan_id, res or [], "Gitleaks", confidence=95)

    
    def _process_dalfox_results(res):
        _save_findings(scan_id, res or [], "Dalfox", confidence=90)

    def _process_arjun_results(res):
        _save_findings(scan_id, res or [], "Arjun", confidence=85)

    def _process_dnsx_results(res):
        _save_findings(scan_id, res or [], "DNSx", confidence=95)

    def _process_katana_results(res):
        _save_findings(scan_id, res or [], "Katana", confidence=90)

    def _process_commix_results(res):
        _save_findings(scan_id, res or [], "Commix", confidence=95)

    def _process_jwt_scanner_results(res):
        _save_findings(scan_id, res or [], "JWT Scanner", confidence=85)

    def _process_wpscan_results(res):
        _save_findings(scan_id, res or [], "WPScan", confidence=90)

    def _process_masscan_results(res):
        _save_findings(scan_id, res or [], "Masscan", confidence=95)

    def _process_paramspider_results(res):
        _save_findings(scan_id, res or [], "Paramspider", confidence=85)

    def _process_cloud_enum_results(res):
        _save_findings(scan_id, res or [], "Cloud Enum", confidence=85)
        
    def _process_zap_results(res):
        _save_findings(scan_id, res or [], "ZAP", confidence=85)


    class ScanCancelled(Exception): pass
    
    # Shadow the global _should_run_step locally to inject cancel checks
    global_should_run_step = globals()['_should_run_step']
    def _should_run_step(step_name, resume_status):
        if cancel_event and cancel_event.is_set():
            raise ScanCancelled(f"Scan cancelled by user at step {step_name}")
        return global_should_run_step(step_name, resume_status)

    try:
        
        from scanners.dalfox import run_dalfox_scan
        from scanners.arjun import run_arjun_scan
        from scanners.dnsx import run_dnsx_scan
        from scanners.katana import run_katana_scan
        from scanners.commix import run_commix_scan
        from scanners.jwt_scanner import run_jwt_scanner_scan
        from scanners.wpscan import run_wpscan_scan
        from scanners.masscan import run_masscan_scan
        from scanners.paramspider import run_paramspider_scan
        from scanners.cloud_enum import run_cloud_enum_scan
        from scanners.zap import run_zap_scan

        from scanners.core.plugin import GenericPlugin
        from scanners.core.dag import DAGOrchestrator
        from scanners.core.registry import get_registered_scanners
        dag_plugins = []
        
        def mac_precondition():
            if not mac_change_ok:
                logger.warning('MAC change failed, skipping active scanner')
                return False
            return True
        


        processors = {
            "HTTPx": _process_httpx_results,
            "WhatWeb": _process_whatweb_results,
            "Subfinder": _process_subfinder_results,
            "CRT.sh": _process_crtsh_results,
            "HackerTarget": _process_ht_results,
            "Whois": _process_whois_results,
            "Wayback Machine": _process_wayback_results,
            "Traceroute": _process_trace_results,
            "Nmap": _process_nmap_results,
            "SSL": _process_ssl_results,
            "Security Headers": _process_headers_results,
            "Robots.txt": _process_robots_results,
            "CORS": _process_cors_results,
            "CMS Scanner": _process_cms_results,
            "Nikto": _process_nikto_results,
            "Nuclei": _process_nuclei_results,
            "ffuf": _process_ffuf_results,
            "Open Redirect": _process_redirect_results,
            "Tech Fingerprint": _process_tech_results,
            "Wapiti": _process_wapiti_results,
            "SQLMap": _process_sqlmap_results,
            "Shodan": _process_shodan_results,
            "ZAP": _process_zap_results,
            "theHarvester": _process_theharvester_results,
            "Gitleaks": _process_gitleaks_results,
            "Dalfox": _process_dalfox_results,
            "Arjun": _process_arjun_results,
            "DNSx": _process_dnsx_results,
            "Katana": _process_katana_results,
            "Commix": _process_commix_results,
            "JWT Scanner": _process_jwt_scanner_results,
            "WPScan": _process_wpscan_results,
            "Masscan": _process_masscan_results,
            "ParamSpider": _process_paramspider_results,
            "Cloud Enum": _process_cloud_enum_results,
        }

        registered_scanners = get_registered_scanners()
        for name, meta in registered_scanners.items():
            # Check Preconditions if required
            precondition = None
            if name in ["Nikto", "Nuclei", "ZAP"]:
                precondition = mac_precondition
            
            if name in ["Trivy", "Prowler"]:
                def cloud_precondition(n=name):
                    if not load_settings().get("enable_enterprise_cloud", False):
                        logger.debug(f"Skipping {n} (Cloud/Container scanning disabled in settings)")
                        return False
                    return True
                precondition = cloud_precondition
                
            if name == "ClamAV":
                def malware_precondition(n=name):
                    if not load_settings().get("enable_enterprise_malware", False):
                        logger.debug(f"Skipping {n} (Malware scanning disabled in settings)")
                        return False
                    return True
                precondition = malware_precondition
                
            if name == "MobSF":
                def mobsf_precondition(n=name):
                    if not load_settings().get("mobsf_api_key", "").strip():
                        logger.debug(f"Skipping {n} (No API key provided in settings)")
                        return False
                    return True
                precondition = mobsf_precondition
                
            def make_process_func(tool_name, confidence):
                def _unified_processor(res):
                    _save_findings(scan_id, res or [], tool_name, confidence=confidence)
                return _unified_processor
                
            process_fn = processors.get(name) or make_process_func(name, meta.get("confidence", 50))
            
            dag_plugins.append(
                GenericPlugin(
                    target_url=url,
                    scan_id=scan_id,
                    name=name,
                    step_name=meta["step_name"],
                    depends_on=meta["depends_on"],
                    scan_func=meta["scan_func"],
                    binary_name=meta["binary_name"],
                    process_func=process_fn,
                    needs_binary=meta["needs_binary"],
                    precondition=precondition,
                    resume_status=resume_status
                )
            )

        logger.info(f"Starting DAG Orchestrator with {len(dag_plugins)} plugins")
        
        def _on_active_change(active_steps):
            if active_steps:
                update_scan_status(scan_id, active_steps[0])
                
        orchestrator = DAGOrchestrator(dag_plugins, max_workers=6, on_active_change=_on_active_change)
        dag_results = orchestrator.run(cancel_event=cancel_event)
        
        # Populate results for Phase 2 correlation
        for plugin in dag_plugins:
            if plugin.name in orchestrator.failed:
                deferred_retry_queue.append((plugin.step_name, plugin.scan_func, plugin.binary_name, plugin.process_func))

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

        # ── Report Generation (pentest report + SBOM in one run) ──────────
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_report, pdf_report, sbom_report = generate_scan_reports(
            scan_id, target, current_findings, previous_scan
        )
        if sbom_report:
            add_log_entry("INFO", f"SBOM Generated: {os.path.basename(sbom_report)}")
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
            from tools.db_manager import backup_all_tables
            backup_scan_to_raw(scan_id, url)
            backup_all_tables()
        except Exception as be:
            logger.error(f"Backup error: {be}")

        update_target_last_scan(target_id, now_str)
        update_scan_status(scan_id, "Completed", end_time=now_str)
        logger.info(f"Scan Completed: {url}")
        add_log_entry("INFO", f"Scan Completed: {url}")

    except ScanCancelled as e:
        logger.warning(f"Scan Cancelled: {url} - {str(e)}")
        add_log_entry("WARNING", f"Scan Cancelled by User: {url}")
        update_scan_status(scan_id, "Cancelled")

    except Exception as e:
        logger.error(f"Scan pipeline failed for {url}: {e}", exc_info=True)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        update_scan_status(scan_id, "Failed", end_time=now_str)
        add_log_entry("ERROR", f"Scanner Failure: {url} – {e}")
    finally:
        pass


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

            last_status = db_status
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if target_url in line:
                            for status in _PIPELINE_STEPS:
                                if status in line:
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

                # Register a cancel event so resumed scans can also be cancelled from the UI
                cancel_event = multiprocessing.Event()
                _cancel_events[target_id] = cancel_event

                process = multiprocessing.Process(
                    target=_run_scan_sequence,
                    args=(target, scan["id"], resume_step, None, cancel_event),
                    daemon=True,
                    name=f"ScanProcess_{target_id}",
                )
                _active_scans[target_id] = process
                _active_urls.add(url)
                process.start()

                waiter = threading.Thread(
                    target=_process_waiter,
                    args=(target_id, url, process),
                    daemon=True
                )
                waiter.start()
                logger.info(f"Resumed scan {scan['id']} for {url} from '{resume_step}'")

    except Exception as e:
        logger.error(f"Error resuming scans: {e}")
