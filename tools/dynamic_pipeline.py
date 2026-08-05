"""
Dynamic Pipeline — SMP V9.2.3
==============================
Stage-feeding scan pipeline inspired by the PentestGPT multi-stage approach.

Instead of a rigid sequential list, this module makes the pipeline *adaptive*:
- Phase 1 (Recon) runs fast OSINT tools and collects findings.
- The results are analysed and used to decide which Phase 2 (Active) scanners
  to prioritise or add dynamically.
- Phase 3 (Exploit) scanners are only triggered when Phase 2 finds evidence
  that makes them relevant (e.g. WordPress found → WPScan; open 22 → Hydra).

Key design decisions taken from PentestGPT:
- Each stage feeds the next via a typed result dict.
- Branching logic is deterministic (no LLM required) — based on technology
  and finding data already in the SMP database.
- All branching decisions are logged through narrative_logger for transparency.

Usage:
    from tools.dynamic_pipeline import DynamicPipeline
    pipeline = DynamicPipeline(scan_id=42, target_url="https://example.com", settings={})
    pipeline.run()
"""

import logging
from typing import Callable

logger = logging.getLogger("smp.pipeline")


# ── Stage definitions ─────────────────────────────────────────────────────────

# Phase 1 — Passive OSINT (always runs)
PHASE_RECON: list[str] = [
    "httpx",
    "whatweb",
    "subfinder",
    "crtsh",
    "hackertarget",
    "whois",
    "wayback",
    "theharvester",
    "traceroute",
]

# Phase 2 — Active scanning (always runs)
PHASE_ACTIVE_CORE: list[str] = [
    "nmap",
    "ssl",
    "headers",
    "robots",
    "cors",
    "cms",
    "nikto",
    "nuclei",
    "ffuf",
    "open_redirect",
    "tech_fingerprint",
    "wapiti",
    "sqlmap",
    "shodan",
    "gitleaks",
]

# Phase 3 — Deep exploit scanners (conditionally activated by stage-feeding)
PHASE_EXPLOIT_CONDITIONAL: dict[str, dict] = {
    "wpscan":      {"condition": "wordpress_detected",   "reason": "WordPress CMS detected"},
    "dalfox":      {"condition": "xss_params_found",     "reason": "URL parameters found — XSS surface"},
    "arjun":       {"condition": "params_found",         "reason": "HTTP parameters discovered"},
    "dnsx":        {"condition": "subdomains_found",     "reason": "Subdomains found — full DNS enumeration"},
    "katana":      {"condition": "web_app_detected",     "reason": "Web application detected — crawling endpoints"},
    "commix":      {"condition": "form_inputs_found",    "reason": "Form inputs found — command injection surface"},
    "jwt":         {"condition": "jwt_tokens_found",     "reason": "JWT tokens found in HTTP responses"},
    "masscan":     {"condition": "large_port_range",     "reason": "Large host — full-range port scan needed"},
    "paramspider": {"condition": "params_found",         "reason": "URL parameters found — mining from archives"},
    "cloud_enum":  {"condition": "cloud_references",     "reason": "Cloud provider references detected"},
    "hydra":       {"condition": "ssh_open",             "reason": "SSH port 22 open — brute-force surface"},
    "zap":         {"condition": "zap_enabled",          "reason": "OWASP ZAP enabled in settings"},
}


# ── Condition evaluators ──────────────────────────────────────────────────────

def _evaluate_conditions(scan_id: int, settings: dict) -> dict[str, bool]:
    """
    Evaluate all branch conditions based on current scan data.

    Returns a dict mapping condition_name -> bool.
    """
    conditions: dict[str, bool] = {}

    try:
        from tools.db_manager import get_technologies_for_scan, get_findings_for_scan
        technologies = list(get_technologies_for_scan(scan_id))
        findings = list(get_findings_for_scan(scan_id))

        tech_names_lower = " ".join(
            (t.get("name", "") + " " + t.get("category", "")).lower()
            for t in technologies
        )
        finding_titles_lower = " ".join(
            f.get("title", "").lower() for f in findings
        )
        combined = tech_names_lower + " " + finding_titles_lower

        conditions["wordpress_detected"] = "wordpress" in combined or "wp-" in combined
        conditions["xss_params_found"]   = "parameter" in combined or "xss" in combined
        conditions["params_found"]        = "parameter" in combined or "form" in combined
        conditions["subdomains_found"]    = any(
            "subdomain" in f.get("title", "").lower() for f in findings
        )
        conditions["web_app_detected"]    = any(
            t.get("category", "").lower() in ("cms", "framework", "web server")
            for t in technologies
        )
        conditions["form_inputs_found"]   = "form" in combined or "input" in combined
        conditions["jwt_tokens_found"]    = "jwt" in combined or "bearer" in combined
        conditions["large_port_range"]    = "port" in combined
        conditions["cloud_references"]    = any(
            kw in combined
            for kw in ("s3", "amazonaws", "azure", "blob", "gcp", "googleapis")
        )
        conditions["ssh_open"]            = "port 22" in combined or "ssh" in combined

    except Exception as e:
        logger.warning(f"[DynamicPipeline] Condition evaluation error: {e}")
        # Default all to False on error — safe degradation to linear pipeline
        for key in PHASE_EXPLOIT_CONDITIONAL:
            conditions.setdefault(PHASE_EXPLOIT_CONDITIONAL[key]["condition"], False)

    # Settings-based conditions
    conditions["zap_enabled"] = bool(settings.get("zap_enabled", False))

    return conditions


# ── Pipeline orchestrator ─────────────────────────────────────────────────────

class DynamicPipeline:
    """
    Adaptive scan pipeline with stage-feeding.

    The pipeline runs in three phases. After Phase 1 and Phase 2, it evaluates
    conditions based on discovered data and dynamically activates additional
    scanners for Phase 3 before executing them.

    Args:
        scan_id:     Database scan ID.
        target_url:  URL to scan.
        settings:    Current settings dict from config_manager.
        runner:      Callable(scanner_name, target_url, scan_id, settings) -> dict.
                     If None, falls back to scan_runner.run_single_scanner.
    """

    def __init__(
        self,
        scan_id: int,
        target_url: str,
        settings: dict,
        runner: Callable | None = None,
    ):
        self.scan_id = scan_id
        self.target_url = target_url
        self.settings = settings
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(scanner: str, target_url: str, scan_id: int, settings: dict) -> dict:
        """Delegate to the existing scan_runner single-scanner execution."""
        try:
            from scanners.scan_runner import run_single_scanner
            return run_single_scanner(scanner, target_url, scan_id, settings)
        except Exception as e:
            logger.error(f"[DynamicPipeline] Runner error for {scanner}: {e}")
            return {"success": False, "data": None, "raw_output": str(e)}

    def _run_phase(self, phase_name: str, scanners: list[str]) -> None:
        """Execute a list of scanners as a named phase."""
        from tools.narrative_logger import emit_stage, emit_scanner_start, emit_finding

        emit_stage(self.scan_id, phase_name, "started")
        logger.info(f"[DynamicPipeline][scan={self.scan_id}] Phase '{phase_name}' starting — {len(scanners)} scanners.")

        for scanner in scanners:
            try:
                emit_scanner_start(self.scan_id, scanner)
                result = self._runner(scanner, self.target_url, self.scan_id, self.settings)
                if result.get("success"):
                    logger.info(f"[DynamicPipeline] {scanner} completed successfully.")
                else:
                    logger.warning(f"[DynamicPipeline] {scanner} returned no results.")
            except Exception as e:
                logger.error(f"[DynamicPipeline] {scanner} raised: {e}")

        emit_stage(self.scan_id, phase_name, "completed")
        logger.info(f"[DynamicPipeline][scan={self.scan_id}] Phase '{phase_name}' completed.")

    def _select_phase3_scanners(self) -> list[str]:
        """
        Evaluate conditions and build the Phase 3 scanner list.

        Returns:
            List of scanner names to run in Phase 3.
        """
        from tools.narrative_logger import emit_branch

        conditions = _evaluate_conditions(self.scan_id, self.settings)
        selected: list[str] = []

        for scanner, meta in PHASE_EXPLOIT_CONDITIONAL.items():
            condition_key = meta["condition"]
            reason = meta["reason"]
            if conditions.get(condition_key, False):
                selected.append(scanner)
                emit_branch(self.scan_id, "phase2", scanner, reason)
                logger.info(f"[DynamicPipeline] Activating '{scanner}' — {reason}")
            else:
                logger.debug(f"[DynamicPipeline] Skipping '{scanner}' — condition '{condition_key}' not met.")

        return selected

    def run(self) -> None:
        """
        Execute the full three-phase adaptive pipeline.

        Phase 1: Passive OSINT  (fixed)
        Phase 2: Active scanning (fixed)
        Phase 3: Exploit scanners (dynamically selected based on Phase 1+2 findings)
        Phase 4: Post-processing (CVE correlation, risk scoring, report generation)
        """
        from tools.narrative_logger import emit

        emit(self.scan_id, "pipeline", f"Adaptive pipeline starting for target: {self.target_url}")
        logger.info(f"[DynamicPipeline] Starting adaptive scan for {self.target_url} (scan_id={self.scan_id})")

        # Phase 1 — Recon
        self._run_phase("recon", PHASE_RECON)

        # Phase 2 — Active core
        self._run_phase("active", PHASE_ACTIVE_CORE)

        # Stage-feeding: evaluate Phase 1+2 results and build Phase 3
        emit(self.scan_id, "pipeline", "Evaluating Phase 1 and 2 results to determine Phase 3 scanners...")
        phase3_scanners = self._select_phase3_scanners()

        if phase3_scanners:
            emit(
                self.scan_id, "pipeline",
                f"Phase 3 activated with {len(phase3_scanners)} conditional scanner(s): "
                + ", ".join(phase3_scanners)
            )
            self._run_phase("exploit", phase3_scanners)
        else:
            emit(self.scan_id, "pipeline", "No conditional scanners activated — Phase 3 skipped.")

        # Phase 4 — Post-processing
        self._run_phase("report", ["cve_correlation", "risk_scoring", "report"])

        emit(self.scan_id, "pipeline", "Adaptive pipeline complete.")
        logger.info(f"[DynamicPipeline] Scan {self.scan_id} complete.")
# Made by mrQhere
