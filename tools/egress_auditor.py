"""
Egress Auditor — V7
====================
Tracks every outbound network request SMP makes during a scan session and
writes a structured audit log to logs/egress_audit.log.

This enables provable data-locality: at the end of a scan, a client can see
exactly which external hosts were contacted, for what purpose, and what data
class was involved.

Usage:
    from tools.egress_auditor import egress_auditor, local_only_mode_active

    # Check mode before making any external call:
    egress_auditor.record("NVD API", "https://services.nvd.nist.gov/...", "CVE enrichment")

    # Or decorate a function to auto-block it in local-only mode:
    @egress_auditor.guard("GreyNoise", "IP reputation lookup")
    def query_greynoise(ip):
        ...

Configuration:
    Set SMP_LOCAL_ONLY=1 in environment, or toggle in Settings → Local-Only Mode.
    In local-only mode, all guarded outbound calls are blocked and logged as BLOCKED.
"""
import os
import json
import logging
import threading
import functools
from datetime import datetime, timezone
from typing import Optional

from tools.config_manager import BASE_DIR

logger = logging.getLogger("smp")

_LOG_DIR  = os.path.join(BASE_DIR, "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "egress_audit.log")
_LOCK     = threading.Lock()

# ── Local-only mode ───────────────────────────────────────────────────────────
# Activated by: SMP_LOCAL_ONLY=1 env var, or config setting "local_only_mode": true
def local_only_mode_active() -> bool:
    """Return True if no outbound calls should be made (except explicitly allowed ones)."""
    if os.environ.get("SMP_LOCAL_ONLY", "").strip() in ("1", "true", "yes"):
        return True
    try:
        from tools.config_manager import load_settings
        return bool(load_settings().get("local_only_mode", False))
    except Exception:
        return False


class EgressAuditor:
    """
    Records every outbound call the platform makes, with:
      - timestamp (UTC)
      - caller/service name
      - destination URL
      - purpose/data class
      - whether the call was allowed or blocked (local-only mode)
    """

    def __init__(self):
        self._session_log: list[dict] = []
        os.makedirs(_LOG_DIR, exist_ok=True)

    # ── Core record method ────────────────────────────────────────────────────
    def record(
        self,
        service: str,
        url: str,
        purpose: str,
        blocked: bool = False,
    ) -> None:
        """
        Record an outbound call attempt.

        Args:
            service:  Name of the intelligence source (e.g. "NVD", "GreyNoise")
            url:      Full destination URL (may be truncated to hide secrets)
            purpose:  Human-readable reason (e.g. "CVE EPSS enrichment")
            blocked:  True if the call was suppressed by local-only mode
        """
        entry = {
            "ts":      datetime.now(timezone.utc).isoformat(),
            "service": service,
            "url":     url,
            "purpose": purpose,
            "status":  "BLOCKED" if blocked else "ALLOWED",
        }
        with _LOCK:
            self._session_log.append(entry)
            try:
                with open(_LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except OSError as exc:
                logger.warning(f"[EgressAudit] Could not write to audit log: {exc}")

        if blocked:
            logger.info(
                f"[EgressAudit] BLOCKED {service} → {url[:80]} (local-only mode active)"
            )
        else:
            logger.debug(f"[EgressAudit] ALLOWED {service} → {url[:80]}")

    # ── Decorator / guard ─────────────────────────────────────────────────────
    def guard(self, service: str, purpose: str, url_kwarg: str = "url"):
        """
        Decorator that records the call and blocks it when local-only mode is active.

        The decorated function must either accept `url` as a positional argument
        or have it accessible via the keyword named by `url_kwarg`.

        Example:
            @egress_auditor.guard("GreyNoise", "IP reputation lookup")
            def check_ip(ip, url="https://api.greynoise.io/..."):
                ...
        """
        def decorator(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                # Best-effort URL extraction for logging
                dest = kwargs.get(url_kwarg, "")
                if not dest and args:
                    dest = str(args[0])

                if local_only_mode_active():
                    self.record(service, dest or "(url unknown)", purpose, blocked=True)
                    return None  # Suppress the call silently

                self.record(service, dest or "(url unknown)", purpose, blocked=False)
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    # ── Session summary ───────────────────────────────────────────────────────
    def get_session_summary(self) -> dict:
        """
        Return a summary of all outbound calls in the current session.
        Useful for appending to scan reports as a data-locality proof.
        """
        with _LOCK:
            log = list(self._session_log)

        allowed = [e for e in log if e["status"] == "ALLOWED"]
        blocked = [e for e in log if e["status"] == "BLOCKED"]
        services = sorted({e["service"] for e in allowed})

        return {
            "total_outbound_calls": len(log),
            "allowed":              len(allowed),
            "blocked":              len(blocked),
            "external_services":    services,
            "local_only_mode":      local_only_mode_active(),
            "audit_log_path":       _LOG_FILE,
            "entries":              log,
        }

    def reset_session(self) -> None:
        """Clear in-memory session log (called at start of each scan)."""
        with _LOCK:
            self._session_log.clear()

    def get_audit_log_path(self) -> str:
        return _LOG_FILE


# Singleton — import this everywhere
egress_auditor = EgressAuditor()
