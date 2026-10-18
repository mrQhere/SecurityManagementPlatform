"""
core/execution_gate.py — Unified Server-Side Scan Execution Gate.

Ensures all scanner launches pass through one central security guard
immediately before execution. Verifies:
  1. Cancellation state (aborts if scan was cancelled)
  2. Engagement validity (must be active, not archived or completed)
  3. Authorization validity (unexpired, not revoked; required for intrusive)
  4. Target scope (target string must match active allow rules via ScopeEngine)
  5. Scanner manifest activity level (cannot exceed policy limit)
  6. User policy permissions (must not be denied by policy allowlist/denylist)

Fails closed on any violation with safe diagnostics and no secret leakage.
"""

import logging
from typing import Any, Dict, Optional, Tuple, Union

from core.scanner_manifest import ActivityLevel
from core.scan_policy import ScanPolicy
from core.scope_engine import (
    ScopeEngine,
    is_activity_allowed,
    resolve_activity_level,
)

logger = logging.getLogger("smp.execution_gate")

# Known scanner activity level mapping (manifest defaults)
SCANNER_ACTIVITY_MAP: Dict[str, ActivityLevel] = {
    # Passive
    "whois": ActivityLevel.PASSIVE,
    "whois_scanner": ActivityLevel.PASSIVE,
    "crt.sh": ActivityLevel.PASSIVE,
    "crtsh": ActivityLevel.PASSIVE,
    "wayback": ActivityLevel.PASSIVE,
    "wayback machine": ActivityLevel.PASSIVE,
    "hackertarget": ActivityLevel.PASSIVE,
    "shodan": ActivityLevel.PASSIVE,
    "shodan_idb": ActivityLevel.PASSIVE,
    "dnsx": ActivityLevel.PASSIVE,
    "robots.txt": ActivityLevel.PASSIVE,
    "robots_scanner": ActivityLevel.PASSIVE,
    "security headers": ActivityLevel.PASSIVE,
    "headers_scanner": ActivityLevel.PASSIVE,
    "tech fingerprint": ActivityLevel.PASSIVE,
    "tech_fingerprint": ActivityLevel.PASSIVE,
    "whatweb": ActivityLevel.PASSIVE,
    "subfinder": ActivityLevel.PASSIVE,
    "amass": ActivityLevel.PASSIVE,
    "gau_scanner": ActivityLevel.PASSIVE,
    "offline_cve": ActivityLevel.PASSIVE,
    "detect_secrets": ActivityLevel.PASSIVE,
    "gitleaks": ActivityLevel.PASSIVE,
    "theharvester": ActivityLevel.PASSIVE,

    # Low-Impact Active
    "httpx": ActivityLevel.LOW_IMPACT_ACTIVE,
    "httpx_scanner": ActivityLevel.LOW_IMPACT_ACTIVE,
    "screenshot_capture": ActivityLevel.LOW_IMPACT_ACTIVE,
    "ssl": ActivityLevel.LOW_IMPACT_ACTIVE,
    "ssl_scanner": ActivityLevel.LOW_IMPACT_ACTIVE,
    "sslyze_scanner": ActivityLevel.LOW_IMPACT_ACTIVE,
    "wafw00f": ActivityLevel.LOW_IMPACT_ACTIVE,
    "cmseek": ActivityLevel.LOW_IMPACT_ACTIVE,
    "cms_scanner": ActivityLevel.LOW_IMPACT_ACTIVE,
    "cors": ActivityLevel.LOW_IMPACT_ACTIVE,
    "cors_scanner": ActivityLevel.LOW_IMPACT_ACTIVE,
    "corscanner": ActivityLevel.LOW_IMPACT_ACTIVE,

    # Active
    "nmap": ActivityLevel.ACTIVE,
    "masscan": ActivityLevel.ACTIVE,
    "naabu": ActivityLevel.ACTIVE,
    "netcat_probe": ActivityLevel.ACTIVE,
    "gobuster": ActivityLevel.ACTIVE,
    "ffuf": ActivityLevel.ACTIVE,
    "dirb": ActivityLevel.ACTIVE,
    "feroxbuster": ActivityLevel.ACTIVE,
    "paramspider": ActivityLevel.ACTIVE,
    "katana": ActivityLevel.ACTIVE,
    "hakrawler": ActivityLevel.ACTIVE,
    "open redirect": ActivityLevel.ACTIVE,
    "open_redirect": ActivityLevel.ACTIVE,
    "crlf_scanner": ActivityLevel.ACTIVE,
    "path_traversal": ActivityLevel.ACTIVE,
    "jwt scanner": ActivityLevel.ACTIVE,
    "jwt_scanner": ActivityLevel.ACTIVE,
    "wpscan": ActivityLevel.ACTIVE,
    "droopescan": ActivityLevel.ACTIVE,
    "joomscan": ActivityLevel.ACTIVE,
    "traceroute": ActivityLevel.ACTIVE,

    # Intrusive
    "nuclei": ActivityLevel.INTRUSIVE,
    "nikto": ActivityLevel.INTRUSIVE,
    "zap": ActivityLevel.INTRUSIVE,
    "wapiti": ActivityLevel.INTRUSIVE,
    "sqlmap": ActivityLevel.INTRUSIVE,
    "sqlninja": ActivityLevel.INTRUSIVE,
    "nosqlmap": ActivityLevel.INTRUSIVE,
    "commix": ActivityLevel.INTRUSIVE,
    "dalfox": ActivityLevel.INTRUSIVE,
    "xsstrike": ActivityLevel.INTRUSIVE,
    "arjun": ActivityLevel.INTRUSIVE,
    "tplmap": ActivityLevel.INTRUSIVE,
    "lfisuite": ActivityLevel.INTRUSIVE,
    "race-the-web": ActivityLevel.INTRUSIVE,
    "race_the_web": ActivityLevel.INTRUSIVE,
    "race-the-web scanner": ActivityLevel.INTRUSIVE,
    "ppmap": ActivityLevel.INTRUSIVE,
    "prototype pollution scanner": ActivityLevel.INTRUSIVE,
    "idor": ActivityLevel.INTRUSIVE,
    "idor scanner": ActivityLevel.INTRUSIVE,
    "idor_scanner": ActivityLevel.INTRUSIVE,
    "wscat": ActivityLevel.INTRUSIVE,
    "websocket scanner": ActivityLevel.INTRUSIVE,
    "wscat_scanner": ActivityLevel.INTRUSIVE,
    "api_fuzzer": ActivityLevel.INTRUSIVE,
    "graphql_scanner": ActivityLevel.INTRUSIVE,
    "smuggler": ActivityLevel.INTRUSIVE,
    "ssrf_scanner": ActivityLevel.INTRUSIVE,
    "ssrfmap_ext": ActivityLevel.INTRUSIVE,
    "xxe_scanner": ActivityLevel.INTRUSIVE,
    "hydra_scanner": ActivityLevel.INTRUSIVE,
    "msfconsole": ActivityLevel.INTRUSIVE,
    "openvas": ActivityLevel.INTRUSIVE,
    "arachni": ActivityLevel.INTRUSIVE,
}


def get_scanner_activity_level(scanner_name: str) -> ActivityLevel:
    """Resolve an activity level for a scanner name based on manifest metadata or registry."""
    if not scanner_name or not isinstance(scanner_name, str):
        return ActivityLevel.ACTIVE

    clean_name = scanner_name.strip()
    if clean_name.startswith("Running "):
        clean_name = clean_name[8:].strip()
    lower_name = clean_name.lower()

    if lower_name in SCANNER_ACTIVITY_MAP:
        return SCANNER_ACTIVITY_MAP[lower_name]

    # Check adapter registry if available
    try:
        from scanners.adapters.nmap_adapter import NmapAdapter
        if lower_name == "nmap":
            return ActivityLevel(NmapAdapter.MANIFEST.get("activity_level", "ACTIVE"))
    except Exception:
        pass

    # Heuristic for unknown scanner names
    if any(k in lower_name for k in ("exploit", "fuzz", "inject", "rce", "sqli", "xss")):
        return ActivityLevel.INTRUSIVE

    return ActivityLevel.ACTIVE


def verify_scan_execution(
    target: str,
    scanner_name: Optional[str] = None,
    scanner_activity: Optional[Union[ActivityLevel, str]] = None,
    engagement_id: Optional[str] = None,
    engagement: Optional[Any] = None,
    auth_id: Optional[str] = None,
    scan_policy: Optional[Union[ScanPolicy, dict]] = None,
    cancel_event: Optional[Any] = None,
    scope_engine: Optional[ScopeEngine] = None,
) -> Tuple[bool, str]:
    """
    Central server-side execution gate.

    Verifies engagement, authorization validity, target scope, scanner manifest
    activity, user policy, and cancellation state immediately before execution.

    Returns:
        tuple (allowed: bool, reason: str)
    """
    # ── 0. Target Validation ──────────────────────────────────────────────────
    if not target or not isinstance(target, str):
        msg = "Invalid target specification"
        logger.warning(f"[ExecutionGate] Blocked: {msg}")
        return False, msg

    from core.url_validator import parse_and_canonicalize_url, check_destination_allowed
    from tools.errors import SMPInvalidTargetError

    parsed_target = None
    target_to_check = target
    try:
        if "://" in target:
            parsed_target = parse_and_canonicalize_url(target)
            target_to_check = parsed_target.url
        elif any(ord(c) < 32 or ord(c) == 127 for c in target) or "@" in target:
            msg = "Target contains invalid control characters or credentials"
            logger.warning(f"[ExecutionGate] Blocked: {msg}")
            return False, msg
        else:
            try:
                parsed_target = parse_and_canonicalize_url(f"http://{target}")
            except SMPInvalidTargetError:
                pass
    except SMPInvalidTargetError as url_err:
        msg = f"Invalid target: {url_err}"
        logger.warning(f"[ExecutionGate] Blocked: {msg}")
        return False, msg

    # ── 1. Cancellation State Check ───────────────────────────────────────────
    if cancel_event is not None:
        is_cancelled = False
        if cancel_event is True:
            is_cancelled = True
        elif hasattr(cancel_event, "is_set"):
            is_cancelled = cancel_event.is_set()
        elif callable(cancel_event):
            try:
                is_cancelled = bool(cancel_event())
            except Exception:
                is_cancelled = False
        if is_cancelled:
            msg = "Scan execution cancelled by user"
            logger.info(f"[ExecutionGate] {msg} for {target}")
            return False, msg

    # ── 2. Engagement Validity Check ──────────────────────────────────────────
    if engagement is not None:
        eng_status = None
        if hasattr(engagement, "status"):
            eng_status = (
                engagement.status.value
                if hasattr(engagement.status, "value")
                else str(engagement.status)
            )
        elif hasattr(engagement, "data") and isinstance(engagement.data, dict):
            eng_status = engagement.data.get("status")
        elif isinstance(engagement, dict):
            eng_status = engagement.get("status")

        if eng_status and str(eng_status).lower() != "active":
            msg = f"Engagement is {eng_status} (not active)"
            logger.warning(f"[ExecutionGate] Blocked: {msg}")
            return False, msg

        if not engagement_id:
            if hasattr(engagement, "data") and isinstance(engagement.data, dict):
                engagement_id = engagement.data.get("engagement_id")
            elif hasattr(engagement, "engagement_id"):
                engagement_id = str(engagement.engagement_id)
            elif isinstance(engagement, dict):
                engagement_id = engagement.get("engagement_id")

    # ── 3. Scan Policy & Allowlist/Denylist Check ──────────────────────────────
    policy_obj = None
    if isinstance(scan_policy, ScanPolicy):
        policy_obj = scan_policy
    elif isinstance(scan_policy, dict):
        try:
            policy_obj = ScanPolicy(scan_policy)
        except Exception:
            policy_obj = None

    if policy_obj is not None and scanner_name:
        clean_name = scanner_name
        if clean_name.startswith("Running "):
            clean_name = clean_name[8:].strip()
        if not policy_obj.is_scanner_allowed(clean_name) and not policy_obj.is_scanner_allowed(clean_name.lower()):
            msg = f"Scanner '{clean_name}' is not allowed by scan policy"
            logger.warning(f"[ExecutionGate] Blocked: {msg}")
            return False, msg

    # ── 4. Scanner Manifest Activity Check ───────────────────────────────────
    resolved_activity = scanner_activity
    if resolved_activity is None:
        if scanner_name:
            resolved_activity = get_scanner_activity_level(scanner_name)
        elif policy_obj is not None:
            resolved_activity = policy_obj.data.get("activity_level_limit", ActivityLevel.ACTIVE)
        else:
            resolved_activity = ActivityLevel.ACTIVE

    limit = ActivityLevel.ACTIVE
    if policy_obj is not None:
        limit = policy_obj.data.get("activity_level_limit", ActivityLevel.ACTIVE)

    act_ok, act_reason = is_activity_allowed(resolved_activity, limit)
    if not act_ok:
        logger.warning(f"[ExecutionGate] Blocked: {act_reason}")
        return False, act_reason

    # ── 5. Authorization Validity Check ───────────────────────────────────────
    # Intrusive activity requires valid auth_id
    current_activity_enum = resolve_activity_level(resolved_activity)
    if current_activity_enum is not None and current_activity_enum >= ActivityLevel.INTRUSIVE:
        if not auth_id:
            msg = "auth_id is required for intrusive scans"
            logger.warning(f"[ExecutionGate] Blocked: {msg}")
            return False, msg

    if auth_id:
        if isinstance(auth_id, dict):
            from core.authorization import is_authorization_currently_valid
            if not is_authorization_currently_valid(auth_id):
                msg = "Authorization is invalid, expired, or revoked."
                logger.warning(f"[ExecutionGate] Blocked: {msg}")
                return False, msg
        else:
            from core.authorization import AuthorizationTracker
            tracker = AuthorizationTracker()
            if not tracker.is_valid(str(auth_id)):
                msg = f"Authorization {auth_id} is invalid, expired, or revoked."
                logger.warning(f"[ExecutionGate] Blocked: {msg}")
                return False, msg

    # ── 6. Scope Engine Resolution ────────────────────────────────────────────
    if scope_engine is None:
        eng_id = engagement_id
        if not eng_id and engagement is not None:
            if hasattr(engagement, "data") and isinstance(engagement.data, dict):
                eng_id = engagement.data.get("engagement_id")
            elif hasattr(engagement, "engagement_id"):
                eng_id = str(engagement.engagement_id)
            elif isinstance(engagement, dict):
                eng_id = engagement.get("engagement_id")
        eng_id = eng_id or "default"
        scope_engine = ScopeEngine(eng_id, policy=policy_obj)

    # ── 7. Destination Security Check (metadata, loopback, link-local, private) ─
    if parsed_target is not None:
        dest_ok, dest_reason = check_destination_allowed(
            parsed_target,
            policy=policy_obj,
            scope_engine=scope_engine,
        )
        if not dest_ok:
            logger.warning(f"[ExecutionGate] Blocked destination for {target}: {dest_reason}")
            return False, f"Destination forbidden: {dest_reason}"

    # ── 8. Target Scope Check ─────────────────────────────────────────────────
    scope_ok, scope_reason = scope_engine.is_allowed(target_to_check, resolved_activity)
    if not scope_ok:
        logger.warning(f"[ExecutionGate] Scope violation for {target}: {scope_reason}")
        return False, f"Scope violation: {scope_reason}"

    return True, "Execution authorized"
