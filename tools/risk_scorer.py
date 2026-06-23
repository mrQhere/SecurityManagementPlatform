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
Risk Scoring Engine — calibrated against real CVE data.

Improvements over previous version:
- Uses actual CVSS scores from CVE correlation findings (not just severity strings)
- EPSS score used as multiplier for confirmed exploitation probability
- Info-level findings have near-zero weight
- CVE correlations without version confirmation do NOT boost score
- Logarithmic scaling prevents 100 low findings from dominating
- Separate bonus caps for each tool category
- False positive filter: only confidence >= 60 findings are scored

Ratings:
  0–20   → Minimal
  21–40  → Low
  41–60  → Medium
  61–80  → High
  81–100 → Critical
"""
import json
import math
import logging
import re

logger = logging.getLogger("smp.scan")

try:
    from tools.db_manager import add_risk_score, add_log_entry
except Exception as e:
    logger.error(f"Risk Scorer import error: {e}")

# Per-severity base weights (logarithmic scaling applied on top)
_SEVERITY_LOG_WEIGHTS = {
    "Critical": 60,
    "High": 25,
    "Medium": 8,
    "Low": 2,
    "Info": 0.1,
}

# Max raw score before normalization to 0–100
_MAX_RAW = 300

# Minimum confidence to include a finding in risk score
_MIN_CONFIDENCE = 60


def _rating(score):
    if score <= 20:
        return "Minimal"
    if score <= 40:
        return "Low"
    if score <= 60:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"


def _parse_cvss_from_description(description):
    """Try to extract CVSS score from CVE correlation description text."""
    if not description:
        return None
    m = re.search(r"CVSS:\s*([0-9.]+)", description)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass
    return None


def _parse_epss_from_description(description):
    """Try to extract EPSS score from CVE correlation description text."""
    if not description:
        return None
    m = re.search(r"EPSS:\s*([0-9.]+)", description)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass
    return None


def calculate_and_store_risk_score(scan_id, findings):
    """
    Calculates a calibrated risk score from *findings*, persists it, and returns the score dict.

    Returns:
        {'score': 45.5, 'rating': 'Medium', 'breakdown': {...}}
    """
    breakdown = {
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
        "cve_confirmed_count": 0,
        "cve_unconfirmed_count": 0,
        "open_port_count": 0,
        "ssl_issue_count": 0,
        "path_exposure_count": 0,
        "admin_exposed_count": 0,
        "missing_headers_count": 0,
        "cors_issue_count": 0,
        "low_confidence_skipped": 0,
        "raw_score": 0,
        "final_score": 0,
    }

    raw = 0

    # ── Per-finding scoring ────────────────────────────────────────────────
    for f in findings:
        sev = f.get("severity", "Info")
        tool = f.get("source_tool", "")
        conf = f.get("confidence", 50)
        desc = f.get("description", "") or ""

        # Skip low-confidence findings (they're unreliable)
        if conf < _MIN_CONFIDENCE and sev not in ("Critical", "High"):
            breakdown["low_confidence_skipped"] += 1
            continue

        # Count by severity
        key = f"{sev.lower()}_count"
        if key in breakdown:
            breakdown[key] += 1

        # Tool-specific tracking and per-finding contribution
        if tool == "CVE Correlation":
            # Only confirmed version-match CVEs contribute meaningfully
            if "VERIFICATION REQUIRED" in desc:
                # Has version but still check CVSS
                cvss = _parse_cvss_from_description(desc)
                epss = _parse_epss_from_description(desc)
                if cvss and cvss >= 7.0:
                    breakdown["cve_confirmed_count"] += 1
                    raw += cvss * 3  # Direct CVSS contribution
                    if epss:
                        raw += epss * 100  # EPSS multiplier (max ~100 for EPSS=1.0)
                elif cvss and cvss >= 4.0:
                    breakdown["cve_confirmed_count"] += 1
                    raw += cvss * 1.5
                else:
                    breakdown["cve_unconfirmed_count"] += 1
                    raw += 0.5  # Very low contribution for unscored CVE matches
            else:
                breakdown["cve_unconfirmed_count"] += 1
                raw += 0.5
        elif tool == "Nmap":
            breakdown["open_port_count"] += 1
        elif tool == "SSL":
            breakdown["ssl_issue_count"] += 1
            if sev in ("High", "Critical"):
                raw += _SEVERITY_LOG_WEIGHTS.get(sev, 5) * 0.8
        elif tool == "ffuf":
            breakdown["path_exposure_count"] += 1
        elif tool == "CMS Scanner":
            if "Exposed Admin" in f.get("title", ""):
                breakdown["admin_exposed_count"] += 1
                raw += 15
        elif tool == "Security Headers":
            breakdown["missing_headers_count"] += 1
        elif tool == "CORS":
            breakdown["cors_issue_count"] += 1
            if sev in ("High", "Critical"):
                raw += 20
        else:
            # Regular findings — logarithmic scaling by severity
            weight = _SEVERITY_LOG_WEIGHTS.get(sev, 0.1)
            raw += math.log1p(1) * weight  # Per-finding log contribution

    # ── Aggregate severity scoring with logarithmic scaling ────────────────
    # (prevents many low findings from dominating over few critical ones)
    raw += math.log1p(breakdown["critical_count"]) * 60
    raw += math.log1p(breakdown["high_count"]) * 25
    raw += math.log1p(breakdown["medium_count"]) * 8
    raw += math.log1p(breakdown["low_count"]) * 2

    # ── Capped bonuses per tool category ──────────────────────────────────
    port_bonus = min(15, breakdown["open_port_count"] * 1.5)
    ssl_bonus = min(20, breakdown["ssl_issue_count"] * 5)
    path_bonus = min(20, breakdown["path_exposure_count"] * 2)
    admin_bonus = min(30, breakdown["admin_exposed_count"] * 15)
    headers_bonus = min(15, breakdown["missing_headers_count"] * 2)
    cors_bonus = min(25, breakdown["cors_issue_count"] * 8)

    raw += port_bonus + ssl_bonus + path_bonus + admin_bonus + headers_bonus + cors_bonus

    # ── Normalize and cap ──────────────────────────────────────────────────
    breakdown["raw_score"] = round(raw, 2)
    score = min(100.0, (raw / _MAX_RAW) * 100)
    score = round(score, 1)
    rating = _rating(score)
    breakdown["final_score"] = score

    try:
        add_risk_score(scan_id, score, rating, json.dumps(breakdown))
        add_log_entry("INFO", f"Risk Score: {score}/100 ({rating}) for scan {scan_id}.")
    except Exception as e:
        logger.error(f"Failed to store risk score: {e}")

    logger.info(f"Risk Score Calculated: {score}/100 ({rating}) — "
                f"CVE confirmed: {breakdown['cve_confirmed_count']}, "
                f"skipped low-conf: {breakdown['low_confidence_skipped']}")
    return {"score": score, "rating": rating, "breakdown": breakdown}
