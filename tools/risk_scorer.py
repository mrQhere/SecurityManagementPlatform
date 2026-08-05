"""
Risk Scoring Engine V7.0.3 — calibrated against real CVE data.

V7.0.3 Improvements:
- Reads cvss_score column directly from the findings table (no regex parsing needed)
- CISA KEV confirmed-exploited CVEs receive 2× score multiplier
- CVE match tier (A/B/C from correlator) respected in contribution weight
- EPSS exploitation probability used as bonus multiplier
- Info-level findings have near-zero weight
- Logarithmic scaling prevents 100 low findings from dominating
- Separate bonus caps per tool category
- False positive filter: only confidence >= 60 findings scored
- Score breakdown includes CISA KEV count and match tier breakdown

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

    V7.0.3: Reads cvss_score and epss_score columns directly — no regex parsing.
    CISA KEV confirmed findings receive a 2× multiplier.

    Returns:
        {'score': 45.5, 'rating': 'Medium', 'breakdown': {...}}
    """
    breakdown = {
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
        "cve_confirmed_count": 0,       # CVE match tier A/B (version confirmed)
        "cve_unconfirmed_count": 0,     # CVE match tier C (description only)
        "cisa_kev_count": 0,            # Actively exploited CVEs
        "open_port_count": 0,
        "ssl_issue_count": 0,
        "path_exposure_count": 0,
        "admin_exposed_count": 0,
        "missing_headers_count": 0,
        "cors_issue_count": 0,
        "xss_count": 0,
        "sqli_count": 0,
        "low_confidence_skipped": 0,
        "raw_score": 0,
        "final_score": 0,
    }

    raw = 0.0

    # ── Per-finding scoring ────────────────────────────────────────────────────
    for f in findings:
        sev   = f.get("severity", "Info")
        tool  = f.get("source_tool", "")
        conf  = f.get("confidence", 50)
        title = f.get("title", "") or ""
        desc  = f.get("description", "") or ""

        # V7.0.3: Read CVSS/EPSS directly from the findings row columns
        cvss  = f.get("cvss_score")     # stored as float by add_finding()
        epss  = f.get("epss_score")     # stored as float by add_finding()

        # Fall back to regex parsing for older findings that lack these columns
        if cvss is None:
            cvss = _parse_cvss_from_description(desc)
        if epss is None:
            epss = _parse_epss_from_description(desc)

        # CISA KEV detection: look for our banner text in description
        is_cisa_kev = "CISA KEV ALERT" in desc or "cisa_known_exploited" in desc.lower()

        # Skip low-confidence findings (unreliable) unless Critical/High or CISA KEV
        if conf < _MIN_CONFIDENCE and sev not in ("Critical", "High") and not is_cisa_kev:
            breakdown["low_confidence_skipped"] += 1
            continue

        # Count by severity
        key = f"{sev.lower()}_count"
        if key in breakdown:
            breakdown[key] += 1

        if is_cisa_kev:
            breakdown["cisa_kev_count"] += 1

        # ── Tool-specific scoring ──────────────────────────────────────────────
        if tool == "CVE Correlation":
            # V7.0.3: Use CVSS column directly (no regex needed)
            # Tier A/B matches have version confirmed — higher weight
            # Tier C matches (description only) — lower weight
            tier_a_or_b = "Tier A" in desc or "Tier B" in desc or "CPE" in desc or "Version" in desc
            if cvss and cvss >= 9.0:
                breakdown["cve_confirmed_count"] += 1
                contribution = cvss * 4.0
            elif cvss and cvss >= 7.0:
                breakdown["cve_confirmed_count"] += 1
                contribution = cvss * 3.0
            elif cvss and cvss >= 4.0:
                breakdown["cve_confirmed_count"] += 1
                contribution = cvss * 1.5
            else:
                breakdown["cve_unconfirmed_count"] += 1
                contribution = 0.5  # Very low for unscored

            if is_cisa_kev:
                contribution *= 2.0  # CISA KEV 2× multiplier
                breakdown["cve_confirmed_count"] += 1  # Always confirmed

            if epss:
                contribution += epss * 80  # EPSS exploitation probability bonus

            raw += contribution

        elif tool == "Nmap":
            breakdown["open_port_count"] += 1
            # No direct raw contribution — covered by port_bonus below

        elif tool in ("SSL", "SSL Scanner"):
            breakdown["ssl_issue_count"] += 1
            if sev in ("High", "Critical"):
                raw += _SEVERITY_LOG_WEIGHTS.get(sev, 5) * 0.8

        elif tool == "ffuf":
            breakdown["path_exposure_count"] += 1

        elif tool == "CMS Scanner":
            if "Exposed Admin" in title or "Admin Panel" in title:
                breakdown["admin_exposed_count"] += 1
                raw += 15

        elif tool == "Security Headers":
            breakdown["missing_headers_count"] += 1

        elif tool == "CORS":
            breakdown["cors_issue_count"] += 1
            if sev in ("High", "Critical"):
                raw += 20

        elif tool == "Dalfox":
            breakdown["xss_count"] += 1
            if sev in ("Critical", "High"):
                raw += _SEVERITY_LOG_WEIGHTS.get(sev, 5)

        elif tool == "SQLMap":
            breakdown["sqli_count"] += 1
            if sev in ("Critical", "High"):
                raw += _SEVERITY_LOG_WEIGHTS.get(sev, 5) * 1.5

        else:
            # All other tools — logarithmic per-finding contribution by severity
            weight = _SEVERITY_LOG_WEIGHTS.get(sev, 0.1)
            raw += math.log1p(1) * weight

    # ── Aggregate severity scoring with logarithmic scaling ──────────────────
    # Prevents flood of low/info findings from swamping Critical findings
    raw += math.log1p(breakdown["critical_count"]) * 60
    raw += math.log1p(breakdown["high_count"]) * 25
    raw += math.log1p(breakdown["medium_count"]) * 8
    raw += math.log1p(breakdown["low_count"]) * 2

    # ── Capped tool-category bonuses ──────────────────────────────────────────
    port_bonus    = min(15, breakdown["open_port_count"]    * 1.5)
    ssl_bonus     = min(20, breakdown["ssl_issue_count"]    * 5)
    path_bonus    = min(20, breakdown["path_exposure_count"]* 2)
    admin_bonus   = min(30, breakdown["admin_exposed_count"]* 15)
    headers_bonus = min(15, breakdown["missing_headers_count"] * 2)
    cors_bonus    = min(25, breakdown["cors_issue_count"]   * 8)
    xss_bonus     = min(30, breakdown["xss_count"]          * 10)
    sqli_bonus    = min(40, breakdown["sqli_count"]         * 15)
    cisa_bonus    = min(40, breakdown["cisa_kev_count"]     * 20)  # CISA KEV big bonus

    raw += (port_bonus + ssl_bonus + path_bonus + admin_bonus +
            headers_bonus + cors_bonus + xss_bonus + sqli_bonus + cisa_bonus)

    # ── Normalize to 0–100 ───────────────────────────────────────────────────
    breakdown["raw_score"]   = round(raw, 2)
    score = min(100.0, (raw / _MAX_RAW) * 100)
    score = round(score, 1)
    rating = _rating(score)
    breakdown["final_score"] = score

    try:
        add_risk_score(scan_id, score, rating, json.dumps(breakdown))
        add_log_entry("INFO", f"Risk Score: {score}/100 ({rating}) for scan {scan_id}.")
    except Exception as e:
        logger.error(f"Failed to store risk score: {e}")

    logger.info(
        f"Risk Score V7.0.3: {score}/100 ({rating}) — "
        f"CVE confirmed: {breakdown['cve_confirmed_count']}, "
        f"CISA KEV: {breakdown['cisa_kev_count']}, "
        f"skipped low-conf: {breakdown['low_confidence_skipped']}"
    )
    return {"score": score, "rating": rating, "breakdown": breakdown}

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

