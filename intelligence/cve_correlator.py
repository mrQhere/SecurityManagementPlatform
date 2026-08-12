"""
CVE-to-Technology Correlation Engine  (V9.4.3)
============================================

Matching strategy (three tiers of confidence):

  Tier A — CPE match (confidence 90–95%)
    Detected product name found in the CVE's affected_products column.
    Most accurate — NVD CPE names are normalised vendor/product identifiers.

  Tier B — Description + version match (confidence 75–85%)
    Tech name appears as a whole word in description AND version appears as
    a bounded token (not substring: "3.4.1" ≠ "3.4.10").

  Tier C — Description-only match with high CVSS/EPSS (confidence 50–65%)
    Tech name whole-word match but no version confirmation.
    Only surfaced when CVSS ≥ 7.0 or EPSS ≥ 0.10 (real exploitation signal).

Filtering rules:
  • CVEs with CVSS < 4.0 AND EPSS < 0.01 are silently skipped (noise reduction).
  • Tech names in the generic blocklist require at least a version match.
  • Duplicate (tech_name, cve_id) pairs are deduplicated per scan.
  • CISA KEV flag (cisa_known_exploited column) triggers a 🔥 CISA KEV banner.
"""
import json
import logging
import re

logger = logging.getLogger("smp.scan")

try:
    from tools.db_manager import (
        get_technologies_for_scan, add_finding, add_log_entry, get_db_connection
    )
except Exception as e:
    logger.error(f"CVE Correlator import error: {e}")


# ── Tunable thresholds ─────────────────────────────────────────────────────────
_MIN_CVSS_SCORE      = 4.0   # Skip informational CVEs below this CVSS
_MIN_EPSS_SCORE      = 0.01  # Skip CVEs with very low exploitation probability
_TIER_C_MIN_CVSS     = 7.0   # For description-only matches, require High+
_TIER_C_MIN_EPSS     = 0.10  # Or an active-exploitation signal

# ── Generic tech names — require version confirmation ─────────────────────────
_TOO_GENERIC = {
    "python", "java", "ruby", "php", "node", "go", "perl", "linux",
    "windows", "android", "ios", "web", "http", "https", "ssl", "tls",
    "tcp", "ip", "dns", "ftp", "smtp", "api", "rest", "json", "xml",
    "html", "css", "js", "sql", "database", "server", "client", "app",
    "nginx", "apache",  # too broad without version
}


def _normalise(text: str) -> str:
    """Lowercase + strip."""
    return text.lower().strip()


def _version_whole_word_pattern(version: str) -> re.Pattern:
    """
    Compile a regex that matches 'version' as a token boundary.
    Prevents '3.4.1' matching '3.4.10' or '13.4.1'.
    """
    escaped = re.escape(version)
    return re.compile(rf"(?<!\d\.){escaped}(?![\.\d])", re.IGNORECASE)


def map_to_mitre_attack(description: str) -> str:
    """Maps CVE description keywords to MITRE ATT&CK tactics (V9.4.3 — expanded)."""
    desc = description.lower()
    tactics = []

    _TACTIC_MAP = [
        (["sql injection", "xss", "cross-site scripting", "code injection",
          "unauthorized access", "bypass authentication", "auth bypass"],
         "TA0001 (Initial Access)"),
        (["privilege escalation", "root access", "admin access", "escalate privileges",
          "local privilege"],
         "TA0004 (Privilege Escalation)"),
        (["remote code execution", " rce ", "execute arbitrary code", "command injection",
          "arbitrary command"],
         "TA0002 (Execution)"),
        (["denial of service", " dos ", " ddos ", "crash", "memory corruption",
          "out-of-memory", "null pointer"],
         "TA0040 (Impact)"),
        (["credentials", "password", "hash dump", "leak", "information disclosure",
          "sensitive data", "plaintext password"],
         "TA0006 (Credential Access)"),
        (["path traversal", "directory traversal", "local file inclusion", " lfi "],
         "TA0005 (Defence Evasion)"),
        (["ssrf", "server-side request forgery", "internal network"],
         "TA0007 (Discovery)"),
        (["xxe", "xml external entity", "xml injection"],
         "TA0009 (Collection)"),
        (["deserialization", "unsafe deserialization", "object injection"],
         "TA0002 (Execution)"),
        (["open redirect", "redirect to", "phishing"],
         "TA0001 (Initial Access)"),
    ]

    seen = set()
    for keywords, tactic in _TACTIC_MAP:
        if any(k in desc for k in keywords) and tactic not in seen:
            tactics.append(tactic)
            seen.add(tactic)

    return ", ".join(tactics) if tactics else "TA0040 (Impact)"


def _get_owasp_category(description: str) -> str:
    """Derive the most relevant OWASP Top 10 category from CVE description."""
    desc = description.lower()
    if any(k in desc for k in ["sql injection", "command injection", "code injection", "xxe", "xss"]):
        return "A03:2021 - Injection"
    if any(k in desc for k in ["broken access control", "path traversal", "idor", "unauthorized"]):
        return "A01:2021 - Broken Access Control"
    if any(k in desc for k in ["cryptographic", "weak cipher", "insecure hash", "md5", "sha1"]):
        return "A02:2021 - Cryptographic Failures"
    if any(k in desc for k in ["default password", "misconfiguration", "debug", "exposed"]):
        return "A05:2021 - Security Misconfiguration"
    if any(k in desc for k in ["outdated", "vulnerable component", "known vulnerability"]):
        return "A06:2021 - Vulnerable and Outdated Components"
    if any(k in desc for k in ["ssrf", "server-side request"]):
        return "A10:2021 - Server-Side Request Forgery"
    if any(k in desc for k in ["authentication", "session fixation", "weak password"]):
        return "A07:2021 - Identification and Authentication Failures"
    return "A06:2021 - Vulnerable and Outdated Components"


def correlate_cves_for_scan(scan_id: int) -> int:
    """
    For every technology detected in *scan_id*, search the CVE database for
    matching advisories using three-tier confidence matching.

    Returns the number of valid correlations added.
    """
    try:
        technologies = get_technologies_for_scan(scan_id)
        add_log_entry("INFO", f"CVE Correlation Started: {len(technologies)} technologies to check.")
    except Exception as e:
        logger.error(f"CVE Correlation Failed during data load: {e}")
        return 0

    if not technologies:
        add_log_entry("INFO", "CVE Correlation Completed: Nothing to correlate.")
        return 0

    correlation_count = 0
    seen_pairs: set = set()  # (tech_name_lower, cve_id) — avoid duplicates per scan

    try:
        conn = get_db_connection()
    except Exception as e:
        logger.error(f"CVE Correlation: Failed to get database connection: {e}")
        return 0

    try:
        for tech in technologies:
            tech_name    = (tech.get("name", "") or "").strip()
            tech_version = (tech.get("version", "") or "").strip()

            if not tech_name:
                continue

            tech_name_lower = _normalise(tech_name)

            # Skip completely generic names that generate massive false-positive lists
            if tech_name_lower in _TOO_GENERIC and not tech_version:
                logger.debug(f"CVE Correlation: Skipping generic name without version: '{tech_name}'")
                continue

            # Whole-word name match regex (prevents "Go" matching "Google")
            escaped_name = re.escape(tech_name)
            word_pattern = re.compile(rf"\b{escaped_name}\b", re.IGNORECASE)

            # Version whole-word token pattern (prevents "3.4.1" matching "3.4.10")
            version_pattern = _version_whole_word_pattern(tech_version) if tech_version else None

            # ── Fetch CVE candidates ─────────────────────────────────────────
            try:
                cursor = conn.cursor()
                # Strategy: Use FTS5 MATCH for high-speed candidate selection
                # Escape double quotes in tech_name to prevent MATCH syntax errors
                safe_tech = tech_name.replace('"', '""')
                match_query = f'"{safe_tech}"'
                
                cursor.execute(
                    "SELECT c.cve, c.title, c.severity, c.description, c.source, "
                    "c.cvss_score, c.epss_score, c.affected_products, "
                    "COALESCE(c.cisa_known_exploited, 0) AS cisa_kev "
                    "FROM cve_db.cves c "
                    "JOIN cve_db.cves_fts f ON c.id = f.rowid "
                    "WHERE cve_db.cves_fts MATCH ?",
                    (match_query,)
                )
                candidates = [dict(row) for row in cursor.fetchall()]
            except Exception as e:
                from tools.errors import SMPUnclassifiedError
                import traceback
                import logging
                logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
                raise SMPUnclassifiedError(str(e))
                # Fallback: older schema without affected_products/cisa_known_exploited
                try:
                    cursor.execute(
                        "SELECT cve, title, severity, description, source, "
                        "cvss_score, epss_score "
                        "FROM cve_db.cves WHERE description LIKE ?",
                        (f"%{tech_name}%",)
                    )
                    candidates = [dict(row) for row in cursor.fetchall()]
                    for c in candidates:
                        c.setdefault("affected_products", "")
                        c.setdefault("cisa_kev", 0)
                except Exception as e2:
                    logger.error(f"CVE Correlation: SQL query failed for '{tech_name}': {e2}")
                    continue

            for cve in candidates:
                cve_id   = cve.get("cve", "")
                desc     = (cve.get("description", "") or "")
                severity = cve.get("severity", "Medium")
                source   = cve.get("source", "")
                cvss     = cve.get("cvss_score")
                epss     = cve.get("epss_score")
                affected = (cve.get("affected_products", "") or "")
                cisa_kev = bool(cve.get("cisa_kev", 0))

                pair_key = (tech_name_lower, cve_id)
                if pair_key in seen_pairs:
                    continue

                # ── Filter: CVSS/EPSS threshold ───────────────────────────────
                cvss_ok = (cvss is not None and cvss >= _MIN_CVSS_SCORE)
                epss_ok = (epss is not None and epss >= _MIN_EPSS_SCORE)
                # CISA KEV = confirmed exploitation — always report regardless of score
                if cisa_kev:
                    cvss_ok = True

                if not cvss_ok and not epss_ok:
                    if severity not in ("High", "Critical"):
                        continue  # Discard low-signal, unscored, non-severe CVEs

                # ── Tier A: CPE / affected_products match (highest confidence) ─
                cpe_match = False
                if affected and tech_name_lower in affected.lower():
                    cpe_match = True

                # ── Tier B/C: Description whole-word match ────────────────────
                if not word_pattern.search(desc) and not cpe_match:
                    continue  # Name not found in either source — skip

                # ── Determine tier and confidence ─────────────────────────────
                if cpe_match and tech_version and version_pattern and version_pattern.search(affected + " " + desc):
                    tier       = "A"   # CPE + version
                    confidence = 95
                elif cpe_match:
                    tier       = "A-"  # CPE name match, no version
                    confidence = 85
                    # Still require version if tech is in generic list
                    if tech_name_lower in _TOO_GENERIC:
                        continue
                elif tech_version and version_pattern and version_pattern.search(desc):
                    tier       = "B"   # Description + version
                    confidence = 80
                else:
                    # Tier C — description-only, no version confirmation
                    # Only report if CVSS ≥ 7.0 or EPSS ≥ 0.10 (strong exploitation signal)
                    if tech_name_lower in _TOO_GENERIC:
                        continue
                    high_cvss = (cvss is not None and cvss >= _TIER_C_MIN_CVSS)
                    high_epss = (epss is not None and epss >= _TIER_C_MIN_EPSS)
                    if not high_cvss and not high_epss and not cisa_kev:
                        continue
                    tier       = "C"
                    confidence = 55

                # Boost confidence for exploitation signals
                if cvss_ok and cvss:
                    confidence = min(97, confidence + int(cvss))
                if epss_ok and epss:
                    confidence = min(97, confidence + 8)
                if cisa_kev:
                    confidence = min(99, confidence + 10)

                seen_pairs.add(pair_key)
                correlation_count += 1

                # ── Format enriched finding description ───────────────────────
                cvss_str    = f" (CVSS: {cvss:.1f})" if cvss else ""
                epss_str    = f" (EPSS: {epss:.4f})" if epss else ""
                tier_labels = {"A": "CPE + Version (High)", "A-": "CPE Match (Medium-High)",
                               "B": "Description + Version (Medium)", "C": "Description Only (Low)"}
                tier_label  = tier_labels.get(tier, tier)

                cisa_banner  = "🔥 [CISA KEV ALERT — Actively Exploited In The Wild]\n" if cisa_kev else ""
                mitre_tactics = map_to_mitre_attack(desc)
                owasp_cat    = _get_owasp_category(desc)

                version_display = f" {tech_version}" if tech_version else " (version unknown)"
                description = (
                    f"Technology Match: {tech_name}{version_display}\n"
                    f"CVE / Advisory:  {cve_id}  [{source}]{cvss_str}{epss_str}\n"
                    f"CVE Severity:    {severity}\n"
                    f"Match Tier:      {tier_label}\n"
                    f"Match Confidence:{confidence}%\n\n"
                    f"{cisa_banner}"
                    f"🛡️  MITRE ATT&CK: {mitre_tactics}\n"
                    f"📋  OWASP:        {owasp_cat}\n\n"
                    f"Description: {desc}\n\n"
                    f"⚠  VERIFICATION REQUIRED: Confirm your specific deployment version "
                    f"is affected before escalating. CPE matches are most reliable; "
                    f"description-only matches require manual verification.\n\n"
                    f"Recommendation: Update {tech_name} to its latest stable release and "
                    f"review the advisory for vendor-specific mitigations."
                )

                try:
                    add_finding(
                        scan_id=scan_id,
                        severity=severity,
                        title=f"[CVE Match] {cve_id} — {tech_name}{version_display}",
                        description=description,
                        source_tool="CVE Correlation",
                        confidence=confidence,
                        cve_id=cve_id,
                        cvss_score=cvss,
                        owasp_category=owasp_cat,
                    )
                except Exception as e:
                    from tools.errors import SMPUnclassifiedError
                    import traceback
                    import logging
                    logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
                    raise SMPUnclassifiedError(str(e))
                    # Retry without optional columns (older schema)
                    try:
                        add_finding(
                            scan_id=scan_id,
                            severity=severity,
                            title=f"[CVE Match] {cve_id} — {tech_name}{version_display}",
                            description=description,
                            source_tool="CVE Correlation",
                            confidence=confidence,
                        )
                    except Exception as e2:
                        logger.error(f"CVE Correlation: Failed to add finding: {e2}")

    finally:
        conn.close()

    logger.info(f"CVE Correlation Completed: {correlation_count} confirmed matches.")
    add_log_entry("INFO", f"CVE Correlation Completed: {correlation_count} confirmed matches.")
    return correlation_count


def does_cve_match_active_targets(cve_id: str, desc: str) -> bool:
    """
    Checks if a newly synced CVE matches any technology currently found on
    actively monitored ('Enabled') targets. Used by the CVE alert engine.

    Returns True only on a whole-word name + version match.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DISTINCT t.name, t.version
            FROM technologies t
            JOIN scans s ON t.scan_id = s.id
            JOIN targets tgt ON s.target_id = tgt.id
            WHERE tgt.status = 'Enabled' AND t.version IS NOT NULL AND t.version != ''
        ''')
        active_techs = [(dict(row)["name"], dict(row).get("version", "")) for row in cursor.fetchall()]
        conn.close()
    except Exception as e:
        logger.error(f"Failed to fetch active technologies for CVE match: {e}")
        return False

    if not active_techs:
        return False

    for tech_name, tech_version in active_techs:
        if not tech_name:
            continue
        if _normalise(tech_name) in _TOO_GENERIC:
            continue
        escaped = re.escape(tech_name)
        if re.search(rf"\b{escaped}\b", desc, re.IGNORECASE):
            if tech_version:
                vp = _version_whole_word_pattern(tech_version)
                if vp.search(desc):
                    return True

    return False
