"""
Finding Deduplicator V9.3.4
==========================
Merges structurally identical findings from multiple scanners into a single
finding with all source scanners cited.

Strategy:
  1. Normalize finding title (lowercase, strip whitespace, scanner prefixes)
  2. Group by (normalized_title, severity) — exact match first
  3. Fuzzy-merge near-duplicate titles (Levenshtein similarity ≥ 0.82)
  4. Keep highest-confidence raw description; merge source tools
"""
import re
import logging

logger = logging.getLogger("smp")

# Patterns to strip from titles before comparison
_STRIP_PATTERNS = [
    r"^\[.*?\]\s*",         # [Scanner] prefix
    r"^(nuclei|nikto|nmap|httpx|dalfox|sqlmap|wapiti|zap|whatweb)[\s:\-]+",
    r"\s+v[\d\.]+\s*$",    # version suffixes
    r"\s+\(.*?\)\s*$",     # parenthetical suffixes
]

# Common title alias groups — any two titles in the same group are treated as identical
_ALIAS_GROUPS: list[frozenset] = [
    frozenset({"sqli", "sql injection", "sql injection confirmed", "sql injection vulnerability"}),
    frozenset({"xss", "cross-site scripting", "cross site scripting", "reflected xss", "stored xss"}),
    frozenset({"missing x-frame-options", "clickjacking", "missing x-frame-options header"}),
    frozenset({"missing content-security-policy", "missing csp", "content security policy missing"}),
    frozenset({"open redirect", "url redirection", "open redirect vulnerability"}),
    frozenset({"ssrf", "server-side request forgery", "server side request forgery"}),
    frozenset({"rce", "remote code execution", "command injection", "remote command execution"}),
    frozenset({"lfi", "local file inclusion", "path traversal", "directory traversal"}),
    frozenset({"xxe", "xml external entity", "xml entity injection"}),
    frozenset({"csrf", "cross-site request forgery", "cross site request forgery"}),
    frozenset({"idor", "insecure direct object reference"}),
    frozenset({"jwt", "jwt weakness", "weak jwt", "jwt misconfiguration"}),
]

# Build lookup: normalized_alias → canonical (first in set)
_ALIAS_MAP: dict[str, str] = {}
for group in _ALIAS_GROUPS:
    canonical = sorted(group)[0]
    for alias in group:
        _ALIAS_MAP[alias] = canonical


def _levenshtein_ratio(a: str, b: str) -> float:
    """Fast Levenshtein similarity ratio between 0.0 and 1.0."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    len_a, len_b = len(a), len(b)
    if abs(len_a - len_b) / max(len_a, len_b) > 0.5:
        return 0.0  # Fast exit if lengths differ too much
    # DP table — one row at a time
    prev = list(range(len_b + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len_b
        for j, cb in enumerate(b, 1):
            curr[j] = min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (0 if ca == cb else 1),
            )
        prev = curr
    dist = prev[len_b]
    return 1.0 - dist / max(len_a, len_b)


def _normalize_title(title: str) -> str:
    """Normalize a finding title for deduplication comparison."""
    t = (title or "").strip().lower()
    for pat in _STRIP_PATTERNS:
        t = re.sub(pat, "", t, flags=re.IGNORECASE).strip()
    t = re.sub(r"\s+", " ", t)
    # Apply alias map
    return _ALIAS_MAP.get(t, t)


def deduplicate_findings(findings: list) -> list:
    """
    Deduplicate a list of finding dicts.

    Each finding dict is expected to have:
        title, severity, tool (optional), description (optional), target_url (optional)

    Returns deduplicated list — merged findings cite all source tools.
    Performs two passes:
      1. Exact key match (normalized_title + severity)
      2. Fuzzy title similarity (≥ 0.82 ratio) within same severity
    """
    if not findings:
        return []

    # Pass 1: exact group by (normalized_title, severity)
    groups: dict[tuple, list] = {}
    for f in findings:
        key = (_normalize_title(f.get("title", "")), (f.get("severity") or "").lower())
        groups.setdefault(key, []).append(f)

    # Pass 2: fuzzy merge across groups with same severity
    keys = list(groups.keys())
    merged_into: dict[int, int] = {}  # index → canonical index

    for i in range(len(keys)):
        if i in merged_into:
            continue
        norm_i, sev_i = keys[i]
        for j in range(i + 1, len(keys)):
            if j in merged_into:
                continue
            norm_j, sev_j = keys[j]
            if sev_i != sev_j:
                continue
            if _levenshtein_ratio(norm_i, norm_j) >= 0.82:
                merged_into[j] = i

    # Build canonical groups
    canonical_groups: dict[int, list] = {}
    for idx, key in enumerate(keys):
        canon = merged_into.get(idx, idx)
        canonical_groups.setdefault(canon, [])
        canonical_groups[canon].extend(groups[key])

    merged = []
    dedup_count = 0

    for _, group in canonical_groups.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        dedup_count += len(group) - 1
        tools: list[str] = []
        best_desc = ""
        best_desc_len = 0
        best_confidence = 0

        for f in group:
            tool = (f.get("tool") or f.get("source_tool") or "").strip()
            if tool and tool not in tools:
                tools.append(tool)
            desc = f.get("description") or ""
            if len(desc) > best_desc_len:
                best_desc = desc
                best_desc_len = len(desc)
            conf = f.get("confidence", 0) or 0
            if conf > best_confidence:
                best_confidence = conf

        base = dict(group[0])
        base["tool"] = ", ".join(tools) if tools else base.get("tool", "Multiple")
        base["description"] = best_desc
        base["confidence"] = best_confidence
        base["deduplicated"] = True
        base["source_count"] = len(group)

        if len(tools) > 1:
            base["description"] += (
                f"\n\n[Dedup Note] Reported by {len(tools)} scanner(s): "
                f"{', '.join(tools)}. Merged by SMP V9.3.4 deduplicator."
            )

        merged.append(base)
        logger.info(
            f"[Dedup] Merged {len(group)} findings → '{group[0].get('title', '')}' "
            f"(tools: {', '.join(tools) or 'unknown'})"
        )

    if dedup_count > 0:
        logger.info(
            f"[Dedup] Complete: {len(findings)} → {len(merged)} "
            f"({dedup_count} duplicate(s) removed)"
        )

    return merged


def deduplicate_db_findings(scan_id: int) -> int:
    """
    Deduplicate findings already stored in the DB for a scan.
    Marks duplicates as soft-deleted (is_deleted=1), keeping the merged record.
    Returns the number of findings removed.
    """
    try:
        from tools.db_manager import get_db_connection, get_findings_for_scan
        findings = list(get_findings_for_scan(scan_id))
        if not findings:
            return 0
        deduped = deduplicate_findings(findings)
        removed = len(findings) - len(deduped)
        if removed == 0:
            return 0

        conn = get_db_connection()
        try:
            conn.execute("UPDATE findings SET is_deleted = 1 WHERE scan_id = ?", (scan_id,))
            for f in deduped:
                conn.execute(
                    """INSERT OR REPLACE INTO findings
                       (scan_id, severity, title, description, tool, confidence, is_deleted)
                       VALUES (?, ?, ?, ?, ?, ?, 0)""",
                    (
                        scan_id,
                        f.get("severity", "Info"),
                        f.get("title", ""),
                        f.get("description", ""),
                        f.get("tool", ""),
                        f.get("confidence", 50),
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        logger.info(f"[Dedup] DB dedup for scan {scan_id}: {len(findings)} → {len(deduped)}")
        return removed
    except Exception as e:
        logger.error(f"[Dedup] DB deduplication failed for scan {scan_id}: {e}")
        return 0
