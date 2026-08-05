"""
Finding Deduplicator V7.0.8
==========================
Merges structurally identical findings from multiple scanners into a single
finding with all source scanners cited (e.g. Nuclei + Nikto both reporting
"Missing X-Frame-Options" → one merged finding: "Nuclei, Nikto").

Strategy:
  1. Normalize finding title (lowercase, strip whitespace, remove scanner name prefixes)
  2. Group by (normalized_title, severity, target_url)
  3. Merge sources into comma-separated "tool" field
  4. Keep highest-confidence raw description
"""
import re
import logging

logger = logging.getLogger("smp")

# Patterns to strip from titles before comparison
_STRIP_PATTERNS = [
    r"^\[.*?\]\s*",         # [Scanner] prefix
    r"^(nuclei|nikto|nmap|httpx|dalfox|sqlmap|wapiti|zap|whatweb)[\s:\-]+",  # Tool name prefix
    r"\s+v[\d\.]+\s*$",    # version suffixes
    r"\s+\(.*?\)\s*$",     # parenthetical suffixes
]


def _normalize_title(title: str) -> str:
    """Normalize a finding title for comparison."""
    t = (title or "").strip().lower()
    for pat in _STRIP_PATTERNS:
        t = re.sub(pat, "", t, flags=re.IGNORECASE).strip()
    # Collapse whitespace
    t = re.sub(r"\s+", " ", t)
    return t


def deduplicate_findings(findings: list) -> list:
    """
    Deduplicate a list of finding dicts.
    
    Each finding dict is expected to have:
        title, severity, tool, description, target_url (optional)
    
    Returns deduplicated list — merged findings show all source tools.
    """
    if not findings:
        return []

    # Group by (normalized_title, severity)
    groups = {}
    for f in findings:
        key = (_normalize_title(f.get("title", "")), (f.get("severity") or "").lower())
        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    merged = []
    dedup_count = 0

    for (norm_title, _), group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        # Merge all sources
        dedup_count += len(group) - 1
        tools = []
        best_desc = ""
        best_desc_len = 0

        for f in group:
            tool = (f.get("tool") or "").strip()
            if tool and tool not in tools:
                tools.append(tool)
            # Keep longest description (most informative)
            desc = f.get("description") or ""
            if len(desc) > best_desc_len:
                best_desc = desc
                best_desc_len = len(desc)

        # Use the first finding as base, update tool and description
        base = dict(group[0])
        base["tool"] = ", ".join(tools) if tools else base.get("tool", "Multiple")
        base["description"] = best_desc
        base["deduplicated"] = True
        base["source_count"] = len(group)

        # Append dedup note to description
        if len(tools) > 1:
            base["description"] += (
                f"\n\n[Dedup Note] This finding was reported by {len(tools)} scanners: "
                f"{', '.join(tools)}. Sources merged by SMP V7.0.8 deduplicator."
            )

        merged.append(base)
        logger.info(
            f"[Dedup] Merged {len(group)} findings → '{group[0].get('title', '')}' "
            f"(tools: {', '.join(tools)})"
        )

    if dedup_count > 0:
        logger.info(f"[Dedup] Deduplicated {dedup_count} redundant findings. "
                    f"Total: {len(findings)} → {len(merged)}")

    return merged


def deduplicate_db_findings(scan_id: int):
    """
    Deduplicate findings already stored in the DB for a scan.
    Marks duplicates as soft-deleted (is_deleted=1) keeping the merged one.
    """
    try:
        from tools.db_manager import get_db_connection, get_findings_for_scan
        findings = get_findings_for_scan(scan_id)
        deduped = deduplicate_findings(list(findings))

        if len(deduped) == len(findings):
            return  # Nothing to dedup

        conn = get_db_connection()
        # Mark all as deleted first
        conn.execute(
            "UPDATE findings SET is_deleted = 1 WHERE scan_id = ?", (scan_id,)
        )
        # Re-insert merged findings
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
                )
            )
        conn.commit()
        logger.info(f"[Dedup] DB dedup complete for scan {scan_id}: {len(findings)} → {len(deduped)}")
    except Exception as e:
        logger.error(f"[Dedup] DB deduplication failed for scan {scan_id}: {e}")
