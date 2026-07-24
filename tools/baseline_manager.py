"""
Port Baseline Manager V6.5
============================
Stores and compares per-target port profiles across scans.
After the first scan, a "baseline" is saved. All subsequent scans
compare against it and flag new/unexpected open ports as High findings.

Fallback chain:
  1. DB-stored baseline (primary)
  2. File-based JSON cache (secondary — survives DB issues)
"""
import os
import json
import logging
from datetime import datetime

logger = logging.getLogger("smp")

_BASELINE_CACHE_DIR = None  # Set at runtime


def _get_cache_dir() -> str:
    global _BASELINE_CACHE_DIR
    if not _BASELINE_CACHE_DIR:
        from tools.config_manager import BASE_DIR
        _BASELINE_CACHE_DIR = os.path.join(BASE_DIR, "cache", "port_baselines")
    os.makedirs(_BASELINE_CACHE_DIR, exist_ok=True)
    return _BASELINE_CACHE_DIR


def _cache_path(target_url: str) -> str:
    """Get file-based cache path for a target."""
    safe = target_url.replace("://", "_").replace("/", "_").replace(":", "_")
    return os.path.join(_get_cache_dir(), f"{safe}.json")


# ── Primary: DB-backed baseline ───────────────────────────────────────────────

def get_baseline_ports(target_id: int) -> list:
    """
    Get the stored port baseline for a target.
    Returns list of port dicts: [{"port": 80, "protocol": "tcp", "service": "http"}, ...]
    Returns empty list if no baseline exists yet.
    
    Fallback: file-based cache if DB fails.
    """
    # Primary: DB
    try:
        from tools.db_manager import get_db_connection
        conn = get_db_connection()
        row = conn.execute(
            "SELECT baseline_ports FROM target_baselines WHERE target_id = ? ORDER BY created_at DESC LIMIT 1",
            (target_id,)
        ).fetchone()
        if row and row[0]:
            return json.loads(row[0])
    except Exception as e:
        logger.warning(f"[Baseline] DB lookup failed for target {target_id}: {e}. Trying file cache.")

    # Fallback: file cache
    try:
        cache_path = _cache_path(str(target_id))
        if os.path.exists(cache_path):
            with open(cache_path, "r") as f:
                data = json.load(f)
            return data.get("ports", [])
    except Exception as e:
        logger.error(f"[Baseline] File cache lookup also failed: {e}")

    return []


def set_baseline_ports(target_id: int, target_url: str, ports: list):
    """
    Save the port baseline for a target.
    
    Args:
        target_id: DB target ID
        target_url: URL string (for file cache key)
        ports: List of port dicts from Nmap/Masscan
    """
    ports_json = json.dumps(ports)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Primary: DB
    try:
        from tools.db_manager import get_db_connection
        conn = get_db_connection()
        # Upsert
        existing = conn.execute(
            "SELECT id FROM target_baselines WHERE target_id = ?",
            (target_id,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE target_baselines SET baseline_ports = ?, updated_at = ? WHERE target_id = ?",
                (ports_json, now, target_id)
            )
        else:
            conn.execute(
                "INSERT INTO target_baselines (target_id, baseline_ports, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (target_id, ports_json, now, now)
            )
        conn.commit()
        logger.info(f"[Baseline] Saved {len(ports)} ports for target {target_id}")
    except Exception as e:
        logger.warning(f"[Baseline] DB save failed: {e}. Using file cache only.")

    # Fallback: file cache (always write, even if DB succeeded)
    try:
        cache_path = _cache_path(target_url)
        with open(cache_path, "w") as f:
            json.dump({"target_id": target_id, "url": target_url, "ports": ports, "updated_at": now}, f, indent=2)
    except Exception as e:
        logger.error(f"[Baseline] File cache write failed: {e}")


def compare_to_baseline(target_id: int, target_url: str, current_ports: list) -> list:
    """
    Compare current scan ports to baseline.
    Returns list of NEW ports (not in baseline) as High-severity finding dicts.
    """
    baseline = get_baseline_ports(target_id)
    if not baseline:
        # No baseline yet — this is the first scan, save as baseline
        set_baseline_ports(target_id, target_url, current_ports)
        logger.info(f"[Baseline] First scan for {target_url} — baseline saved.")
        return []

    # Build baseline port set: (port, protocol)
    baseline_set = {(p.get("port"), p.get("protocol", "tcp")) for p in baseline}
    current_set  = {(p.get("port"), p.get("protocol", "tcp")) for p in current_ports}

    new_ports = current_set - baseline_set
    if not new_ports:
        logger.info(f"[Baseline] No new ports detected for {target_url}")
        return []

    findings = []
    for port, protocol in sorted(new_ports):
        # Get service info from current scan
        service_info = next(
            (p for p in current_ports if p.get("port") == port and p.get("protocol", "tcp") == protocol),
            {}
        )
        service = service_info.get("service", "unknown")
        version = service_info.get("version", "")
        description = (
            f"New port detected that was NOT in the baseline scan.\n"
            f"Port: {port}/{protocol}\n"
            f"Service: {service}\n"
            f"Version: {version}\n\n"
            f"This port was not open during the initial baseline scan. "
            f"Investigate whether this is an authorized change."
        )
        findings.append({
            "severity": "High",
            "title": f"New Open Port Detected: {port}/{protocol} ({service})",
            "description": description,
            "tool": "Baseline Comparator",
        })
        logger.warning(f"[Baseline] NEW PORT: {port}/{protocol} ({service}) on {target_url}")

    return findings
