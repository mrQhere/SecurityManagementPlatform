"""
System Resource Pre-Scan Checker V7.0.4
======================================
Checks CPU, RAM, disk space, and network before a scan starts.
If any threshold is exceeded, the caller gets a structured warning
with a list of issues so the UI can show a "Continue Anyway / Cancel" dialog.

Thresholds (all configurable in settings):
  cpu_warn_pct   : CPU usage > 80%   → warn
  ram_warn_mb    : Free RAM < 500 MB → warn
  disk_warn_gb   : Free disk < 1 GB  → warn
  net_check_host : Attempt TCP connect to verify network reachability

Fallback chain:
  1. Use psutil for accurate metrics
  2. Fall back to /proc/meminfo + shutil.disk_usage (no psutil needed)
"""
import os
import shutil
import socket
import logging

logger = logging.getLogger("smp")

# Default thresholds
_CPU_WARN_PCT  = 80.0   # Warn if CPU > 80%
_RAM_WARN_MB   = 500    # Warn if free RAM < 500 MB
_DISK_WARN_GB  = 1.0    # Warn if free disk < 1 GB
_NET_HOST      = "8.8.8.8"
_NET_PORT      = 53
_NET_TIMEOUT   = 3      # seconds


def _get_cpu_percent() -> float:
    """Get current CPU usage. Tries psutil first, then falls back to /proc/stat."""
    try:
        import psutil
        return psutil.cpu_percent(interval=0.5)
    except ImportError:
        pass
    try:
        # Fallback: read /proc/stat (Linux only)
        def _read_stat():
            with open("/proc/stat") as f:
                line = f.readline()
            vals = list(map(int, line.split()[1:8]))
            idle = vals[3]
            total = sum(vals)
            return idle, total

        idle1, total1 = _read_stat()
        import time; time.sleep(0.3)
        idle2, total2 = _read_stat()
        d_idle = idle2 - idle1
        d_total = total2 - total1
        return round((1.0 - d_idle / max(d_total, 1)) * 100, 1)
    except Exception:
        return 0.0  # Cannot determine — assume ok


def _get_free_ram_mb() -> float:
    """Get free RAM in MB. Tries psutil, then /proc/meminfo."""
    try:
        import psutil
        vm = psutil.virtual_memory()
        return vm.available / (1024 * 1024)
    except ImportError:
        pass
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        mem = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                mem[parts[0].rstrip(":")] = int(parts[1])
        available_kb = mem.get("MemAvailable", mem.get("MemFree", 0))
        return available_kb / 1024
    except Exception:
        return 9999  # Cannot determine — assume ok


def _get_free_disk_gb(path: str = "/") -> float:
    """Get free disk space in GB for the given path."""
    try:
        usage = shutil.disk_usage(path)
        return usage.free / (1024 ** 3)
    except Exception:
        return 9999  # Cannot determine — assume ok


def _check_network(host: str = _NET_HOST, port: int = _NET_PORT) -> bool:
    """Check network reachability via TCP connect."""
    try:
        sock = socket.create_connection((host, port), timeout=_NET_TIMEOUT)
        sock.close()
        return True
    except Exception:
        # Try fallback: DNS resolution
        try:
            socket.gethostbyname("scanme.nmap.org")
            return True
        except Exception:
            return False


def check_system_resources(settings: dict = None) -> dict:
    """
    Main entry point. Returns a result dict:
    {
        "ok": bool,           — True if all checks passed
        "warnings": [str],    — list of human-readable warnings
        "metrics": {          — raw metrics for display
            "cpu_pct": float,
            "free_ram_mb": float,
            "free_disk_gb": float,
            "network_ok": bool
        }
    }
    """
    settings = settings or {}
    cpu_warn   = float(settings.get("sys_cpu_warn_pct", _CPU_WARN_PCT))
    ram_warn   = float(settings.get("sys_ram_warn_mb", _RAM_WARN_MB))
    disk_warn  = float(settings.get("sys_disk_warn_gb", _DISK_WARN_GB))

    warnings = []

    # CPU check
    cpu = _get_cpu_percent()
    if cpu > cpu_warn:
        warnings.append(
            f"⚠️  High CPU usage: {cpu:.1f}% (threshold: {cpu_warn:.0f}%). "
            "Running a scan now may cause slowdowns or timeouts."
        )

    # RAM check
    ram_mb = _get_free_ram_mb()
    if ram_mb < ram_warn:
        warnings.append(
            f"⚠️  Low available RAM: {ram_mb:.0f} MB free (minimum recommended: {ram_warn:.0f} MB). "
            "Some scanners may fail or crash."
        )

    # Disk check
    disk_gb = _get_free_disk_gb()
    if disk_gb < disk_warn:
        warnings.append(
            f"⚠️  Low disk space: {disk_gb:.2f} GB free (minimum recommended: {disk_warn:.1f} GB). "
            "Raw scan outputs and reports may fail to save."
        )

    # Network check
    net_ok = _check_network()
    if not net_ok:
        warnings.append(
            "⚠️  Network unreachable. Cannot reach external hosts. "
            "Scans against remote targets will fail."
        )

    result = {
        "ok": len(warnings) == 0,
        "warnings": warnings,
        "metrics": {
            "cpu_pct": cpu,
            "free_ram_mb": ram_mb,
            "free_disk_gb": disk_gb,
            "network_ok": net_ok,
        }
    }

    if not result["ok"]:
        logger.warning(f"[SystemChecker] Pre-scan warnings: {'; '.join(warnings)}")
    else:
        logger.info(f"[SystemChecker] All system checks passed. CPU={cpu:.1f}% RAM={ram_mb:.0f}MB Disk={disk_gb:.2f}GB")

    return result
