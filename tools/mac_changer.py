# =============================================================================
# PROPRIETARY SOFTWARE — ALL RIGHTS RESERVED
# Security Management Platform (SMP)
# Owner: Authorised Personnel Only
#
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  ⚠  CRITICAL NOTICE — Read way.md before ANY changes.                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# =============================================================================
"""
MAC Address Changer — assigns a random MAC on every program startup.

Improvement over previous version:
- Does NOT bring the interface down (avoids network dropout and DHCP loss)
- Uses 'ip link set <iface> address <mac>' directly (works on most kernels
  without requiring the interface to be down first — depends on driver)
- Falls back to macchanger binary if ip-link fails
- Fails gracefully if permissions are missing
"""
import os
import re
import random
import logging
import subprocess

logger = logging.getLogger("smp")


def _get_primary_interface():
    """Detect the primary active network interface (default route)."""
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    iface = parts[0]
                    if iface and iface != "lo":
                        return iface
    except Exception:
        pass

    # Fallback: first non-loopback interface from `ip link`
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show", "up"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            m = re.match(r"\d+:\s+(\S+):", line)
            if m:
                iface = m.group(1).rstrip(":")
                if iface not in ("lo", "loopback"):
                    return iface
    except Exception:
        pass

    return None


def _generate_random_mac():
    """Generate a random locally-administered unicast MAC address."""
    first_byte = random.randint(0, 255)
    first_byte = (first_byte & 0xFE) | 0x02  # unicast + locally administered
    rest = [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in [first_byte] + rest)


def _try_ip_link(iface, new_mac):
    """Attempt MAC change using 'ip link set <iface> address <mac>' without bringing down."""
    cmd = ["ip", "link", "set", "dev", iface, "address", new_mac]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd
    result = subprocess.run(
        cmd,
        capture_output=True, text=True, timeout=10
    )
    return result.returncode == 0, result.stderr.strip()


def _try_macchanger(iface, new_mac):
    """Fallback: use macchanger binary if available."""
    try:
        cmd = ["macchanger", "--mac", new_mac, iface]
        if os.geteuid() != 0:
            cmd = ["sudo", "-n"] + cmd
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0, result.stderr.strip()
    except FileNotFoundError:
        return False, "macchanger not installed"


def change_mac_address():
    """
    Assign a random MAC to the primary interface WITHOUT bringing it down.

    Returns (success: bool, message: str).
    """
    try:
        iface = _get_primary_interface()
        if not iface:
            return False, "MAC Changer: Could not detect primary network interface. Skipped."

        new_mac = _generate_random_mac()

        # Strategy 1: ip link set address directly (no bring-down)
        ok, err = _try_ip_link(iface, new_mac)
        if ok:
            msg = f"MAC Changer: {iface} → {new_mac} ✓"
            logger.info(msg)
            return True, msg

        # Strategy 2: macchanger fallback
        ok2, err2 = _try_macchanger(iface, new_mac)
        if ok2:
            msg = f"MAC Changer: {iface} → {new_mac} (via macchanger) ✓"
            logger.info(msg)
            return True, msg

        # Both failed — non-fatal
        return False, f"MAC Changer: Could not change MAC ({err}). Skipped (non-fatal)."

    except PermissionError:
        return False, "MAC Changer: Permission denied. Skipped (non-fatal)."
    except FileNotFoundError:
        return False, "MAC Changer: 'ip' command not found. Skipped (non-fatal)."
    except Exception as e:
        return False, f"MAC Changer: {e}. Skipped (non-fatal)."
