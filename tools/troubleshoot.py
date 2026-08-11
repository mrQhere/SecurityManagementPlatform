#!/usr/bin/env python3
"""
SMP V9.4.2 — Unified Self-Healing, Error Resolution & Troubleshooting Engine
=============================================================================
Centralized engine for finding errors, mapping solutions, running system diagnostic
checks, and performing automated self-healing across the Security Management Platform.

Usage:
    # Programmatic API:
    from tools.troubleshoot import get_error_solution, auto_heal_system
    solution = get_error_solution("SMP-1001")
    report = auto_heal_system()

    # CLI Execution:
    python3 tools/troubleshoot.py         # Run diagnostics & view solutions
    python3 tools/troubleshoot.py --fix   # Run diagnostics & apply self-healing fixes
"""

import os
import sys
import re
import shutil
import logging
import subprocess
from typing import Dict, Any, List

logger = logging.getLogger("smp.troubleshoot")

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Terminal colors for CLI
RED = "\033[91m"
GRN = "\033[92m"
YEL = "\033[93m"
BLU = "\033[94m"
RST = "\033[0m"
BLD = "\033[1m"


# ── 1. Error Solution Database ───────────────────────────────────────────────

ERROR_KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {
    "SMP-1001": {
        "code": "SMP-1001",
        "category": "Authentication",
        "title": "Invalid Passphrase or Authentication Token Failure",
        "description": "User provided an incorrect database master password or expired API JWT token.",
        "cause": "Incorrect credentials supplied during startup or session expiration.",
        "solution": "Verify password entry. To reset encryption password, delete config/settings.json or use recovery key.",
        "auto_fixable": False,
    },
    "SMP-1002": {
        "code": "SMP-1002",
        "category": "Authentication",
        "title": "JWT Token Expired",
        "description": "Bearer JWT token has exceeded its validity window.",
        "cause": "API request made with a token generated >24h ago.",
        "solution": "Re-authenticate against /api/v9.4.2/auth/token to receive a fresh bearer token.",
        "auto_fixable": False,
    },
    "SMP-2001": {
        "code": "SMP-2001",
        "category": "Scanner Execution",
        "title": "Required Security Tool Binary Missing",
        "description": "A required scanner CLI tool (e.g. nmap, nuclei, ffuf, wpscan) is not installed in PATH or bin/.",
        "cause": "Missing system binary or incomplete tool installation.",
        "solution": "Run 'python3 tools/tool_installer.py' or 'python3 tools/troubleshoot.py --fix' to auto-install missing tools.",
        "auto_fixable": True,
    },
    "SMP-2002": {
        "code": "SMP-2002",
        "category": "Scanner Execution",
        "title": "Scanner Execution Timeout",
        "description": "A scanner exceeded its designated maximum execution timeout window.",
        "cause": "Network latency, large target scope, or blocking firewall.",
        "solution": "Increase 'scanner_timeout' in config/settings.json or switch target profile to Standard/Fast.",
        "auto_fixable": False,
    },
    "SMP-2003": {
        "code": "SMP-2003",
        "category": "Scanner Execution",
        "title": "Scanner Subprocess Crash or Non-Zero Exit",
        "description": "Subprocess exited unexpectedly with error output.",
        "cause": "Tool syntax mismatch, missing dependency shared library, or target unreachable.",
        "solution": "Inspect tool raw_output logs or verify target connectivity.",
        "auto_fixable": True,
    },
    "SMP-3001": {
        "code": "SMP-3001",
        "category": "Database",
        "title": "SQLCipher Encrypted Database Connection Error",
        "description": "Unable to establish connection to encrypted SQLite security.db.",
        "cause": "Missing SQLCipher driver, invalid passphrase, or database lock file contention.",
        "solution": "Verify libsqlcipher-dev is installed and database password is set.",
        "auto_fixable": True,
    },
    "SMP-3002": {
        "code": "SMP-3002",
        "category": "Database",
        "title": "Database Integrity Check Failed",
        "description": "PRAGMA integrity_check returned corruption errors.",
        "cause": "Abrupt process termination during SQLite write transaction.",
        "solution": "SMP self-healing automatically restores from latest backup/ snapshot container.",
        "auto_fixable": True,
    },
    "SMP-4001": {
        "code": "SMP-4001",
        "category": "Validation & Target",
        "title": "Target Attestation / Responsibility Check Required",
        "description": "Attempted active scan on target without written permission attestation.",
        "cause": "Target responsibility attestation check was not accepted.",
        "solution": "Check responsibility checkbox in Dashboard UI or populate target_attestation in database.",
        "auto_fixable": False,
    },
    "SMP-5001": {
        "code": "SMP-5001",
        "category": "Network & Interface",
        "title": "MAC Address Changer Execution Warning",
        "description": "MAC address rotation failed or non-interactive sudo required a password.",
        "cause": "Sudo privileges missing or network interface driver does not support netlink set address.",
        "solution": "Grant setcap cap_net_raw,cap_net_admin to nmap, or pass sudo_password. Scan non-destructively proceeds anyway.",
        "auto_fixable": True,
    },
}


def get_error_solution(error_input: str) -> Dict[str, Any]:
    """
    Looks up exact error details, root cause, and copy-paste / auto-fix solutions.
    Can accept an error code (e.g. "SMP-2001") or a raw exception string.
    """
    if not error_input:
        return {
            "code": "SMP-9999",
            "title": "Unknown Error",
            "description": "No error string provided.",
            "cause": "Undefined error input.",
            "solution": "Review smp.log for details.",
            "auto_fixable": False,
        }

    # Match explicit SMP-xxxx error code
    m = re.search(r"SMP-\d{4}", str(error_input).upper())
    if m and m.group(0) in ERROR_KNOWLEDGE_BASE:
        return ERROR_KNOWLEDGE_BASE[m.group(0)]

    # Keyword matching for raw exceptions
    err_str = str(error_input).lower()
    if "mac" in err_str or "sudo" in err_str or "interface" in err_str:
        return ERROR_KNOWLEDGE_BASE["SMP-5001"]
    elif "sqlcipher" in err_str or "database" in err_str or "locked" in err_str:
        return ERROR_KNOWLEDGE_BASE["SMP-3001"]
    elif "binary" in err_str or "not found" in err_str or "not installed" in err_str:
        return ERROR_KNOWLEDGE_BASE["SMP-2001"]
    elif "timeout" in err_str:
        return ERROR_KNOWLEDGE_BASE["SMP-2002"]
    elif "password" in err_str or "auth" in err_str or "token" in err_str:
        return ERROR_KNOWLEDGE_BASE["SMP-1001"]

    return {
        "code": "SMP-9999",
        "title": "Unclassified SMP System Exception",
        "description": str(error_input),
        "cause": "Unhandled runtime exception caught during execution.",
        "solution": "Check system logs in logs/smp.log. Run 'python3 tools/troubleshoot.py --fix' for automated repair.",
        "auto_fixable": True,
    }


# ── 2. Automated Diagnostic Checks & Self-Healing Engine ────────────────────

def check_python_dependencies() -> List[str]:
    """Verify python packages."""
    missing = []
    required = ["requests", "pysqlcipher3", "apscheduler", "jinja2"]
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    return missing


def check_system_binaries() -> List[str]:
    """Verify system security binaries."""
    bins = ["nmap", "nikto", "sqlmap", "nuclei", "ffuf", "wpscan", "macchanger"]
    missing = []
    for b in bins:
        if not shutil.which(b):
            # Check local bin/
            local_bin = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin", b))
            if not (os.path.exists(local_bin) and os.access(local_bin, os.X_OK)):
                missing.append(b)
    return missing


def auto_heal_system() -> Dict[str, Any]:
    """
    Executes automated self-healing:
    1. Initializes missing workspace directories.
    2. Repairs missing scanner binary links / auto-downloads.
    3. Runs database WAL checkpoint & recovery if needed.
    4. Validates permissions.
    """
    report = {
        "healed_items": [],
        "warnings": [],
        "errors": [],
        "success": True
    }

    # 1. Directory self-healing
    try:
        from tools.config_manager import init_directories
        init_directories()
        report["healed_items"].append("Workspace directories verified and initialized.")
    except Exception as e:
        report["errors"].append(f"Failed directory initialization: {e}")

    # 2. Python dependency check
    missing_py = check_python_dependencies()
    if missing_py:
        report["warnings"].append(
            f"Missing Python libraries: {', '.join(missing_py)}. "
            f"Fix with: pip install {' '.join(missing_py)}"
        )

    # 3. Binary self-healing
    missing_bins = check_system_binaries()
    if missing_bins:
        try:
            from tools.tool_installer import install_single_tool
            for b in missing_bins:
                logger.info(f"[SelfHealing] Attempting to auto-install missing tool: {b}")
                ok = install_single_tool(b)
                if ok:
                    report["healed_items"].append(f"Auto-installed missing tool binary: {b}")
                else:
                    report["warnings"].append(f"Could not auto-install tool binary: {b}")
        except Exception as e:
            report["warnings"].append(f"Tool auto-installer invocation failed: {e}")

    # 4. Database self-healing
    try:
        from tools.db_manager import get_db_connection, is_main_db_corrupt_or_missing
        if is_main_db_corrupt_or_missing():
            from tools.db_manager import init_db
            init_db()
            report["healed_items"].append("Database integrity restored from backup/initialization schema.")
        else:
            conn = get_db_connection()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            conn.close()
            report["healed_items"].append("Database WAL journal checkpointed successfully.")
    except Exception as e:
        report["warnings"].append(f"Database self-healing warning: {e}")

    return report


# ── 3. Interactive CLI Interface ─────────────────────────────────────────────

def print_header(title: str):
    print(f"\n{BLD}{BLU}=== {title} ==={RST}")


def run_cli_troubleshoot(auto_fix: bool = False):
    print(f"{BLD}Security Management Platform (SMP) V9.4.2{RST}")
    print("Unified Self-Healing & Troubleshooting Engine\n")

    print_header("1. Checking Environment & Directories")
    try:
        from tools.config_manager import init_directories
        init_directories()
        print(f"  {GRN}[OK]{RST} System directories initialized.")
    except Exception as e:
        print(f"  {RED}[FAIL]{RST} Directory error: {e}")

    print_header("2. Checking Python Dependencies")
    missing_py = check_python_dependencies()
    if not missing_py:
        print(f"  {GRN}[OK]{RST} All required Python dependencies satisfied.")
    else:
        print(f"  {RED}[FAIL]{RST} Missing Python modules: {', '.join(missing_py)}")
        print(f"  {YEL}Solution:{RST} pip install {' '.join(missing_py)}")

    print_header("3. Checking System & Scanner Binaries")
    missing_bins = check_system_binaries()
    if not missing_bins:
        print(f"  {GRN}[OK]{RST} All required scanner binaries present.")
    else:
        print(f"  {RED}[FAIL]{RST} Missing binaries: {', '.join(missing_bins)}")
        sol = get_error_solution("SMP-2001")
        print(f"  {YEL}Solution ({sol['code']}):{RST} {sol['solution']}")

    print_header("4. Checking Permissions & MAC Changer capabilities")
    res = subprocess.run(["sudo", "-n", "nmap", "-V"], capture_output=True, text=True)
    if res.returncode == 0:
        print(f"  {GRN}[OK]{RST} Non-interactive sudo Nmap capability active.")
    else:
        print(f"  {YEL}[WARN]{RST} Non-interactive sudo Nmap requires password or setcap.")
        sol = get_error_solution("SMP-5001")
        print(f"  {YEL}Solution ({sol['code']}):{RST} {sol['solution']}")

    if auto_fix:
        print_header("Executing Self-Healing Auto-Fixes")
        heal_report = auto_heal_system()
        for item in heal_report["healed_items"]:
            print(f"  {GRN}[HEALED]{RST} {item}")
        for warn in heal_report["warnings"]:
            print(f"  {YEL}[WARNING]{RST} {warn}")
        for err in heal_report["errors"]:
            print(f"  {RED}[ERROR]{RST} {err}")

    print(f"\n{BLD}{GRN}Diagnostic check complete.{RST}")


if __name__ == "__main__":
    auto_fix_flag = "--fix" in sys.argv or "-f" in sys.argv
    run_cli_troubleshoot(auto_fix=auto_fix_flag)
