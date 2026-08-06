"""Feroxbuster — Recursive content discovery (fast, async, Rust-based)."""
import os
import subprocess
import logging
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

FEROXBUSTER_TIMEOUT = 1800  # 30min — recursive scan needs time

_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]

_SENSITIVE = (".env", "config", "backup", ".git", "wp-config", "credentials", "secret", "private")
_HIGH_RISK  = ("admin", "panel", "dashboard", "debug", "actuator", "swagger", "console", "manager")


@register_scanner(name="Feroxbuster", step_name="Running Feroxbuster", depends_on=['Katana'], binary_name="feroxbuster", needs_binary=True, confidence=85)
def run_feroxbuster_scan(url):
    """Recursive directory/file brute-force. Returns list of finding dicts."""
    logger.info(f"Feroxbuster: Recursive scan on {url}")

    wordlist = next((w for w in _WORDLISTS if os.path.isfile(w)), "")

    cmd = [
        "feroxbuster", "--url", url,
        "--silent",
        "-d", "4",              # 4 levels deep (was 2; --no-recursion removed)
        "--timeout", "10",
        "--threads", "100",     # 100 async threads (feroxbuster is Rust/tokio)
        "--rate-limit", "200",  # 200 req/s
        "--auto-tune",          # adaptive throttle on errors
        "--collect-extensions", # mine extensions from responses
        "--collect-words",      # mine words from responses for wordlist expansion
        "--redirects",
        "-x", "php,asp,aspx,jsp,html,bak,json,xml,sql,zip",
        "--filter-status", "404,429",
        "--no-state",           # don't save .feroxbuster state file
        "-H", "User-Agent: SMP/9.3.2 (Security Audit)",
    ]
    if wordlist:
        cmd += ["-w", wordlist]

    findings = []
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=FEROXBUSTER_TIMEOUT)
        hits = []
        for line in (r.stdout + r.stderr).splitlines():
            line = line.strip()
            if not line:
                continue
            # feroxbuster output: 200      GET     1l    10w    512c https://target/admin
            parts = line.split()
            if len(parts) >= 5 and parts[0].isdigit():
                code     = parts[0]
                path_url = parts[-1] if parts[-1].startswith("http") else line
                path     = path_url.replace(url.rstrip("/"), "").lower()
                if any(k in path for k in _SENSITIVE):
                    sev = "Critical"
                elif any(k in path for k in _HIGH_RISK) and code in ("200", "201"):
                    sev = "High"
                elif code in ("200", "201"):
                    sev = "Medium"
                else:
                    sev = "Low"
                hits.append({"code": code, "path": path, "url": path_url, "severity": sev})

        # Emit individual findings per hit for proper severity tracking
        for hit in hits:
            findings.append({
                "severity":    hit["severity"],
                "title":       f"Path Discovered [{hit['code']}]: {hit['path']}",
                "description": (
                    f"URL: {hit['url']}\n"
                    f"Status: {hit['code']}\n"
                    f"Feroxbuster discovered this path via recursive brute-force."
                ),
                "template_id": f"FEROX-{hit['code']}",
            })

        logger.info(f"Feroxbuster Completed: {len(findings)} paths found")
        return findings

    except FileNotFoundError:
        logger.warning("feroxbuster not found — skipping")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"Feroxbuster timed out after {FEROXBUSTER_TIMEOUT}s")
        return findings
    except Exception as e:
        logger.error(f"Feroxbuster: {e}")
        return []
