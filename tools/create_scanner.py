#!/usr/bin/env python3
"""
SMP Custom Scanner Generator
=============================
Scaffolds a new scanner plugin for the Security Management Platform.
This removes the boilerplate and registers your tool automatically.

Usage:
  python3 tools/create_scanner.py --name "MyTool" --binary "mytool" --severity Medium
"""

import os
import sys
import argparse

TEMPLATE = '''"""
{name} Scanner — SMP V7.0.3
=========================
Auto-generated scanner plugin.
"""

import logging
import subprocess
import json

logger = logging.getLogger("smp.scan")

# V7.0.3 Zero-Friction Plugin Registration
PLUGIN_META = {{
    "name": "{name}",
    "binary": "{binary}",
    "severity": "{severity}",
    "step_name": "Running {name} Scan",
    "confidence": 75,
    "depends_on": []  # e.g., ["Nmap"] if you need Nmap to run first
}}

def scan(target_url: str, scan_id: int, settings: dict) -> dict:
    from tools.narrative_logger import emit_scanner_start, emit_finding
    emit_scanner_start(scan_id, "{binary}")

    # 1. Define your command
    cmd = ["{binary}", "-u", target_url, "--json"]
    
    logger.info(f"[{binary}] Running: {{' '.join(cmd)}}")
    findings = []
    raw_output = ""

    try:
        # 2. Execute the tool
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        raw_output = result.stdout + result.stderr

        # 3. Parse the output
        if result.returncode == 0 and result.stdout:
            try:
                # Assuming JSON output. Modify this to match your tool's actual output format!
                data = json.loads(result.stdout)
                
                # TODO: Iterate over your tool's results
                # for item in data:
                #     title = item.get("title", "Found issue")
                #     desc = item.get("description", "")
                #
                #     # 4. Save finding to Database
                #     from tools.db_manager import add_finding
                #     add_finding(
                #         scan_id=scan_id,
                #         scanner="{name}",
                #         severity="{severity}",
                #         title=title,
                #         description=desc,
                #         evidence=raw_output[:1000]
                #     )
                #     
                #     findings.append({{"title": title, "severity": "{severity}"}})
                #
                pass

            except json.JSONDecodeError:
                logger.error("[{binary}] Failed to parse JSON output.")
                # You can use regex here instead if your tool outputs plain text

    except FileNotFoundError:
        logger.error(f"[{binary}] Binary not found. Is it installed and in PATH?")
    except Exception as e:
        logger.error(f"[{binary}] Error: {{e}}")
        raw_output = str(e)

    # 5. Return results to the pipeline orchestrator
    return {{
        "success": len(findings) > 0,
        "data": findings,
        "raw_output": raw_output,
    }}
'''

def main():
    parser = argparse.ArgumentParser(description="SMP Custom Scanner Generator")
    parser.add_argument("--name", required=True, help="Display name of the scanner (e.g., 'MyTool')")
    parser.add_argument("--binary", required=True, help="Binary command to execute (e.g., 'mytool')")
    parser.add_argument("--severity", default="Medium", help="Default severity (Info, Low, Medium, High, Critical)")
    
    args = parser.parse_args()
    
    filename = args.binary.lower().replace("-", "_") + ".py"
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    scanners_dir = os.path.join(root, "scanners")
    
    if not os.path.exists(scanners_dir):
        print(f"[✗] Scanners directory not found at {scanners_dir}")
        sys.exit(1)
        
    filepath = os.path.join(scanners_dir, filename)
    if os.path.exists(filepath):
        print(f"[✗] Scanner file {filename} already exists!")
        sys.exit(1)
        
    content = TEMPLATE.format(
        name=args.name,
        binary=args.binary,
        severity=args.severity
    )
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
        
    # Make script executable
    os.chmod(os.path.abspath(__file__), 0o755)
        
    print(f"\n[✓] Scaffolded custom scanner: {filepath}")
    print(f"    1. Open {filepath}")
    print(f"    2. Update the `cmd` arguments for your tool.")
    print(f"    3. Update the output parsing logic in step 3.")
    print(f"    4. That's it! SMP will auto-discover it on the next run.\n")

if __name__ == "__main__":
    main()
