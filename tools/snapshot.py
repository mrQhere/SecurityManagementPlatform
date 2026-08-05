#!/usr/bin/env python3
"""
SMP Auto-Snapshot Tool
=========================
Automatically increments the semantic version patch number, bumps the version
across the codebase, and commits all changes to local git.

Usage: python3 tools/snapshot.py [optional commit message]
"""

import os
import sys
import json
import subprocess
import re

GRN = "\033[92m"
YEL = "\033[93m"
RED = "\033[91m"
RST = "\033[0m"

def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    meta_path = os.path.join(root, "config", "metadata.json")

    # 1. Read current version
    if not os.path.exists(meta_path):
        print(f"  {RED}[✗]{RST} metadata.json not found.")
        sys.exit(1)

    with open(meta_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    current_ver = data.get("version", "V0.0.0")

    # 2. Parse and increment semver
    # Match V<major>.<minor>[.<patch>]
    match = re.match(r'^[vV]?(\d+)\.(\d+)(?:\.(\d+))?$', current_ver)
    if not match:
        print(f"  {RED}[✗]{RST} Current version '{current_ver}' is not valid semver (V.Major.Minor.Patch).")
        sys.exit(1)

    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) else 0

    new_patch = patch + 1
    new_version = f"V{major}.{minor}.{new_patch}"

    print(f"\n{'═'*55}")
    print(f"  SMP Auto-Snapshot")
    print(f"  Bumping version: {current_ver} → {new_version}")
    print(f"{'═'*55}\n")

    # 3. Bump version using the existing tool
    bump_script = os.path.join(root, "tools", "bump_version.py")
    try:
        subprocess.run([sys.executable, bump_script, new_version], check=True, cwd=root)
    except subprocess.CalledProcessError:
        print(f"  {RED}[✗]{RST} Failed to bump version. Aborting commit.")
        sys.exit(1)

    # 4. Prepare commit message
    user_msg = " ".join(sys.argv[1:]).strip()
    commit_msg = f"chore: Snapshot auto-update to {new_version}"
    if user_msg:
        commit_msg += f" - {user_msg}"

    # 5. Git add and commit
    try:
        print(f"\n  {YEL}Staging files in git...{RST}")
        subprocess.run(["git", "add", "."], check=True, cwd=root)
        
        print(f"  {YEL}Committing changes...{RST}")
        subprocess.run(["git", "commit", "-m", commit_msg], check=True, cwd=root)
        print(f"\n  {GRN}✅ Snapshot successful! Changes saved locally as {new_version}.{RST}\n")
    except subprocess.CalledProcessError as e:
        print(f"\n  {RED}[✗]{RST} Git commit failed (is git initialized? are there no changes?): {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
