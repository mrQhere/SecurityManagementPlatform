#!/usr/bin/env python3
"""
SMP Version Bumper — updates version everywhere it matters.

Usage:
  python3 tools/bump_version.py V9.4.3          # set explicit version
  python3 tools/bump_version.py --patch          # auto-bump patch (V9.4.3 → V9.4.3)
  python3 tools/bump_version.py --minor          # auto-bump minor (V9.4.3 → V9.4.0)
  python3 tools/bump_version.py --major          # auto-bump major (V9.4.3 → V10.0.0)
  python3 tools/bump_version.py --dry-run V9.4.3 # preview without writing
"""
import sys
import json
import os
import re
import argparse

GRN = "\033[92m"
YEL = "\033[93m"
RED = "\033[91m"
RST = "\033[0m"

def _ok(msg):   print(f"  {GRN}[✓]{RST} {msg}")
def _warn(msg): print(f"  {YEL}[!]{RST} {msg}")
def _err(msg):  print(f"  {RED}[✗]{RST} {msg}")


def _read_current_version(root: str) -> str:
    """Read the current version from config/metadata.json."""
    meta_path = os.path.join(root, "config", "metadata.json")
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("version", "V0.0.0")
    return "V0.0.0"


def _auto_bump(current: str, part: str) -> str:
    """Bump major, minor, or patch from a version string like 'V9.4.3'."""
    m = re.match(r"[vV]?(\d+)\.(\d+)\.(\d+)", current)
    if not m:
        raise ValueError(f"Cannot parse current version '{current}' for auto-bump.")
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if part == "major":
        return f"V{major + 1}.0.0"
    if part == "minor":
        return f"V{major}.{minor + 1}.0"
    return f"V{major}.{minor}.{patch + 1}"  # patch


def main():
    parser = argparse.ArgumentParser(
        description="SMP Version Bumper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("version", nargs="?", metavar="VERSION",
                       help="Explicit version string, e.g. V9.4.3")
    group.add_argument("--patch", action="store_true", help="Auto-bump patch version")
    group.add_argument("--minor", action="store_true", help="Auto-bump minor version")
    group.add_argument("--major", action="store_true", help="Auto-bump major version")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview changes without writing any files")

    args = parser.parse_args()

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    current = _read_current_version(root)

    # Resolve new version
    if args.patch:
        new_version = _auto_bump(current, "patch")
    elif args.minor:
        new_version = _auto_bump(current, "minor")
    elif args.major:
        new_version = _auto_bump(current, "major")
    elif args.version:
        new_version = args.version.strip()
        if new_version.lower().startswith("v") and not new_version.startswith("V"):
            new_version = "V" + new_version[1:]
    else:
        parser.print_help()
        sys.exit(1)

    ver_num = new_version.lstrip("vV")
    dry = args.dry_run

    prefix = "  [DRY RUN]" if dry else ""
    print(f"\n{'═'*55}")
    print(f"  SMP Version Bump  {current} → {new_version}" + (" (dry run)" if dry else ""))
    print(f"{'═'*55}\n")

    # 1. Update config/metadata.json
    meta_path = os.path.join(root, "config", "metadata.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, encoding="utf-8") as f:
                data = json.load(f)
            data["version"] = new_version
            if not dry:
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
            _ok(f"{prefix} config/metadata.json  {current} → {new_version}")
        except Exception as e:
            _err(f"Failed to update metadata.json: {e}")
    else:
        _warn("config/metadata.json not found — creating it")
        if not dry:
            os.makedirs(os.path.join(root, "config"), exist_ok=True)
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump({"version": new_version}, f, indent=4)

    # 2. Global recursive regex replace on SMP_VERSION markers
    version_regex = re.compile(
        r'((?:SMP(?:_VERSION)?|Security Management Platform(?:\s*\(SMP\))?|Intelligence Feed|V)[^\dvV]*?)([vV][4-9]\.\d+(?:\.\d+)?\b)', re.IGNORECASE
    )
    badge_regex = re.compile(r'version-[4-9]\.\d+(?:\.\d+)?')

    valid_exts = {".py", ".md", ".txt", ".sh", ".bat", ".ps1", ".json"}
    ignore_dirs = {".git", "__pycache__", "venv", ".vscode", "reports", ".codegraph"}

    total_replacements = 0
    files_changed = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            ext = os.path.splitext(filename)[1].lower()
            if ext not in valid_exts and filename not in ("Makefile", "Dockerfile", "LICENSE"):
                continue
            if filename == "metadata.json" and "config" in dirpath:
                continue
            try:
                with open(filepath, encoding="utf-8") as f:
                    content = f.read()
            except (UnicodeDecodeError, OSError):
                continue

            def replacer(match):
                prefix_m = match.group(1)
                version_str = match.group(2)
                return prefix_m + ("v" if version_str.startswith("v") else "V") + ver_num

            new_content, n = version_regex.subn(replacer, content)
            new_content, m = badge_regex.subn(f"version-{ver_num}", new_content)
            total_n = n + m

            if total_n > 0:
                if not dry:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(new_content)
                rel_path = os.path.relpath(filepath, root)
                _ok(f"{prefix} {rel_path} — {total_n} reference(s)")
                total_replacements += total_n
                files_changed += 1

    status = "Would update" if dry else "Updated"
    print(f"\n{'═'*55}")
    print(f"  {GRN}✅ Version bumped to {new_version}!{RST}" if not dry else
          f"  {YEL}[DRY RUN] Would bump to {new_version}{RST}")
    print(f"  {status} {total_replacements} reference(s) across {files_changed} file(s).")
    print(f"{'═'*55}\n")


if __name__ == "__main__":
    main()
