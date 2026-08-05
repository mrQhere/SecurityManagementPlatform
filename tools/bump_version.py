#!/usr/bin/env python3
"""
SMP Version Bumper — updates version everywhere it matters.
Usage: python3 tools/bump_version.py V9.2.3
"""
import sys, json, os, re

GRN = "\033[92m"; YEL = "\033[93m"; RED = "\033[91m"; RST = "\033[0m"
def _ok(msg):   print(f"  {GRN}[✓]{RST} {msg}")
def _warn(msg): print(f"  {YEL}[!]{RST} {msg}")
def _err(msg):  print(f"  {RED}[✗]{RST} {msg}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 bump_version.py <NEW_VERSION>")
        print("Example: python3 bump_version.py V9.2.3")
        sys.exit(1)

    new_version = sys.argv[1].strip()
    if new_version.lower().startswith("v") and not new_version.startswith("V"):
        new_version = "V" + new_version[1:]
    ver_num = new_version.lstrip("vV")
    
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    print(f"\n{'═'*55}\n  SMP Version Bump → {new_version}\n{'═'*55}\n")

    # 1. Update config/metadata.json explicitly
    meta_path = os.path.join(root, "config", "metadata.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            old_v = data.get("version", "?")
            data["version"] = new_version
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            _ok(f"config/metadata.json  {old_v} → {new_version}")
        except Exception as e:
            _err(f"Failed to update metadata.json: {e}")
    else:
        _warn("config/metadata.json not found — creating it")
        os.makedirs(os.path.join(root, "config"), exist_ok=True)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"version": new_version}, f, indent=4)

    # 2. Global recursive regex replace
    version_regex = re.compile(r'\b(?:[vV])[4-9]\.\d+(?:\.\d+)?\b')
    
    valid_exts = {".py", ".md", ".txt", ".sh", ".bat", ".ps1", ".json"}
    ignore_dirs = {".git", "__pycache__", "venv", ".vscode", "reports"}
    
    total_replacements = 0
    files_changed = 0

    for dirpath, dirnames, filenames in os.walk(root):
        # Filter out ignored directories
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
        
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            ext = os.path.splitext(filename)[1].lower()
            
            # Skip if not a target extension
            if ext not in valid_exts and filename not in ["Makefile", "Dockerfile", "LICENSE"]:
                continue
            
            # Skip metadata.json since we handled it above
            if filename == "metadata.json" and "config" in dirpath:
                continue

            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                continue # Skip binary or weirdly encoded files
                
            def replacer(match):
                matched_str = match.group(0)
                if matched_str.startswith('v'):
                    return "v" + ver_num
                return new_version

            new_content, n = version_regex.subn(replacer, content)
            
            # Additional replacement for version-X.Y format in markdown badges
            badge_regex = re.compile(r'version-[4-9]\.\d+(?:\.\d+)?')
            new_content, m = badge_regex.subn(f'version-{ver_num}', new_content)
            
            total_n = n + m
            
            if total_n > 0:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(new_content)
                rel_path = os.path.relpath(filepath, root)
                _ok(f"{rel_path} — {total_n} inline version(s)")
                total_replacements += total_n
                files_changed += 1

    print(f"\n{'═'*55}\n  {GRN}✅ Version bumped to {new_version}!{RST}")
    print(f"  Updated {total_replacements} references across {files_changed} files.\n{'═'*55}\n")

if __name__ == "__main__":
    main()
