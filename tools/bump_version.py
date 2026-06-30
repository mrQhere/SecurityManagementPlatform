#!/usr/bin/env python3
import sys
import json
import os
import re

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 bump_version.py <NEW_VERSION>")
        print("Example: python3 bump_version.py V5.2")
        sys.exit(1)

    new_version = sys.argv[1]
    
    # 1. Update metadata.json
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "metadata.json")
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            data = json.load(f)
        old_version = data.get("version", "V5.0")
        data["version"] = new_version
        with open(config_path, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Updated config/metadata.json from {old_version} to {new_version}")
    else:
        print("[-] config/metadata.json not found!")
        sys.exit(1)

    # 2. Update README.md and USER_GUIDE.md
    docs = [
        os.path.join(os.path.dirname(__file__), "..", "README.md"),
        os.path.join(os.path.dirname(__file__), "..", "USER_GUIDE.md")
    ]

    for doc in docs:
        if os.path.exists(doc):
            with open(doc, "r") as f:
                content = f.read()
            
            # Simple string replace for the old version
            # Because V5.0 might be lowercase, we do a regex case-insensitive replace
            # but we need to be careful. It's safer to just replace the exact old string.
            new_content = re.sub(re.escape(old_version), new_version, content, flags=re.IGNORECASE)
            
            with open(doc, "w") as f:
                f.write(new_content)
            print(f"[+] Updated {os.path.basename(doc)}")

    print(f"\n✅ Version successfully bumped to {new_version}!")

if __name__ == "__main__":
    main()
