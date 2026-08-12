#!/bin/bash
BIN_DIR="./bin"
tools=(nuclei subfinder httpx katana dnsx ffuf gitleaks dalfox race-the-web trivy)
for tool in "${tools[@]}"; do
    if [ -f "$BIN_DIR/$tool" ]; then
        sha256sum "$BIN_DIR/$tool"
    else
        echo "$tool not found"
    fi
done
