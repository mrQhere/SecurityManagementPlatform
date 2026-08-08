#!/usr/bin/env python3
"""
SMP V9.4.2 — Troubleshooting Simulator & Auto-Fixer
Simulates a scan environment and provides exact copy-paste solutions for missing dependencies.
"""
import os
import sys
import shutil

RED = "\033[91m"
GRN = "\033[92m"
YEL = "\033[93m"
BLU = "\033[94m"
RST = "\033[0m"
BLD = "\033[1m"

def print_header(title):
    print(f"\n{BLD}{BLU}=== {title} ==={RST}")

def check_python_deps():
    print_header("Checking Python Dependencies")
    missing = []
    
    try:
        import pysqlcipher3
        print(f"  {GRN}[OK]{RST} pysqlcipher3 is installed.")
    except ImportError:
        print(f"  {RED}[FAIL]{RST} pysqlcipher3 is MISSING.")
        missing.append("pysqlcipher3")

    try:
        import requests
        print(f"  {GRN}[OK]{RST} requests is installed.")
    except ImportError:
        print(f"  {RED}[FAIL]{RST} requests is MISSING.")
        missing.append("requests")

    if missing:
        print(f"\n{YEL}Copy-paste the following to fix Python dependencies:{RST}")
        print(f"{BLD}sudo apt update && sudo apt install -y libsqlcipher-dev libsqlcipher0 build-essential python3-dev{RST}")
        print(f"{BLD}pip install {' '.join(missing)}{RST}")
    else:
        print(f"\n{GRN}All Python dependencies are satisfied.{RST}")

def check_system_binaries():
    print_header("Checking System & Scanner Binaries")
    
    binaries = {
        "nmap": "sudo apt install -y nmap",
        "nikto": "sudo apt install -y nikto",
        "macchanger": "sudo apt install -y macchanger",
        "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && sudo cp ~/go/bin/nuclei /usr/local/bin/",
        "ffuf": "go install -v github.com/ffuf/ffuf/v2@latest && sudo cp ~/go/bin/ffuf /usr/local/bin/",
        "wpscan": "sudo gem install wpscan",
        "sqlmap": "sudo apt install -y sqlmap"
    }
    
    missing_cmds = []
    
    for bin_name, fix_cmd in binaries.items():
        if shutil.which(bin_name):
            print(f"  {GRN}[OK]{RST} {bin_name} found.")
        else:
            # Check local bin/
            local_bin = os.path.join(os.path.dirname(__file__), "..", "bin", bin_name)
            if os.path.exists(local_bin) and os.access(local_bin, os.X_OK):
                print(f"  {GRN}[OK]{RST} {bin_name} found in local bin/.")
            else:
                print(f"  {RED}[FAIL]{RST} {bin_name} is MISSING.")
                missing_cmds.append(fix_cmd)
                
    if missing_cmds:
        print(f"\n{YEL}Copy-paste the following to install missing binaries:{RST}")
        for cmd in missing_cmds:
            print(f"{BLD}{cmd}{RST}")
    else:
        print(f"\n{GRN}All required binaries are installed.{RST}")

def check_permissions():
    print_header("Checking Permissions (Nmap root access)")
    
    print(f"  {BLU}[INFO]{RST} Checking if nmap can run as root without password...")
    
    # Try nmap with sudo non-interactive
    import subprocess
    result = subprocess.run(["sudo", "-n", "nmap", "-sS", "-p", "80", "127.0.0.1"], 
                            capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"  {GRN}[OK]{RST} Sudo Nmap works perfectly.")
    else:
        print(f"  {YEL}[WARN]{RST} Sudo requires password or nmap fails. Nmap SYN scans will fail.")
        print(f"\n{YEL}Copy-paste the following to grant Nmap root privileges (Option 1):{RST}")
        print(f"{BLD}sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap){RST}")
        print(f"\n{YEL}Or configure sudoers (Option 2):{RST}")
        print(f"{BLD}echo \"$USER ALL=(ALL) NOPASSWD: /usr/bin/nmap\" | sudo tee /etc/sudoers.d/nmap_smp{RST}")

def main():
    print(f"{BLD}Security Management Platform (SMP) V9.4.2{RST}")
    print("Troubleshooting Simulator starting...\n")
    
    check_python_deps()
    check_system_binaries()
    check_permissions()
    
    print(f"\n{BLD}{GRN}Simulation complete. Apply any copy-paste fixes above and re-run to verify.{RST}")

if __name__ == "__main__":
    main()
