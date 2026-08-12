import urllib.request
import re

TOOLS = {
    "nuclei": ("projectdiscovery/nuclei", "v3.3.9", "nuclei_3.3.9_checksums.txt"),
    "subfinder": ("projectdiscovery/subfinder", "v2.6.8", "subfinder_2.6.8_checksums.txt"),
    "httpx": ("projectdiscovery/httpx", "v1.6.8", "httpx_1.6.8_checksums.txt"),
    "katana": ("projectdiscovery/katana", "v1.1.0", "katana_1.1.0_checksums.txt"),
    "dnsx": ("projectdiscovery/dnsx", "v1.2.1", "dnsx_1.2.1_checksums.txt"),
    "ffuf": ("ffuf/ffuf", "v2.1.0", "ffuf_2.1.0_checksums.txt"),
    "gitleaks": ("zricethezav/gitleaks", "v8.18.2", "gitleaks_8.18.2_checksums.txt"),
    "dalfox": ("hahwul/dalfox", "v2.10.0", None),
    "trivy": ("aquasecurity/trivy", "v0.55.0", "trivy_0.55.0_checksums.txt")
}

print("declare -A T_SHA_AMD")
print("declare -A T_SHA_ARM")

for tool, (repo, tag, chk_file) in TOOLS.items():
    if not chk_file:
        continue
    url = f"https://github.com/{repo}/releases/download/{tag}/{chk_file}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            text = response.read().decode('utf-8')
            for line in text.split('\n'):
                parts = line.strip().split()
                if len(parts) == 2:
                    sha, filename = parts
                    if 'linux_amd64.tar.gz' in filename or 'Linux_x86_64.tar.gz' in filename or 'linux-amd64' in filename or 'Linux-64bit' in filename:
                        print(f'T_SHA_AMD[{tool}]="{sha}"')
                    elif 'linux_arm64.tar.gz' in filename or 'Linux_arm64.tar.gz' in filename or 'linux-arm64' in filename or 'Linux-ARM64' in filename:
                        print(f'T_SHA_ARM[{tool}]="{sha}"')
    except Exception as e:
        print(f"# Failed to fetch {tool}: {e}")
