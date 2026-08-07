# 🔬 Scanner Errors — SMP V9.4.0

## Nmap: requires root / permission denied

```
QUITTING! -- Error: You requested a scan type which requires root privileges.
```

**Fix option 1 — sudoers (recommended):**
```bash
sudo visudo
# Add line:
youruser ALL=(ALL) NOPASSWD: /usr/bin/nmap
```

**Fix option 2 — passwordless sudo for session:**  
Enter your sudo password in **Settings → Sudo Password** in the GUI.

**Fix option 3 — capabilities (no sudo needed):**
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
```

---

## Nuclei: templates missing or outdated

```bash
# Update templates
nuclei -update-templates

# If nuclei not in PATH
bin/nuclei -update-templates

# Force template directory
mkdir -p ~/.local/nuclei-templates
nuclei -update-templates -t ~/.local/nuclei-templates
```

---

## Nikto: not installed

```bash
sudo apt install nikto
# verify
nikto -Version
```

---

## ffuf: too many results / false positives

SMP automatically filters SPA catch-all responses (when ≥80% of results share the same Content-Length). If results are still excessive:

1. Check narrative log for `ffuf SPA Filter: Removed X catch-all false positives`
2. If filter didn't trigger, increase wordlist specificity in scanner config
3. The target may genuinely expose many paths — review manually

---

## Gitleaks: no findings but repo has secrets

Gitleaks scans the local git history. If targeting a remote URL without cloning:
```bash
# Clone target repo first (if authorized)
git clone https://github.com/target/repo /tmp/target_repo
gitleaks detect --source /tmp/target_repo --report-format json
```

SMP's Gitleaks integration runs against cloned repos only.

---

## Dalfox / Katana: binary not found

```bash
# Check bin/ directory
ls -la bin/dalfox bin/katana

# Re-download if missing
curl -fsSL https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_amd64.tar.gz \
  | tar -xz -C bin/ dalfox
chmod +x bin/dalfox

curl -fsSL https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip \
  -o /tmp/katana.zip && unzip /tmp/katana.zip -d bin/ && chmod +x bin/katana
```

---

## SQLMap: target not responding to probes

SQLMap uses heuristics to detect injectable parameters. If no injection points found:
- Target URL may not have SQL-injectable parameters
- Try `standard` profile which includes parameter discovery (Arjun) before SQLMap
- Check if target has WAF blocking SQLMap user-agent

---

## WPScan: API token required for CVE data

WPScan's vulnerability database requires a free API token for full CVE data:
1. Register at `https://wpscan.com/` (free tier: 25 requests/day)
2. Add to `config/settings.json`:
```bash
python3 -c "import json, os; p='config/settings.json'; d=json.load(open(p)) if os.path.exists(p) else {}; d['wpscan_api_token']='your_token_here'; json.dump(d, open(p,'w'), indent=4)"
```

Without a token, WPScan still runs but returns fewer vulnerability details.

---

## WPScan Docker: image pull slow

First run pulls the `wpscanteam/wpscan` image (~150 MB). Pre-pull it:
```bash
docker pull wpscanteam/wpscan
```

---

## GreyNoise: rate limit (HTTP 429)

Community API allows ~50 requests/minute. SMP caches results per-session, so each IP is only looked up once. If hitting rate limits:
- Check if the same IP appears in many findings (normal — it's cached)
- Register a free GreyNoise API key and add to `config/settings.json`:
```bash
python3 -c "import json, os; p='config/settings.json'; d=json.load(open(p)) if os.path.exists(p) else {}; d['greynoise_api_key']='your_key_here'; json.dump(d, open(p,'w'), indent=4)"
```

---

## theHarvester: module not found

```bash
source venv/bin/activate
pip install theHarvester

# or install from source
git clone https://github.com/laramies/theHarvester /tmp/theharvester
pip install -r /tmp/theharvester/requirements.txt
```

---

## Scanner timeout — step skipped

If a scanner step times out, SMP adds it to the deferred retry queue and tries again with 1.5× timeout after the main pipeline completes. You'll see:

```
[*] Retrying failed/timed out step: Running Nikto with 1.5x timeout...
[✅ RECOVERY] Fallback execution succeeded for step: Running Nikto
```

If retry also fails, the step is logged as `Persistent Execution Failure` and the scan continues without it. This is intentional — one slow tool should not block an entire engagement.

---

## MAC changer failed — scan still proceeds

```
[MAC] MAC change failed (non-fatal): [Errno 1] Operation not permitted
```

MAC changing requires `ip link` or `macchanger` with sudo privileges. This is non-fatal — the scan continues without MAC randomisation. To fix:
```bash
sudo apt install macchanger
sudo visudo
# Add: youruser ALL=(ALL) NOPASSWD: /sbin/ip, /usr/bin/macchanger
```

To disable MAC changing entirely:
```bash
python3 -c "import json, os; p='config/settings.json'; d=json.load(open(p)) if os.path.exists(p) else {}; d['mac_changer_enabled']=False; json.dump(d, open(p,'w'), indent=4)"
```
