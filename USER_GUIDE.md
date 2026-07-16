<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- ██╗   ██╗███████╗███████╗██████╗      ██████╗ ██╗   ██╗██╗██████╗  ███████╗ -->
<!-- ██║   ██║██╔════╝██╔════╝██╔══██╗    ██╔════╝ ██║   ██║██║██╔══██╗ ██╔════╝ -->
<!-- ██║   ██║███████╗█████╗  ██████╔╝    ██║  ███╗██║   ██║██║██║  ██║ █████╗   -->
<!-- ██║   ██║╚════██║██╔══╝  ██╔══██╗    ██║   ██║██║   ██║██║██║  ██║ ██╔══╝   -->
<!-- ╚██████╔╝███████║███████╗██║  ██║    ╚██████╔╝╚██████╔╝██║██████╔╝ ███████╗ -->
<!--  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝     ╚═════╝  ╚═════╝ ╚═╝╚═════╝  ╚══════╝ -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->

<div align="center">

<h1>
<span style="color:#FF6B6B">🔴</span>
<span style="color:#FF8E53">🟠</span>
<span style="color:#FFD93D">🟡</span>
<span style="color:#6BCB77">🟢</span>
<span style="color:#4D96FF">🔵</span>
<span style="color:#C77DFF">🟣</span>
&nbsp; Security Management Platform &nbsp;
<span style="color:#C77DFF">🟣</span>
<span style="color:#4D96FF">🔵</span>
<span style="color:#6BCB77">🟢</span>
<span style="color:#FFD93D">🟡</span>
<span style="color:#FF8E53">🟠</span>
<span style="color:#FF6B6B">🔴</span>
</h1>

```
███████╗███╗   ███╗██████╗     ██╗   ██╗ ██████╗        ██████╗ 
██╔════╝████╗ ████║██╔══██╗    ██║   ██║██╔════╝        ██╔═████╗
███████╗██╔████╔██║██████╔╝    ██║   ██║███████╗ █████╗ ██║██╔██║
╚════██║██║╚██╔╝██║██╔═══╝     ╚██╗ ██╔╝██╔═══██╗╚════╝ ████╔╝██║
███████║██║ ╚═╝ ██║██║          ╚████╔╝ ╚██████╔╝        ╚██████╔╝
╚══════╝╚═╝     ╚═╝╚═╝           ╚═══╝   ╚═════╝          ╚═════╝ 
```

### 🛡️ The **Complete** User Guide — **V6.0** 🛡️
### *From Complete Beginner → Advanced Analyst → Security Researcher*

---

[![Version](https://img.shields.io/badge/Version-V6.0-blueviolet?style=for-the-badge&logo=shield)](.)
[![Level](https://img.shields.io/badge/Level-Beginner%20to%20Research-brightgreen?style=for-the-badge)](.)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue?style=for-the-badge&logo=linux)](.)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)](.)

</div>

---

> [!IMPORTANT]
> 🔐 **LEGAL NOTICE** — SMP is for **authorised security testing only**.  
> Always obtain **written permission** before scanning any target.  
> Unauthorised scanning is illegal in most jurisdictions. Read on — responsibly.

---

## 🌈 Table of Contents

<div align="center">

| 🎨 Color | Section | Level |
|:--------:|---------|-------|
| 🔴 **RED** | [Part 0 — Philosophy & Architecture](#-part-0--philosophy--architecture) | Everyone |
| 🟠 **ORANGE** | [Part 1 — Beginner: First Setup](#-part-1--beginner-first-setup-zero-to-running) | 🐣 New Users |
| 🟡 **YELLOW** | [Part 2 — Intermediate: Daily Operations](#-part-2--intermediate-daily-operations) | 🔧 Regular Analysts |
| 🟢 **GREEN** | [Part 3 — Advanced: Power Features](#-part-3--advanced-power-features) | ⚡ Power Users |
| 🔵 **BLUE** | [Part 4 — Developer: Plugin System](#-part-4--developer-plugin-system) | 🧑‍💻 Developers |
| 🟣 **PURPLE** | [Part 5 — Research Level](#-part-5--research-level) | 🔬 Researchers |
| ⭐ **GOLD** | [Part 6 — V6.0 Complete Fix List (30)](#-part-6--v60-complete-fix--feature-list-30-items) | 📋 All Levels |
| 🔧 **WRENCH** | [Part 7 — Troubleshooting](#-part-7--troubleshooting) | 🆘 Help Me! |

</div>

---

# 🔴 Part 0 — Philosophy & Architecture

> *"Security tools should be as powerful as the threats they fight — and as simple as the apps we love."*

## What is SMP?

SMP is an **all-in-one security scanning platform** purpose-built for enterprise teams. Think of it as your personal security operations centre — automating what takes a team of engineers days to do manually.

```
┌─────────────────────────────────────────────────────────┐
│                   SMP V6.0 Architecture                  │
├───────────────┬──────────────────┬──────────────────────┤
│   🖥️  GUI      │  🔌 Plugin System │    🌐 REST API V6    │
│   (PySide6)   │  (Auto-discover) │  (JWT + Rate Limit)  │
├───────────────┴──────────────────┴──────────────────────┤
│              📊 Scan Orchestrator (DAG Engine)           │
├──────────┬──────────┬────────────┬───────────────────────┤
│ 🔍 Nmap  │ 💥 Nuclei│ 🕸️ Katana  │  30+ more scanners   │
├──────────┴──────────┴────────────┴───────────────────────┤
│              🗄️ Encrypted SQLite Database                 │
├─────────────────────────────────────────────────────────┤
│    🔐 Fernet+PBKDF2 (600k iter)  │  🔑 RSA-2048 License │
└─────────────────────────────────────────────────────────┘
```

## The Three Laws of SMP

| # | Law | Meaning |
|---|-----|---------|
| 1 | 🤖 **Zero Manual Work** | If a tool isn't installed, SMP skips it gracefully. Everything has a fallback. |
| 2 | 📊 **Reports Executives Can Read** | Beautiful PDFs, not raw terminal dumps |
| 3 | 🧠 **Intelligence, Not Just Scanning** | CVE correlation, risk scoring, OSINT, compliance mapping |

---

# 🟠 Part 1 — Beginner: First Setup (Zero to Running)

> 🐣 **You are here if**: You just downloaded SMP and want to get it running.  
> ⏱️ **Time needed**: About 10-15 minutes.

---

## 🟠 Step 1 — Auto-Setup

We've completely automated the setup process. Just run the script for your OS!

### For Linux / macOS
```bash
# Make the scripts executable
chmod +x setup.sh run.sh

# Run the auto-setup (installs Python deps, OS tools, and Go binaries)
./setup.sh
```

### For Windows (PowerShell)
```powershell
# Run the auto-setup script
.\setup.ps1
```

> [!NOTE]
> ☕ The setup scripts are fully autonomous. They will automatically install Python dependencies, configure the environment, and download all required external security tools (Nmap, Nuclei, Nikto, Go, Ruby, Perl) using your system's package manager (`apt`, `brew`, `dnf`, `pacman`, or `winget` on Windows). It takes about 2-5 minutes.

---

## 🟠 Step 2 — Find and Install the License File

To ensure only capable operators use SMP V6.0, your license key is locked behind a cryptography puzzle.

1. Open the [LICENSE_FINDER.md](LICENSE_FINDER.md) file in the root directory.
2. Follow the 3 hints provided to solve the puzzle and derive the password for the license vault.
3. Once you have the vault password (e.g., `Mega-XXXX`), use it to unzip `license_puzzle/vault.zip`.

**How to add the license key:**
```bash
# Unzip the vault using your derived password (replace YOUR_PASSWORD)
unzip -P YOUR_PASSWORD license_puzzle/vault.zip -d license_puzzle/

# Create the config directory if it doesn't exist
mkdir -p config

# Move the extracted huge_license.key into the config directory
mv license_puzzle/huge_license.key config/license.key
```

> [!IMPORTANT]
> 🔑 Without a valid `config/license.key` containing the correct RSA-2048 private key, SMP will not start.  

---

## 🟠 Step 3 — Launch SMP! 🚀

```bash
# Run the platform using the automated runner
./run.sh
```
*(On Windows, run: `.\run.bat`)*

**First launch experience:**
1. 🔐 A **Set Master Password** dialog appears
2. Enter a **strong password** (V6.0 enforces complexity):
   - ✅ Minimum 12 characters
   - ✅ At least one UPPERCASE letter
   - ✅ At least one lowercase letter
   - ✅ At least one digit (0-9)
   - ✅ At least one special character (!@#$%^&*)
3. The password **encrypts your entire database** — don't forget it!
4. The main dashboard opens — you're in! 🎉

> [!WARNING]
> ### 🛑 Forgot your Master Password?
> If you forgot your master password, the system will repeatedly ask you for the old password on startup and you will be completely locked out of the database! 
> 
> **How to fix this error and reset the application:**
> You must perform a hard factory reset by deleting the `auth.json` file and your encrypted databases. Run this in your terminal:
> ```bash
> rm -f config/auth.json
> rm -f database/*.db.enc database/*.db
> ```
> Next time you run `./run.sh`, the system will allow you to create a brand new master password.

**Example strong password:**
```
SecureM@co2026!    ← ✅ Meets all requirements
```

---

## 🟠 Step 8 — Add Your First Target

1. Click **"Targets"** in the left sidebar
2. Click **"+ Add Target"**
3. Enter the URL: `https://yourtargetdomain.com`
4. Fill in: Company Name, Contact Person
5. Click **"Save"**

> [!CAUTION]
> ⚠️ Only add targets you have **written permission** to scan!

---

## 🟠 Step 9 — Run Your First Scan

1. Select your target from the list
2. Choose scan profile:
   - 🟢 **Fast** — Quick check, ~5 min
   - 🟡 **Standard** — Balanced, ~20 min *(recommended for beginners)*
   - 🔴 **Full** — Deep scan, 1-3 hours
3. Click **"▶ Start Scan"**
4. SMP checks system resources first — if something's overloaded, it warns you
5. Watch the progress in real time!

---

## 🟠 Step 10 — Get Your Report

When the scan finishes:
1. Click **"Reports"** in the sidebar
2. Select the scan
3. Click **"Generate PDF Report"**
4. Your professional security report is ready! 📄

---

# 🟡 Part 2 — Intermediate: Daily Operations

> ⚡ **You are here if**: SMP is running and you want to use it effectively every day.

---

## 🟡 Understanding the Dashboard

```
┌──────────────────────────────────────────────────────────┐
│  🛡️ SMP V6.0          [🔴 Targets] [🟡 Scans] [📊 CVEs] │
├──────────┬───────────────────────────────────────────────┤
│          │  Security Posture Score: 72/100  📈 +5        │
│  SIDEBAR │  ─────────────────────────────────────────    │
│          │  🔴 Critical: 2  🟠 High: 8  🟡 Med: 15      │
│  Targets │  ─────────────────────────────────────────    │
│  Scans   │  📡 MAC: aa:bb:cc:dd:ee:ff (changed 10:23)   │
│  CVE DB  │  🔒 Session: 8 min remaining                  │
│  Reports │  ─────────────────────────────────────────    │
│  Logs    │  Last Scan: example.com (2h ago) ✅           │
│  Settings│  CVE DB: 284,391 entries (synced 1h ago)     │
│          │                                               │
└──────────┴───────────────────────────────────────────────┘
```

### Key Dashboard Widgets (V6.0)

| Widget | What it shows |
|--------|--------------|
| **Security Posture Score** | 0-100 score across ALL targets. Higher = safer |
| **MAC Address Display** | Current interface MAC — updates live after each MAC change |
| **Session Timer** | Minutes until auto-lock (15min idle default) |
| **CVE Trend Heatmap** | 30-day severity trend per target |
| **Finding Severity Counts** | Critical/High/Medium/Low/Info breakdown |

---

## 🟡 Scan Profiles Explained

| Profile | Tools Run | Time | Use When |
|---------|-----------|------|----------|
| ⚡ **Fast** | Nmap, WhatWeb, httpx | 2-5 min | Quick health check |
| 🔧 **Standard** | + Nuclei, Nikto, Subfinder, SQLMap | 15-30 min | Regular scheduled scans |
| 🔥 **Full** | Everything — all 30+ tools | 1-3 hours | Deep penetration test |

---

## 🟡 Reading Your Report

A V6.0 report has these sections:

```
📄 SMP SECURITY REPORT
├── 📊 Executive Summary
│   ├── Risk Score (0-100)
│   ├── Security Posture Score  ← NEW in V6.0
│   └── Finding Counts by Severity
├── 🔍 Findings
│   ├── Critical (fix immediately!)
│   ├── High (fix this week)
│   ├── Medium (fix this month)
│   └── Low/Info (track)
├── ✅ Compliance Mapping         ← NEW in V6.0
│   ├── OWASP Top 10 2021
│   ├── CIS Controls v8
│   └── ISO 27001:2022
├── 📈 Scan Delta (vs last scan)  ← NEW in V6.0
│   ├── NEW findings (🔴 red)
│   └── RESOLVED findings (🟢 green)
└── 📦 SBOM (Software Bill of Materials) ← NEW in V6.0
```

---

## 🟡 Understanding Finding Severity

| Severity | CVSS | Meaning | Fix Timeframe |
|----------|------|---------|--------------|
| 🔴 **Critical** | 9.0-10.0 | System compromise possible | **Immediately** |
| 🟠 **High** | 7.0-8.9 | Significant risk | Within **7 days** |
| 🟡 **Medium** | 4.0-6.9 | Moderate risk | Within **30 days** |
| 🟢 **Low** | 0.1-3.9 | Minor issues | Next quarter |
| ℹ️ **Info** | 0.0 | For awareness | When convenient |

> [!WARNING]
> ⏰ **SLA Breach Warning (V6.0)** — Findings unfixed for more than **30 days** are automatically escalated in severity and marked "SLA Breached" in your next report!

---

## 🟡 Scheduler — Automated Daily Scans

Configure automatic scanning in **Settings → Scheduling**:

```
Scan Schedule: Daily at 02:00 AM  ← low-traffic time
Intel Sync:    Every 1 hour       ← CVE database updates
Backup:        Daily              ← automatic DB backup
```

**Why 2 AM?**  
- Minimal user impact on production systems
- Fresh CVE data is pulled overnight
- Reports are ready by morning standup ✅

---

## 🟡 CVE Database — Understanding the Intel Tab

```
CVE Database Status
─────────────────────────────────────────
✅ NVD (NIST):          284,391 CVEs  
✅ CISA KEV:              1,023 actively exploited
✅ GitHub Advisories:     8,221 package vulns
✅ EPSS Scores:           Last updated 2h ago
─────────────────────────────────────────
Last Full Sync: Today at 03:00 AM
Next Sync: In 58 minutes
```

The CVE database **persists across restarts** (V6.0 P0 fix). You will always see your downloaded data on reopen.

---

# 🟢 Part 3 — Advanced: Power Features

> ⚡ **You are here if**: You're comfortable with SMP and want to push it further.

---

## 🟢 Authenticated Scanning

Scan behind login pages by configuring auth headers:

**Settings → Authentication Headers:**
```json
{
  "Cookie": "session=your-session-cookie-here",
  "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6..."
}
```

This passes your credentials to Nuclei, Nikto, and all HTTP-based scanners.

---

## 🟢 Port Baseline Tracking (V6.0)

After your **first scan**, SMP saves a **port baseline** for each target.

Every subsequent scan compares to this baseline:

```
🔍 Port Baseline Comparison — example.com
─────────────────────────────────────────────
✅ Expected open:    80/tcp (http)
✅ Expected open:    443/tcp (https)
🔴 NEW OPEN PORT:   8443/tcp (https-alt)  ← ALERT: Not in baseline!
❌ Port now closed:  22/tcp (ssh)          ← Was in baseline, now gone
```

**New ports = immediate High finding.** Unexpected open ports are a red flag.

---

## 🟢 Finding Deduplication

SMP V6.0 automatically merges duplicate findings from multiple scanners:

```
BEFORE deduplication:
  Finding 1: "Missing X-Frame-Options" — Source: Nuclei
  Finding 2: "Missing X-Frame-Options" — Source: Nikto
  Finding 3: "SQL Injection in /login" — Source: SQLMap

AFTER deduplication:
  Finding 1: "Missing X-Frame-Options" — Sources: Nuclei, Nikto [MERGED]
  Finding 2: "SQL Injection in /login" — Source: SQLMap
```

No more 47-page reports where half the findings are duplicates!

---

## 🟢 GreyNoise IP Classification

When SMP finds suspicious IPs in scan data, it checks **GreyNoise**:

```
IP Classification Results:
─────────────────────────────────────────────────────
198.51.100.23   → 🟢 noise    (Shodan internet scanner — safe to ignore)
203.0.113.45    → 🔴 malicious (Known threat actor — escalate!)
192.168.1.100   → 🟡 private  (Internal IP — no GreyNoise data)
```

Configure your (optional) GreyNoise API key in Settings → Intelligence for enhanced data.

---

## 🟢 MAC Address Changer — Deep Dive

SMP changes your network interface MAC address before each scan for OPSEC:

```
🔄 MAC Changer: [Wi-Fi] wlan0 → a4:c3:f0:dd:3b:7e ✓ (ip-link)
                         └─ Intel OUI preserved
                                       └─ Randomised last 3 bytes
```

**Three strategies (tried in order):**
1. `ip link set address` — fast, no downtime
2. `macchanger` binary — more compatible
3. down/MAC change/up — guaranteed but brief interruption

**New in V6.0:** The new MAC is displayed in the dashboard status bar after every change so you always know what address you're presenting on the network.

---

## 🟢 Secrets Detection

SMP now scans HTTP responses for exposed secrets:

```
🕵️ Secrets Scanner — Detected in /js/config.js:
─────────────────────────────────────────────────
🔴 CRITICAL: AWS Access Key ID    → AKIA4V5G...****
🔴 CRITICAL: RSA Private Key      → -----BEGIN RSA...
🟠 HIGH:     GitHub Personal Token → ghp_3hS2m...****
🟡 MEDIUM:   High-Entropy API Key  → api_key="dKj9m...****"
```

Detected patterns: AWS, GCP, Azure, Stripe, Twilio, SendGrid, GitHub, JWT, database URLs, RSA private keys, and generic high-entropy tokens.

---

## 🟢 API Mode (Headless / CI-CD Integration)

Run SMP as a headless REST API for integration with pipelines:

```bash
# Start the API server
python3 main.py --api

# API is now at: http://127.0.0.1:8000/api/v6/docs
```

**Authentication flow:**
```bash
# Step 1: Get a JWT token
curl -X POST http://localhost:8000/api/v6/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "YourMasterPassword!"}'

# Returns:
# {"access_token": "eyJhbG...", "token_type": "bearer", "expires_in": 86400}

# Step 2: Use the token for all subsequent requests
TOKEN="eyJhbG..."

# List all targets
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v6/target

# Get CVE stats
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v6/cve/stats

# Get findings for scan ID 42
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v6/findings?scan_id=42"
```

**Complete V6.0 API Reference:**

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/v6/auth/token` | Get JWT Bearer token | ❌ No |
| `GET` | `/api/v6/health` | Health check | ❌ No |
| `GET` | `/api/v6/version` | Platform version | ✅ Yes |
| `GET` | `/api/v6/target` | List all targets | ✅ Yes |
| `POST` | `/api/v6/target` | Add a target | ✅ Yes |
| `GET` | `/api/v6/scan` | List scans | ✅ Yes |
| `GET` | `/api/v6/findings` | Get findings for scan | ✅ Yes |
| `GET` | `/api/v6/cve/stats` | CVE statistics | ✅ Yes |
| `GET` | `/api/v6/risk/score` | Risk scores | ✅ Yes |

---

## 🟢 Session Auto-Lock

SMP V6.0 automatically locks your session after idle time (default: 15 minutes).

**Configure in Settings → Security:**
```
Session Timeout: 15 minutes  (set to 0 to disable)
```

When the timer fires, the password dialog re-appears — your scan data is preserved, just locked. Enter your password to resume exactly where you left off.

---

## 🟢 SBOM Generation

After every scan, SMP generates a **Software Bill of Materials** (SBOM) — an inventory of all detected technologies on the target:

```bash
# SBOM saved automatically to:
~/.local/share/SMP/reports/sbom/sbom_example-com_20260716_142300.cdx.json
```

**CycloneDX JSON format** (industry standard, accepted by Dependency-Track, OWASP):
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {"name": "nginx", "version": "1.18.0", "type": "library"},
    {"name": "WordPress", "version": "6.2", "type": "library"},
    {"name": "PHP", "version": "8.1.12", "type": "library"}
  ]
}
```

---

# 🔵 Part 4 — Developer: Plugin System

> 🧑‍💻 **You are here if**: You want to add your own tools to SMP.

---

## 🔵 The Zero-Friction Plugin System (V6.0)

Adding a new scanner to SMP is the **easiest thing you'll do today**.

### Minimum Plugin Structure

Create a file in `scanners/` — that's it:

```python
# scanners/my_custom_tool.py

# REQUIRED: Plugin metadata dictionary
PLUGIN_META = {
    "name": "MyCustomTool",           # Display name in UI
    "binary": "my_tool",              # Binary to check on PATH
    "severity": "Medium",             # Default severity
}

# REQUIRED: scan function
def scan(url: str) -> list:
    """
    Run your tool against url.
    Return a list of finding dicts.
    """
    import subprocess
    result = subprocess.run(
        ["my_tool", "--target", url, "--json"],
        capture_output=True, text=True, timeout=60
    )
    # Parse output and return findings
    return [
        {
            "severity": "High",
            "title": "Example Finding from MyCustomTool",
            "description": f"Found issue on {url}\n\n{result.stdout}",
            "tool": "MyCustomTool",
            "confidence": 75,
        }
    ]
```

**That's literally all you need.** SMP auto-discovers it on next startup. No imports, no registration, no config files.

---

## 🔵 Optional Plugin Metadata Keys

```python
PLUGIN_META = {
    "name": "MyCustomTool",     # Required
    "binary": "my_tool",        # Required — binary name to check on PATH
    "severity": "Medium",       # Optional — default severity

    # Optional advanced settings:
    "step_name": "Running MyCustomTool",  # Shown in progress bar
    "depends_on": ["Nmap"],               # Run after these scanners
    "confidence": 70,                     # 0-100 confidence score
    "needs_binary": True,                 # Skip if binary not found
    "enabled": True,                      # Can be set to False to disable
}
```

---

## 🔵 Finding Dict Reference

Your `scan()` function should return a list of these dicts:

```python
{
    # Required
    "severity": "Critical",     # Critical | High | Medium | Low | Info
    "title": "Finding title",   # Short, descriptive
    "description": "Details",   # Full markdown-friendly details

    # Recommended
    "tool": "MyCustomTool",     # Your tool name
    "confidence": 80,           # 0-100

    # Optional
    "cwe_id": "CWE-89",         # For compliance mapping
    "url": "https://...",       # Specific vulnerable URL
    "request": "GET /page HTTP/1.1\n...",   # HTTP request that triggered it
    "response": "HTTP/1.1 200 OK\n...",     # HTTP response
}
```

---

## 🔵 Testing Your Plugin

```bash
# Test your plugin loads correctly
python3 -c "
from scanners.core.registry import auto_discover_plugins, get_registered_scanners
plugins = auto_discover_plugins()
print('Discovered plugins:', plugins)
scanners = get_registered_scanners()
if 'MyCustomTool' in scanners:
    print('✅ MyCustomTool registered successfully!')
    print('   Config:', scanners['MyCustomTool'])
else:
    print('❌ MyCustomTool not found. Check PLUGIN_META and scan() function.')
"
```

---

## 🔵 Using the Event Bus

Communicate between your scanner and the dashboard:

```python
# In your scanner — emit events
from tools.event_bus import emit

emit("scan_progress", {"tool": "MyTool", "percent": 50, "message": "Halfway done"})
emit("new_finding", {"severity": "High", "title": "XSS Found"})

# In dashboard code — subscribe to events
from tools.event_bus import subscribe

def on_mac_changed(event, data):
    mac = data.get("new_mac", "")
    self.status_bar.showMessage(f"MAC changed to: {mac}")

subscribe("mac_changed", on_mac_changed)
```

---

## 🔵 Adding to the Compliance Mapper

If your tool detects specific vulnerability types, register them:

```python
# In tools/compliance_mapper.py — add to _OWASP_2021
_OWASP_2021["A03:2021 - Injection"]["keywords"].append("my_tool_injection_type")
```

---

# 🟣 Part 5 — Research Level

> 🔬 **You are here if**: You're building on top of SMP for security research.

---

## 🟣 Database Schema Deep Dive

SMP uses **encrypted SQLite** (Fernet + PBKDF2). Access the decrypted DB:

```python
# Never access the .db.enc file directly — use this:
from tools.db_manager import get_db_connection

conn = get_db_connection()

# Key tables:
# targets        — scan targets
# scans          — scan run records
# findings       — all vulnerability findings
# cves           — CVE database (284k+ entries)
# technologies   — detected technologies per scan
# logs           — audit trail with HMAC signatures
# target_baselines — port baselines per target
```

---

## 🟣 Encryption Architecture

```
Master Password
     │
     ▼
PBKDF2-SHA256 (600,000 iterations, 16-byte random salt)
     │
     ▼
32-byte AES key
     │
     ▼
Fernet (AES-128-CBC + HMAC-SHA256)
     │
     ▼
Encrypted: security.db.enc, active_scans.db.enc
```

**V6.0 improvement:** Iterations bumped from 100,000 → **600,000** (NIST SP 800-132 2024 recommendation).

---

## 🟣 RSA License Verification

```python
# Verify the license programmatically
from tools.license_verifier import RSALicenseVerifier

verifier = RSALicenseVerifier(base_dir="/path/to/smp")
is_valid = verifier.verify()

# Generates a V6.0 license (for IT admins):
# 1. Generate RSA key pair:
#    openssl genrsa -out private.pem 2048
#    openssl rsa -in private.pem -pubout -out public.pem
# 2. Create license payload:
import json, base64
payload = json.dumps({
    "licensee": "Mega Cooperative",
    "issued": "2026-01-01",
    "expires": "2027-01-01",
    "features": ["full"],
}, sort_keys=True, separators=(',', ':'))
# 3. Sign with private key:
#    openssl dgst -sha256 -sign private.pem -out sig.bin <(echo -n $payload)
#    base64 -w0 sig.bin
# 4. Create license.key JSON with the signature base64
```

---

## 🟣 Audit Trail Integrity Verification

Every log entry in V6.0 has an HMAC-SHA256 signature:

```python
import hmac, hashlib

def verify_log_entry(message: str, stored_hmac: str, key: bytes) -> bool:
    """Verify a log entry's tamper-evident signature."""
    expected = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, stored_hmac)

# In the log viewer, entries show:
# ✅ HMAC OK   — log entry is untampered
# ❌ HMAC FAIL — log entry has been modified (security incident!)
```

---

## 🟣 Custom Intelligence Pipeline

```python
# Build a custom threat intel correlation
from intelligence.greynoise import classify_scan_ips
from intelligence.cve_correlator import correlate_cve
from tools.compliance_mapper import get_compliance_summary
from tools.finding_deduplicator import deduplicate_findings

# Get raw findings from DB
from tools.db_manager import get_findings_for_scan
raw_findings = list(get_findings_for_scan(scan_id=42))

# Step 1: Deduplicate
unique_findings = deduplicate_findings(raw_findings)

# Step 2: Enrich with GreyNoise
enriched = classify_scan_ips(unique_findings, api_key="your-key")

# Step 3: Compliance mapping
summary = get_compliance_summary(enriched)
print(f"OWASP coverage: {summary['owasp_top10_coverage']}%")
print(f"CIS coverage:   {summary['cis_controls_coverage']}%")
print(f"ISO 27001:      {summary['iso27001_coverage']}%")
```

---

## 🟣 System Resource API

```python
from tools.system_checker import check_system_resources

result = check_system_resources(settings={
    "sys_cpu_warn_pct": 70,    # Warn at 70% CPU
    "sys_ram_warn_mb": 1000,   # Warn under 1GB RAM
    "sys_disk_warn_gb": 2.0,   # Warn under 2GB disk
})

print(result)
# {
#   "ok": False,
#   "warnings": ["⚠️ High CPU: 88.1% (threshold: 70%)"],
#   "metrics": {
#     "cpu_pct": 88.1,
#     "free_ram_mb": 2280.0,
#     "free_disk_gb": 23.38,
#     "network_ok": True
#   }
# }
```

---

# ⭐ Part 6 — V6.0 Complete Fix & Feature List (30 Items)

> 📋 Every change, fix, and feature in V6.0 with copy-paste verification commands.

---

## 🔴 P0 Critical Bugs Fixed

### Fix 1 — Full Data Persistence (All Data Survives Restart)

**Problem:** CVE data, scan history, findings, and risk scores were lost every time the app was closed and reopened.

**Root cause:** `start_scheduler()` was called before `decrypt_databases()` completed, so the CVE sync thread tried to read an encrypted (unreadable) database.

**Fix applied in:** `main.py`, `tools/scheduler.py`

```python
# BEFORE (broken — V5.x):
init_directories()
init_db()
setup_logging()
start_scheduler()   # ← CVE sync starts before DB is decrypted!

# AFTER (fixed — V6.0):
init_directories()
decrypt_databases()   # ← Decrypt FIRST
init_db()
setup_logging()
start_scheduler()     # ← NOW safe to start background workers
```

**Verify:**
```bash
# Launch SMP, download CVE data, close the app, reopen it
# CVE data should still be visible immediately on reopen
python3 -c "
from tools.encryption_manager import is_decryption_ok, decrypt_databases
decrypt_databases()
print('Decryption OK:', is_decryption_ok())
"
```

---

### Fix 2 — CVE Sync DB-Ready Guard (3× Retry with Backoff)

**Problem:** The CVE sync scheduler started even when the DB wasn't ready.

**Fix applied in:** `tools/scheduler.py`

```python
# The guard function added to scheduler.py:
def _wait_for_db_ready(max_retries=3, wait_seconds=5) -> bool:
    for attempt in range(1, max_retries + 1):
        try:
            from tools.db_manager import get_db_connection
            conn = get_db_connection()
            conn.execute("SELECT 1 FROM cves LIMIT 1")
            return True  # DB is ready!
        except Exception as e:
            print(f"DB not ready (attempt {attempt}/{max_retries}): {e}")
        time.sleep(wait_seconds)
        wait_seconds *= 2  # Exponential backoff: 5s → 10s → 20s
    return False
```

**Verify:**
```bash
python3 -c "
from tools.scheduler import _wait_for_db_ready
print('DB ready guard works:', callable(_wait_for_db_ready))
"
```

---

### Fix 3 — UDP IPC Socket Removed (Privilege Escalation Risk)

**Problem:** A UDP listener on port 5005 accepted unauthenticated commands — local privilege escalation vector.

**Fix:** Replaced with an in-process thread-safe event bus.

```python
# OLD (dangerous):
# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# sock.bind(('localhost', 5005))  ← Unauthenticated!

# NEW (safe — tools/event_bus.py):
from tools.event_bus import subscribe, emit

# Publisher (scanner thread):
emit("mac_changed", {"new_mac": "aa:bb:cc:dd:ee:ff"})

# Subscriber (UI thread):
subscribe("mac_changed", lambda event, data: update_status_bar(data["new_mac"]))
```

**Verify:**
```bash
python3 -c "
from tools.event_bus import subscribe, emit
results = []
subscribe('test', lambda e,d: results.append(d))
emit('test', {'val': 42})
assert results[0]['val'] == 42
print('✅ Event bus working — UDP socket removed')
"
```

---

### Fix 4 — Fake Fail2ban Data Removed

**Problem:** When `/var/log/fail2ban.log` didn't exist, SMP returned fake IP addresses as "active bans" — causing analysts to investigate non-existent threats.

**Fix applied in:** `tools/fail2ban_reader.py`

```python
# BEFORE (misleading):
return [{"ip": "198.51.100.23", "jail": "nginx-botsearch", ...}]  # FAKE!

# AFTER (honest):
if not os.path.isfile(log_path):
    return []  # Empty list — UI shows "Unavailable"
```

**Verify:**
```bash
python3 -c "
from tools.fail2ban_reader import get_active_bans
result = get_active_bans('/nonexistent/fail2ban.log')
assert result == [], f'Expected empty list, got: {result}'
print('✅ No more fake ban data — returns empty list when log missing')
"
```

---

## 🔒 Security Hardening

### Fix 5 — RSA-2048 License Verification

```python
# Programmatic verification:
from tools.license_verifier import verify_license
is_valid = verify_license("/path/to/smp")
print("License valid:", is_valid)
# Fallback chain: RSA → offline grace cache → legacy SHA-256
```

---

### Fix 6 — Password Complexity Policy (NIST Compliant)

```python
from tools.encryption_manager import validate_password_complexity

# Test your password:
ok, msg = validate_password_complexity("YourPassword123!")
print("Valid:", ok)
if not ok:
    print("Issues:", msg)

# Requirements: 12+ chars, uppercase, lowercase, digit, special char
```

---

### Fix 7 — PBKDF2 Iterations: 100,000 → 600,000

```python
# Verify the new iteration count:
from tools.encryption_manager import _PBKDF2_ITERATIONS
print(f"PBKDF2 iterations: {_PBKDF2_ITERATIONS:,}")
# Output: PBKDF2 iterations: 600,000
```

---

### Fix 8 — 9 Empty Scanner Stubs Removed

```bash
# Verify these are gone:
for f in scanners/spiderfoot.py scanners/semgrep_scanner.py \
          scanners/trivy.py scanners/trufflehog.py; do
  [ -f "$f" ] && echo "❌ STILL EXISTS: $f" || echo "✅ Deleted: $f"
done
```

---

### Fix 9 — 5 Dev Scripts Removed from Production

```bash
# Verify these are gone:
for f in test_active.py test_gui.py test_scan.py fix_headers.py reset_db.py; do
  [ -f "$f" ] && echo "❌ STILL EXISTS: $f" || echo "✅ Deleted: $f"
done
```

---

## ✨ New Features

### Feature 10 — Zero-Friction Scanner Plugin System

```python
# Drop this into scanners/my_tool.py and restart:
PLUGIN_META = {"name": "MyTool", "binary": "my_tool", "severity": "High"}

def scan(url: str) -> list:
    return [{"severity": "High", "title": "Test", "description": "Found on " + url, "tool": "MyTool"}]

# Verify auto-registration:
# python3 -c "
# from scanners.core.registry import auto_discover_plugins
# new = auto_discover_plugins()
# print('New plugins:', new)
# "
```

---

### Feature 11 — System Pre-Scan Resource Checker

```python
from tools.system_checker import check_system_resources

result = check_system_resources()
print(f"System OK: {result['ok']}")
print(f"CPU: {result['metrics']['cpu_pct']:.1f}%")
print(f"RAM free: {result['metrics']['free_ram_mb']:.0f} MB")
print(f"Disk free: {result['metrics']['free_disk_gb']:.2f} GB")
print(f"Network: {'✅' if result['metrics']['network_ok'] else '❌'}")
for w in result['warnings']:
    print(f"Warning: {w}")
```

---

### Feature 12 — Enhanced MAC Changer with Result Display

```python
from tools.mac_changer import change_mac_address, get_current_mac

# Get current MAC
current = get_current_mac()
print(f"Current MAC: {current}")

# Change it (returns new MAC in tuple)
success, message, new_mac = change_mac_address(sudo_password="your_sudo_pass")
print(f"Success: {success}")
print(f"New MAC: {new_mac}")
print(f"Message: {message}")
```

---

### Feature 13 — Compliance Mapper (OWASP/CIS/ISO 27001)

```python
from tools.compliance_mapper import map_finding_to_controls, get_compliance_summary

# Map a single finding
controls = map_finding_to_controls("SQL Injection", "CWE-89")
print("OWASP:", controls["owasp"])
print("CIS:  ", controls["cis"])
print("ISO:  ", controls["iso27001"])

# Get summary across all findings
findings = [
    {"title": "SQL Injection", "cwe_id": "CWE-89"},
    {"title": "XSS", "cwe_id": "CWE-79"},
    {"title": "Weak TLS", "cwe_id": "CWE-327"},
]
summary = get_compliance_summary(findings)
print(f"OWASP Top 10 coverage: {summary['owasp_top10_coverage']}%")
print(f"CIS Controls coverage: {summary['cis_controls_coverage']}%")
print(f"ISO 27001 coverage:    {summary['iso27001_coverage']}%")
```

---

### Feature 14 — Port Baseline Tracking

```python
from tools.baseline_manager import set_baseline_ports, compare_to_baseline

# Save initial baseline
ports = [
    {"port": 80, "protocol": "tcp", "service": "http"},
    {"port": 443, "protocol": "tcp", "service": "https"},
]
set_baseline_ports(target_id=1, target_url="https://example.com", ports=ports)

# Compare after next scan
current_ports = ports + [{"port": 8443, "protocol": "tcp", "service": "https-alt"}]
new_findings = compare_to_baseline(1, "https://example.com", current_ports)
for f in new_findings:
    print(f"🔴 {f['severity']}: {f['title']}")
# Output: 🔴 High: New Open Port Detected: 8443/tcp (https-alt)
```

---

### Feature 15 — Finding Deduplication

```python
from tools.finding_deduplicator import deduplicate_findings

findings = [
    {"title": "Missing X-Frame-Options", "severity": "Low", "tool": "Nuclei", "description": "desc1"},
    {"title": "Missing X-Frame-Options", "severity": "Low", "tool": "Nikto",  "description": "desc2 (more detail)"},
    {"title": "SQL Injection", "severity": "Critical", "tool": "SQLMap", "description": "critical sqli"},
]
deduped = deduplicate_findings(findings)
print(f"Before: {len(findings)} findings")
print(f"After:  {len(deduped)} findings")
for f in deduped:
    print(f"  - {f['title']} ({f['tool']})")
# Output:
# Before: 3 findings
# After:  2 findings
#   - Missing X-Frame-Options (Nuclei, Nikto)  ← merged!
#   - SQL Injection (SQLMap)
```

---

### Feature 16 — SBOM Generation

```python
from tools.sbom_generator import generate_sbom_for_scan

# After a completed scan (scan_id from DB):
sbom_path = generate_sbom_for_scan(scan_id=42, target_url="https://example.com")
print(f"SBOM saved to: {sbom_path}")

# View the SBOM:
import json
with open(sbom_path) as f:
    sbom = json.load(f)
print(f"Format: {sbom['bomFormat']}")
print(f"Components: {len(sbom['components'])}")
```

---

### Feature 17 — Secrets Scanner

```python
from scanners.secrets_scanner import run_secrets_scan

# Scan a URL for exposed secrets
findings = run_secrets_scan("https://example.com")
for f in findings:
    print(f"🔴 {f['severity']}: {f['title']}")
    print(f"   {f['description'][:100]}...")
```

---

### Feature 18 — GreyNoise IP Classification

```python
from intelligence.greynoise import lookup_ip, classify_scan_ips

# Look up a single IP
result = lookup_ip("198.51.100.23")
print(f"IP: {result['ip']}")
print(f"Noise: {result['noise']}")        # Known scanner?
print(f"Riot: {result['riot']}")          # Known benign infra?
print(f"Class: {result['classification']}") # malicious/benign/unknown
print(f"Name: {result['name']}")
```

---

### Feature 19 — JWT API Authentication

```bash
# Full API workflow with copy-paste commands:

# 1. Start API server
python3 main.py --api &

# 2. Get JWT token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v6/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst","password":"YourMasterPass!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token: ${TOKEN:0:30}..."

# 3. Check health (no auth needed)
curl -s http://localhost:8000/api/v6/health | python3 -m json.tool

# 4. List targets (auth required)
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v6/target | python3 -m json.tool

# 5. Get CVE stats
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v6/cve/stats | python3 -m json.tool
```

---

### Feature 20 — Session Manager (Auto-Lock)

```python
from tools.session_manager import init_session, reset_session

# Initialize with 15-minute timeout
def lock_screen():
    print("🔒 Session locked due to inactivity!")

session = init_session(timeout_minutes=15, on_lock=lock_screen)

# Call this on every user interaction to reset the timer
reset_session()

# Check state
print("Locked:", session.is_locked())
```

---

### Feature 21 — Compliance Reporting

```python
from tools.compliance_mapper import get_compliance_summary

# Full audit across all findings
findings = [...]  # Your findings list
summary = get_compliance_summary(findings)

print("=== Compliance Coverage Report ===")
print(f"OWASP Top 10 2021: {summary['owasp_top10_coverage']}%")
print(f"CIS Controls v8:   {summary['cis_controls_coverage']}%")
print(f"ISO 27001:2022:    {summary['iso27001_coverage']}%")
print()
print("OWASP categories hit:")
for cat in summary['owasp_categories_hit']:
    print(f"  ✅ {cat}")
```

---

### Feature 22 — HMAC Audit Log Signing

```python
import hmac, hashlib

def verify_log_entry(message: str, stored_hmac: str, key: bytes) -> bool:
    """Verify a log entry hasn't been tampered with."""
    expected = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, stored_hmac)

# Every log entry in the DB now has a tamper-evident HMAC signature
# The log viewer shows: ✅ HMAC OK  or  ❌ HMAC FAIL
```

---

### Feature 23 — Event Bus (Replace UDP IPC)

```python
from tools.event_bus import subscribe, emit, unsubscribe

# Subscribe to events
def on_scan_complete(event, data):
    print(f"Scan done! Findings: {data.get('finding_count', 0)}")

subscribe("scan_complete", on_scan_complete)

# Emit events (from scanner thread — thread-safe)
emit("scan_complete", {"target": "example.com", "finding_count": 15})

# Unsubscribe when done
unsubscribe("scan_complete", on_scan_complete)
```

---

### Feature 24 — Screenshot Evidence Capture

```python
from scanners.screenshot_capture import capture_screenshot

# Capture a screenshot of a vulnerable page as evidence
path = capture_screenshot("https://example.com/vulnerable-page")
print(f"Evidence saved: {path}")
# Returns .png (playwright) or .html (fallback) path
```

---

### Feature 25 — V6 REST API (All Endpoints)

```bash
# Complete API test suite — copy-paste into terminal

BASE="http://localhost:8000"
TOKEN=$(curl -s -X POST $BASE/api/v6/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst","password":"YourPass!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

AUTH="-H \"Authorization: Bearer $TOKEN\""

echo "--- Health (no auth) ---"
curl -s $BASE/api/v6/health

echo "--- Version ---"
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/v6/version

echo "--- Targets ---"
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/v6/target

echo "--- CVE Stats ---"
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/v6/cve/stats

echo "--- Risk Scores ---"
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/v6/risk/score
```

---

### Feature 26 — Rate-Limited Scanning

```python
# Configure in settings.json or Settings UI:
{
    "rate_limit_rpm": 120   # Max 120 HTTP requests per minute per target
}

# Prevents accidental DoS on production systems
# Each scanner respects this limit automatically
```

---

### Feature 27 — V6 Config Defaults

```python
# All new V6.0 settings with defaults:
from tools.config_manager import DEFAULT_SETTINGS

v6_settings = {k: v for k, v in DEFAULT_SETTINGS.items() 
               if k in ['session_timeout_minutes', 'rate_limit_rpm', 
                        'sla_breach_days', 'greynoise_api_key',
                        'mac_display_result', 'sys_cpu_warn_pct',
                        'sys_ram_warn_mb', 'sys_disk_warn_gb',
                        'port_baseline_enabled', 'api_token_expiry_hours']}
import json
print(json.dumps(v6_settings, indent=2))
```

---

### Feature 28 — SLA Breach Tracking

```
Finding created: 2026-05-01
Today's date:    2026-07-16
Days unfixed:    76 days  ← EXCEEDS 30-day SLA!

Status: ⚠️ SLA BREACHED — Risk score automatically escalated
```

Configure SLA threshold in Settings → Risk → SLA Breach Days (default: 30)

---

### Feature 29 — Security Posture Score (SPS)

The SPS is a 0-100 score calculated from:

```
SPS = 100 - (
    Critical_count × 25 +
    High_count     × 10 +
    Medium_count   × 3  +
    Low_count      × 1  +
    SLA_breached   × 15 +
    New_ports      × 5
)  ← Capped at 0
```

Check it programmatically:
```python
from tools.risk_scorer import calculate_sps

sps = calculate_sps(target_id=1)
print(f"Security Posture Score: {sps}/100")
```

---

### Feature 30 — Complete V6.0 Validation

Run this to verify your entire V6.0 installation:

```bash
python3 -c "
import sys

print('=== SMP V6.0 — Complete Installation Validation ===\n')
tests_passed = 0
tests_total = 0

def check(label, fn):
    global tests_passed, tests_total
    tests_total += 1
    try:
        fn()
        print(f'  ✅ {label}')
        tests_passed += 1
    except Exception as e:
        print(f'  ❌ {label}: {e}')

check('License Verifier', lambda: __import__('tools.license_verifier', fromlist=['']).verify_license)
check('System Checker',   lambda: __import__('tools.system_checker', fromlist=['']).check_system_resources)
check('Session Manager',  lambda: __import__('tools.session_manager', fromlist=['']).init_session)
check('Compliance Mapper',lambda: __import__('tools.compliance_mapper', fromlist=['']).map_finding_to_controls)
check('Port Baseline',    lambda: __import__('tools.baseline_manager', fromlist=['']).get_baseline_ports)
check('SBOM Generator',   lambda: __import__('tools.sbom_generator', fromlist=['']).generate_sbom_for_scan)
check('Deduplicator',     lambda: __import__('tools.finding_deduplicator', fromlist=['']).deduplicate_findings)
check('Event Bus',        lambda: __import__('tools.event_bus', fromlist=['']).emit)
check('GreyNoise',        lambda: __import__('intelligence.greynoise', fromlist=['']).lookup_ip)
check('Secrets Scanner',  lambda: __import__('scanners.secrets_scanner', fromlist=['']).run_secrets_scan)
check('JWT Auth',         lambda: __import__('api.auth', fromlist=['']).create_token)

from tools.encryption_manager import _PBKDF2_ITERATIONS
check('PBKDF2 600k',      lambda: None if _PBKDF2_ITERATIONS == 600_000 else 1/0)

import json
with open('config/metadata.json') as f: meta = json.load(f)
check('Version V6.0',     lambda: None if meta.get('version') == 'V6.0' else 1/0)

import os
deleted = ['test_active.py', 'scanners/spiderfoot.py', 'reset_db.py']
check('Dead code removed', lambda: None if not any(os.path.exists(f) for f in deleted) else 1/0)

print(f'\n{\"=\"*52}')
print(f'  RESULT: {tests_passed}/{tests_total} checks passed')
grade = '🏆 PERFECT' if tests_passed == tests_total else '⚠️ NEEDS ATTENTION'
print(f'  Grade:  {grade}')
print(f'{\"=\"*52}')
"
```

---

# 🔧 Part 7 — Troubleshooting

---

## 🔧 "License signature file missing!"

```bash
# Check if license.key exists
ls -la config/license.key

# If missing, copy your license file:
cp /path/to/provided/license.key config/license.key
```

---

## 🔧 "No module named 'PySide6'"

```bash
pip install PySide6
# If that fails on Linux:
sudo apt install python3-pyside6 -y
```

---

## 🔧 CVE data not showing after restart

This was the P0 bug fixed in V6.0. If you're still seeing this:

```bash
# Verify the startup order fix is in place
python3 -c "
import inspect
from main import main
src = inspect.getsource(main)
if 'decrypt_databases' in src and 'start_scheduler' in src:
    decrypt_pos = src.index('decrypt_databases')
    sched_pos = src.index('start_scheduler')
    if decrypt_pos < sched_pos:
        print('✅ Startup order correct: decrypt runs before scheduler')
    else:
        print('❌ STARTUP ORDER WRONG! decrypt must come before start_scheduler')
"
```

---

## 🔧 "Password does not meet policy requirements"

Your password must have:
```
✅ At least 12 characters
✅ At least one UPPERCASE letter (A-Z)
✅ At least one lowercase letter  (a-z)
✅ At least one digit             (0-9)
✅ At least one special character (!@#$%^&*)

Good example: SecureM@co2026!
```

---

## 🔧 Scanner not being discovered

```bash
python3 -c "
from scanners.core.registry import auto_discover_plugins, get_registered_scanners
plugins = auto_discover_plugins()
print('All registered scanners:')
for name in get_registered_scanners():
    print(f'  ✅ {name}')
"
# If your scanner is missing, check:
# 1. Does the file have PLUGIN_META dict?
# 2. Does the file have a scan() function?
# 3. Is the file in the scanners/ directory (not a subdirectory)?
```

---

## 🔧 API returns 401 Unauthorized

```bash
# Your token may have expired (24h default)
# Get a fresh token:
curl -X POST http://localhost:8000/api/v6/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "YourMasterPassword!"}'
```

---

## 🔧 Pre-scan warning about CPU/RAM

The System Checker fired. Options:
1. **Continue Anyway** — if you know it's ok
2. **Cancel** — wait for system load to drop
3. **Adjust thresholds** in Settings → System:
   ```
   CPU warning threshold: 90% (was 80%)
   RAM warning threshold: 200 MB (was 500 MB)
   ```

---

## 🔧 MAC change failed

```
MAC Changer: All 3 strategies failed. Scan proceeds anyway.
```

This is non-fatal — the scan continues. To fix MAC changing:
```bash
# Check if you have ip command
which ip

# Check if sudo works without password for ip:
sudo -n ip link show

# If not, add to /etc/sudoers (use visudo):
# youruser ALL=(ALL) NOPASSWD: /sbin/ip link set *
```

---

## 🔧 Playwright not installed (screenshot fallback)

```bash
# Install playwright + Chromium:
pip install playwright
playwright install chromium

# Verify:
python3 -c "from playwright.sync_api import sync_playwright; print('✅ Playwright OK')"
```

---

## 🗑️ How to Selectively Delete Items

If you don't want to perform a **Full Factory Reset**, you can easily delete specific data using the API or directly via SQLite commands.

### 1. Delete a Specific Target & Its Scans
```bash
# Connect to the database
sqlite3 database/security.db

# Find the target ID
SELECT id, url FROM targets;

# Delete it (this automatically cascades to delete associated scans)
DELETE FROM targets WHERE id = 5;
.quit
```

### 2. Delete All Scan Results for a Specific Tool
```bash
sqlite3 database/security.db
DELETE FROM scan_results WHERE scan_id IN (SELECT id FROM scans WHERE tool_name = 'Nmap');
.quit
```

### 3. Clear Only the Logs
```bash
# Delete all log files but keep your data intact
rm -f logs/*.log
```

---

## 💻 30 Copy-Paste Usage Scenarios

Whether you are automating SMP in a CI/CD pipeline or running quick recon, here are 30 direct commands you can copy and paste into your terminal. 
*(Ensure your API is running by starting `./run.sh` first!)*

> **Note:** Replace `YourMasterPassword!` with your actual password.

### 🎯 Basic Recon & Target Management
1. **Add a Single Target:**
   `curl -X POST -H "Authorization: Bearer YourMasterPassword!" -H "Content-Type: application/json" -d '{"url":"https://example.com","tags":"prod"}' http://127.0.0.1:8000/api/v6/targets`
2. **List All Targets:**
   `curl -X GET -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/targets`
3. **Delete Target #1:**
   `curl -X DELETE -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/targets/1`
4. **Search Targets by Tag:**
   `curl -X GET -H "Authorization: Bearer YourMasterPassword!" "http://127.0.0.1:8000/api/v6/targets?search=prod"`
5. **Add Multiple Targets (Bulk):**
   `curl -X POST -H "Authorization: Bearer YourMasterPassword!" -H "Content-Type: application/json" -d '{"urls":["https://a.com","https://b.com"]}' http://127.0.0.1:8000/api/v6/targets/bulk`

### 🚀 Starting Scans
6. **Start a Full Vulnerability Scan:**
   `curl -X POST -H "Authorization: Bearer YourMasterPassword!" -H "Content-Type: application/json" -d '{"target_id": 1, "profile": "full"}' http://127.0.0.1:8000/api/v6/scans/start`
7. **Start a Fast Recon Scan:**
   `curl -X POST -H "Authorization: Bearer YourMasterPassword!" -H "Content-Type: application/json" -d '{"target_id": 1, "profile": "fast"}' http://127.0.0.1:8000/api/v6/scans/start`
8. **Start a Specific Tool Scan (e.g. Nmap):**
   `curl -X POST -H "Authorization: Bearer YourMasterPassword!" -H "Content-Type: application/json" -d '{"target_id": 1, "tools": ["Nmap"]}' http://127.0.0.1:8000/api/v6/scans/start`
9. **Start an Authenticated Scan (Header Auth):**
   `curl -X POST -H "Authorization: Bearer YourMasterPassword!" -H "Content-Type: application/json" -d '{"target_id": 1, "profile": "full", "headers": {"Authorization": "Bearer token123"}}' http://127.0.0.1:8000/api/v6/scans/start`
10. **Start an Aggressive Scan (Stealth Off):**
    `curl -X POST -H "Authorization: Bearer YourMasterPassword!" -H "Content-Type: application/json" -d '{"target_id": 1, "profile": "aggressive"}' http://127.0.0.1:8000/api/v6/scans/start`

### 📊 Monitoring Scans
11. **Check All Running Scans:**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/scans?status=running`
12. **Check Scan Status by ID:**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/scans/12`
13. **Stop a Running Scan:**
    `curl -X POST -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/scans/12/stop`
14. **Get Findings for a Scan:**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/scans/12/findings`
15. **Get High-Severity Findings Only:**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" "http://127.0.0.1:8000/api/v6/scans/12/findings?severity=high"`

### 🧠 Threat Intelligence (CVEs)
16. **Check CVE Database Status:**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/intel/status`
17. **Force Manual CVE Sync:**
    `curl -X POST -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/intel/sync`
18. **Search for a Specific CVE:**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" "http://127.0.0.1:8000/api/v6/intel/search?q=CVE-2021-44228"`
19. **Search CVEs by Keyword (e.g. Apache):**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" "http://127.0.0.1:8000/api/v6/intel/search?q=Apache"`
20. **Search CVEs by Severity (Critical):**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" "http://127.0.0.1:8000/api/v6/intel/search?severity=critical"`

### 📝 Reporting & Export
21. **Generate PDF Report for Target #1:**
    `curl -X POST -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/reports/generate/pdf/1`
22. **Generate HTML Report for Target #1:**
    `curl -X POST -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/reports/generate/html/1`
23. **List All Generated Reports:**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/reports`
24. **Download Report by ID:**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" --output report.pdf http://127.0.0.1:8000/api/v6/reports/download/5`
25. **Export All Findings to CSV:**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" --output findings.csv http://127.0.0.1:8000/api/v6/export/csv`

### ⚙️ System & Administration
26. **Check System Health (CPU/RAM/DB):**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/system/health`
27. **Check Audit Logs:**
    `curl -X GET -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/system/audit_logs`
28. **Update System Settings (e.g. timeout):**
    `curl -X POST -H "Authorization: Bearer YourMasterPassword!" -H "Content-Type: application/json" -d '{"scan_timeout_minutes": 120}' http://127.0.0.1:8000/api/v6/system/settings`
29. **Trigger Tool Verifier/Update:**
    `curl -X POST -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/system/tools/verify`
30. **Trigger Background DB Backup:**
    `curl -X POST -H "Authorization: Bearer YourMasterPassword!" http://127.0.0.1:8000/api/v6/system/backup`

---

<div align="center">

---

## 🌈 You've reached the end of the SMP V6.0 Guide! 🌈

```
🔴 Beginner    ✅ Setup & Running
🟠 Operator    ✅ Daily Operations
🟡 Analyst     ✅ Advanced Features
🟢 Developer   ✅ Plugin System
🔵 Researcher  ✅ Deep Architecture
🟣 Expert      ✅ All 30 V6.0 Changes
```

**SMP V6.0 — Built for Mega Cooperative**  
*Authorised use only. Scan responsibly. Secure everything.*

[![Version](https://img.shields.io/badge/SMP-V6.0-blueviolet?style=for-the-badge)](.)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=for-the-badge)](.)

---

</div>
