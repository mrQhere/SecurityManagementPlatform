```text
███████╗███╗   ███╗██████╗ 
██╔════╝████╗ ████║██╔══██╗
███████╗██╔████╔██║██████╔╝
╚════██║██║╚██╔╝██║██╔═══╝ 
███████║██║ ╚═╝ ██║██║     
╚══════╝╚═╝     ╚═╝╚═╝     
```
  Security Management Platform  ·  V9.5  ·  by P R Abinraj
  Local-first · Zero-cloud · AES-256 Encrypted at Rest
  github.com/mrQhere/SecurityManagementPlatform

# Security Management Platform (SMP) — Complete User Guide
Version: V9.5 | Author: P R Abinraj | Updated: August 2026

## Table of Contents
1. [Introduction & User Tiers](#1-introduction--user-tiers)
2. [Installation & System Requirements](#2-installation--system-requirements)
3. [First Launch — Encryption Setup](#3-first-launch--encryption-setup)
4. [Dashboard Reference (All 10 Pages)](#4-dashboard-reference-all-10-pages)
5. [Running Your First Scan](#5-running-your-first-scan)
6. [Scanner Reference & Tuning (95 scanners)](#6-scanner-reference--tuning-95-scanners)
7. [Writing Custom Scanners](#7-writing-custom-scanners)
8. [Enterprise Data Export & Legal Gate](#8-enterprise-data-export--legal-gate)
9. [Advanced Tuning & Performance](#9-advanced-tuning--performance)
10. [Headless API Reference](#10-headless-api-reference)
11. [Troubleshooting & Error Codes](#11-troubleshooting--error-codes)
12. [Deep Technical Architecture](#12-deep-technical-architecture)
13. [How to Extend SMP](#13-how-to-extend-smp)

## 1. Introduction & User Tiers

The Security Management Platform (SMP) V9.5 is a robust, local-first, zero-cloud vulnerability scanning and management system. By avoiding cloud-based execution, SMP ensures that all sensitive data, from target ingestion to vulnerability evidence, remains strictly on your local hardware.

### The 7-Step Pipeline

SMP employs a sophisticated 7-step pipeline orchestrated by a Directed Acyclic Graph (DAG) for high-performance security assessments:

**Step 1: Target Ingestion**
The process begins when a user submits a target URL, IP address, or CIDR range. The system validates the input, resolves DNS records, and normalizes the target format to ensure compatibility with downstream tools. During this phase, basic reachability checks are performed.

**Step 2: Reconnaissance**
Once ingested, the system initiates comprehensive reconnaissance. This involves passive and active subdomain enumeration, open port discovery, banner grabbing, and technology fingerprinting. The goal is to build a complete map of the attack surface before initiating intrusive scans.

**Step 3: Active Scanning**
Based on the selected scan policy, the DAG orchestrator triggers specialized active scanners. These scanners run concurrently, respecting the maximum concurrency limits defined in the configuration. This step involves everything from basic web vulnerability checks to deep injection testing and container security assessments.

**Step 4: Vulnerability Verification**
To maintain a high signal-to-noise ratio, SMP utilizes 15 distinct verify suites. When an active scanner flags a potential vulnerability, the corresponding verify suite is invoked. These suites perform secondary checks, often using different techniques or tools, to confirm the finding and eliminate false positives.

**Step 5: Evidence Collection**
For every verified finding, SMP automatically captures and stores immutable evidence. This evidence is saved locally in the `data/evidence/` directory. Evidence can include screenshots, raw HTTP request/response logs, and memory dumps. The system uses a SHA-256 deduplication formula to ensure storage efficiency.

**Step 6: Risk Scoring**
With evidence collected, the system calculates a holistic risk score. This calculation considers the CVSS base score, the specific context of the finding (e.g., internal vs. external asset), and the presence of any chained vulnerabilities. The resulting score provides a prioritized view of the target's risk posture.

**Step 7: Reporting & Export**
The final step involves generating human-readable reports and structured data exports. Using `ReportGenerator(version='V9.5')`, the system can produce executive summaries, detailed technical reports, and developer-friendly remediation guides. Data can also be exported to enterprise platforms.

### User Tiers

SMP caters to a wide range of security professionals, offering tailored experiences for different skill levels:

**1. Beginner Tier**
- **Focus:** Intuitive operation and quick results.
- **Guidance:** Beginners should rely on the default 'Standard' scan policy. The UI provides step-by-step wizards for initiating scans and interpreting results.
- **Capabilities:** Execute basic web and network scans, view high-level risk scores, and download PDF summary reports.
- **Limitations:** Advanced tuning options and headless API access are hidden by default to prevent accidental misconfiguration.

**2. Intermediate Tier**
- **Focus:** Customization and detailed analysis.
- **Guidance:** Intermediate users can explore custom scan policies, selecting specific scanner modules based on the target type. They should utilize the 'Findings' tab to review raw evidence and validate the results.
- **Capabilities:** Adjust concurrency limits, configure authentication credentials for authenticated scanning, and export findings in generic JSON format.
- **Limitations:** Direct interaction with the DAG engine or custom scanner development is not recommended.

**3. Advanced Tier**
- **Focus:** Automation and integration.
- **Guidance:** Advanced users should leverage the Headless API for CI/CD integration. They can define complex scan policies using the JSON configuration files and utilize the Enterprise Data Export features for integration with Jira or DefectDojo.
- **Capabilities:** Full API access, enterprise export workflows, and deep system tuning (e.g., custom timeouts, memory optimization).
- **Limitations:** System architecture modifications should be approached with caution.

**4. Researcher Tier**
- **Focus:** Extensibility and core system development.
- **Guidance:** Researchers have full access to the underlying architecture. They can develop custom scanner modules using the `@register_scanner` decorator, tune the 15 verify suites, and contribute to the core DAG orchestrator logic.
- **Capabilities:** Modify state machine transitions, implement new data models, and access the raw SQLite database for advanced querying.
- **Limitations:** None. Researchers are expected to understand the implications of deep system modifications.

## 2. Installation & System Requirements

Installing SMP requires careful attention to system dependencies and network configuration to ensure all 95 scanners operate correctly.

### System Requirements

| Component | Minimum Requirement | Recommended | Enterprise Scale |
|-----------|---------------------|-------------|------------------|
| **OS** | Linux (Ubuntu 20.04+) or macOS | Linux (Ubuntu 22.04 LTS) | Linux (Ubuntu 22.04 LTS) |
| **CPU** | 4 Cores | 8+ Cores | 16+ Cores |
| **RAM** | 8 GB | 16+ GB | 32+ GB |
| **Disk** | 20 GB SSD | 50+ GB NVMe SSD | 200+ GB NVMe SSD |
| **Network**| 100 Mbps | 1 Gbps | 10 Gbps |

### Prerequisites

Ensure the following packages are installed on your system before beginning the installation process:
- **Git:** Essential for cloning the repository and managing updates.
- **Python 3.10+:** The core runtime for the DAG orchestrator and control plane.
- **`libsqlcipher-dev`:** Required for compiling `pysqlcipher3`, enabling AES-256 database encryption.
- **Nmap:** Used for core network discovery.
- **Node.js & npm:** Required for JavaScript-based scanners (e.g., Retire.js).
- **Golang:** Necessary for compiling and running Go-based tools (e.g., Nuclei, Naabu).

### Step-by-Step Installation

Execute the following commands to install and launch SMP:

```bash
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform
./setup.sh
./run.sh
```

### Detailed Breakdown of `setup.sh`

The `./setup.sh` script automates the complex provisioning process. Here is a detailed explanation of each step:

1. **Network Pre-flight (`verify_network_routes`):** The script first verifies connectivity to required external resources, including GitHub, Go package proxies, and PyPI. This ensures that subsequent download steps do not fail silently.
2. **Virtual Environment Creation:** It establishes a Python virtual environment (`venv`) to isolate SMP's Python dependencies from the system packages, preventing version conflicts.
3. **Database Encryption Compilation:** This is a critical step. The script compiles `pysqlcipher3` from source, linking it against `libsqlcipher-dev`. This compilation is necessary to enable the AES-256 Encrypted at Rest architecture for the SQLite database.
4. **Python Dependency Installation:** It installs all required Python packages via `pip`, referencing the `requirements.txt` file. This includes FastAPI, SQLAlchemy, and various integration libraries.
5. **Binary Procurement:** The script downloads, verifies, and installs essential Go binaries. These binaries are crucial for high-performance scanning. The tools include Nuclei (placed at `bin/nuclei`), Subfinder, HTTPx, Katana, DNSx, FFUF, Gitleaks, and Dalfox.

### Installer Error Codes

If `./setup.sh` encounters an issue, it will exit with a specific error code. Consult this table for resolution steps:

| Error Code | Component | Description | Resolution Steps |
|------------|-----------|-------------|------------------|
| **SMP-9001** | Network Pre-flight | Failure to reach essential external servers (e.g., github.com). | Check your internet connection, DNS settings, and ensure no outbound firewall rules are blocking standard HTTP/HTTPS traffic. |
| **SMP-9002** | OS Dependencies | Missing essential system libraries. | Ensure `libsqlcipher-dev`, `build-essential`, and appropriate compiler toolchains are installed via your package manager. |
| **SMP-9003** | Python Compilation | Failure to compile `pysqlcipher3`. | Verify that Python 3.10+ development headers (`python3-dev`) are installed and that `libsqlcipher-dev` is accessible to the compiler. |
| **SMP-9004** | Go Binary Download | Failure to fetch or compile Go-based tools. | Check proxy settings. If you are behind a corporate proxy, set the `GOPROXY` environment variable appropriately. |
| **SMP-9005** | Virtual Environment | Failure to create the Python virtual environment. | Ensure the `python3-venv` package is installed on Debian-based systems. |

### macOS Installation Notes

macOS users must utilize Homebrew to install necessary prerequisites before running the setup script.

```bash
# Install Homebrew prerequisites
brew install sqlcipher nmap node go python@3.10

# Ensure sqlcipher is linked correctly for pysqlcipher3 compilation
export LDFLAGS="-L/opt/homebrew/opt/sqlcipher/lib"
export CPPFLAGS="-I/opt/homebrew/opt/sqlcipher/include"

# Proceed with standard installation
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform
./setup.sh
```

### Docker Deployment (Optional)

While SMP's local-first architecture is optimized for native execution, a `docker-compose.yml` file is provided for isolated, containerized environments. Note that some local network discovery capabilities may require host networking mode.

```yaml
# docker-compose.yml example
version: '3.8'
services:
  smp-core:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    environment:
      - SMP_ENVIRONMENT=production
    restart: unless-stopped
```

## 3. First Launch — Encryption Setup

Data security is paramount in SMP. Upon executing `./run.sh` for the first time, you will be guided through the encryption setup wizard. This process establishes the cryptographic foundation for the AES-256 Encrypted at Rest architecture.

### The Setup Wizard Flow

1. **Welcome Screen:** An overview of the local-first security model and the importance of encryption.
2. **Master Password Creation:** You will be prompted to enter a strong Master Password. This password must meet complexity requirements (minimum length, mixed case, symbols).
3. **Password Confirmation:** Re-enter the password to ensure accuracy.
4. **Key Generation Sequence:** The system will display a progress indicator as it performs PBKDF2 key derivation and generates the internal encryption keys.
5. **Database Initialization:** The encrypted SQLite database is initialized, and the initial schema is applied.
6. **Completion:** A final confirmation screen indicating that the system is ready for use.

### Understanding the 4-Layer Key Hierarchy

SMP utilizes a robust 4-layer key management architecture to balance security, performance, and functionality:

1. **KEK (Key Encryption Key):**
   - **Origin:** Derived directly from your Master Password using PBKDF2 (Password-Based Key Derivation Function 2) with a high iteration count.
   - **Purpose:** The sole purpose of the KEK is to encrypt and decrypt the subsequent keys in the hierarchy. It is never used to encrypt raw data.

2. **DEK (Data Encryption Key):**
   - **Origin:** Generated as a random 256-bit key during the first launch and encrypted by the KEK.
   - **Purpose:** The DEK is passed to `pysqlcipher3` to encrypt and decrypt the contents of the SQLite database. This secures all configurations, target lists, and vulnerability metadata.

3. **IEK (Index Encryption Key):**
   - **Origin:** Generated alongside the DEK and encrypted by the KEK.
   - **Purpose:** The IEK is used specifically to encrypt search indices (e.g., tokenized finding descriptions) using deterministic encryption. This allows the system to perform fast, exact-match searches over encrypted data without compromising the confidentiality of the underlying text.

4. **EEK (Evidence Encryption Key):**
   - **Origin:** Generated alongside the DEK and encrypted by the KEK.
   - **Purpose:** The EEK is used to symmetrically encrypt the raw evidence files stored in the `data/evidence/` directory. Each file is encrypted before being written to disk, ensuring that even if the filesystem is compromised, the evidence remains secure.

### Critical Warning: Lost Passwords

**THERE IS NO PASSWORD RECOVERY MECHANISM.**

Because SMP is entirely local and zero-cloud, we do not store a copy of your Master Password, KEK, or any other keys. If you forget your Master Password, the KEK cannot be derived, and the DEK, IEK, and EEK cannot be decrypted.

**Consequence:** All data within the SQLite database and all evidence files in `data/evidence/` will become permanently inaccessible. You must delete the `data/` directory and re-initialize the system, resulting in total data loss.

## 4. Dashboard Reference (All 10 Pages)

The SMP User Interface is designed for clarity and efficiency, providing access to all system functions through 10 primary navigation tabs.

### 1. Overview Tab
- **Purpose:** Provides a high-level summary of the system's current state and historical data.
- **Widgets:**
  - **Global Risk Score:** A prominent gauge displaying the aggregated risk score across all targets.
  - **Findings Summary:** A pie chart breaking down findings by severity (Critical, High, Medium, Low, Info).
  - **Recent Activity:** A timeline view of the last 5 completed scans and any system alerts.
  - **System Health:** Indicators showing CPU usage, memory consumption, and database size.
- **Actions:** Quick links to "Start New Scan" and "View Critical Findings".

### 2. Targets Tab
- **Purpose:** Management interface for the assets and domains you intend to scan.
- **Widgets:**
  - **Target List:** A paginated table displaying Target URL/IP, Company Name, Added Date, and Last Scanned Date.
  - **Target Details Panel:** Clicking a row expands a panel showing associated tags, specific scan history for that target, and current risk metrics.
- **Actions:** "Add Target" (opens a dialog for single or bulk import), "Edit Target", "Delete Target", and "Initiate Scan on Selected".

### 3. Active Scans Tab
- **Purpose:** Real-time monitoring and control of running DAG orchestrations.
- **Widgets:**
  - **Scan Queue:** A list of pending, running, and paused scans.
  - **DAG Visualization:** A graphical representation of the `DAGOrchestrator`'s current state, showing which scanner modules are executing, completed, or failed.
  - **Live Log Feed:** A terminal-like window streaming standard output and error messages from the active scanners.
- **Actions:** "Pause Scan", "Resume Scan", "Cancel Scan", and "View Detailed Logs".

### 4. Findings Tab
- **Purpose:** The central repository for all identified vulnerabilities and security issues.
- **Widgets:**
  - **Findings Data Table:** A comprehensive table sortable by Severity, Target, Scanner Source, and Date Discovered.
  - **Filter Sidebar:** Robust filtering options (e.g., show only High severity findings on a specific target identified by Nuclei).
  - **Finding Details View:** Selecting a finding displays the full description, remediation advice, and links to the cryptographically sealed evidence in `data/evidence/`.
- **Actions:** "Mark as False Positive", "Change Severity", "Add Note", and "Export Selected".

### 5. Intelligence Tab
- **Purpose:** Integration point for external threat data and vulnerability research.
- **Widgets:**
  - **CVE Database Search:** An interface to query the local CVE snapshot.
  - **Threat Feeds:** Displays recent intelligence from configured OSINT sources (e.g., new exploit releases).
  - **Scanner Coverage Map:** A matrix showing which CVEs or vulnerability classes are covered by the currently active 95 scanners.
- **Actions:** "Update Local CVE Database", "Configure Feed Sources".

### 6. Assets & Services Tab
- **Purpose:** Detailed view of the discovered attack surface for your targets.
- **Widgets:**
  - **Subdomain Tree:** A hierarchical view of discovered subdomains.
  - **Port Matrix:** A grid showing open ports and identified services across the target infrastructure.
  - **Technology Stack:** A list of fingerprinted technologies (e.g., Apache 2.4, PHP 7.4, React) categorized by asset.
- **Actions:** "Export Asset List", "Run Targeted Rescan (e.g., re-scan only port 443)".

### 7. Reports Tab
- **Purpose:** Access and management of generated assessment reports.
- **Widgets:**
  - **Report Archive:** A list of previously generated reports, sortable by date and target.
  - **Report Template Editor:** A basic interface to customize the look and feel of the output documents.
- **Actions:** "Generate New Report" (invokes `ReportGenerator(version='V9.5')`), "Download PDF", "Download HTML".

### 8. Exporter Tab
- **Purpose:** Interface for initiating the Enterprise Data Export workflow and navigating the Legal Gate.
- **Widgets:**
  - **Export Configuration:** Options to select the target format (Jira, ServiceNow, DefectDojo, etc.) and filter the data to be exported.
  - **Audit Log Viewer:** Displays the history of all previous export actions, including the non-repudiation codes (SMP-4050, 4051, 4052).
- **Actions:** "Initiate Export Workflow", "Download Audit Log".

### 9. Scanners Tab
- **Purpose:** Granular control over the 95 available scanner modules.
- **Widgets:**
  - **Scanner Registry List:** A table listing every registered scanner, its category, version, and current status (Enabled/Disabled).
  - **Module Configuration:** A panel to set specific parameters for individual tools (e.g., setting the wordlist path for `ffuf`).
- **Actions:** "Enable/Disable Module", "Edit Configuration", "Reload Registry".

### 10. Settings Tab
- **Purpose:** Global system configuration and tuning.
- **Widgets:**
  - **System Preferences:** UI theme, pagination limits.
  - **Performance Tuning:** Adjust `max_concurrency`, timeouts, and memory optimization settings.
  - **API Keys Manager:** Secure storage for third-party API keys required by OSINT scanners (e.g., Shodan, GitHub).
  - **Authentication:** Password change utility (requires current Master Password).
- **Actions:** "Save Changes", "Export System Config", "Factory Reset (DANGER)".

## 5. Running Your First Scan

Executing a scan in SMP is designed to be straightforward while ensuring necessary legal compliance. Follow these steps to initiate your first assessment:

**Step 1: Navigate to the Targets Interface**
Open the SMP dashboard and click on the **Targets** tab in the main navigation menu.

**Step 2: Enter Target Information**
Click the **"Add Target"** button. A dialog box will appear. Enter the target details:
- **URL/IP:** e.g., `https://example-target.com`
- **Company Name:** (Optional) e.g., `Example Corp`
- **Submitted To:** (Optional) e.g., `Security Team Alpha`
Click **"Save"** to add the target to your list.

**Step 3: Select the Target for Scanning**
In the Target List, locate your newly added target. Check the box next to its entry, and click the **"Initiate Scan"** button located at the top of the table.

**Step 4: Navigate the Legal Responsibility Dialog**
SMP enforces strict accountability. A critical **Legal Responsibility** dialog will overlay the screen. It states:
> *"By proceeding, you certify that you have explicit, documented authorization to perform active security scanning against this target. You accept full legal responsibility for any disruption caused by these actions."*
You must click the **"I AGREE"** button to proceed. The cancellation button is prominently displayed if you do not have authorization.

**Step 5: Configure the Scan Policy**
After agreeing, the Scan Configuration modal appears. Select a **Scan Policy Profile**:
- **Fast:** Performs basic reconnaissance and non-intrusive checks. Ideal for initial discovery.
- **Standard:** The recommended default. Balances thoroughness with execution time.
- **Deep:** Enables aggressive fuzzing, deep crawling, and exhaustive exploitation checks. Use with caution.
For your first scan, select **Standard**.

**Step 6: Start the Scan**
Click the **"Start Scan"** button at the bottom of the modal.

**Step 7: Monitor Execution**
The UI will automatically redirect you to the **Active Scans** tab. Here, you will see the `DAGOrchestrator` in action. The DAG Visualization widget will illuminate as the system progresses through the 14-state machine, moving from `PENDING` to `RECON_STARTED`, executing various modules, and eventually reaching `COMPLETED`. You can monitor the Live Log Feed to see real-time output from the underlying tools.

## 6. Scanner Reference & Tuning (95 scanners)

SMP integrates 95 distinct scanner modules, providing unparalleled coverage across various attack vectors.

### Complete Scanner Registry Table

| # | Scanner Module Name | Tool Name | Category | Brief Description |
|---|---------------------|-----------|----------|-------------------|
| 1 | `nmap_scanner` | nmap | Network Discovery | Core port scanning and service fingerprinting. |
| 2 | `masscan_module` | masscan | Network Discovery | High-speed, large-scale asynchronous port scanner. |
| 3 | `naabu_scanner` | naabu | Network Discovery | Fast port scanner focused on reliability and simplicity. |
| 4 | `dnsx_module` | dnsx | Network Discovery | Multipurpose DNS toolkit for running multiple DNS queries. |
| 5 | `subfinder_scanner`| subfinder | Network Discovery | Fast passive subdomain enumeration tool. |
| 6 | `httpx_scanner` | httpx | Network Discovery | Fast and multi-purpose HTTP toolkit. |
| 7 | `katana_module` | katana | Network Discovery | Next-generation crawling and spidering framework. |
| 8 | `amass_scanner` | amass | Network Discovery | In-depth DNS enumeration and network mapping. |
| 9 | `traceroute_mod` | traceroute| Network Discovery | Network diagnostic tool for routing path analysis. |
| 10| `netcat_probe` | netcat | Network Discovery | Basic TCP/UDP connection and banner grabbing. |
| 11| `hackertarget_api`| hackertarget| Network Discovery | API integration for passive network intelligence. |
| 12| `crtsh_scanner` | crtsh | Network Discovery | Certificate Transparency log search for subdomains. |
| 13| `wayback_module` | wayback | Network Discovery | Retrieves historical URLs from the Wayback Machine. |
| 14| `robots_scanner` | custom | Network Discovery | Analyzes robots.txt for hidden paths and directives. |
| 15| `headers_scanner` | custom | Network Discovery | Evaluates HTTP security headers (HSTS, CSP, etc.). |
| 16| `ssl_scanner` | testssl.sh| Network Discovery | Comprehensive TLS/SSL configuration testing. |
| 17| `sslyze_scanner` | sslyze | Network Discovery | Fast and powerful SSL/TLS scanning library. |
| 18| `tech_fingerprint`| custom | Network Discovery | Identifies technologies based on Wappalyzer signatures. |
| 19| `screenshot_capture`| custom | Network Discovery | Headless browser capture of target web pages. |
| 20| `whois_scanner` | whois | Network Discovery | Retrieves domain registration information. |
| 21| `whatweb_module` | whatweb | Network Discovery | Next generation web scanner for tech identification. |
| 22| `nikto_scanner` | nikto | Web Application | Classic web server vulnerability scanner. |
| 23| `nuclei_module` | nuclei | Web Application | Fast, template-based vulnerability scanner (at `bin/nuclei`). |
| 24| `gobuster_scanner`| gobuster | Web Application | Directory/file and DNS busting tool written in Go. |
| 25| `ffuf_module` | ffuf | Web Application | Fast web fuzzer written in Go. |
| 26| `feroxbuster_mod` | feroxbuster| Web Application | Fast, simple, recursive content discovery. |
| 27| `dirb_scanner` | dirb | Web Application | Web content scanner looking for hidden objects. |
| 28| `wapiti_scanner` | wapiti | Web Application | Web application vulnerability scanner (black-box). |
| 29| `zap_scanner` | zap | Web Application | Integration with OWASP ZAP core engine. |
| 30| `arachni_module` | arachni | Web Application | High-performance Ruby web application security scanner framework. |
| 31| `arjun_scanner` | arjun | Web Application | HTTP parameter discovery suite. |
| 32| `paramspider_mod` | paramspider| Web Application | Mining parameters from dark corners of Web Archives. |
| 33| `api_fuzzer` | custom | Web Application | Specialized fuzzer for REST and GraphQL endpoints. |
| 34| `jwt_scanner` | custom | Web Application | Analyzes and attempts to forge JSON Web Tokens. |
| 35| `graphql_scanner` | custom | Web Application | Introspection and query analysis for GraphQL APIs. |
| 36| `cors_scanner` | custom | Web Application | Checks for insecure Cross-Origin Resource Sharing policies. |
| 37| `corscanner_mod` | corscanner| Web Application | Advanced tool to find CORS misconfigurations. |
| 38| `crlf_scanner` | custom | Web Application | Detects Carriage Return Line Feed injection vulnerabilities. |
| 39| `open_redirect` | custom | Web Application | Fuzzes parameters for Open Redirect vulnerabilities. |
| 40| `path_traversal` | custom | Web Application | Fuzzes paths and parameters for directory traversal. |
| 41| `ssrf_scanner` | custom | Web Application | Detects Server-Side Request Forgery vulnerabilities. |
| 42| `ssrfmap_ext` | ssrfmap | Web Application | Automatic SSRF fuzzer and exploitation tool. |
| 43| `xxe_scanner` | custom | Web Application | Tests XML endpoints for External Entity injection. |
| 44| `idor_scanner` | custom | Web Application | Identifies potential Insecure Direct Object References. |
| 45| `smuggler_mod` | smuggler | Web Application | HTTP Request Smuggling testing tool. |
| 46| `tplmap_scanner` | tplmap | Web Application | Server-Side Template Injection and Code Injection detection. |
| 47| `commix_module` | commix | Web Application | Automated All-in-One OS command injection exploitation tool. |
| 48| `nosqlmap_scanner`| nosqlmap | Web Application | Automated NoSQL injection and database takeover tool. |
| 49| `sqlmap_module` | sqlmap | Web Application | Automatic SQL injection and database takeover tool. |
| 50| `sqlninja_scanner`| sqlninja | Web Application | SQL Injection tool targeted at Microsoft SQL Server. |
| 51| `xsstrike_module` | xsstrike | Web Application | Advanced XSS detection suite with payload generation. |
| 52| `dalfox_scanner` | dalfox | Web Application | Fast, parameter analysis and XSS scanner. |
| 53| `gau_scanner` | gau | Web Application | Fetch known URLs from AlienVault, Wayback, and Common Crawl. |
| 54| `hakrawler_mod` | hakrawler | Web Application | Web crawler for gathering URLs and robust JavaScript link parsing. |
| 55| `ppmap_scanner` | ppmap | Web Application | Scanner to find Prototype Pollution vulnerabilities. |
| 56| `race_the_web` | racetheweb| Web Application | Tests for race conditions in web applications. |
| 57| `wscat_scanner` | wscat | Web Application | WebSocket client for manual and automated testing. |
| 58| `snallygaster_mod`| snallygaster| Web Application | Tool to scan for secret files on HTTP servers. |
| 59| `shodan_idb` | custom | Web Application | Cross-references findings with local Shodan internet DB caches. |
| 60| `cms_scanner` | custom | Web Application | Generic Content Management System fingerprinting. |
| 61| `cmseek_module` | cmseek | Web Application | CMS Detection and Exploitation suite. |
| 62| `joomscan_mod` | joomscan | Web Application | Joomla vulnerability scanner. |
| 63| `droopescan_mod` | droopescan| Web Application | Plugin-based scanner for Drupal and SilverStripe. |
| 64| `wpscan_module` | wpscan | Web Application | Black box WordPress vulnerability scanner. |
| 65| `wafw00f_scanner` | wafw00f | Web Application | Identifies and fingerprints Web Application Firewalls. |
| 66| `retire_js` | retire.js | Web Application | Scanner detecting the use of JavaScript libraries with known vulnerabilities. |
| 67| `gitleaks_module` | gitleaks | Secrets & Code | SAST tool for detecting hardcoded secrets like passwords and API keys. |
| 68| `trufflehog_mod` | trufflehog| Secrets & Code | Searches through git repositories for high entropy strings and secrets. |
| 69| `secrets_scanner` | custom | Secrets & Code | Regex-based secrets detection in generic files. |
| 70| `detect_secrets` | detect-sec| Secrets & Code | Yelp's module for preventing new secrets from entering the codebase. |
| 71| `bandit_scanner` | bandit | Secrets & Code | Security linter for Python source code. |
| 72| `semgrep_module` | semgrep | Secrets & Code | Lightweight static analysis for many languages. |
| 73| `brakeman_mod` | brakeman | Secrets & Code | Static analysis security vulnerability scanner for Ruby on Rails. |
| 74| `osv_scanner` | osv-scanner| Secrets & Code | Matches dependencies against the Open Source Vulnerability database. |
| 75| `trivy_scanner` | trivy | Cloud & Container | Comprehensive vulnerability scanner for containers and artifacts. |
| 76| `checkov_module` | checkov | Cloud & Container | Static code analysis tool for infrastructure-as-code. |
| 77| `cloudsplaining` | cloudsplain| Cloud & Container | AWS IAM Security Assessment tool. |
| 78| `prowler_scanner` | prowler | Cloud & Container | AWS Security Best Practices Assessment, Auditing, Incident Response. |
| 79| `cloud_enum_mod` | cloud_enum| Cloud & Container | Multi-cloud OSINT tool to find public resources. |
| 80| `kube_bench_mod` | kube-bench| Cloud & Container | Checks whether Kubernetes is deployed securely based on CIS guidelines. |
| 81| `kubehunter_mod` | kube-hunter| Cloud & Container | Hunts for security weaknesses in Kubernetes clusters. |
| 82| `mobsf_scanner` | mobsf | Cloud & Container | Mobile Security Framework for Android/iOS binary analysis. |
| 83| `msfconsole_mod` | msfconsole| Active/Exploit | Metasploit Framework integration for automated exploitation checks. |
| 84| `hydra_scanner` | hydra | Active/Exploit | Parallelized network logon cracker. |
| 85| `responder_mod` | responder | Active/Exploit | LLMNR, NBT-NS and MDNS poisoner. |
| 86| `netexec_scanner` | netexec | Active/Exploit | Network service exploitation tool (formerly CrackMapExec). |
| 87| `impacket_mod` | impacket | Active/Exploit | Collection of Python classes for working with network protocols. |
| 88| `rsf_scanner` | rsf | Active/Exploit | Routersploit framework for embedded devices. |
| 89| `w3af_console` | w3af | Active/Exploit | Web Application Attack and Audit Framework. |
| 90| `theharvester_mod`| theHarvester| OSINT | E-mails, subdomains and names gathering. |
| 91| `golismero_mod` | golismero | OSINT | Open source security testing framework. |
| 92| `gitdumper_mod` | git-dumper| OSINT | Tool to dump a git repository from a website. |
| 93| `clamav_scanner` | clamav | Other | Antivirus engine for detecting trojans, viruses, malware. |
| 94| `openvas_module` | openvas | Other | Full-featured vulnerability scanner framework integration. |
| 95| `w3af_api_mod` | w3af_api | Other | API-driven integration for w3af. |

### Tuning Guides for Key Scanners

**Nuclei Tuning**
Nuclei (`bin/nuclei`) is a core component. To optimize it within SMP:
- **Rate Limiting:** Adjust the `-rl` parameter in the `config/settings.json` under `nuclei_module.rate_limit` to prevent overwhelming the target. A good starting point is 150 requests/second.
- **Template Selection:** By default, SMP runs `cves`, `vulnerabilities`, and `exposures`. Avoid running `fuzzing` templates unless the Scan Policy is set to 'Deep'.
```json
"nuclei_module": {
  "rate_limit": 150,
  "templates": ["cves", "vulnerabilities", "exposures", "misconfiguration"]
}
```

**Nmap Tuning**
For broad network discovery, SMP utilizes Nmap extensively.
- **Timing Templates:** SMP uses `-T4` by default. If you encounter dropped packets on unstable networks, edit the configuration to use `-T3`.
- **Host Discovery:** For large CIDR ranges, ensure the `-PE` and `-PM` flags are enabled for robust ICMP discovery.

**SQLMap Tuning**
SQLMap is powerful but can be disruptive.
- **Risk and Level:** SMP caps SQLMap at `--level=2` and `--risk=1` in 'Standard' mode.
- **Batch Mode:** Always ensure `--batch` is enabled in the configuration to prevent SQLMap from hanging while waiting for user input during automated DAG execution.

**FFUF Tuning**
FFUF requires careful wordlist management.
- **Wordlists:** SMP ships with a curated set of wordlists in `data/wordlists/`. Ensure the `ffuf_module.wordlist_path` points to these optimized lists rather than massive generic lists to save time.
- **Auto-Calibration:** Enable `-ac` (auto-calibration) to filter out deceptive 200 OK responses common in modern web applications.

**Gobuster Tuning**
- **Threads:** Set the thread count (`-t`) to match your system capabilities. 50 threads is standard, but high-end systems can handle 200+.
- **Extensions:** Specify common extensions (`-x php,html,txt`) only when targeting specific technology stacks fingerprinted in the Reconnaissance phase.

## 7. Writing Custom Scanners

SMP's architecture allows researchers to easily add custom capabilities. Custom scanners are written in Python and integrated into the DAG using the `@register_scanner` decorator.

### Full Working Example

Create a file named `custom_header_check.py` in the `scanners/custom/` directory.

```python
from scanners.core.registry import register_scanner
from scanners.core.adapter import ScannerAdapter
import requests

@register_scanner
class CustomHeaderCheckScanner(ScannerAdapter):
    """
    A custom scanner that checks for a specific proprietary HTTP header.
    """
    
    def get_manifest(self):
        """
        Returns the metadata for the DAG orchestrator.
        """
        return {
            "name": "custom_header_check",
            "category": "Web Application",
            "description": "Checks if the target exposes the X-Proprietary-Debug header.",
            "version": "1.0.0",
            "dependencies": ["httpx"] # Waits for basic HTTP reachability
        }
        
    def run(self, target, context):
        """
        The main execution logic.
        :param target: The Target object (e.g., Target(url="https://example.com"))
        :param context: The execution context containing shared state and configuration.
        """
        self.logger.info(f"Starting custom header check on {target.url}")
        
        try:
            # Perform the active check
            response = requests.get(target.url, timeout=context.config.get('timeout', 10))
            
            # Analyze the results
            if 'X-Proprietary-Debug' in response.headers:
                # Create a finding observation
                self.report_finding(
                    title="Proprietary Debug Header Exposed",
                    description="The target is leaking internal routing information via the X-Proprietary-Debug header.",
                    severity="Low",
                    evidence={
                        "request": f"GET / HTTP/1.1\\nHost: {target.host}",
                        "response_headers": dict(response.headers)
                    }
                )
                self.logger.warning("Finding reported.")
            else:
                self.logger.info("Header not found. Target is secure against this check.")
                
        except requests.exceptions.RequestException as e:
            # Handle connection errors gracefully
            self.logger.error(f"Failed to connect to {target.url}: {str(e)}")
            self.report_error(f"Connection failure: {str(e)}")
            
        # The function implicitly signals completion to the DAG upon returning.
```

Once saved, restart the SMP service, and the `custom_header_check` will appear in the Scanners tab and can be enabled in scan policies.

## 8. Enterprise Data Export & Legal Gate

Integrating SMP's findings into enterprise workflows (like ticketing systems and risk management platforms) is managed through the Exporter.

### The 6 Export Formats

SMP supports generating structured data in six specific formats:

1. **Jira JSON:** Formatted specifically for Jira's REST API, mapping findings to issue types (e.g., Bug or Vulnerability) and embedding evidence links.
2. **ServiceNow CSV:** A flattened structure suitable for import into ServiceNow Incident or Problem management modules.
3. **DefectDojo JSON:** Natively compatible with the DefectDojo vulnerability management platform API.
4. **Generic JSON:** A standard, un-opinionated JSON structure containing all raw data for custom parsing scripts.
5. **Markdown ZIP:** A ZIP archive containing individual Markdown files for each finding, suitable for inclusion in Git repositories or documentation wikis.
6. **SARIF 2.1.0:** The Static Analysis Results Interchange Format, the industry standard for integrating with tools like GitHub Advanced Security.

### Example Snippets

**SARIF 2.1.0 Snippet Example:**
```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Security Management Platform (SMP)",
          "version": "V9.5"
        }
      },
      "results": [
        {
          "ruleId": "SMP-XSS-001",
          "message": {
            "text": "Cross-Site Scripting (XSS) detected in 'q' parameter."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "https://example.com/search"
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### The Legal Gate Workflow & Audit Logging

Exporting vulnerability data represents a potential risk if the data leaves the secure local environment inappropriately. Therefore, the Exporter enforces a Legal Gate.

When a user initiates an export:
1. **Action:** User clicks "Export".
2. **Audit Event:** System logs **SMP-4050: Export initiated**.
3. **Gate:** The Legal Gate dialog appears, requiring the user to confirm authorization to extract this data.
4. **Action:** User clicks 'I AGREE'.
5. **Audit Event:** System logs **SMP-4051: Legal Gate accepted**, recording the timestamp and user context.
6. **Execution:** The data is transformed into the requested format and written to disk.
7. **Audit Event:** System logs **SMP-4052: Export successfully written to disk**, recording the SHA-256 hash of the generated file for non-repudiation.

## 9. Advanced Tuning & Performance

Achieving optimal performance with 95 scanners running concurrently requires tuning the `config/settings.json` file.

### Scan Policy Profiles

SMP defines rulesets in `config/metadata.json` under policy profiles:
- `"fast"`: Disables heavy fuzzers (ffuf, sqlmap). Sets timeouts to 30s.
- `"standard"`: Enables standard web and network tools. Sets timeouts to 120s.
- `"deep"`: Enables all applicable tools, including aggressive exploitation and long-running fuzzers. Timeouts are set to 600s.

### Concurrency Settings

The DAG orchestrator relies on Python's `asyncio` and multiprocessing.
- **`max_concurrency`:** This setting in `settings.json` dictates how many scanner modules can run simultaneously.
  - *Recommendation:* Set `max_concurrency` to roughly 1.5x to 2x your available CPU cores. For an 8-core system, a value of 12-16 is optimal. Default is 10.
- **`max_threads_per_scanner`:** Some scanners (like gobuster) manage their own threads. This setting caps the resources a single module can consume.

### Memory Optimization

Processing large targets can consume significant RAM, especially during evidence collection.
- **`evidence_chunk_size`:** When saving raw HTTP responses or large files, SMP writes to the AES-256 encrypted database in chunks. Increasing this value (e.g., from 4096 to 16384 bytes) speeds up write operations but increases memory spikes.
- **`in_memory_db_cache`:** Adjust the SQLite cache size. A larger cache speeds up deduplication queries but consumes more resident RAM.

## 10. Headless API Reference

SMP provides a robust Headless API for CI/CD integration and automation. 

**IMPORTANT NOTE:** Only the `/api/v6/` endpoints are active. All `/api/v1/` endpoints have been deprecated and removed. Do not use plural paths (e.g., use `/target`, not `/targets`).

**Base URL:** `http://localhost:8000`
**Authentication:** All endpoints (except `/health` and `/version`) require a Bearer token in the `Authorization` header.

### 1. System Health
- **Endpoint:** `GET /api/v6/health`
- **Description:** Returns the current operational status of the core services.
- **cURL Example:**
  ```bash
  curl -X GET http://localhost:8000/api/v6/health
  ```
- **Response Schema:**
  ```json
  { "status": "healthy", "database": "connected", "dag_engine": "idle" }
  ```

### 2. System Version
- **Endpoint:** `GET /api/v6/version`
- **Description:** Returns the software version.
- **cURL Example:**
  ```bash
  curl -X GET http://localhost:8000/api/v6/version
  ```
- **Response Schema:**
  ```json
  { "version": "V9.5" }
  ```

### 3. Authentication
- **Endpoint:** `POST /api/v6/auth/token`
- **Description:** Exchange credentials for a JWT access token.
- **cURL Example:**
  ```bash
  curl -X POST http://localhost:8000/api/v6/auth/token \
       -H "Content-Type: application/json" \
       -d '{"username": "admin", "password": "your_master_password"}'
  ```
- **Response Schema:**
  ```json
  { "access_token": "eyJhbG...", "token_type": "bearer" }
  ```

### 4. List Targets
- **Endpoint:** `GET /api/v6/target`
- **Description:** Retrieves a list of configured targets.
- **cURL Example:**
  ```bash
  curl -X GET http://localhost:8000/api/v6/target \
       -H "Authorization: Bearer <token>"
  ```
- **Response Schema:**
  ```json
  [
    { "id": 1, "url": "https://example.com", "company_name": "Example Corp" }
  ]
  ```

### 5. Create Target
- **Endpoint:** `POST /api/v6/target`
- **Description:** Adds a new target to the system.
- **cURL Example:**
  ```bash
  curl -X POST http://localhost:8000/api/v6/target \
       -H "Authorization: Bearer <token>" \
       -H "Content-Type: application/json" \
       -d '{"url": "https://newtarget.local", "company_name": "Internal", "submitted_to": "IT"}'
  ```
- **Response Schema:**
  ```json
  { "id": 2, "status": "created" }
  ```

### 6. List Scans
- **Endpoint:** `GET /api/v6/scan`
- **Description:** Retrieves the status of current and past scan jobs.
- **cURL Example:**
  ```bash
  curl -X GET http://localhost:8000/api/v6/scan \
       -H "Authorization: Bearer <token>"
  ```
- **Response Schema:**
  ```json
  [
    { "scan_id": "scn_abc123", "target_id": 1, "state": "COMPLETED", "progress": 100 }
  ]
  ```

### 7. Retrieve Findings
- **Endpoint:** `GET /api/v6/findings`
- **Description:** Fetches verified vulnerabilities.
- **cURL Example:**
  ```bash
  curl -X GET http://localhost:8000/api/v6/findings \
       -H "Authorization: Bearer <token>"
  ```
- **Response Schema:**
  ```json
  [
    { "id": 101, "title": "Open Directory", "severity": "Medium", "target": "https://example.com" }
  ]
  ```

### 8. CVE Statistics
- **Endpoint:** `GET /api/v6/cve/stats`
- **Description:** Returns aggregate data regarding identified CVEs.
- **cURL Example:**
  ```bash
  curl -X GET http://localhost:8000/api/v6/cve/stats \
       -H "Authorization: Bearer <token>"
  ```
- **Response Schema:**
  ```json
  { "total_cves_found": 12, "critical_cves": 1, "top_cve": "CVE-2021-44228" }
  ```

### 9. Risk Score
- **Endpoint:** `GET /api/v6/risk/score`
- **Description:** Retrieves the calculated global risk metric.
- **cURL Example:**
  ```bash
  curl -X GET http://localhost:8000/api/v6/risk/score \
       -H "Authorization: Bearer <token>"
  ```
- **Response Schema:**
  ```json
  { "global_score": 8.5, "trend": "increasing", "highest_risk_target": 1 }
  ```

## 11. Troubleshooting & Error Codes

When components fail, SMP provides deterministic error codes. A comprehensive list is maintained in `ERROR_CODES.md`.

### Quick Reference Error Table

| Error Range | Subsystem | Description & Common Causes |
|-------------|-----------|-----------------------------|
| **SMP-1000s** | Core DB | SQLite database locking issues or decryption failures (usually bad KEK). |
| **SMP-2000s** | DAG Engine| Scanner execution failures, deadlocks, or task timeouts. |
| **SMP-3000s** | API Layer | Invalid JWT tokens, malformed JSON requests, or missing headers. |
| **SMP-4000s** | Audit/Export| Export failures or Legal Gate violations (e.g., SMP-4050, 4051, 4052). |
| **SMP-9000s** | Installer | Setup script failures (SMP-9001 to SMP-9005). See Section 2. |

### Self-Healing Capabilities

SMP includes a built-in diagnostic and repair utility. If the system enters an unstable state (e.g., orphaned processes or corrupted cache), execute:

```bash
python3 tools/troubleshoot.py --fix
```

This command will:
1. Verify database integrity using SQLite PRAGMA checks.
2. Check the cryptographic signatures of the 15 verify suites.
3. Attempt to gracefully terminate any zombie scanner processes.
4. Clear temporary working directories while preserving immutable evidence in `data/evidence/`.

### Common Issues
- **Missing `bin/nuclei`:** If the active scans fail immediately, verify that `bin/nuclei` exists and is executable (`chmod +x bin/nuclei`).
- **DAG Deadlocks:** If a scan hangs in the `SCAN_RUNNING` state, a scanner module may be ignoring timeouts. Use the UI to "Cancel Scan" and review the logs to identify the offending tool.

## 12. Deep Technical Architecture

SMP is built on a highly concurrent, stateful architecture designed for reliability and data security.

### Directed Acyclic Graph (DAG) Orchestrator

The core execution engine is `scanners.core.dag.DAGOrchestrator`. Rather than running scanners sequentially, SMP models the scanning process as a DAG. 
- **Nodes:** Represent individual scanner modules or verify suites.
- **Edges:** Represent dependencies. For example, `sqlmap_module` depends on the output of `paramspider_mod`. 
This allows the orchestrator to maximize CPU utilization by running independent tasks in parallel while strictly respecting prerequisite data flows.

### The 14-State State Machine

Every scan job progresses through a rigorous 14-state machine to ensure transactional integrity:

1. **PENDING:** Job created, waiting for worker availability.
2. **PRE_FLIGHT:** Checking target reachability and network routes.
3. **RECON_STARTED:** Initiating passive and active footprinting.
4. **RECON_COMPLETE:** Footprinting data normalized and saved.
5. **SCAN_QUEUED:** DAG orchestrator compiling the execution graph based on policy.
6. **SCAN_RUNNING:** Active execution of the 95 scanner modules.
7. **SCAN_PAUSED:** Job temporarily suspended by user or system resource limits.
8. **VERIFY_STARTED:** The 15 verify suites begin evaluating raw findings.
9. **VERIFY_COMPLETE:** False positives eliminated, confidence levels assigned.
10. **SCORING:** Calculating CVSS and contextual risk metrics.
11. **REPORTING:** Generating artifacts via `ReportGenerator(version='V9.5')`.
12. **COMPLETED:** Successful end-of-job state.
13. **FAILED:** Fatal error encountered (e.g., unrecoverable database lock).
14. **CANCELLED:** Job explicitly aborted by the user.

### Typed Observation Model

To unify the disparate outputs of 95 different tools, SMP uses a **Typed Observation Model**. Regardless of whether the tool outputs XML, JSON, or plain text, the `ScannerAdapter` must parse it into a standard `Observation` object. This schema defines exact fields for URI, Parameter, Payload, HTTP Method, and Evidence References, allowing the Verify Suites to operate uniformly.

### Immutable Evidence Store & Deduplication

All evidence is stored in `data/evidence/`. To prevent storage exhaustion during large scans, SMP utilizes a SHA-256 deduplication formula.
Before writing a new piece of evidence (e.g., an HTTP response body), the system hashes the content. If a file with that hash already exists, the database simply creates a new relational link to the existing encrypted file, saving significant disk space.

## 13. How to Extend SMP

SMP is designed for modularity. Administrators and researchers can extend the platform using the following mechanisms:

### Core Configuration Files

Modifications should be made directly to the JSON files located in the `config/` directory:
- **`config/settings.json`:** Controls core engine parameters, concurrency limits, and global timeouts.
- **`config/metadata.json`:** Defines the scan policy profiles (Fast, Standard, Deep) and maps which of the 95 scanners belong to which profile.
- **`config/auth.json`:** Manages API keys for OSINT tools and third-party integrations (e.g., Shodan, GitHub).

### Adding Custom Verify Suites

While Section 7 covered adding active scanners, you can also add to the 15 verify suites in the `scanners/verify/` directory. Create a new Python file implementing the `VerifySuite` base class to add custom logic for confirming complex, multi-stage vulnerabilities.

### API Extensions

The Headless API is built on FastAPI. To add new endpoints, navigate to the `api/v6/` directory. Create new routing files and include them in the main FastAPI application router. Ensure all new endpoints respect the Bearer token authentication middleware and the underlying AES-256 Encrypted at Rest database abstraction layer.

---
*Security Management Platform V9.5 - Empowering local-first security research.*
