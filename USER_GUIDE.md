```
███████╗███╗   ███╗██████╗     ██╗   ██╗ █████╗     ███████╗
██╔════╝████╗ ████║██╔══██╗    ██║   ██║██╔══██╗    ╚════██║
███████╗██╔████╔██║██████╔╝    ██║   ██║╚██████║        ██╔╝
╚════██║██║╚██╔╝██║██╔═══╝     ╚██╗ ██╔╝ ╚═══██║       ██╔╝
███████║██║ ╚═╝ ██║██║          ╚████╔╝  █████╔╝        ██║
╚══════╝╚═╝     ╚═╝╚═╝           ╚═══╝   ╚════╝         ╚═╝
  Security Management Platform V9.5  ·  by mrQhere
  Local-first · Zero-cloud · AES-256 Encrypted at Rest
  github.com/mrQhere/SecurityManagementPlatform
```

# Security Management Platform V9.5 (SMP V9.5) User Guide: Part 1 - Introduction and Setup

## Table of Contents
1. [Introduction & User Tiers](#1-introduction)
2. [Installation & System Requirements](#2-installation--system-requirements)
3. [First Launch — Encryption Setup](#3-first-launch--encryption-setup)
4. [Dashboard Reference (All 10 Pages)](#4-dashboard-reference)
5. [Running Your First Scan](#5-running-your-first-scan)
6. [Scanner Reference & Tuning](#6-scanner-reference--tuning)
7. [Writing Custom Scanners](#7-writing-custom-scanners)
8. [Enterprise Data Export & Legal Gate](#8-enterprise-data-export--legal-gate)
9. [Advanced Tuning & Performance](#9-advanced-tuning--performance)
10. [Headless API Reference](#10-headless-api-reference)
11. [Troubleshooting & Error Codes](#11-troubleshooting--error-codes)

## 1. Introduction

Welcome to the Security Management Platform V9.5 (SMP V9.5), the premier
enterprise-grade solution for comprehensive security orchestration, automation,
and response (SOAR). Whether you are taking your first steps into the world of
cybersecurity, managing an established penetration testing engagement, or
conducting advanced threat research, SMP V9.5 is designed to meet your needs
with unparalleled flexibility, power, and security.

This guide is structured to accompany you through every stage of your journey
with SMP V9.5. We have meticulously designed the platform to be accessible yet
profoundly deep, ensuring that as your skills and requirements evolve, the
platform scales effortlessly alongside you.

### 1.1 For the Beginner
If you are new to security management, SMP V9.5 offers an intuitive, guided experience. The platform abstracts complex security concepts into digestible, actionable insights. Upon launching the application, you will be greeted by a streamlined dashboard that highlights critical alerts without overwhelming you with raw data. 

For beginners, the platform provides:
- **Automated Triage:** SMP V9.5 automatically categorizes incoming alerts based
on severity, allowing you to focus on what truly matters.
- **Playbook Templates:** We include dozens of industry-standard response
playbooks out-of-the-box. These templates guide you step-by-step through
incident mitigation, ensuring you follow best practices even if you lack
extensive prior experience.
- **Contextual Help:** Throughout the user interface, you will find tooltips,
inline definitions, and links to detailed documentation, effectively serving as
an on-the-job training tool.

### 1.2 For the Intermediate and Advanced User
As you gain proficiency, SMP V9.5 reveals its underlying architecture, granting you granular control over your security posture. Security analysts and engineers will appreciate the ability to customize every aspect of the platform.

For intermediate to advanced users, the platform offers:
- **Custom Playbook Creation:** Move beyond templates by designing intricate,
multi-step automated response playbooks using our  or
via our robust Python API.
- **Advanced Threat Hunting:** Utilize our proprietary query language to sift
through terabytes of log data across your entire enterprise infrastructure in
milliseconds.
- **Integration Ecosystem:** Seamlessly connect SMP V9.5 with over 500 third-
party security tools, firewalls, endpoint detection and response (EDR)
solutions, and threat intelligence feeds.

### 1.3 For the Researcher
For the security researcher, reverse engineer, and malware analyst, SMP V9.5 is an indispensable laboratory. We understand that researchers require unvarnished access to raw data and the ability to execute code in secure, isolated environments.

For researchers, the platform includes:
- **Sandboxed Execution Environments:** Safely detonate suspicious payloads
within dynamically provisioned, heavily instrumented virtual machines. SMP V9.5
captures every system call, network request, and memory modification.
- **Memory Forensics Integration:** Built-in capabilities to ingest, parse, and
analyze volatile memory dumps, allowing you to uncover sophisticated fileless
malware and rootkits.
- **Threat Intelligence Export:** easily package your findings, Indicators of
Compromise (IoCs), and custom detection rules into standard formats 
for distribution to the broader security community.

---

## 2. Installation

Deploying SMP V9.5 correctly is critical to ensuring its effectiveness and
security. This section details the prerequisites and step-by-step installation
procedures for various environments.

### 2.1 Prerequisites

Before initiating the installation process, ensure your infrastructure meets the
following minimum requirements:

**Hardware Requirements:**
- **CPU:** Minimum 8 cores (16+ cores recommended for high-volume environments).
- **RAM:** Minimum 32 GB (64+ GB recommended for memory forensics and heavy
virtualization).
- **Storage:** Minimum 1 TB SSD for the operating system and application
binaries. An additional 5+ TB NVMe storage array is highly recommended for hot
log data storage and database operations.
- **Network:** Dedicated gigabit network interface cards (NICs) for management
and data ingestion.

**Software Requirements:**
- **Operating System:** Supported distributions include Ubuntu 22.04 LTS, Red
Hat Enterprise Linux (RHEL) 8.x/9.x, and CentOS Stream 9. Windows Server 2022 is
supported for standalone sensor deployments only.
- **Dependencies:** Python 3.10+, PostgreSQL 14+, Redis 6+, and Docker CE (if
utilizing containerized execution environments).

### 2.2 Getting the Software

SMP V9.5 is distributed via our secure enterprise portal.

1. Log in to the Customer Success Portal using your provided credentials.
2. Navigate to the "Downloads" section and select the appropriate package for
your operating system.
3. Download the installation archive (e.g., `smp-v9.5.0-linux-x86_64.tar.gz`).
4. **Crucial Step:** Download the accompanying detached signature file (`.sig`)
and the public PGP key. You must verify the integrity and authenticity of the
installation archive before proceeding.

```bash
gpg --import smp-public-key.asc
gpg --verify smp-v9.5.0-linux-x86_64.tar.gz.sig smp-v9.5.0-linux-x86_64.tar.gz
```
Ensure the output indicates a "Good signature" from the official release team.

### 2.3 Installation Process (Linux)

For this guide, we will outline the installation process on a standard Linux
environment.

1. **Extract the Archive:**
   ```bash
   tar -xzf smp-v9.5.0-linux-x86_64.tar.gz
   cd smp-v9.5.0
   ```

2. **Execute the Installer script:**
   The installation script must be run with administrative privileges. It will
handle the extraction of binaries, creation of necessary service accounts, and
setting up systemd services.
   ```bash
   sudo ./install.sh
   ```

3. **Follow the Interactive Prompts:**
   The installer will prompt you for configuration details such as the desired
installation directory (default is `/opt/smp`), network binding addresses, and
database connection strings.

4. **Service Verification:**
   Upon completion, verify that the core services are running correctly:
   ```bash
   sudo systemctl status smp-core
   sudo systemctl status smp-database
   sudo systemctl status smp-web
   ```

---

## 3. System Readiness Checks

Before the SMP V9.5 application can fully initialize, it undergoes a rigorous
series of System Readiness Checks. These pre-flight diagnostics ensure that the
environment is sound and that all prerequisites are functioning as expected.
Failure at this stage will prevent the application from starting, safeguarding
against potential data corruption or security vulnerabilities.

### 3.1 Pre-Flight Diagnostics

When you first execute the application (`smp-start`), the system readiness
module is the first component to load. It performs the following sequential
checks:

1. **Hardware Validation:** The system queries the host kernel to verify CPU
core count, available memory, and storage space. If the system falls below the
minimum required specifications, a critical warning is logged, and the startup
sequence is halted.
2. **Network Port Binding:** The application verifies that required ports (e.g.,
TCP 443 for the web interface, TCP 8080 for API ingestion, TCP 514 for Syslog)
are available and not currently bound by conflicting services.
3. **Dependency Health Check:** SMP V9.5 attempts to establish preliminary
connections to required external services, such as the PostgreSQL database and
the Redis caching layer. It verifies network connectivity, authentication
credentials, and database schema versions.
4. **Filesystem Permissions:** The readiness module scans the installation
directories (`/opt/smp/`, `/var/log/smp/`, `/var/lib/smp/`) to ensure that the
designated service accounts have the appropriate read, write, and execute
permissions. Incorrect permissions are a common source of runtime errors and are
aggressively flagged during startup.

### 3.2 Interpreting Readiness Results

The results of the readiness checks are displayed in the terminal and logged to
`/var/log/smp/startup.log`.

- **[PASS]:** The check completed successfully.
- **[WARN]:** The system detected a non-critical issue (e.g., running close to minimum RAM limits). The application will start, but performance may be degraded.
- **[FAIL]:** A critical prerequisite was not met. The application will immediately shut down. The log output will provide specific remediation steps, such as "Ensure PostgreSQL is running and accepting connections on port 5432."

By enforcing these strict readiness checks, SMP V9.5 guarantees that when the
system is operational, it is running in a stable and supported configuration.

---

## 4. First Launch and PBKDF2 Encryption Setup

Data security is the cornerstone of the Security Management Platform. We operate
under the assumption that the platform will handle your organization's most
sensitive data—incident reports, vulnerability assessments, and potentially
compromised credentials. Therefore, strong encryption is not an optional
feature; it is a mandatory foundational requirement.

When SMP V9.5 successfully passes the system readiness checks for the first
time, it enters the Initial Setup Wizard. The most critical phase of this wizard
is the configuration of the cryptographic subsystem.

### 4.1 The Need for Robust Encryption

SMP V9.5 utilizes AES-256-GCM (Advanced Encryption Standard with Galois/Counter
Mode) to encrypt all sensitive data at rest within the database. This includes
configuration secrets, integration API keys, and sensitive fields within
incident records.

However, the AES encryption algorithm requires a symmetric key. Hardcoding this
key within the application binary or storing it in plaintext on the filesystem
would represent a catastrophic security flaw. If an attacker gains access to the
filesystem, they would instantly possess the key to decrypt the database.

To mitigate this, SMP V9.5 requires a human-provided Master Password, which is
then mathematically transformed into the AES Master Key.

### 4.2 Introduction to PBKDF2

The transformation of your Master Password into an encryption key is handled by
the PBKDF2 (Password-Based Key Derivation Function 2) algorithm, specifically
utilizing HMAC-SHA256 as the pseudorandom function.

PBKDF2 is designed specifically to thwart brute-force and dictionary attacks. It
achieves this through two primary mechanisms: the introduction of a
cryptographic salt and computational iteration.

#### 4.2.1 The Cryptographic Salt

During the first launch, the setup wizard automatically generates a long,
cryptographically secure random sequence known as a "salt."

When you enter your Master Password, the salt is appended to it before
processing. Why is this important? If two users happen to choose the exact same
password, they would normally generate the exact same encryption key. An
attacker could pre-compute a massive database of common passwords and their
corresponding keys (known as a Rainbow Table attack). By adding a unique, random
salt to every installation, SMP V9.5 ensures that even common passwords result
in entirely unique encryption keys, rendering pre-computed attacks completely
useless.

#### 4.2.2 Computational Iteration (Key Stretching)

The core defense of PBKDF2 is iteration, often referred to as "key stretching."
The algorithm does not simply hash the password and salt once; it hashes the
result, and then hashes that result, repeating the process thousands of times.

SMP V9.5 uses a very high iteration count (e.g., 600,000+ iterations). To a
legitimate user typing in their password during startup, this mathematical heavy
lifting takes only a fraction of a second—a delay that is barely noticeable.
However, to an attacker attempting to guess millions of passwords per second,
this delay is devastating. It dramatically increases the computational cost of
attempting a brute-force attack, turning an operation that might take hours into
one that would take centuries, even with state-of-the-art specialized hardware
(ASICs or GPU clusters).

### 4.3 The Initial Setup Wizard

The process of establishing this encryption framework is guided by the Initial
Setup Wizard:

1. **Master Password Prompt:** You will be prompted to create a Master Password.
This password must adhere to strict complexity requirements (minimum length,
inclusion of special characters, mixed case, and numerals).
2. **Password Confirmation:** You must enter the password a second time to
prevent typographic errors.
3. **Warning and Acceptance:** The system will display a stark warning: *The
Master Password cannot be recovered if lost. Without it, the encrypted database
cannot be read.* You must acknowledge this warning to proceed.
4. **Key Derivation Phase:** The application displays a progress bar indicating
that key derivation is underway. During this phase, the application generates
the random salt and performs the hundreds of thousands of PBKDF2 iterations to
produce the final 256-bit AES Master Key.
5. **Database Initialization:** Once the Master Key is derived, the application
initializes the secure database tables and writes a test encrypted string to
verify the integrity of the cryptographic subsystem.

### 4.4 Managing the Master Password

The security of your entire deployment hinges entirely on the secrecy and
strength of the Master Password.

- **Do not** store the Master Password on the same server hosting SMP V9.5.
- **Do not** write it down on physical media left in unsecured locations.
- **Do** store the Master Password in a secure, enterprise-grade password manager (such as a hardware security module or an encrypted digital vault).
- **Do** establish a clear organizational policy regarding who has access to the vault containing the Master Password and the protocol for its retrieval.

Every time the SMP V9.5 core service is restarted—whether due to a scheduled
reboot, a power failure, or a system upgrade—an administrator must provide the
Master Password to unlock the cryptographic subsystem and resume normal
operations.

By enforcing this PBKDF2 key derivation and requiring human intervention upon
restart, SMP V9.5 ensures that physical theft of the server or unauthorized
cloning of the virtual machine will yield only useless, encrypted data to the
attacker. The true key remains secure in your organization's designated vault,
and the data remains uncompromised.


# Security Management Platform (SMP) V9.5 User Guide
## Part 2: UI Dashboard Comprehensive Reference

Welcome to Part 2 of the Security Management Platform (SMP) V9.5 User Guide.
This section provides an exhaustive, comprehensive reference for the SMP V9.5
User Interface. Navigating the SMP interface efficiently is crucial for security
analysts, system administrators, and Chief Information Security Officers (CISOs)
alike to derive maximum value from the platform. The UI is built around a
centralized navigation menu located on the left-hand side of the screen,
providing instant access to all core platform capabilities.

This guide covers every single tab available in the main navigation sidebar:
Dashboard, Targets, Scans, Findings, Intel, Assets, Reports, Exporter, Scanners,
and Settings. Furthermore, we will delve deeply into the globally accessible CVE
Search functionality and the crucial Finding Detail Panel.

---

### 1. The Dashboard Tab

The **Dashboard Tab** is the default landing page upon logging into SMP V9.5. It
provides a single-pane-of-glass overview of your organization's security
posture.

*   **Global Time Range Filter Button**: Located at the top right, this button
allows you to filter all dashboard widgets by a specific time period (e.g., Last
24 Hours, Last 7 Days, Last 30 Days, Custom Range).
*   **Refresh Dashboard Button**: Forces an immediate pull of the latest data
from the backend database, circumventing the standard 5-minute auto-refresh
interval.
*   **Customize Layout Button**: Enables "Edit Mode." In this mode, users can
drag and drop widgets, resize them, or click the "Add Widget" button to
introduce new metrics (like Top 10 Vulnerable Assets, Scan Execution Trends, or
SLA Compliance metrics).
*   **Export Dashboard Button**: Generates a high-fidelity PDF snapshot of the
current dashboard view, perfect for quick executive updates.
*   **Summary Widgets**: By default, the dashboard displays "Total Open
Findings," "Critical/High Severity Breakdown," "Average Time to Remediate
(MTTR)," and "Active Scans." Clicking on any of these widgets acts as a
shortcut, pivoting you directly into the Findings or Scans tab with the relevant
filters pre-applied.

---

### 2. The Targets Tab

The **Targets Tab** is where administrators define the scope of their security
operations. A "Target" can be a single IP address, a CIDR block, a hostname, or
a web application URL.

*   **New Target Button**: Opens a modal window to manually input a new target.
You must specify the Target Name, Network Address (IP/URL), and assign it to an
appropriate Asset Group.
*   **Import Targets Button**: Allows bulk creation of targets by uploading a
standard CSV file. The UI provides a "Download Template" link to ensure your CSV
headers match the platform's expectations.
*   **Export Targets Button**: Dumps the current list of targets (respecting
applied filters) into a CSV or Excel file for offline auditing.
*   **Bulk Actions Dropdown**: After selecting multiple targets via the
checkboxes on the left side of the data grid, this dropdown allows you to
perform actions en masse. Options include "Assign Tags," "Change Group,"
"Deactivate Targets," and "Delete Targets."
*   **Target Data Grid**: Displays all configured targets. Columns include
Target Name, IP/Hostname, OS Guess, Last Scanned Date, and a proprietary Risk
Score. Clicking column headers sorts the data.
*   **Target Details Action Icon**: The small gear/eye icon next to each target
opens a slide-out panel showing specific authentication credentials attached to
the target and its historical scan calendar.

---

### 3. The Scans Tab

The **Scans Tab** controls the execution engine of the SMP V9.5 platform. It is
divided into "Active Scans," "Scheduled Scans," and "Scan History."

*   **New Scan Button**: Launches the Scan Configuration Wizard. Here, you
define the Scan Name, select a Scan Template (e.g., Full TCP Port Scan, Web App
Auth Scan, Fast Discovery), attach Targets or Target Groups, and configure
scheduling.
*   **Play/Pause/Stop Buttons**: Active scans feature real-time controls. The
"Pause" button suspends network traffic generation (useful during unforeseen
network load spikes), while the "Stop" button terminates the scan immediately,
saving whatever partial results were gathered. "Resume" restarts a paused scan.
*   **Clone Scan Button**: Available in the Scan History sub-tab, this highly
useful button takes a previous scan's exact configuration and duplicates it,
allowing you to re-run it instantly without navigating the configuration wizard.
*   **View Logs Button**: Opens a raw text modal detailing the exact scanner
engine outputs, connection timeouts, and plugin compilation logs. This is
critical for troubleshooting when a scan fails to complete.

---

### 4. The Findings Tab

The **Findings Tab** is the heart of the analyst's workflow, where
vulnerabilities, misconfigurations, and compliance violations are triaged.

*   **Advanced Filter Toggle**: Expands a comprehensive filtering matrix. You
can filter by CVSS Score, Severity (Critical, High, Medium, Low, Info), Status
(Open, Closed, Risk Accepted, False Positive), Asset Tag, and First Discovered
date.
*   **Mark False Positive Button**: Moves the selected finding out of the "Open"
queue. This requires the user to input a mandatory justification note, which is
logged for audit purposes.
*   **Accept Risk Button**: Similar to False Positive, but used when the
vulnerability is legitimate but business context dictates it will not be fixed.
Requires an expiration date (e.g., Risk Accepted for 90 days), after which the
finding will revert to "Open."
*   **Create Ticket Button**: Integrates directly with ITSM tools (like Jira or
ServiceNow). Clicking this pushes the finding details to the ticketing system
and attaches the resulting Ticket ID to the finding row in SMP for bidirectional
tracking.
*   **Verify/Retest Button**: Commands the scanning engine to immediately
perform a targeted, single-plugin scan against the specific asset to verify if
the vulnerability has been remediated, without requiring a full system scan.

---

### 5. The Intel Tab

The **Intel Tab** integrates global Threat Intelligence directly into your
platform.

*   **Threat Feeds Section**: Displays the synchronization status of external
intelligence feeds (e.g., CISA KEV, National Vulnerability Database, proprietary
Zero-Day feeds). A "Force Sync" button allows manual updating of these feeds.
*   **Zero-Day Alerts Panel**: A scrolling marquee of newly announced, high-
profile vulnerabilities. Clicking an alert automatically cross-references the
CVE against your Assets inventory to identify immediate exposure.
*   **Advisory Export Button**: Downloads high-level PDF advisories regarding
specific threat actors or vulnerability campaigns to share with non-technical
stakeholders.

#### Deep Dive: CVE Search Functionality
Located prominently within the Intel Tab (and globally via the top navigation bar), the **CVE Search** is an immensely powerful tool.
*   **Search Bar**: Accepts standard CVE IDs (e.g., CVE-2023-12345).
*   **Advanced Query Builder**: Clicking the "+" icon next to the search bar allows operators to use boolean logic and specific operators. For example, typing `vendor:microsoft AND cvss:>8.0 AND published:>2024-01-01` returns all high-severity Microsoft vulnerabilities disclosed this year.
*   **EPSS Score Display**: Every searched CVE displays its Exploit Prediction Scoring System (EPSS) probability, indicating the real-world likelihood of exploitation.
*   **"Find in My Environment" Button**: Once a CVE is searched, this button executes a rapid query against the local SMP database, instantly listing any internally managed assets that suffer from this specific CVE.

---

### 6. The Assets Tab

The **Assets Tab** provides a purely inventory-centric view of the network,
built dynamically from scan results and API integrations.

*   **Discover Assets Button**: Triggers a lightweight ICMP/ARP sweep across
predefined subnet ranges to populate the inventory without running intrusive
vulnerability checks.
*   **Add Asset Button**: For manually adding un-scannable assets (e.g., offline
cold-storage servers) to maintain a complete centralized ledger.
*   **Manage Tags Button**: Opens the taxonomy manager. Tags (e.g., "PCI-Scope",
"Production", "Third-Party") can be created here and later applied to assets for
granular reporting.
*   **Set Criticality Button**: Allows administrators to override default asset
importance. Setting an asset to "Mission Critical" will automatically elevate
the risk score of any vulnerabilities found on it.

---

### 7. The Reports Tab

The **Reports Tab** is the dissemination engine of SMP V9.5, transforming raw
data into actionable intelligence.

*   **Generate New Report Button**: Initiates the report creation flow. Users
first select a template.
*   **Template Manager**: Distinguishes between "Executive Summaries" (high-
level graphs, risk trending, minimal jargon) and "Technical Remediation Reports"
(deep technical details, exact file paths, patch links).
*   **Schedule Report Button**: Allows users to automate reporting. For example,
configuring a "Weekly Patching Delta" report to be emailed to the IT Operations
group every Monday at 8:00 AM.
*   **Download/Share Buttons**: Previously generated reports are stored in a
history grid. They can be downloaded locally (PDF, HTML) or shared via a secure,
time-expiring link directly from the platform.

---

### 8. The Exporter Tab

The **Exporter Tab** is designed for integrating SMP data into downstream data
lakes, SIEMs, or continuous monitoring tools.

*   **New Export Task Button**: Opens a configuration pane to set up a
continuous or scheduled data push.
*   **Format Selection Dropdown**: Users can choose to export raw data in JSON,
CSV, or XML formats.
*   **Webhook Configuration Button**: Allows administrators to set up real-time
HTTP POST callbacks. For instance, whenever a new Critical vulnerability is
discovered, a webhook can be fired instantly to a custom Slack/Teams bot.
*   **Test Connection Button**: Essential for troubleshooting API keys and
network routes. It sends a mock payload to the configured destination to verify
successful transmission before saving the export task.

---

### 9. The Scanners Tab

The **Scanners Tab** is an infrastructure management page used to control the
distributed scanning sensors.

*   **Deploy Node Button**: Generates a unique, one-time execution script (bash
for Linux, PowerShell for Windows) to install a new scanner agent in a remote
network segment.
*   **Scanner Grid**: Displays all active and offline scanners. Columns show
Node Name, IP, Polling Status, Current CPU/RAM Load, and Plugin Version.
*   **Restart Service Button**: Allows administrators to remotely restart the
scanner daemon on a specific node without requiring SSH/RDP access to the
underlying OS.
*   **Update Feed Button**: Pushes the latest vulnerability signatures to a
specific scanner node immediately, overriding the nightly automatic update
schedule.

---

### 10. The Settings Tab

The **Settings Tab** governs platform administration, access control, and system
maintenance.

*   **User Management Button**: Create, delete, or suspend analyst accounts.
*   **RBAC Configuration**: Role-Based Access Control is managed here. Create
custom roles (e.g., "View-Only Auditor", "Remediation Specialist") and assign
granular permissions to specific UI tabs or asset groups.
*   **SSO/SAML Configuration Button**: Facilitates integration with Identity
Providers like Okta, Azure AD, or PingIdentity for seamless federated login.
*   **System Preferences**: Manage global variables such as password complexity
requirements, session timeout durations, and custom branding (uploading company
logos to replace the default SMP logo).
*   **Audit Logs Button**: Downloads an immutable CSV ledger of every action
performed within the platform by any user—crucial for compliance and internal
security investigations.

---

### 11. Deep Dive: The Finding Detail Panel

While the Findings Tab lists vulnerabilities in a tabular format, clicking on
any single row slides out the **Finding Detail Panel**, which is arguably the
most critical interface for a security analyst. It is divided into several
highly detailed sections:

*   **Header & Summary View**: At the top, the panel clearly displays the
Vulnerability Name, the affected Asset Name (hyperlinked to the Asset Tab), the
numerical CVSS v3.1 score, and a color-coded Severity badge. A large "Actions"
button in the top right replicates the triage actions (Create Ticket, Accept
Risk, Mark FP).
*   **Vulnerability Description & Impact**: A comprehensive, human-readable
explanation of the flaw. This section explains *how* the vulnerability works and
the potential business impact if an adversary successfully exploits it (e.g.,
remote code execution, data exfiltration, denial of service).
*   **CVSS Vector String & Calculator**: Displays the raw CVSS vector (e.g.,
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). Crucially, this UI element is
interactive. Analysts can adjust the metrics (like changing Attack Vector from
Network to Local) to see how environmental compensations alter the final score,
aiding in environmental risk scoring.
*   **Proof of Concept (PoC) / Evidence**: This is where SMP proves the
vulnerability exists. It displays the exact HTTP request sent by the scanner and
the corresponding HTTP response from the server that triggered the alert. For
authenticated scans, it may show the output of a specific shell command or
registry key value. This is vital for eliminating false positives and convincing
system administrators that the flaw is real.
*   **Remediation & Solutions**: Provides actionable advice. This section
includes exact patch numbers (e.g., KB5001234), direct hyperlinks to vendor
advisories, or configuration workarounds (e.g., "Disable SMBv1 in the Windows
Registry").
*   **Linked Assets / Blast Radius**: A visual dependency graph showing other
assets in the same network segment that also suffer from this vulnerability.
This helps analysts understand the "blast radius" and prioritize patching on
central pivot points.
*   **Activity & Triage Log**: An immutable chronological timeline at the bottom
of the panel. It records when the finding was first discovered, every time it
was seen in subsequent scans, and any human interactions (e.g., "John Doe marked
this as Risk Accepted on Oct 12th," "Ticket SEC-4423 created on Oct 13th").
*   **Export Finding Button**: A localized button within the panel that exports
just this specific vulnerability's technical details to a secure, password-
protected PDF, intended for direct handover to the specific developer or
sysadmin responsible for the fix.

---
*End of Part 2 - UI Dashboard Comprehensive Reference*


# Security Management Platform (SMP) V9.5 User Guide

## Part 3: Exhaustive Scanner Tuning & Configuration

Welcome to Part 3 of the SMP V9.5 User Guide. This section provides an
exhaustive, in-depth overview of the scanning engines integrated into the
Security Management Platform (SMP) V9.5. To achieve optimal performance,
accuracy, and operational safety during active engagements, it is critical that
security operators understand how to tune and configure each scanner. The SMP
orchestrates these tools using a Directed Acyclic Graph (DAG) execution engine,
ensuring that prerequisite tasks (like discovery and port scanning) complete
before specialized vulnerability identification phases begin.

This document details over twenty distinct scanners supported by SMP V9.5. For
each scanner, you will find information regarding required dependencies, tuning
parameters, and its specific position within the DAG execution order.

---

### 1. Nmap (Network Mapper)
**Description:** Nmap is the foundational network discovery and security auditing tool in SMP V9.5.
**Dependencies:** `libpcap`, `nmap` >= 7.90.
**DAG Execution Order:** Phase 2 (Port Scanning). Depends on Phase 1 (Host Discovery).
**Tuning & Configuration:**
- `Timing Templates (-T0 to -T5):` SMP defaults to `-T4` for internal network scans and `-T3` for external engagements to minimize dropped packets and IDS/IPS alarms.
- `Min/Max Parallelism (--min-parallelism, --max-parallelism):` Adjust based on the target network's bandwidth capacity. For robust corporate networks, SMP recommends `--min-parallelism 100 --max-parallelism 500`.
- `Packet Rate (--min-rate, --max-rate):` Specify packets per second. A safe external configuration is `--max-rate 300` to prevent rate limiting from stateful firewalls.

### 2. Masscan
**Description:** Masscan is an incredibly fast TCP port scanner, capable of transmitting millions of packets per second.
**Dependencies:** `libpcap-dev`, `gcc`, `make`.
**DAG Execution Order:** Phase 2 (Port Scanning - Large Scope). Typically runs in parallel with or instead of Nmap for /8 or /16 subnets.
**Tuning & Configuration:**
- `Rate Limitation (--rate):` The most critical parameter. Set `--rate 1000` to `--rate 10000` depending on the uplink. Warning: setting this too high will cause severe local network degradation or crash stateful firewalls on the target path.
- `Source IP and Port (--router-mac, --source-ip):` Essential when scanning over specific VPNs or multi-homed SMP orchestrator instances.

### 3. RustScan
**Description:** The modern port scanner. RustScan is incredibly fast and pipes output directly into Nmap for deep service enumeration.
**Dependencies:** `rustc`, `cargo` (for building), or Docker.
**DAG Execution Order:** Phase 2 (Port Scanning). Can be used as a rapid front-end to Nmap.
**Tuning & Configuration:**
- `Batch Size (-b):` Controls how many ports to scan in one batch. Default is 4500; increasing it to 10000 requires increasing system `ulimit -n`.
- `Timeout (-t):` Default is 1500ms. On high-latency networks, increase this to 3000ms.
- `Nmap Arguments (--):` SMP dynamically passes `-- -A -sV -sC` to RustScan to ensure that once open ports are found, Nmap aggressively enumerates them.

### 4. Nuclei
**Description:** A fast, template-based vulnerability scanner focusing on massive extensibility and zero-day detection.
**Dependencies:** `go` >= 1.20, `nuclei-templates` repository updated daily by SMP.
**DAG Execution Order:** Phase 4 (Vulnerability Identification). Depends on HTTP/S service discovery.
**Tuning & Configuration:**
- `Concurrency (-c, -bs, -rl):` `-c 50` (templates to execute in parallel), `-bs 50` (hosts to scan per template), `-rl 150` (requests per second limit).
- `Custom Headers (-H):` SMP injects custom user-agents or authorization tokens via `nuclei -H "Authorization: Bearer $TOKEN"`.
- `Template Selection (-t, -et, -tags):` Use `-tags cve,exposure,vuln` to focus on critical findings, while excluding disruptive templates via `-etags dos,fuzz`.

### 5. Amass (OWASP Amass)
**Description:** The premier tool for in-depth DNS enumeration, attack surface mapping, and external asset discovery.
**Dependencies:** `go` >= 1.19. Requires API keys configured in the SMP secret vault for optimal performance.
**DAG Execution Order:** Phase 1 (Host and Subdomain Discovery).
**Tuning & Configuration:**
- `Active vs. Passive:` SMP configures Amass in `enum -passive` for stealth operations, or `enum -active` for comprehensive discovery, which attempts zone transfers and certificate parsing.
- `Timeouts and Retries:` Adjust `-timeout` to 30 (minutes) for massive root domains, ensuring the DAG node does not timeout prematurely.
- `Configuration File (-config):` SMP mounts a centralized `config.ini` populated with Censys, Shodan, and SecurityTrails API keys.

### 6. Sublist3r
**Description:** A legacy but effective Python tool designed to enumerate subdomains using OSINT.
**Dependencies:** `python3`, `requests`, `dnspython`.
**DAG Execution Order:** Phase 1 (Subdomain Discovery). Runs concurrently with Amass.
**Tuning & Configuration:**
- `Engines (-e):` Specify search engines (e.g., `-e baidu,yahoo,google,bing`). SMP limits Google queries to prevent CAPTCHA blocking.
- `Threads (-t):` Default 10 threads. SMP sets this to 30 to speed up DNS resolution of discovered subdomains.
- `Bruteforce (-b):` Disabled by default in SMP to prevent unnecessary noise, relying on Gobuster for dedicated DNS bruteforcing.

### 7. Assetfinder
**Description:** A lightweight Go tool by Tomnomnom for rapid subdomain discovery without API overhead.
**Dependencies:** `go` >= 1.15.
**DAG Execution Order:** Phase 1 (Subdomain Discovery).
**Tuning & Configuration:**
- `Subs Only (--subs-only):` SMP explicitly uses this flag to ensure only subdomains of the target domain are passed downstream in the DAG.
- Assetfinder is minimally configurable; SMP relies on parallel execution via GNU Parallel to run multiple domains through Assetfinder simultaneously.

### 8. SQLMap
**Description:** The industry standard for automatic SQL injection and database takeover.
**Dependencies:** `python3` >= 3.8.
**DAG Execution Order:** Phase 5 (Exploitation/Deep Validation). Triggered dynamically by SMP when Phase 4 flags potential SQLi parameters.
**Tuning & Configuration:**
- `Level and Risk (--level, --risk):` SMP sets `--level=3` and `--risk=2` to ensure comprehensive testing of headers and cookies without executing aggressive, potentially disruptive UPDATE/DELETE statements.
- `Batch Mode (--batch):` Essential for SMP’s headless DAG execution. Never prompt the user.
- `Technique (--technique):` By default `BEUSTQ`. If network latency is high, SMP temporarily disables time-based blind SQLi (`--technique=BEUSQ`) to prevent DAG timeouts.

### 9. Nikto
**Description:** A classic, comprehensive web server scanner examining servers for dangerous files, outdated software, and misconfigurations.
**Dependencies:** `perl`, `Net::SSLeay`.
**DAG Execution Order:** Phase 3 (Service Enumeration & Web Crawling).
**Tuning & Configuration:**
- `Tuning (-Tuning):` Use `-Tuning 1234567890abcx` to enable all checks, or restrict to specific categories (e.g., `-T 4` for XSS).
- `Format (-Format):` SMP forces `-Format JSON` or XML for parsing into the central vulnerability database.
- `Mutate (-mutate):` Can be configured to guess file names, but SMP disables this by default to manage scan duration.

### 10. Dirb
**Description:** A traditional web content scanner that looks for hidden web objects.
**Dependencies:** `gcc`, `libcurl4-openssl-dev`.
**DAG Execution Order:** Phase 3 (Directory and File Bruteforcing).
**Tuning & Configuration:**
- `Wordlists:` SMP replaces Dirb's default wordlist with the SecLists `raft-large-directories.txt`.
- `Delay (-z):` Specify milliseconds to delay between requests. `dirb http://target/ -z 100` prevents triggering rate limits.
- `Extensions (-X):` Target specific file types based on the detected backend (e.g., `-X .php,.bak,.tar.gz` for Apache/PHP environments).

### 11. Gobuster
**Description:** A wildly fast directory and DNS bruteforcing tool written in Go.
**Dependencies:** `go` >= 1.19.
**DAG Execution Order:** Phase 3 (Directory Bruteforcing) and Phase 1 (DNS Bruteforcing).
**Tuning & Configuration:**
- `Mode:` `dir`, `dns`, or `vhost`. SMP dynamically spins up a Gobuster node for each mode depending on the target profile.
- `Threads (-t):` Set to 50 for normal operations. For internal gigabit networks, SMP increases this to `-t 200`.
- `Wildcard bypass (-w):` For DNS mode, Gobuster can dynamically detect wildcard resolution and ignore false positives.
- `Status Codes (-s):` In dir mode, SMP tracks 200,204,301,302,307,401,403.

### 12. Ffuf (Fuzz Faster U Fool)
**Description:** The ultimate web fuzzer, vastly outperforming legacy tools in speed and flexibility.
**Dependencies:** `go` >= 1.18.
**DAG Execution Order:** Phase 3 (Advanced Content Discovery).
**Tuning & Configuration:**
- `Auto-calibration (-ac):` SMP enforces `-ac` to automatically detect and filter out wildcards or custom 404 pages based on response size and words.
- `Matchers and Filters (-mc, -fc, -ms, -fs):` Match status `-mc 200,301,403` and filter out specific response sizes `-fs 42` to eliminate noise.
- `Rate Limiting (-rate):` Set requests per second. SMP throttles Ffuf to 150 r/s for external targets.

### 13. Feroxbuster
**Description:** A fast, simple, recursive content discovery tool written in Rust.
**Dependencies:** `rust`, `cargo`.
**DAG Execution Order:** Phase 3 (Recursive Directory Bruteforcing).
**Tuning & Configuration:**
- `Recursion Depth (-d):` Controls how deep into discovered directories the tool will scan. SMP restricts this to `-d 3` to prevent endless loops.
- `Threads (-t):` Default is 50.
- `Extract Links (-e):` SMP enables `-e` to extract links from response bodies, feeding them back into the DAG for crawling.

### 14. Wfuzz
**Description:** A flexible web application brute forcer.
**Dependencies:** `python3`, `pycurl`.
**DAG Execution Order:** Phase 3 (Parameter and Header Fuzzing).
**Tuning & Configuration:**
- `Payloads (-z):` SMP uses `file,wordlist.txt` or `range,1-100` to fuzz GET/POST parameters discovered during crawling.
- `Output Formatting (-f):` Output is directed to `/tmp/wfuzz_out.json,-` in JSON format for SMP ingestion.
- `Filters (--hc, --hl, --hw, --hc):` Hide responses by code, lines, words, or chars. Essential for removing false positives during parameter fuzzing.

### 15. Wapiti
**Description:** A web application vulnerability scanner acting as a black-box tester.
**Dependencies:** `python3`, `requests`, `beautifulsoup4`.
**DAG Execution Order:** Phase 4 (Vulnerability Identification - Web).
**Tuning & Configuration:**
- `Modules (-m):` Allows enabling/disabling specific attacks (e.g., `xss,sql,crlf,exec`). SMP disables `blindsql` in Wapiti, offloading that task to SQLMap for higher accuracy.
- `Scope (-S):` `folder`, `page`, `domain`. SMP restricts to `domain` but excludes logout endpoints using the `--exclude` flag to prevent terminating active sessions.
- `Timeout (-t):` Set request timeout. Default 6 seconds is generally sufficient.

### 16. Arachni
**Description:** A high-performance, modular Ruby framework for web application security.
**Dependencies:** `ruby` >= 2.5, `libcurl`, `sqlite3`.
**DAG Execution Order:** Phase 4 (Heavy Web Vulnerability Scanning).
**Tuning & Configuration:**
- `Checks (--checks):` SMP runs Arachni with `--checks=active/*,-*do*` to run all active checks except Denial of Service.
- `Scope (--scope-page-limit):` Prevents spider traps by setting a hard limit, typically `--scope-page-limit=500`.
- `Plugins (--plugin):` SMP enables the `autologin` plugin, feeding it credentials from the secret vault to perform authenticated scanning.

### 17. ZAP (OWASP ZAP)
**Description:** The world's most widely used web app scanner. SMP integrates ZAP in headless daemon mode.
**Dependencies:** `java` >= 11.
**DAG Execution Order:** Phase 3 (Crawling) and Phase 4 (Active Scanning).
**Tuning & Configuration:**
- `Daemon Mode (-daemon):` SMP starts ZAP with `-daemon -port 8080 -config api.disablekey=true` within isolated Docker containers.
- `Context Files:` SMP generates `.context` files dynamically, defining the target scope, authentication scripts, and regex patterns to exclude from scanning (e.g., `.*logout.*`).
- `Active Scan Policies:` Tuned via API to 'Medium' strength and 'High' threshold to reduce false positives.

### 18. Burp Suite Professional (Headless)
**Description:** The premium toolkit for web security testing. SMP utilizes Burp's REST API for enterprise scanning.
**Dependencies:** Burp Suite Pro License, `java` >= 17.
**DAG Execution Order:** Phase 4 (Premium Vulnerability Scanning).
**Tuning & Configuration:**
- `Headless Execution:` Run via `java -jar burpsuite_pro.jar -Djava.awt.headless=true --project-file=smp.burp`.
- `Configuration JSON:` SMP loads a highly customized `scan_config.json` via the REST API, disabling out-of-band (OAST) checks if the target network is strictly air-gapped.
- `Crawl Limitations:` Maximum link depth is set to 10, and maximum crawl time is capped at 60 minutes per host.

### 19. XSStrike
**Description:** An advanced Cross Site Scripting (XSS) detection suite equipped with four hand-written parsers.
**Dependencies:** `python3`, `fuzzywuzzy`.
**DAG Execution Order:** Phase 5 (Exploitation/Deep Validation - XSS).
**Tuning & Configuration:**
- `Crawling (--crawl):` SMP sets crawling depth to 3 (`--crawl -l 3`).
- `Delay (-d):` Delay between requests. SMP sets `-d 2` to avoid WAF blocking during the intensive fuzzing phase.
- `Skip DOM (-skip-dom):` To speed up execution on static sites, SMP sometimes toggles this flag, though DOM XSS checking is usually preferred.

### 20. Wpscan
**Description:** The definitive black box WordPress vulnerability scanner.
**Dependencies:** `ruby`, `curl`, WPScan API token.
**DAG Execution Order:** Phase 3 (CMS Specific Enumeration).
**Tuning & Configuration:**
- `API Token (--api-token):` Essential for pulling vulnerability data. Injected automatically by SMP from the vault.
- `Enumeration (--enumerate):` SMP defaults to `--enumerate vp,vt,tt,cb,dbe,u,m` (vulnerable plugins/themes, timthumbs, config backups, database exports, users, media).
- `Stealth (--stealthy):` Uses random user agents and bypasses basic WAF rules by altering request characteristics.

### 21. JoomScan
**Description:** OWASP Joomla Vulnerability Scanner.
**Dependencies:** `perl`, `libwww-perl`.
**DAG Execution Order:** Phase 3 (CMS Specific Enumeration).
**Tuning & Configuration:**
- `Target (-u):` Provide the base URL of the detected Joomla installation.
- `User Agent (-a):` SMP sets a custom User-Agent to masquerade as standard web traffic.
- `Random Agent (-r):` SMP frequently uses the `-r` flag to rotate user agents per request.

### 22. Droopescan
**Description:** A plugin-based scanner that identifies issues in CMSs like Drupal, SilverStripe, and WordPress.
**Dependencies:** `python3`, `requests`.
**DAG Execution Order:** Phase 3 (CMS Specific Enumeration).
**Tuning & Configuration:**
- `CMS Type (-a):` While Droopescan can auto-detect, SMP passes the specific CMS type (e.g., `-a drupal`) based on earlier Wappalyzer/Nuclei fingerprinting, saving execution time.
- `Threads (-t):` SMP increases the default thread count from 4 to 15 (`-t 15`).
- `Enumeration Types (-e):` SMP runs specific checks: `p,t,v` (plugins, themes, version).

---

## Conclusion
Proper configuration and tuning of the above 22 scanners are imperative for maintaining the operational integrity of the SMP V9.5. The Directed Acyclic Graph architecture relies heavily on operators ensuring that API keys, thread limits, and rate limits are accurately mapped to the environmental constraints of the target network. Always consult the target's Rules of Engagement (RoE) prior to modifying these baseline configurations, particularly regarding rate limits and destructive payloads in Phase 4 and Phase 5.


# Part 4: Advanced Usage and Configuration

## Introduction

Welcome to Part 4 of the Security Management Platform (SMP) V9.5 User Guide. In
the previous sections, we covered the fundamental features of SMP, including
installation, basic scanning, and interpreting reports. Now, we delve into the
advanced capabilities that make SMP an extensible, high-performance security
tool suitable for enterprise environments and automated pipelines.

This section is designed for security engineers, DevSecOps practitioners, and
system administrators who require deep integration, custom security checks, and
optimized execution. We will explore three primary areas of advanced usage:
writing custom scanners to detect proprietary vulnerabilities, optimizing the
database and thread pool for maximum throughput, and seamlessly integrating the
SMP headless API into Continuous Integration and Continuous Deployment (CI/CD)
workflows.

By mastering these advanced topics, you will be able to tailor the Security
Management Platform precisely to your organization's unique threat landscape and
operational requirements.

## Writing Custom Scanners

One of the most powerful features of SMP V9.5 is its extensible architecture.
While SMP comes with a comprehensive suite of default scanners, organizations
often have internal coding standards, proprietary frameworks, or specific
misconfigurations that require custom detection logic. SMP allows you to build
custom scanners effortlessly using Python.

### The Scanning Architecture

The SMP scanning engine operates asynchronously, feeding target files and
metadata into registered scanner modules. Each scanner evaluates the input
against its ruleset and generates `Observation` objects when a potential
security issue is identified. The engine aggregates these observations,
deduplicates them, and compiles them into the final report.

### The `Observation` Object

At the core of the custom scanning API is the `Observation` object. An
`Observation` represents a single discrete finding generated by a scanner. When
writing a custom scanner, your primary goal is to instantiate and yield (or
return) `Observation` objects when vulnerabilities are detected.

An `Observation` typically requires the following attributes:
- **rule_id**: A unique string identifier for the rule (e.g., `CUST-AUTH-001`).
- **title**: A concise, human-readable title for the finding.
- **description**: A detailed explanation of the vulnerability, the risk it
poses, and context about why it was flagged.
- **severity**: The severity level, usually an enumeration (`Severity.LOW`,
`Severity.MEDIUM`, `Severity.HIGH`, `Severity.CRITICAL`).
- **file_path**: The absolute or relative path to the file where the issue was
found.
- **line_number**: The specific line number in the source code where the
vulnerability resides.
- **snippet**: A short excerpt of the code containing the vulnerability to aid
in triaging.
- **remediation**: Actionable advice on how to fix the vulnerability.

### The `@register_scanner` Decorator

To integrate your custom scanner into the SMP engine, you must use the
`@register_scanner` decorator. This decorator signals to the SMP plugin loader
that your class or function should be instantiated and invoked during the
scanning phase.

The `@register_scanner` decorator accepts several arguments, including the name
of the scanner, its version, and the file types it supports. This ensures that
the engine only feeds relevant files to your scanner, optimizing overall
performance.

### Example: Building a Custom Hardcoded Secret Scanner

Let's walk through building a custom scanner that detects a proprietary company
token format (e.g., `ACME_TOKEN_<alphanumeric>`).

```python
import re
from smp.core.engine import register_scanner
from smp.core.models import Observation, Severity
from smp.core.base import BaseScanner

@register_scanner(
    name="AcmeProprietaryTokenScanner",
    version="1.0.0",
    description="Detects hardcoded ACME internal tokens.",
    target_extensions=[".py", ".json", ".yaml", ".yml", ".txt", ".conf"]
)
class AcmeProprietaryTokenScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        # Compile the regex once during initialization for performance
        self.token_pattern = re.compile(r'ACME_TOKEN_[A-Za-z0-9]{16}')

    def scan_file(self, file_context):
        """
        The main entry point called by the SMP engine for each file.
        :param file_context: An object containing file content, path, and
metadata.
        """
        observations = []
        content = file_context.get_content()
        
        # If the file is too large or binary, get_content might return None
        if not content:
            return observations

        for line_num, line in enumerate(content.splitlines(), start=1):
            matches = self.token_pattern.finditer(line)
            for match in matches:
                snippet = line.strip()
                # Optional: redact the actual token in the snippet to prevent
leaking it in reports
                redacted_snippet =
self.token_pattern.sub('ACME_TOKEN_***REDACTED***', snippet)
                
                obs = Observation(
                    rule_id="CUST-SEC-01",
                    title="Hardcoded ACME Token",
                    description="A proprietary ACME authentication token was
found hardcoded in the source file. "
                                "Hardcoded credentials can be easily extracted
by unauthorized parties and used to "
                                "compromise internal systems.",
                    severity=Severity.CRITICAL,
                    file_path=file_context.file_path,
                    line_number=line_num,
                    snippet=redacted_snippet,
                    remediation="Remove the hardcoded token and migrate it to a
secure secrets management "
                                "system such as HashiCorp Vault or AWS Secrets
Manager. Use environment variables "
                                "to inject the token at runtime."
                )
                observations.append(obs)
                
        return observations
```

### Best Practices for Custom Scanners

1. **Regex Optimization**: Pre-compile regular expressions in the `__init__`
method. Scanning thousands of files with uncompiled regexes will drastically
degrade performance.
2. **Fail Gracefully**: Wrap file parsing logic in `try...except` blocks. If a
file is malformed (e.g., invalid JSON), your scanner should log a warning rather
than crashing the entire SMP engine.
3. **Context Awareness**: Use the `file_context` object effectively. It provides
methods like `is_test_file()` or `get_ast()` which can help reduce false
positives by skipping test directories or leveraging Abstract Syntax Trees
instead of raw text parsing.

---

## Optimizing Performance: WAL Mode and Concurrency Limits

As your codebase grows, the time required to perform comprehensive security
scans naturally increases. SMP V9.5 is built to handle massive enterprise
repositories, but achieving maximum performance requires tuning the system to
match your hardware and workload profile. The two most impactful areas for
tuning are the database backend and the internal concurrency thread pool.

### Understanding SQLite WAL Mode

SMP uses an embedded SQLite database to store state, cache intermediate scanning
results, and build the final relational report data. By default, SQLite operates
in a traditional rollback journal mode. While highly reliable, this mode locks
the entire database during write operations, severely bottlenecking multi-
threaded applications like SMP when multiple scanners are attempting to save
`Observation` objects simultaneously.

To resolve this write contention, SMP allows you to enable **Write-Ahead Logging
(WAL)** mode.

WAL mode changes the underlying database architecture. Instead of writing
directly to the main database file and locking it, SQLite writes changes to a
separate `wal` file. This allows simultaneous readers and writers. In the
context of SMP, it means that multiple scanner threads can persist their
findings concurrently without waiting on database locks, yielding a massive
increase in throughput, especially on machines with fast NVMe SSDs.

#### Enabling WAL Mode

You can enable WAL mode via the `smp_config.yaml` file:

```yaml
database:
  connection_string: "sqlite:///smp_results.db"
  wal_mode: true
  synchronous: "NORMAL"
```

In addition to setting `wal_mode: true`, it is highly recommended to set the
`synchronous` pragma to `NORMAL`. In WAL mode, `synchronous=NORMAL` is generally
completely safe against data loss from application crashes and provides an
order-of-magnitude speedup over the default `FULL` synchronization mode.

### Adjusting ThreadPoolExecutor Concurrency Limits

SMP utilizes Python's `concurrent.futures.ThreadPoolExecutor` to distribute
scanning tasks across multiple threads. By default, SMP determines the number of
threads based on `os.cpu_count() + 4`. While this is a sane default for general-
purpose use, it may not be optimal for your specific deployment infrastructure.

Scanning operations are a mix of I/O-bound tasks (reading files from disk,
writing to the database) and CPU-bound tasks (parsing Abstract Syntax Trees,
executing complex regex).

#### Tuning the Thread Limit

If your environment consists of high-core-count servers (e.g., 32 or 64 vCPUs)
combined with extremely fast storage, you might actually experience diminishing
returns or thrashing if the thread count is set too high. Conversely, if your
storage is slow (e.g., a network-attached SAN), increasing the thread count can
help ensure the CPU remains fed while other threads block on I/O.

You can explicitly override the ThreadPoolExecutor concurrency limits in the
`smp_config.yaml`:

```yaml
engine:
  concurrency:
    max_workers: 16
    chunk_size: 50
```

- **max_workers**: This defines the absolute maximum number of threads in the pool. A good rule of thumb for optimization:
  - For standard local SSDs: Set `max_workers` to exactly `number_of_cores * 2`.
  - For network storage: Set `max_workers` higher, potentially `number_of_cores * 4`, to compensate for high latency.
  - For highly CPU-intensive custom AST scanners: Restrict `max_workers` to the exact `number_of_cores` to prevent context-switching overhead.
- **chunk_size**: This defines how many files are dispatched to a worker thread in a single batch. Increasing chunk size reduces the overhead of task submission but can lead to uneven thread utilization at the end of a scan.

Monitoring your system's `iostat` and CPU utilization during a test run is the
best way to dial in these values. You want to see CPU utilization pinned near
100% without disk I/O wait times skyrocketing.

---

## CI/CD Integration using the Headless API

For security to be truly effective, it must be embedded directly into the
software development lifecycle. SMP V9.5 features a robust Headless API
specifically designed for seamless integration into CI/CD pipelines such as
GitHub Actions, GitLab CI, Jenkins, and Azure DevOps.

Using the headless API allows you to trigger scans programmatically, enforce
security gates, and block pull requests that introduce new vulnerabilities, all
without interacting with the SMP graphical user interface.

### Enabling the Headless API

First, you must start the SMP platform in daemon mode with the API enabled. This
is typically done on a dedicated security scanning server or within a
containerized sidecar.

```bash
smp-server --daemon --enable-api --port 8443
```

### Authentication and API Keys

The headless API requires authentication. You must generate an API key using the
CLI admin tools:

```bash
smp-admin generate-api-key --user "cicd_service_account" --role "scan_runner"
```

Save the output token securely in your CI/CD platform's secrets manager (e.g.,
GitHub Secrets).

### Initiating a Scan

To trigger a scan from your pipeline, you will make a POST request to the
`/api/v1/scans` endpoint. You must provide the path to the repository or
artifact to be scanned, and the desired ruleset.

Example using `curl`:

```bash
curl -X POST https://smp.internal.corp:8443/api/v1/scans \
     -H "Authorization: Bearer $SMP_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
           "target_path": "/mnt/ci_builds/project_repo",
           "profile": "strict_ci",
           "wait_for_completion": true
         }'
```

Setting `wait_for_completion: true` ensures the HTTP request blocks until the
scan is finished. For very large repositories, you may prefer an asynchronous
approach, setting it to `false` and polling the `/api/v1/scans/{scan_id}/status`
endpoint.

### Processing Results and Enforcing Security Gates

When the scan completes, the API returns a JSON payload containing a summary of
findings. A common CI/CD requirement is to fail the build (exit code > 0) if any
CRITICAL or HIGH vulnerabilities are detected.

You can parse the API response using standard tools like `jq`. Here is a
complete example of a shell script that could run in a CI pipeline step:

```bash
#!/bin/bash

echo "Starting SMP Security Scan..."

RESPONSE=$(curl -s -X POST https://smp.internal.corp:8443/api/v1/scans \
     -H "Authorization: Bearer $SMP_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"target_path": "'$WORKSPACE'", "profile": "ci_default",
"wait_for_completion": true}')

# Extract counts using jq
CRITICAL_COUNT=$(echo $RESPONSE | jq '.summary.severities.CRITICAL')
HIGH_COUNT=$(echo $RESPONSE | jq '.summary.severities.HIGH')
SCAN_URL=$(echo $RESPONSE | jq -r '.report_url')

echo "Scan complete. View full report at: $SCAN_URL"
echo "Critical Findings: $CRITICAL_COUNT"
echo "High Findings: $HIGH_COUNT"

if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ]; then
    echo "ERROR: Security vulnerabilities detected exceeding threshold."
    echo "Build failed. Please remediate findings."
    exit 1
else
    echo "SUCCESS: No blocking security vulnerabilities found."
    exit 0
fi
```

### GitHub Actions Integration Example

If you are using GitHub Actions, you can encapsulate the above logic into a
reusable workflow step.

```yaml
name: SMP Security Scan
on: [pull_request]

jobs:
  smp-scan:
    runs-on: self-hosted
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Execute SMP Headless Scan
        env:
          SMP_API_TOKEN: ${{ secrets.SMP_API_TOKEN }}
        run: |
          # Use the python smp-client utility for cleaner integration
          pip install smp-client
          smp-client scan --target . --fail-on high,critical --token
$SMP_API_TOKEN --server https://smp.internal.corp:8443
```

By leveraging the `@register_scanner` decorator for custom policies, optimizing
the ThreadPoolExecutor and SQLite WAL mode for performance, and utilizing the
headless API for CI/CD, SMP V9.5 transforms from a standalone desktop
application into a foundational element of enterprise DevSecOps automation.


# Part 5: Troubleshooting and Error Codes

## 5.1 Overview
Welcome to the troubleshooting and error resolution guide for the Security Management Platform (SMP) V9.5. This section is designed to provide comprehensive details regarding error codes, their root causes, and step-by-step remediation procedures to ensure uninterrupted operation of your security environment. SMP utilizes a standardized error code nomenclature. Every error is prefixed with `SMP-` followed by a four-digit numeric identifier. These identifiers are grouped by subsystems to help administrators quickly identify the source of the issue.

The error ranges are categorized as follows:
*   **1xxx:** Authentication & Authorization errors.
*   **2xxx:** Scanner & Engine errors.
*   **3xxx:** Database & Storage errors.
*   **4xxx:** Evidence & Export errors.
*   **5xxx:** Threat Intelligence Integration errors.
*   **6xxx:** Policy & Compliance errors.

In addition to referencing this guide, we strongly recommend checking the SMP
System Logs located at `/var/log/smp/syslog.log` for additional contextual
details when an error occurs. Understanding the logs is a critical part of the
troubleshooting process, and this guide should be used in tandem with log
analysis.

---

## 5.2 Category 1xxx: Authentication & Authorization

Authentication and Authorization errors occur when the system cannot verify a
user's identity, fails to establish a secure session, or denies access to a
requested resource due to insufficient privileges. These errors are critical as
they directly impact user access and system security.

### SMP-1001: Invalid Credentials
**Description:** The username or password provided does not match our records or the Active Directory/LDAP backend.
**Root Cause:** Typos in the login form, expired passwords, or temporary synchronization issues with LDAP/Active Directory servers. Sometimes, caching issues on the client browser can also lead to stale login attempts.
**Resolution:**
1. Verify the username and password are correct. Ensure Caps Lock is not enabled.
2. If using Active Directory, check the AD connection status in `Settings > Directory Services`. Ensure the service account used for binding is active.
3. Force a manual sync with the directory server using the administrative dashboard.
4. Have the user reset their password via the self-service portal, ensuring it meets the new V9.5 password complexity requirements.

### SMP-1002: Token Expired or Invalid
**Description:** The JWT (JSON Web Token) used for API or UI authentication has expired or is cryptographically invalid.
**Root Cause:** Session timeout due to inactivity (default is 30 minutes), clock skew between the client and server, or tampering with the token structure.
**Resolution:**
1. Refresh the web interface to obtain a new session token, forcing a re-authentication prompt if necessary.
2. Ensure the NTP (Network Time Protocol) service is running and correctly synchronized on both the SMP server and the client machine. A clock skew of more than 5 minutes will invalidate tokens.
3. If using API access, generate a new API token from the user profile settings and ensure your automation scripts are using the updated token.

### SMP-1003: Multi-Factor Authentication (MFA) Failure
**Description:** The second-factor authentication mechanism failed to validate the provided code within the acceptable time window.
**Root Cause:** Incorrect code entry, time desynchronization on the authenticator app (like Google Authenticator or Authy), or SMS gateway failure if using text-based MFA.
**Resolution:**
1. Request a new MFA code or use a backup code generated during the initial MFA setup.
2. Verify the time settings on the user's mobile device are set to automatic network time.
3. Check the SMS gateway logs in `/var/log/smp/mfa-gateway.log` if SMS fallback is enabled, looking for rate limits or provider outages.

### SMP-1005: Account Locked
**Description:** The user account has been temporarily locked due to excessive failed login attempts.
**Root Cause:** Brute-force login attempts from malicious actors, or a user repeatedly entering the wrong password, often due to a stuck key or forgotten password.
**Resolution:**
1. Wait for the standard lockout duration (default 15 minutes) to expire automatically.
2. An administrator can manually unlock the account via `Administration > Users > Action > Unlock`.
3. Investigate the source IP of the failed attempts in the authentication logs (`/var/log/smp/auth.log`) to determine if a targeted attack is occurring.

### SMP-1010: Insufficient Permissions (RBAC Violation)
**Description:** The authenticated user attempted to access a module or perform an action not permitted by their assigned role.
**Root Cause:** Misconfigured Role-Based Access Control (RBAC) settings, or the user legitimately lacks the necessary clearance for the operation (e.g., a read-only user attempting to launch a scan).
**Resolution:**
1. Review the user's assigned roles in the Administration panel.
2. Verify that the role contains the necessary permissions (e.g., `SCANNER_EXECUTE`, `REPORT_EXPORT`, `POLICY_WRITE`).
3. Update the user's role assignment if authorized, or instruct the user to request elevated privileges through the internal IT ticketing system.

### SMP-1015: Single Sign-On (SSO) Provider Unreachable
**Description:** The SMP platform could not communicate with the configured SAML or OIDC Identity Provider (IdP).
**Root Cause:** Network connectivity issues between the SMP server and the IdP (like Okta or Azure AD), incorrect metadata URL configuration, or expired IdP certificates.
**Resolution:**
1. Verify that the SMP server has outbound HTTPS access to the IdP's URLs.
2. Check `Settings > Authentication > SSO` to ensure the metadata URL is correct and accessible.
3. Update the IdP's public certificate in the SMP configuration if it has recently expired or been rotated.

---

## 5.3 Category 2xxx: Scanner & Engine

Scanner and Engine errors are related to the core vulnerability detection
engine, plugin execution, target reachability, and network interactions during
active scanning phases.

### SMP-2001: Target Unreachable
**Description:** The scanning engine could not establish a basic network connection with the specified target IP or hostname.
**Root Cause:** The target host is powered down, blocked by an intermediate firewall, or routing issues exist between the SMP scanner node and the target network subnet.
**Resolution:**
1. Ping the target from the scanner node's CLI to confirm basic ICMP reachability.
2. Verify that there are no firewalls (host-based like Windows Defender Firewall, or network-based like Palo Alto/Cisco) dropping traffic on the scanning ports (e.g., 22, 135, 443).
3. Check for any dropped packets in the edge router logs and ensure proper VLAN tagging if scanning across segmented networks.

### SMP-2002: Authentication to Target Failed
**Description:** The scanner could reach the target but failed to authenticate for a deep, credentialed scan.
**Root Cause:** Incorrect credentials supplied in the scan configuration, insufficient privileges on the target system, disabled remote administration services (like WinRM, SSH, or SMB), or account lockouts on the target itself.
**Resolution:**
1. Verify the credentials configured in `Scan Profiles > Credentials`. Test them manually from the scanner node.
2. For Windows targets, ensure WinRM is enabled (`Enable-PSRemoting`) and the firewall allows incoming connections on port 5985/5986.
3. For Linux targets, verify that the SSH key or password is valid and the user is listed in the `sudoers` file if privilege escalation (sudo) is required for comprehensive checks.

### SMP-2005: Plugin Timeout
**Description:** A specific vulnerability checking plugin exceeded its maximum execution time.
**Root Cause:** The target service is responding too slowly under load, the network connection is experiencing severe latency, or the plugin is stuck in an infinite loop due to unexpected application behavior on the target.
**Resolution:**
1. Increase the global plugin timeout setting in `Settings > Scanner Settings > Advanced` from the default 120 seconds to 300 seconds.
2. Disable the specific plugin (by its ID) in the scan policy if it is known to be problematic and not strictly necessary for your compliance requirements.
3. Check the target system's performance metrics (CPU/RAM usage) to ensure it is not overloaded during the scan window.

### SMP-2010: Scan Engine Out of Memory
**Description:** The scanning process crashed or halted because it consumed all available system RAM.
**Root Cause:** Scanning too many complex targets simultaneously, handling massive web application crawling structures, or a rare memory leak in a specific parsing plugin.
**Resolution:**
1. Reduce the "Maximum Concurrent Targets" setting in the scan profile to lower the memory footprint.
2. Allocate more RAM to the SMP virtual machine or physical server (minimum recommended for heavy scanning is 32GB).
3. Restart the `smp-engine` service: `systemctl restart smp-engine` to clear the immediate memory pressure.

### SMP-2020: Invalid Scan Configuration
**Description:** The scan engine refused to start a job because the provided configuration parameters are mutually exclusive or malformed.
**Root Cause:** Selecting conflicting options (e.g., enabling "Safe Checks Only" while simultaneously enabling "Destructive Exploitation" modules), or an invalid IP range format (like `192.168.1.300`).
**Resolution:**
1. Review the scan profile settings carefully, ensuring logical consistency.
2. Validate all IP ranges, CIDR blocks, and hostnames for correct syntax.
3. Save the profile again, paying attention to any UI validation warnings before launching the scan.

---

## 5.4 Category 3xxx: Database & Storage

These errors pertain to backend PostgreSQL operations, ElasticSearch indexing,
disk space management, and data retention policies.

### SMP-3001: Database Connection Refused
**Description:** The core SMP application cannot connect to the primary PostgreSQL database.
**Root Cause:** The database service is down, there is a network partition between the application and database servers (in distributed deployments), or incorrect database credentials are in the configuration file.
**Resolution:**
1. Verify the PostgreSQL service is running: `systemctl status postgresql-14`. Start it if necessary.
2. Check the `pg_hba.conf` file to ensure the application server IP is allowed to connect using MD5 or SCRAM authentication.
3. Verify the credentials stored in `/etc/smp/database.conf` match those of the database user.

### SMP-3002: Disk Space Critical
**Description:** The storage volume holding the database or scan results is at or above 95% capacity, putting the system at risk of a hard crash.
**Root Cause:** Accumulation of historical scan data over years, large debug logs left enabled, or insufficient initial storage provisioning during installation.
**Resolution:**
1. Identify large directories and files using `du -sh /var/lib/smp/*`.
2. Execute the data retention policy cleanup script manually to purge old data: `smp-manage db cleanup --days 90`.
3. Expand the logical volume via LVM or attach additional storage arrays to the database partition.

### SMP-3005: Index Synchronization Failure
**Description:** Data in the PostgreSQL database is out of sync with the ElasticSearch full-text search indices, leading to missing results in the global search bar.
**Root Cause:** Sudden power loss, an elasticsearch service crash, or overwhelming data ingestion rates during massive concurrent scans.
**Resolution:**
1. Check the ElasticSearch cluster health via `curl -X GET "localhost:9200/_cluster/health"`. Ensure the status is 'green' or 'yellow'.
2. Run the full index rebuild utility: `smp-manage search rebuild-all`. Note: This process is I/O intensive and may take several hours depending on the database size.

### SMP-3012: Query Execution Timeout
**Description:** A complex database query (typically during reporting or complex dashboard rendering) took too long to complete and was terminated by the query killer.
**Root Cause:** Missing database indexes due to a failed migration, excessively large datasets spanning multiple years, or poorly optimized custom SQL report queries.
**Resolution:**
1. Run the database optimization and maintenance script: `smp-manage db optimize` to rebuild statistics and indexes.
2. Restrict the time range or scope of the dashboard widget or report causing the issue.
3. As a temporary measure, increase the `statement_timeout` value in `postgresql.conf`, but revert this once the root cause is addressed.

### SMP-3020: Database Migration Failed
**Description:** An automated database schema update failed during a software upgrade process.
**Root Cause:** Incompatible data in a column, insufficient disk space during table reconstruction, or an interrupted upgrade script.
**Resolution:**
1. Check the upgrade logs in `/var/log/smp/upgrade.log` for the exact SQL statement that failed.
2. Restore the database from the pre-upgrade backup taken automatically by the installer.
3. Contact SMP Support with the logs before attempting the upgrade again.

---

## 5.5 Category 4xxx: Evidence & Export

Errors in this category occur during the generation of PDF/CSV reports,
exporting of evidence files, handling of packet captures (PCAPs), and large-
scale data offloading.

### SMP-4001: Report Generation Failed
**Description:** The PDF or HTML report rendering engine crashed or failed to produce an output file.
**Root Cause:** Missing system fonts, corrupted custom HTML template files, or insufficient memory allocated to the asynchronous reporting microservice.
**Resolution:**
1. Ensure the `wkhtmltopdf` binary is installed and correctly referenced in the configuration.
2. Revert any recent changes to custom report templates to the default state.
3. Restart the dedicated reporting service: `systemctl restart smp-reporter`.

### SMP-4005: Invalid Evidence Format
**Description:** An attempt was made to upload or process an evidence file (e.g., PCAP, screenshot, memory dump) that is corrupted or of an unsupported file type.
**Root Cause:** File corruption during transfer, or a user attempting to upload a disallowed executable file type (e.g., `.exe`, `.bat`) instead of standard evidence formats.
**Resolution:**
1. Ensure the uploaded file is a valid, uncorrupted PCAP or standard image format (PNG, JPEG).
2. Check the file size against the maximum allowed upload limit (default 50MB, configurable in Settings).

### SMP-4010: Export Queue Congestion
**Description:** The background job queue for exporting large datasets is completely full, causing new export requests to fail or be delayed indefinitely.
**Root Cause:** Too many users requesting massive CSV exports simultaneously, or a stuck worker process consuming all queue slots.
**Resolution:**
1. View the live queue status in `Administration > System Health > Background Jobs`.
2. Manually cancel stalled or excessively large export jobs that have been running for more than an hour.
3. Restart the Celery worker nodes to clear the queue cache: `systemctl restart smp-celery-workers`.

### SMP-4015: Export Destination Unreachable
**Description:** An automated scheduled report failed to upload to the configured remote destination (SMB share, AWS S3, or SFTP server).
**Root Cause:** Network changes blocking outbound traffic, changed credentials on the remote server, or the destination storage is full.
**Resolution:**
1. Test the connection to the remote destination using the 'Test Connection' button in the Scheduled Reports interface.
2. Verify credentials and permissions on the target SMB share or S3 bucket.
3. Ensure firewalls allow outbound traffic on the required ports (e.g., 445 for SMB, 22 for SFTP).

### SMP-4050: Evidence Encryption Key Missing
**Description:** The system cannot decrypt stored evidence files because the cryptographic key is missing, corrupted, or inaccessible.
**Root Cause:** The Key Management Service (KMS) is temporarily unreachable, or the local keystore file was accidentally deleted during maintenance.
**Resolution:**
1. Verify network connectivity to the configured KMS provider (AWS KMS, HashiCorp Vault, etc.).
2. If using local file-based keys, restore `/etc/smp/keys/evidence.key` from a secure, off-site backup.
3. Check filesystem permissions on the key directory to ensure the `smp` service user can read the files.

---

## 5.6 Category 5xxx: Threat Intelligence

These errors relate to the ingestion, parsing, and utilization of external
threat intelligence feeds, including  integrations, MISP, and
commercial feed providers.

### SMP-5001: Feed Sync Failed
**Description:** The platform failed to download the latest threat indicators from a configured intelligence feed provider.
**Root Cause:** Invalid API keys, feed provider infrastructure downtime, or a corporate outbound proxy/firewall blocking HTTPS connections to the provider's domain.
**Resolution:**
1. Verify the API keys and feed URLs in `Settings > Threat Intelligence`.
2. Test network connectivity to the feed provider using `curl -v` from the SMP server to check for proxy interference.
3. Check if the feed provider's API rate limits have been exceeded, requiring an upgrade to your subscription tier.

### SMP-5002: TAXII Polling Error
**Description:** The TAXII client encountered an error during discovery or polling of collections from a remote TAXII server.
**Root Cause:** Incompatible TAXII version (e.g., the server mandates TAXII 2.1 but SMP is configured for TAXII 1.1), or missing/expired client certificates for mutual TLS authentication.
**Resolution:**
1. Confirm the exact TAXII version supported by the provider and adjust the SMP integration configuration accordingly.
2. If mutual TLS (mTLS) is required, ensure the correct client certificate and private key are uploaded and assigned in the feed settings.

### SMP-5005: Indicator Parsing Error
**Description:** A downloaded intelligence feed contains malformed data or unrecognized STIX objects that the local engine cannot process.
**Root Cause:** The feed provider made an unannounced breaking change to their data format, or the JSON/XML data was corrupted during transit.
**Resolution:**
1. Review the `/var/log/smp/ti-processor.log` for specific parsing exceptions to identify the problematic data block or field.
2. Temporarily disable the failing feed to prevent queue blockages and system strain.
3. Contact the feed provider for clarification or update the SMP platform to the latest patch release, which frequently includes updated parsers.

### SMP-5010: MISP Integration Failure
**Description:** The system failed to push or pull events from a configured Malware Information Sharing Platform (MISP) instance.
**Root Cause:** The MISP automation key is invalid, the MISP server is unreachable, or the configured tag filters are rejecting all events.
**Resolution:**
1. Regenerate the API key in the MISP instance and update the SMP configuration.
2. Ensure the MISP server URL is reachable and the SSL certificate is trusted by the SMP server.
3. Review the event filtering rules in the integration settings to ensure they are not overly restrictive.

---

## 5.7 Category 6xxx: Policy & Compliance

Policy and compliance errors typically involve issues with parsing custom
compliance frameworks, executing configuration checks against remote targets, or
evaluating complex OVAL definitions.

### SMP-6001: Invalid Policy Syntax
**Description:** A custom compliance policy uploaded by the user failed validation due to severe syntax errors.
**Root Cause:** Missing brackets, incorrect YAML indentation, invalid keywords, or malformed regular expressions in the policy definition file.
**Resolution:**
1. Review the uploaded policy file using a standard YAML/JSON linter to catch basic formatting issues.
2. Ensure the policy adheres strictly to the SMP Custom Policy Language (CPL) specification outlined in Part 3 of this manual.
3. Correct the syntax errors and re-upload the policy via the UI.

### SMP-6002: OVAL Definition Evaluation Failed
**Description:** The engine failed to evaluate an OVAL (Open Vulnerability and Assessment Language) definition against a target system.
**Root Cause:** The target operating system is completely unsupported by the specific OVAL definition, or required system utilities (like WMI on Windows or `rpm`/`dpkg` on Linux) are missing, broken, or restricted by endpoint security software.
**Resolution:**
1. Verify that the OVAL definition is explicitly applicable to the target's OS family and exact version.
2. Ensure the scanning account has sufficient administrative privileges to query the necessary system states (e.g., registry keys, deep file attributes).
3. Check the target system for corruption in its package manager database, repairing it if necessary.

### SMP-6005: Compliance Baseline Mismatch
**Description:** The assigned compliance baseline references checks, rules, or controls that do not exist in the current system database.
**Root Cause:** Importing a baseline exported from a newer version of SMP into an older instance, or accidental deletion of core compliance objects from the database.
**Resolution:**
1. Ensure your SMP installation is fully updated to the latest available version.
2. Re-import the official, certified compliance content pack using the CLI: `smp-manage content update --type compliance`.
3. Review the baseline mapping in the UI to manually remove or replace references to missing controls.

### SMP-6010: Remote Registry Access Denied
**Description:** A compliance check attempting to read Windows Registry keys failed due to access restrictions.
**Root Cause:** The Remote Registry service is not running on the target, or the scanning account lacks the specific permissions required to read the hive.
**Resolution:**
1. Ensure the "Remote Registry" service is set to 'Automatic' and is running on the target Windows machines.
2. Verify the scanning service account is a member of the local Administrators group or has explicitly been granted read permissions to the required registry paths via Group Policy.

---

## 5.8 Advanced Debugging and Diagnostics

When standard troubleshooting steps outlined above do not resolve an issue,
administrators should utilize the built-in diagnostic tools to gather deeper
insights.

### Generating a Diagnostic Bundle
The diagnostic bundle collects all relevant logs, configuration files (automatically sanitized of passwords and secrets), and system state information into a single compressed archive. This is essential for escalating issues to SMP Technical Support.

Run the following command from the administrative shell:
```bash
sudo smp-diag generate --full
```
This process may take a few minutes. It will produce a `.tar.gz` file located in
`/var/lib/smp/diagnostics/`. Please attach this specific file when opening a
support ticket via the customer portal.

### Enabling Debug Mode
For highly intermittent issues, enabling debug logging can provide deeper insight into background system operations.
Modify `/etc/smp/logging.conf` and change the root log level parameter from `INFO` to `DEBUG`.
Restart the SMP services to apply the change: `systemctl restart smp-core smp-engine smp-reporter`.
*Warning: Debug logging generates a massive amount of data and can quickly consume available disk space. Only leave debug logging enabled while actively reproducing and troubleshooting a specific issue, and revert it to INFO immediately afterward.*

## 5.9 Conclusion
Effective troubleshooting in complex environments requires a systematic and patient approach: accurately identify the error code, understand the surrounding context from the system logs, and apply the appropriate resolution methodically. By familiarizing yourself with these common error categories and their typical root causes, administrators can maintain a highly resilient, reliable, and effective security management platform.


