# Appendix A: Comprehensive Scanner Compendium

To fulfill the rigorous orchestration requirements of the Security Management Platform, the `scanners/` directory contains over 50 distinct Python wrapper modules. Each module dictates the execution parameters, Directed Acyclic Graph (DAG) dependencies, timeout constraints, and standard-output parsing logic for a specific third-party security binary. 

This appendix provides an exhaustive, highly technical data dump of the core scanning tools implemented within the V9.4.0 architecture, categorized by their operational phase.

## A.1 Network and Infrastructure Phase

These modules operate at Layer 3 and Layer 4 of the OSI model, establishing the fundamental topological map of the target.

### 1. `nmap.py` (Network Mapper)
- **Binary**: `nmap`
- **DAG Dependencies**: `[HTTPx, Subfinder]`
- **Timeout**: 1800 seconds (30 minutes)
- **Execution Logic**: Invokes Nmap with aggressive SYN scanning, OS detection, and service versioning (`nmap -sS -sV -O -p- --max-retries 2`). The module parses the resulting XML output to populate the `ports` and `services` tables within the internal SQLite database.
- **Risk Parsing**: Identifies deprecated services (e.g., Telnet, FTP) and assigns an immediate baseline CVSS score of 5.0 to plaintext protocols.

### 2. `masscan.py` (High-Speed Port Scanner)
- **Binary**: `masscan`
- **DAG Dependencies**: `[Traceroute]`
- **Timeout**: 600 seconds (10 minutes)
- **Execution Logic**: Utilizes asynchronous transmission to scan the entire IPv4 port space (0-65535) at speeds exceeding 100,000 packets per second. To prevent localized state-table exhaustion on the host kernel, the SMP wrapper enforces a strict `--max-rate 10000` parameter.

### 3. `traceroute.py` (Path Topology)
- **Binary**: Native OS `traceroute` or `tracert`
- **DAG Dependencies**: None (In-Degree: 0)
- **Timeout**: 120 seconds
- **Execution Logic**: Maps the physical network hops between the SMP host and the target. Used by the Neural Brain to establish physical chokepoints in the centrality graph.

## A.2 Passive Reconnaissance Phase

These modules interact strictly with third-party APIs and open-source intelligence (OSINT) repositories. They do not send active payloads to the target.

### 4. `subfinder.py` (Passive DNS)
- **Binary**: `subfinder` (Go)
- **DAG Dependencies**: `[Traceroute]`
- **Execution Logic**: Queries 30+ passive DNS sources (e.g., Censys, Shodan, SecurityTrails) to discover subdomains. The wrapper parses the JSON output and dynamically injects newly discovered subdomains back into the DAG execution queue for secondary processing.

### 5. `cloud_enum.py` (Cloud Asset Discovery)
- **Binary**: `cloud_enum.py`
- **DAG Dependencies**: `[Subfinder]`
- **Execution Logic**: Performs dictionary permutations against AWS S3 buckets, Azure Blob Storage, and GCP buckets to identify unauthenticated cloud assets related to the target domain.

### 6. `amass.py` (Deep OSINT)
- **Binary**: `amass` (Go)
- **DAG Dependencies**: `[Subfinder, DNSx]`
- **Execution Logic**: A heavy-weight enumeration engine. Due to its massive memory consumption and prolonged execution times, SMP restricts `amass` exclusively to the `full` scan profile, bypassing it during `standard` and `osint` engagements.

## A.3 Web Application Phase

These scanners operate at Layer 7 (HTTP/HTTPS), actively probing web servers and API endpoints.

### 7. `httpx_scanner.py` (HTTP Prober)
- **Binary**: `httpx` (Go)
- **DAG Dependencies**: `[Traceroute]`
- **Execution Logic**: Verifies which discovered subdomains are actively serving HTTP/HTTPS content. It captures the status code, title, and response length. Any subdomain that does not return a 200-403 status code is mathematically pruned from the DAG, saving hours of wasted execution time on dead endpoints.

### 8. `nuclei.py` (Template-Based Fuzzer)
- **Binary**: `nuclei` (Go)
- **DAG Dependencies**: `[HTTPx, Nikto]`
- **Timeout**: 7200 seconds (2 hours)
- **Execution Logic**: The most critical vulnerability scanner in the platform. Nuclei matches network responses against thousands of YAML-based CVE templates. The SMP wrapper executes Nuclei with the `-json-export` flag, reads the JSON blob dynamically, and pipes every identified template ID directly into the Neural Brain for TF-IDF clustering.

### 9. `ffuf.py` / `feroxbuster.py` (Directory Fuzzers)
- **Binary**: `ffuf` / `feroxbuster`
- **DAG Dependencies**: `[HTTPx]`
- **Execution Logic**: Performs highly concurrent dictionary attacks to discover hidden directories and unlinked API endpoints. To prevent generating thousands of False Positives on Single Page Applications (SPAs) that route all URLs to a `200 OK` index file, the SMP wrapper implements an advanced entropy filter. If $> 80\%$ of the discovered paths share the exact same `Content-Length`, the wrapper mathematically determines it is an SPA wildcard and drops the findings.

## A.4 Advanced Exploitation Phase

These scanners send aggressive payloads (e.g., SQLi, XSS, SSRF) to validate the presence of a vulnerability.

### 10. `sqlmap.py` (SQL Injection)
- **Binary**: `sqlmap` (Python)
- **DAG Dependencies**: `[ParamSpider, Arjun]`
- **Timeout**: 3600 seconds (1 hour)
- **Execution Logic**: Target URLs and parameters discovered by `ParamSpider` are piped directly into SQLMap. The SMP wrapper explicitly enforces the `--batch` and `--random-agent` flags to bypass interactive prompts and WAF restrictions.

### 11. `dalfox.py` (Cross-Site Scripting)
- **Binary**: `dalfox` (Go)
- **DAG Dependencies**: `[Wapiti]`
- **Execution Logic**: A parameter analysis and XSS fuzzer. It verifies reflections identified by earlier scanners and attempts to execute localized JavaScript payloads to confirm exploitability.

### 12. `ssrf_scanner.py` / `xxe_scanner.py` (Out-of-Band Callbacks)
- **Binary**: Custom Python implementations
- **DAG Dependencies**: `[HTTPx]`
- **Execution Logic**: These scanners attempt Server-Side Request Forgery and XML External Entity injections by injecting unique payload tokens. If the target server reaches out to the SMP host (or an external webhook), the vulnerability is confirmed.

## A.5 Code and Secrets Phase

### 13. `gitleaks.py` (Secret Scanning)
- **Binary**: `gitleaks` (Go)
- **DAG Dependencies**: `[HTTPx, DirB]`
- **Execution Logic**: If a directory fuzzer discovers an exposed `.git/` directory on a web server, the `gitleaks` wrapper automatically clones the repository to a localized `/tmp/` volume and scans the full commit history for AWS keys, JWTs, and database passwords using regex entropy matching.

### 14. `retire_js.py` (Dependency Auditing)
- **Binary**: Node.js `retire`
- **DAG Dependencies**: `[Tech_Fingerprint]`
- **Execution Logic**: Analyzes the Javascript files served by the target. It cross-references the internal versions (e.g., `jQuery 1.8.3`) against known NVD vulnerability matrices.

*(Note: The above list highlights 14 of the 57 integrated scanners. The remaining 43 wrappers—including `prowler`, `trivy`, `wpscan`, `commix`, and `jwt_tool`—adhere to identical architectural constraints, defined strictly by their DAG In-Degree dependencies and Subprocess Watchdog TTL parameters).*
