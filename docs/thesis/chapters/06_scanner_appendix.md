# 6. The 57-Scanner Arsenal (Integration Appendix)

This chapter details the exact technical parameters of all integrated security scanners, proving the massive scale of the DAG orchestration engine.

## 6.2 Scanner: API Fuzzer
- **Step Name**: Running API Fuzzer
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 80%
- **DAG Dependencies**: Katana
- **Execution Function**: `run_api_fuzzer`

```python
@register_scanner(
    name="API Fuzzer",
    step_name="Running API Fuzzer",
    depends_on=['Katana'],
    binary_name="",
    needs_binary=False,
    confidence=80
)
def run_api_fuzzer(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.1 Scanner: Amass
- **Step Name**: Running Amass
- **Binary Name**: `amass`
- **Requires Binary**: True
- **Base Confidence**: 85%
- **DAG Dependencies**: Subfinder
- **Execution Function**: `run_amass_scan`

```python
@register_scanner(
    name="Amass",
    step_name="Running Amass",
    depends_on=['Subfinder'],
    binary_name="amass",
    needs_binary=True,
    confidence=85
)
def run_amass_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.3 Scanner: Arjun
- **Step Name**: Running Arjun
- **Binary Name**: `arjun`
- **Requires Binary**: True
- **Base Confidence**: 85%
- **DAG Dependencies**: Dalfox
- **Execution Function**: `run_arjun_scan`

```python
@register_scanner(
    name="Arjun",
    step_name="Running Arjun",
    depends_on=['Dalfox'],
    binary_name="arjun",
    needs_binary=True,
    confidence=85
)
def run_arjun_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.21 Scanner: Auth Brute-Force Test
- **Step Name**: Running Auth Brute-Force Test
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 85%
- **DAG Dependencies**: Tech Fingerprint
- **Execution Function**: `run_hydra_scanner`

```python
@register_scanner(
    name="Auth Brute-Force Test",
    step_name="Running Auth Brute-Force Test",
    depends_on=['Tech Fingerprint'],
    binary_name="",
    needs_binary=False,
    confidence=85
)
def run_hydra_scanner(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.6 Scanner: CMS Scanner
- **Step Name**: Running CMS Scanner
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 85%
- **DAG Dependencies**: CORS
- **Execution Function**: `run_cms_scan`

```python
@register_scanner(
    name="CMS Scanner",
    step_name="Running CMS Scanner",
    depends_on=['CORS'],
    binary_name="",
    needs_binary=False,
    confidence=85
)
def run_cms_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.8 Scanner: CORS
- **Step Name**: Running CORS
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 95%
- **DAG Dependencies**: Robots.txt
- **Execution Function**: `run_cors_scan`

```python
@register_scanner(
    name="CORS",
    step_name="Running CORS",
    depends_on=['Robots.txt'],
    binary_name="",
    needs_binary=False,
    confidence=95
)
def run_cors_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.10 Scanner: CRLF Scanner
- **Step Name**: Running CRLF Scanner
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 85%
- **DAG Dependencies**: Tech Fingerprint
- **Execution Function**: `run_crlf_scan`

```python
@register_scanner(
    name="CRLF Scanner",
    step_name="Running CRLF Scanner",
    depends_on=['Tech Fingerprint'],
    binary_name="",
    needs_binary=False,
    confidence=85
)
def run_crlf_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.11 Scanner: CRT.sh
- **Step Name**: Running CRT.sh
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 95%
- **DAG Dependencies**: theHarvester
- **Execution Function**: `run_crtsh_scan`

```python
@register_scanner(
    name="CRT.sh",
    step_name="Running CRT.sh",
    depends_on=['theHarvester'],
    binary_name="",
    needs_binary=False,
    confidence=95
)
def run_crtsh_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.4 Scanner: ClamAV
- **Step Name**: Running Malware Scan (ClamAV)
- **Binary Name**: `clamscan`
- **Requires Binary**: True
- **Base Confidence**: 99%
- **DAG Dependencies**: None (In-Degree 0)
- **Execution Function**: `scan`

```python
@register_scanner(
    name="ClamAV",
    step_name="Running Malware Scan (ClamAV)",
    depends_on=[],
    binary_name="clamscan",
    needs_binary=True,
    confidence=99
)
def scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.5 Scanner: Cloud Enum
- **Step Name**: Running Cloud Enum
- **Binary Name**: `cloud_enum`
- **Requires Binary**: True
- **Base Confidence**: 85%
- **DAG Dependencies**: ParamSpider
- **Execution Function**: `run_cloud_enum_scan`

```python
@register_scanner(
    name="Cloud Enum",
    step_name="Running Cloud Enum",
    depends_on=['ParamSpider'],
    binary_name="cloud_enum",
    needs_binary=True,
    confidence=85
)
def run_cloud_enum_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.7 Scanner: Commix
- **Step Name**: Running Commix
- **Binary Name**: `commix`
- **Requires Binary**: True
- **Base Confidence**: 95%
- **DAG Dependencies**: Katana
- **Execution Function**: `run_commix_scan`

```python
@register_scanner(
    name="Commix",
    step_name="Running Commix",
    depends_on=['Katana'],
    binary_name="commix",
    needs_binary=True,
    confidence=95
)
def run_commix_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.9 Scanner: CrackMapExec
- **Step Name**: Running Internal AD Recon (CrackMapExec)
- **Binary Name**: `cme`
- **Requires Binary**: True
- **Base Confidence**: 95%
- **DAG Dependencies**: None (In-Degree 0)
- **Execution Function**: `scan`

```python
@register_scanner(
    name="CrackMapExec",
    step_name="Running Internal AD Recon (CrackMapExec)",
    depends_on=[],
    binary_name="cme",
    needs_binary=True,
    confidence=95
)
def scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.13 Scanner: DNSx
- **Step Name**: Running DNSx
- **Binary Name**: `dnsx`
- **Requires Binary**: True
- **Base Confidence**: 95%
- **DAG Dependencies**: Subfinder
- **Execution Function**: `run_dnsx_scan`

```python
@register_scanner(
    name="DNSx",
    step_name="Running DNSx",
    depends_on=['Subfinder'],
    binary_name="dnsx",
    needs_binary=True,
    confidence=95
)
def run_dnsx_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.12 Scanner: Dalfox
- **Step Name**: Running Dalfox
- **Binary Name**: `dalfox`
- **Requires Binary**: True
- **Base Confidence**: 90%
- **DAG Dependencies**: Gitleaks
- **Execution Function**: `run_dalfox_scan`

```python
@register_scanner(
    name="Dalfox",
    step_name="Running Dalfox",
    depends_on=['Gitleaks'],
    binary_name="dalfox",
    needs_binary=True,
    confidence=90
)
def run_dalfox_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.14 Scanner: Feroxbuster
- **Step Name**: Running Feroxbuster
- **Binary Name**: `feroxbuster`
- **Requires Binary**: True
- **Base Confidence**: 85%
- **DAG Dependencies**: Katana
- **Execution Function**: `run_feroxbuster_scan`

```python
@register_scanner(
    name="Feroxbuster",
    step_name="Running Feroxbuster",
    depends_on=['Katana'],
    binary_name="feroxbuster",
    needs_binary=True,
    confidence=85
)
def run_feroxbuster_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.16 Scanner: Gitleaks
- **Step Name**: Running Gitleaks
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 95%
- **DAG Dependencies**: Shodan
- **Execution Function**: `run_gitleaks_scan`

```python
@register_scanner(
    name="Gitleaks",
    step_name="Running Gitleaks",
    depends_on=['Shodan'],
    binary_name="",
    needs_binary=False,
    confidence=95
)
def run_gitleaks_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.17 Scanner: GraphQL Scanner
- **Step Name**: Running GraphQL Scanner
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 80%
- **DAG Dependencies**: Katana
- **Execution Function**: `run_graphql_scanner`

```python
@register_scanner(
    name="GraphQL Scanner",
    step_name="Running GraphQL Scanner",
    depends_on=['Katana'],
    binary_name="",
    needs_binary=False,
    confidence=80
)
def run_graphql_scanner(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.36 Scanner: HTTP Smuggling Scanner
- **Step Name**: Running HTTP Smuggling Scanner
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 80%
- **DAG Dependencies**: Nmap
- **Execution Function**: `run_smuggler_scan`

```python
@register_scanner(
    name="HTTP Smuggling Scanner",
    step_name="Running HTTP Smuggling Scanner",
    depends_on=['Nmap'],
    binary_name="",
    needs_binary=False,
    confidence=80
)
def run_smuggler_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.20 Scanner: HTTPx
- **Step Name**: Running HTTPx
- **Binary Name**: `httpx`
- **Requires Binary**: True
- **Base Confidence**: 95%
- **DAG Dependencies**: None (In-Degree 0)
- **Execution Function**: `run_httpx_scan`

```python
@register_scanner(
    name="HTTPx",
    step_name="Running HTTPx",
    depends_on=[],
    binary_name="httpx",
    needs_binary=True,
    confidence=95
)
def run_httpx_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.18 Scanner: HackerTarget
- **Step Name**: Running HackerTarget
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 90%
- **DAG Dependencies**: CRT.sh
- **Execution Function**: `run_hackertarget_scan`

```python
@register_scanner(
    name="HackerTarget",
    step_name="Running HackerTarget",
    depends_on=['CRT.sh'],
    binary_name="",
    needs_binary=False,
    confidence=90
)
def run_hackertarget_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.22 Scanner: JWT Scanner
- **Step Name**: Running JWT Scanner
- **Binary Name**: `jwt_tool`
- **Requires Binary**: True
- **Base Confidence**: 85%
- **DAG Dependencies**: Commix
- **Execution Function**: `run_jwt_scanner_scan`

```python
@register_scanner(
    name="JWT Scanner",
    step_name="Running JWT Scanner",
    depends_on=['Commix'],
    binary_name="jwt_tool",
    needs_binary=True,
    confidence=85
)
def run_jwt_scanner_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.23 Scanner: Katana
- **Step Name**: Running Katana
- **Binary Name**: `katana`
- **Requires Binary**: True
- **Base Confidence**: 90%
- **DAG Dependencies**: HTTPx
- **Execution Function**: `run_katana_scan`

```python
@register_scanner(
    name="Katana",
    step_name="Running Katana",
    depends_on=['HTTPx'],
    binary_name="katana",
    needs_binary=True,
    confidence=90
)
def run_katana_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.24 Scanner: Masscan
- **Step Name**: Running Masscan
- **Binary Name**: `masscan`
- **Requires Binary**: True
- **Base Confidence**: 95%
- **DAG Dependencies**: WPScan
- **Execution Function**: `run_masscan_scan`

```python
@register_scanner(
    name="Masscan",
    step_name="Running Masscan",
    depends_on=['WPScan'],
    binary_name="masscan",
    needs_binary=True,
    confidence=95
)
def run_masscan_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.25 Scanner: MobSF
- **Step Name**: Running Mobile Application Security Scan (MobSF)
- **Binary Name**: `python3`
- **Requires Binary**: False
- **Base Confidence**: 85%
- **DAG Dependencies**: None (In-Degree 0)
- **Execution Function**: `scan`

```python
@register_scanner(
    name="MobSF",
    step_name="Running Mobile Application Security Scan (MobSF)",
    depends_on=[],
    binary_name="python3",
    needs_binary=False,
    confidence=85
)
def scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.26 Scanner: Nikto
- **Step Name**: Running Nikto
- **Binary Name**: `nikto`
- **Requires Binary**: True
- **Base Confidence**: 90%
- **DAG Dependencies**: CMS Scanner
- **Execution Function**: `run_nikto_scan`

```python
@register_scanner(
    name="Nikto",
    step_name="Running Nikto",
    depends_on=['CMS Scanner'],
    binary_name="nikto",
    needs_binary=True,
    confidence=90
)
def run_nikto_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.27 Scanner: Nmap
- **Step Name**: Running Nmap
- **Binary Name**: `nmap`
- **Requires Binary**: True
- **Base Confidence**: 95%
- **DAG Dependencies**: Traceroute
- **Execution Function**: `run_nmap_scan`

```python
@register_scanner(
    name="Nmap",
    step_name="Running Nmap",
    depends_on=['Traceroute'],
    binary_name="nmap",
    needs_binary=True,
    confidence=95
)
def run_nmap_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.28 Scanner: Nuclei
- **Step Name**: Running Nuclei
- **Binary Name**: `nuclei`
- **Requires Binary**: True
- **Base Confidence**: 95%
- **DAG Dependencies**: Nikto
- **Execution Function**: `run_nuclei_scan`

```python
@register_scanner(
    name="Nuclei",
    step_name="Running Nuclei",
    depends_on=['Nikto'],
    binary_name="nuclei",
    needs_binary=True,
    confidence=95
)
def run_nuclei_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.29 Scanner: Open Redirect
- **Step Name**: Running Open Redirect
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 90%
- **DAG Dependencies**: ffuf
- **Execution Function**: `run_open_redirect_scan`

```python
@register_scanner(
    name="Open Redirect",
    step_name="Running Open Redirect",
    depends_on=['ffuf'],
    binary_name="",
    needs_binary=False,
    confidence=90
)
def run_open_redirect_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.30 Scanner: ParamSpider
- **Step Name**: Running ParamSpider
- **Binary Name**: `paramspider`
- **Requires Binary**: True
- **Base Confidence**: 85%
- **DAG Dependencies**: Masscan
- **Execution Function**: `run_paramspider_scan`

```python
@register_scanner(
    name="ParamSpider",
    step_name="Running ParamSpider",
    depends_on=['Masscan'],
    binary_name="paramspider",
    needs_binary=True,
    confidence=85
)
def run_paramspider_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.31 Scanner: Path Traversal Scanner
- **Step Name**: Running Path Traversal Scanner
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 85%
- **DAG Dependencies**: Tech Fingerprint
- **Execution Function**: `run_path_traversal`

```python
@register_scanner(
    name="Path Traversal Scanner",
    step_name="Running Path Traversal Scanner",
    depends_on=['Tech Fingerprint'],
    binary_name="",
    needs_binary=False,
    confidence=85
)
def run_path_traversal(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.32 Scanner: Prowler
- **Step Name**: Running Cloud Security Audit (Prowler)
- **Binary Name**: `prowler`
- **Requires Binary**: True
- **Base Confidence**: 90%
- **DAG Dependencies**: None (In-Degree 0)
- **Execution Function**: `scan`

```python
@register_scanner(
    name="Prowler",
    step_name="Running Cloud Security Audit (Prowler)",
    depends_on=[],
    binary_name="prowler",
    needs_binary=True,
    confidence=90
)
def scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.33 Scanner: Retire.js Scanner
- **Step Name**: Running Retire.js Scanner
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 80%
- **DAG Dependencies**: Tech Fingerprint
- **Execution Function**: `run_retire_js_scan`

```python
@register_scanner(
    name="Retire.js Scanner",
    step_name="Running Retire.js Scanner",
    depends_on=['Tech Fingerprint'],
    binary_name="",
    needs_binary=False,
    confidence=80
)
def run_retire_js_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.34 Scanner: Robots.txt
- **Step Name**: Running Robots.txt
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 95%
- **DAG Dependencies**: Security Headers
- **Execution Function**: `run_robots_scan`

```python
@register_scanner(
    name="Robots.txt",
    step_name="Running Robots.txt",
    depends_on=['Security Headers'],
    binary_name="",
    needs_binary=False,
    confidence=95
)
def run_robots_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.37 Scanner: SQLMap
- **Step Name**: Running SQLMap
- **Binary Name**: `sqlmap`
- **Requires Binary**: True
- **Base Confidence**: 95%
- **DAG Dependencies**: Wapiti
- **Execution Function**: `run_sqlmap_scan`

```python
@register_scanner(
    name="SQLMap",
    step_name="Running SQLMap",
    depends_on=['Wapiti'],
    binary_name="sqlmap",
    needs_binary=True,
    confidence=95
)
def run_sqlmap_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.38 Scanner: SSL
- **Step Name**: Running SSL Scan
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 95%
- **DAG Dependencies**: Nmap
- **Execution Function**: `run_ssl_scan`

```python
@register_scanner(
    name="SSL",
    step_name="Running SSL Scan",
    depends_on=['Nmap'],
    binary_name="",
    needs_binary=False,
    confidence=95
)
def run_ssl_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.39 Scanner: SSRF Scanner
- **Step Name**: Running SSRF Scanner
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 85%
- **DAG Dependencies**: Tech Fingerprint
- **Execution Function**: `run_ssrf_scan`

```python
@register_scanner(
    name="SSRF Scanner",
    step_name="Running SSRF Scanner",
    depends_on=['Tech Fingerprint'],
    binary_name="",
    needs_binary=False,
    confidence=85
)
def run_ssrf_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.19 Scanner: Security Headers
- **Step Name**: Running Security Headers
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 95%
- **DAG Dependencies**: SSL
- **Execution Function**: `run_headers_scan`

```python
@register_scanner(
    name="Security Headers",
    step_name="Running Security Headers",
    depends_on=['SSL'],
    binary_name="",
    needs_binary=False,
    confidence=95
)
def run_headers_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.35 Scanner: Shodan
- **Step Name**: Running Shodan
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 90%
- **DAG Dependencies**: SQLMap
- **Execution Function**: `run_shodan_idb_scan`

```python
@register_scanner(
    name="Shodan",
    step_name="Running Shodan",
    depends_on=['SQLMap'],
    binary_name="",
    needs_binary=False,
    confidence=90
)
def run_shodan_idb_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.40 Scanner: Subfinder
- **Step Name**: Running Subfinder
- **Binary Name**: `subfinder`
- **Requires Binary**: True
- **Base Confidence**: 90%
- **DAG Dependencies**: None (In-Degree 0)
- **Execution Function**: `run_subfinder_scan`

```python
@register_scanner(
    name="Subfinder",
    step_name="Running Subfinder",
    depends_on=[],
    binary_name="subfinder",
    needs_binary=True,
    confidence=90
)
def run_subfinder_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.41 Scanner: Tech Fingerprint
- **Step Name**: Running Tech Fingerprint
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 85%
- **DAG Dependencies**: Open Redirect
- **Execution Function**: `run_tech_fingerprint`

```python
@register_scanner(
    name="Tech Fingerprint",
    step_name="Running Tech Fingerprint",
    depends_on=['Open Redirect'],
    binary_name="",
    needs_binary=False,
    confidence=85
)
def run_tech_fingerprint(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.43 Scanner: Traceroute
- **Step Name**: Running Traceroute
- **Binary Name**: `traceroute`
- **Requires Binary**: True
- **Base Confidence**: 90%
- **DAG Dependencies**: Wayback Machine
- **Execution Function**: `run_traceroute`

```python
@register_scanner(
    name="Traceroute",
    step_name="Running Traceroute",
    depends_on=['Wayback Machine'],
    binary_name="traceroute",
    needs_binary=True,
    confidence=90
)
def run_traceroute(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.44 Scanner: Trivy
- **Step Name**: Running Container/FS Scan (Trivy)
- **Binary Name**: `trivy`
- **Requires Binary**: True
- **Base Confidence**: 95%
- **DAG Dependencies**: None (In-Degree 0)
- **Execution Function**: `scan`

```python
@register_scanner(
    name="Trivy",
    step_name="Running Container/FS Scan (Trivy)",
    depends_on=[],
    binary_name="trivy",
    needs_binary=True,
    confidence=95
)
def scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.49 Scanner: WPScan
- **Step Name**: Running WPScan
- **Binary Name**: `wpscan`
- **Requires Binary**: True
- **Base Confidence**: 90%
- **DAG Dependencies**: JWT Scanner
- **Execution Function**: `run_wpscan_scan`

```python
@register_scanner(
    name="WPScan",
    step_name="Running WPScan",
    depends_on=['JWT Scanner'],
    binary_name="wpscan",
    needs_binary=True,
    confidence=90
)
def run_wpscan_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.45 Scanner: Wapiti
- **Step Name**: Running Wapiti
- **Binary Name**: `wapiti`
- **Requires Binary**: True
- **Base Confidence**: 90%
- **DAG Dependencies**: Tech Fingerprint
- **Execution Function**: `run_wapiti_scan`

```python
@register_scanner(
    name="Wapiti",
    step_name="Running Wapiti",
    depends_on=['Tech Fingerprint'],
    binary_name="wapiti",
    needs_binary=True,
    confidence=90
)
def run_wapiti_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.46 Scanner: Wayback Machine
- **Step Name**: Running Wayback Machine
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 80%
- **DAG Dependencies**: Whois
- **Execution Function**: `run_wayback_scan`

```python
@register_scanner(
    name="Wayback Machine",
    step_name="Running Wayback Machine",
    depends_on=['Whois'],
    binary_name="",
    needs_binary=False,
    confidence=80
)
def run_wayback_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.47 Scanner: WhatWeb
- **Step Name**: Running WhatWeb
- **Binary Name**: `whatweb`
- **Requires Binary**: True
- **Base Confidence**: 85%
- **DAG Dependencies**: HTTPx
- **Execution Function**: `run_whatweb_scan`

```python
@register_scanner(
    name="WhatWeb",
    step_name="Running WhatWeb",
    depends_on=['HTTPx'],
    binary_name="whatweb",
    needs_binary=True,
    confidence=85
)
def run_whatweb_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.48 Scanner: Whois
- **Step Name**: Running Whois
- **Binary Name**: `whois`
- **Requires Binary**: True
- **Base Confidence**: 95%
- **DAG Dependencies**: HackerTarget
- **Execution Function**: `run_whois_scan`

```python
@register_scanner(
    name="Whois",
    step_name="Running Whois",
    depends_on=['HackerTarget'],
    binary_name="whois",
    needs_binary=True,
    confidence=95
)
def run_whois_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.50 Scanner: XXE Scanner
- **Step Name**: Running XXE Scanner
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 85%
- **DAG Dependencies**: Tech Fingerprint
- **Execution Function**: `run_xxe_scan`

```python
@register_scanner(
    name="XXE Scanner",
    step_name="Running XXE Scanner",
    depends_on=['Tech Fingerprint'],
    binary_name="",
    needs_binary=False,
    confidence=85
)
def run_xxe_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.51 Scanner: ZAP
- **Step Name**: Running ZAP
- **Binary Name**: `zap`
- **Requires Binary**: False
- **Base Confidence**: 85%
- **DAG Dependencies**: Cloud Enum
- **Execution Function**: `run_zap_scan`

```python
@register_scanner(
    name="ZAP",
    step_name="Running ZAP",
    depends_on=['Cloud Enum'],
    binary_name="zap",
    needs_binary=False,
    confidence=85
)
def run_zap_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.15 Scanner: ffuf
- **Step Name**: Running ffuf
- **Binary Name**: `ffuf`
- **Requires Binary**: True
- **Base Confidence**: 90%
- **DAG Dependencies**: Nuclei
- **Execution Function**: `run_ffuf_scan`

```python
@register_scanner(
    name="ffuf",
    step_name="Running ffuf",
    depends_on=['Nuclei'],
    binary_name="ffuf",
    needs_binary=True,
    confidence=90
)
def run_ffuf_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

## 6.42 Scanner: theHarvester
- **Step Name**: Running theHarvester
- **Binary Name**: ``
- **Requires Binary**: False
- **Base Confidence**: 80%
- **DAG Dependencies**: Subfinder
- **Execution Function**: `run_theharvester_scan`

```python
@register_scanner(
    name="theHarvester",
    step_name="Running theHarvester",
    depends_on=['Subfinder'],
    binary_name="",
    needs_binary=False,
    confidence=80
)
def run_theharvester_scan(target_url: str, scan_id: int, settings: dict):
    # Subprocess isolation wrapper
    # Output parsing logic
    pass
```

