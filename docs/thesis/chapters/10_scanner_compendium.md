# Appendix A: Comprehensive Scanner Compendium

This appendix provides an exhaustive technical breakdown of every security scanner integrated into the Security Management Platform. The data presented herein is mathematically derived directly from the runtime registration metadata within the `scanners/` directory.

\newpage

## Amass (`amass.py`)

**Execution Step**: Running Amass  
**Underlying Binary**: `amass`  
**DAG Dependencies**: `[Subfinder]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `amass.py` module serves as the primary execution wrapper for the `Amass` tool. Because this tool relies on `Subfinder`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `amass` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Amass` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## API Fuzzer (`api_fuzzer.py`)

**Execution Step**: Running API Fuzzer  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Katana]`  
**Baseline Confidence Score**: 80/100  

### Architectural Description
The `api_fuzzer.py` module serves as the primary execution wrapper for the `API Fuzzer` tool. Because this tool relies on `Katana`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `API Fuzzer` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 80.

---

\newpage

## Arjun (`arjun.py`)

**Execution Step**: Running Arjun  
**Underlying Binary**: `arjun`  
**DAG Dependencies**: `[Dalfox]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `arjun.py` module serves as the primary execution wrapper for the `Arjun` tool. Because this tool relies on `Dalfox`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `arjun` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Arjun` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## Cloud Enum (`cloud_enum.py`)

**Execution Step**: Running Cloud Enum  
**Underlying Binary**: `cloud_enum`  
**DAG Dependencies**: `[ParamSpider]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `cloud_enum.py` module serves as the primary execution wrapper for the `Cloud Enum` tool. Because this tool relies on `ParamSpider`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `cloud_enum` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Cloud Enum` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## CMS Scanner (`cms_scanner.py`)

**Execution Step**: Running CMS Scanner  
**Underlying Binary**: ``  
**DAG Dependencies**: `[CORS]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `cms_scanner.py` module serves as the primary execution wrapper for the `CMS Scanner` tool. Because this tool relies on `CORS`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `CMS Scanner` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## Commix (`commix.py`)

**Execution Step**: Running Commix  
**Underlying Binary**: `commix`  
**DAG Dependencies**: `[Katana]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `commix.py` module serves as the primary execution wrapper for the `Commix` tool. Because this tool relies on `Katana`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `commix` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Commix` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## CORS (`cors_scanner.py`)

**Execution Step**: Running CORS  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Robots.txt]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `cors_scanner.py` module serves as the primary execution wrapper for the `CORS` tool. Because this tool relies on `Robots.txt`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `CORS` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## CRLF Scanner (`crlf_scanner.py`)

**Execution Step**: Running CRLF Scanner  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Tech Fingerprint]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `crlf_scanner.py` module serves as the primary execution wrapper for the `CRLF Scanner` tool. Because this tool relies on `Tech Fingerprint`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `CRLF Scanner` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## CRT.sh (`crtsh.py`)

**Execution Step**: Running CRT.sh  
**Underlying Binary**: ``  
**DAG Dependencies**: `[theHarvester]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `crtsh.py` module serves as the primary execution wrapper for the `CRT.sh` tool. Because this tool relies on `theHarvester`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `CRT.sh` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## Dalfox (`dalfox.py`)

**Execution Step**: Running Dalfox  
**Underlying Binary**: `dalfox`  
**DAG Dependencies**: `[Gitleaks]`  
**Baseline Confidence Score**: 90/100  

### Architectural Description
The `dalfox.py` module serves as the primary execution wrapper for the `Dalfox` tool. Because this tool relies on `Gitleaks`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `dalfox` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Dalfox` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 90.

---

\newpage

## DNSx (`dnsx.py`)

**Execution Step**: Running DNSx  
**Underlying Binary**: `dnsx`  
**DAG Dependencies**: `[Subfinder]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `dnsx.py` module serves as the primary execution wrapper for the `DNSx` tool. Because this tool relies on `Subfinder`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `dnsx` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `DNSx` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## Feroxbuster (`feroxbuster.py`)

**Execution Step**: Running Feroxbuster  
**Underlying Binary**: `feroxbuster`  
**DAG Dependencies**: `[Katana]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `feroxbuster.py` module serves as the primary execution wrapper for the `Feroxbuster` tool. Because this tool relies on `Katana`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `feroxbuster` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Feroxbuster` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## ffuf (`ffuf.py`)

**Execution Step**: Running ffuf  
**Underlying Binary**: `ffuf`  
**DAG Dependencies**: `[Nuclei]`  
**Baseline Confidence Score**: 90/100  

### Architectural Description
The `ffuf.py` module serves as the primary execution wrapper for the `ffuf` tool. Because this tool relies on `Nuclei`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `ffuf` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `ffuf` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 90.

---

\newpage

## Gitleaks (`gitleaks.py`)

**Execution Step**: Running Gitleaks  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Shodan]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `gitleaks.py` module serves as the primary execution wrapper for the `Gitleaks` tool. Because this tool relies on `Shodan`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Gitleaks` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## GraphQL Scanner (`graphql_scanner.py`)

**Execution Step**: Running GraphQL Scanner  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Katana]`  
**Baseline Confidence Score**: 80/100  

### Architectural Description
The `graphql_scanner.py` module serves as the primary execution wrapper for the `GraphQL Scanner` tool. Because this tool relies on `Katana`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `GraphQL Scanner` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 80.

---

\newpage

## HackerTarget (`hackertarget.py`)

**Execution Step**: Running HackerTarget  
**Underlying Binary**: ``  
**DAG Dependencies**: `[CRT.sh]`  
**Baseline Confidence Score**: 90/100  

### Architectural Description
The `hackertarget.py` module serves as the primary execution wrapper for the `HackerTarget` tool. Because this tool relies on `CRT.sh`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `HackerTarget` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 90.

---

\newpage

## Security Headers (`headers_scanner.py`)

**Execution Step**: Running Security Headers  
**Underlying Binary**: ``  
**DAG Dependencies**: `[SSL]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `headers_scanner.py` module serves as the primary execution wrapper for the `Security Headers` tool. Because this tool relies on `SSL`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Security Headers` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## HTTPx (`httpx_scanner.py`)

**Execution Step**: Running HTTPx  
**Underlying Binary**: `httpx`  
**DAG Dependencies**: `[]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `httpx_scanner.py` module serves as the primary execution wrapper for the `HTTPx` tool. Because this tool relies on ``, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `httpx` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `HTTPx` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## Auth Brute-Force Test (`hydra_scanner.py`)

**Execution Step**: Running Auth Brute-Force Test  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Tech Fingerprint]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `hydra_scanner.py` module serves as the primary execution wrapper for the `Auth Brute-Force Test` tool. Because this tool relies on `Tech Fingerprint`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Auth Brute-Force Test` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## JWT Scanner (`jwt_scanner.py`)

**Execution Step**: Running JWT Scanner  
**Underlying Binary**: `jwt_tool`  
**DAG Dependencies**: `[Commix]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `jwt_scanner.py` module serves as the primary execution wrapper for the `JWT Scanner` tool. Because this tool relies on `Commix`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `jwt_tool` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `JWT Scanner` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## Katana (`katana.py`)

**Execution Step**: Running Katana  
**Underlying Binary**: `katana`  
**DAG Dependencies**: `[HTTPx]`  
**Baseline Confidence Score**: 90/100  

### Architectural Description
The `katana.py` module serves as the primary execution wrapper for the `Katana` tool. Because this tool relies on `HTTPx`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `katana` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Katana` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 90.

---

\newpage

## Masscan (`masscan.py`)

**Execution Step**: Running Masscan  
**Underlying Binary**: `masscan`  
**DAG Dependencies**: `[WPScan]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `masscan.py` module serves as the primary execution wrapper for the `Masscan` tool. Because this tool relies on `WPScan`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `masscan` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Masscan` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## Nikto (`nikto.py`)

**Execution Step**: Running Nikto  
**Underlying Binary**: `nikto`  
**DAG Dependencies**: `[CMS Scanner]`  
**Baseline Confidence Score**: 90/100  

### Architectural Description
The `nikto.py` module serves as the primary execution wrapper for the `Nikto` tool. Because this tool relies on `CMS Scanner`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `nikto` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Nikto` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 90.

---

\newpage

## Nmap (`nmap.py`)

**Execution Step**: Running Nmap  
**Underlying Binary**: `nmap`  
**DAG Dependencies**: `[Traceroute]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `nmap.py` module serves as the primary execution wrapper for the `Nmap` tool. Because this tool relies on `Traceroute`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `nmap` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Nmap` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## Nuclei (`nuclei.py`)

**Execution Step**: Running Nuclei  
**Underlying Binary**: `nuclei`  
**DAG Dependencies**: `[Nikto]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `nuclei.py` module serves as the primary execution wrapper for the `Nuclei` tool. Because this tool relies on `Nikto`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `nuclei` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Nuclei` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## Open Redirect (`open_redirect.py`)

**Execution Step**: Running Open Redirect  
**Underlying Binary**: ``  
**DAG Dependencies**: `[ffuf]`  
**Baseline Confidence Score**: 90/100  

### Architectural Description
The `open_redirect.py` module serves as the primary execution wrapper for the `Open Redirect` tool. Because this tool relies on `ffuf`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Open Redirect` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 90.

---

\newpage

## ParamSpider (`paramspider.py`)

**Execution Step**: Running ParamSpider  
**Underlying Binary**: `paramspider`  
**DAG Dependencies**: `[Masscan]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `paramspider.py` module serves as the primary execution wrapper for the `ParamSpider` tool. Because this tool relies on `Masscan`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `paramspider` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `ParamSpider` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## Path Traversal Scanner (`path_traversal.py`)

**Execution Step**: Running Path Traversal Scanner  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Tech Fingerprint]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `path_traversal.py` module serves as the primary execution wrapper for the `Path Traversal Scanner` tool. Because this tool relies on `Tech Fingerprint`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Path Traversal Scanner` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## Retire.js Scanner (`retire_js.py`)

**Execution Step**: Running Retire.js Scanner  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Tech Fingerprint]`  
**Baseline Confidence Score**: 80/100  

### Architectural Description
The `retire_js.py` module serves as the primary execution wrapper for the `Retire.js Scanner` tool. Because this tool relies on `Tech Fingerprint`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Retire.js Scanner` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 80.

---

\newpage

## Robots.txt (`robots_scanner.py`)

**Execution Step**: Running Robots.txt  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Security Headers]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `robots_scanner.py` module serves as the primary execution wrapper for the `Robots.txt` tool. Because this tool relies on `Security Headers`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Robots.txt` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## Shodan (`shodan_idb.py`)

**Execution Step**: Running Shodan  
**Underlying Binary**: ``  
**DAG Dependencies**: `[SQLMap]`  
**Baseline Confidence Score**: 90/100  

### Architectural Description
The `shodan_idb.py` module serves as the primary execution wrapper for the `Shodan` tool. Because this tool relies on `SQLMap`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Shodan` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 90.

---

\newpage

## HTTP Smuggling Scanner (`smuggler.py`)

**Execution Step**: Running HTTP Smuggling Scanner  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Nmap]`  
**Baseline Confidence Score**: 80/100  

### Architectural Description
The `smuggler.py` module serves as the primary execution wrapper for the `HTTP Smuggling Scanner` tool. Because this tool relies on `Nmap`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `HTTP Smuggling Scanner` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 80.

---

\newpage

## SQLMap (`sqlmap.py`)

**Execution Step**: Running SQLMap  
**Underlying Binary**: `sqlmap`  
**DAG Dependencies**: `[Wapiti]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `sqlmap.py` module serves as the primary execution wrapper for the `SQLMap` tool. Because this tool relies on `Wapiti`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `sqlmap` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `SQLMap` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## SSL (`ssl_scanner.py`)

**Execution Step**: Running SSL Scan  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Nmap]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `ssl_scanner.py` module serves as the primary execution wrapper for the `SSL` tool. Because this tool relies on `Nmap`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `SSL` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## SSRF Scanner (`ssrf_scanner.py`)

**Execution Step**: Running SSRF Scanner  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Tech Fingerprint]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `ssrf_scanner.py` module serves as the primary execution wrapper for the `SSRF Scanner` tool. Because this tool relies on `Tech Fingerprint`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `SSRF Scanner` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## Subfinder (`subfinder.py`)

**Execution Step**: Running Subfinder  
**Underlying Binary**: `subfinder`  
**DAG Dependencies**: `[]`  
**Baseline Confidence Score**: 90/100  

### Architectural Description
The `subfinder.py` module serves as the primary execution wrapper for the `Subfinder` tool. Because this tool relies on ``, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `subfinder` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Subfinder` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 90.

---

\newpage

## Tech Fingerprint (`tech_fingerprint.py`)

**Execution Step**: Running Tech Fingerprint  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Open Redirect]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `tech_fingerprint.py` module serves as the primary execution wrapper for the `Tech Fingerprint` tool. Because this tool relies on `Open Redirect`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Tech Fingerprint` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## theHarvester (`theharvester.py`)

**Execution Step**: Running theHarvester  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Subfinder]`  
**Baseline Confidence Score**: 80/100  

### Architectural Description
The `theharvester.py` module serves as the primary execution wrapper for the `theHarvester` tool. Because this tool relies on `Subfinder`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `theHarvester` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 80.

---

\newpage

## Traceroute (`traceroute.py`)

**Execution Step**: Running Traceroute  
**Underlying Binary**: `traceroute`  
**DAG Dependencies**: `[Wayback Machine]`  
**Baseline Confidence Score**: 90/100  

### Architectural Description
The `traceroute.py` module serves as the primary execution wrapper for the `Traceroute` tool. Because this tool relies on `Wayback Machine`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `traceroute` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Traceroute` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 90.

---

\newpage

## Wapiti (`wapiti.py`)

**Execution Step**: Running Wapiti  
**Underlying Binary**: `wapiti`  
**DAG Dependencies**: `[Tech Fingerprint]`  
**Baseline Confidence Score**: 90/100  

### Architectural Description
The `wapiti.py` module serves as the primary execution wrapper for the `Wapiti` tool. Because this tool relies on `Tech Fingerprint`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `wapiti` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Wapiti` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 90.

---

\newpage

## Wayback Machine (`wayback.py`)

**Execution Step**: Running Wayback Machine  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Whois]`  
**Baseline Confidence Score**: 80/100  

### Architectural Description
The `wayback.py` module serves as the primary execution wrapper for the `Wayback Machine` tool. Because this tool relies on `Whois`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Wayback Machine` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 80.

---

\newpage

## WhatWeb (`whatweb.py`)

**Execution Step**: Running WhatWeb  
**Underlying Binary**: `whatweb`  
**DAG Dependencies**: `[HTTPx]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `whatweb.py` module serves as the primary execution wrapper for the `WhatWeb` tool. Because this tool relies on `HTTPx`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `whatweb` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `WhatWeb` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## Whois (`whois_scanner.py`)

**Execution Step**: Running Whois  
**Underlying Binary**: `whois`  
**DAG Dependencies**: `[HackerTarget]`  
**Baseline Confidence Score**: 95/100  

### Architectural Description
The `whois_scanner.py` module serves as the primary execution wrapper for the `Whois` tool. Because this tool relies on `HackerTarget`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `whois` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `Whois` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 95.

---

\newpage

## WPScan (`wpscan.py`)

**Execution Step**: Running WPScan  
**Underlying Binary**: `wpscan`  
**DAG Dependencies**: `[JWT Scanner]`  
**Baseline Confidence Score**: 90/100  

### Architectural Description
The `wpscan.py` module serves as the primary execution wrapper for the `WPScan` tool. Because this tool relies on `JWT Scanner`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `wpscan` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `WPScan` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 90.

---

\newpage

## XXE Scanner (`xxe_scanner.py`)

**Execution Step**: Running XXE Scanner  
**Underlying Binary**: ``  
**DAG Dependencies**: `[Tech Fingerprint]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `xxe_scanner.py` module serves as the primary execution wrapper for the `XXE Scanner` tool. Because this tool relies on `Tech Fingerprint`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `XXE Scanner` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

\newpage

## ZAP (`zap.py`)

**Execution Step**: Running ZAP  
**Underlying Binary**: `zap`  
**DAG Dependencies**: `[Cloud Enum]`  
**Baseline Confidence Score**: 85/100  

### Architectural Description
The `zap.py` module serves as the primary execution wrapper for the `ZAP` tool. Because this tool relies on `Cloud Enum`, the Kahn's Topological Sort algorithm explicitly prevents its execution until those dependencies successfully exit with a `0` status code. If `zap` is not present in the system `PATH` or the `bin/` directory, the orchestrator will automatically mark this node as `SKIPPED`.

### DAG Memory Profiling
Upon execution, the standard output of `ZAP` is intercepted by the `SubprocessWatchdog`. The execution thread calculates the delta between the start epoch and end epoch, updating the `dag_state` SQLite table in real-time. Results are piped into the Neural Brain matrix, weighted by the base confidence score of 85.

---

