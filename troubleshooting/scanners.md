# 🔬 Scanners & DAG Engine Troubleshooting — V9.5

This guide provides technical diagnosis and resolutions for scanner plugins, dependency injection, and DAG scheduling.

---

## Error Codes Covered

| Code | Slug | Issue Description |
|---|---|---|
| `SMP-2001` | `scanner_timeout` | Scanner exceeded maximum execution time |
| `SMP-2002` | `scanner_binary_missing` | Required security binary not found |
| `SMP-2003` | `scanner_crashed` | Scanner subprocess crashed (segfault / OOM) |
| `SMP-2004` | `scanner_output_parse_error` | Observation parser failed to decode output |
| `SMP-2005` | `dag_cycle_detected` | Scanner dependency graph contains cycle |
| `SMP-2006` | `invalid_state_transition` | Scanner attempted illegal state transition |
| `SMP-2008` | `missing_dependency_tool` | Upstream parent scanner dependency failed |
| `SMP-4040` | `exploit_timeout` | Interactive shell or exploit framework stalled |
| `SMP-4042` | `port_collision` | Local port collision on privileged binding |

---

## Common Scenarios & Resolutions

### Scenario 1: Nmap Requires Root Privileges for SYN Scanning (`-sS`)

**Symptom:** Nmap fails with `You requested a scan type which requires root privileges. QUITTING!`.

**Root Cause:** Running standard/full scans without Linux raw socket capabilities granted to the `nmap` binary.

**Copy-Paste Solution:**
```bash
# Grant raw network capabilities to Nmap without requiring full sudo
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Verify capabilities
getcap $(which nmap)
```

---

### Scenario 2: DAG Dependency Cycle Detected (`SMP-2005`)

**Symptom:** Scan planner fails during startup with `SMP-2005: Scanner dependency graph contains circular dependency`.

**Root Cause:** Two scanner plugins declared mutually recursive dependencies in their manifests.

**Copy-Paste Solution:**
```bash
# Validate and print DAG topological order
python3 -c "
from scanners.core.dag import DAGOrchestrator
orchestrator = DAGOrchestrator()
try:
    orchestrator.validate_dag()
    print('DAG is valid and acyclic.')
except Exception as e:
    print('Cycle detected involving scanners:', e)
"
```

---

### Scenario 3: Responder Port 53 Collision (`SMP-4042`)

**Symptom:** Responder crashes immediately with `[!] Error starting TCP/UDP server on port 53: [Errno 98] Address already in use`.

**Root Cause:** Local caching DNS resolver (`systemd-resolved` or `dnsmasq`) is bound to UDP port 53.

**Copy-Paste Solution:**
```bash
# Option A: Temporarily stop systemd-resolved for the duration of LLMNR/NBT-NS testing
sudo systemctl stop systemd-resolved

# Option B: Rebind systemd-resolved to 127.0.0.53 without intercepting 0.0.0.0
sudo sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
```

---

### Scenario 4: Nuclei Community Templates Outdated or Corrupted

**Symptom:** Nuclei scan produces zero findings or emits `[ERR] Could not load templates`.

**Root Cause:** Nuclei template cache in `~/.local/nuclei-templates` is empty, corrupted, or incompatible with installed Nuclei version. Note that Nuclei is a pre-compiled binary located at `bin/nuclei`.

**Copy-Paste Solution:**
```bash
# Force fresh update of official Nuclei templates using the local binary
bin/nuclei -update-templates -force

# Verify template syntax
bin/nuclei -validate
```

---

### Scenario 5: FFUF Directory Fuzzing Out-of-Memory / High False Positives

**Symptom:** FFUF process killed with `OOMKilled` (Exit code 137) or returns thousands of false 200 OK responses.

**Root Cause:** Target returns generic 200 OK for custom 404 pages (soft 404), or concurrency `-t` is set too high for available RAM.

**Copy-Paste Solution:**
```bash
# Configure automatic calibration and filter size in scanner profile
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u http://target.internal/FUZZ \
  -ac \
  -t 20 \
  -p 0.1 \
  -o work/ffuf_out.json -of json
```

---

### Scenario 6: Metasploit / SQLMap Interactive Shell Hang (`SMP-4040`)

**Symptom:** Exploitation phase hangs indefinitely at 99% CPU or blocks DAG progression.

**Root Cause:** Tool dropped into interactive console prompt waiting for terminal stdin.

**Copy-Paste Solution:**
Ensure all offensive tools are executed with non-interactive batch flags:
- **SQLMap:** `--batch --non-interactive`
- **Metasploit:** `msfconsole -q -x "..."`
- **Hydra:** `-I` (ignore unrecoverable connection drops)

```bash
# Test SQLMap non-interactive execution
sqlmap -u "http://target.internal/api?id=1" --batch --smart --random-agent
```
