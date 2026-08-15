# 📦 Installation & Runtime Troubleshooting — V9.5

This guide provides technical diagnosis and resolutions for operating system dependencies, Python virtual environments, PySide6 GUI platform plugins (XCB/Wayland), and compiler toolchains.

---

## Error Codes Covered

| Code | Slug | Issue Description |
|---|---|---|
| `SMP-2002` | `scanner_binary_missing` | Required security binary not installed or not in PATH |
| `SMP-3001` | `db_connection_error` | `pysqlcipher3` C-extension missing or build failure |
| `SMP-4041` | `binary_incompatibility` | Native binary architecture mismatch (x86_64 vs arm64) |
| `SMP-5001` | `config_missing` | Missing configuration templates or environment variables |
| `SMP-9001` | `network_route_failure` | Pre-flight network reachability check failed |
| `SMP-9002` | `dpkg_lock` | DPKG/APT locked by another process |
| `SMP-9003` | `python_env_lock` | Python virtual environment lock |
| `SMP-9004` | `binary_download_failure` | Tool binary download failed |
| `SMP-9005` | `checksum_mismatch` | SHA-256 checksum mismatch / partial download |

---

## Common Scenarios & Resolutions

### Scenario 1: PySide6 GUI Fails to Launch (`Qt platform plugin "xcb" missing`)

**Symptom:** Running `./run.sh` fails with:
`qt.qpa.plugin: Could not load the Qt platform plugin "xcb" in "" even though it was found.`

**Root Cause:** Missing X11/XCB display server libraries on Debian/Ubuntu/Kali systems.

**Copy-Paste Solution:**
```bash
# Install required Qt6 XCB platform dependencies
sudo apt-get update
sudo apt-get install -y \
  libxcb-cursor0 \
  libxcb-xinerama0 \
  libxcb-icccm4 \
  libxcb-image0 \
  libxcb-keysyms1 \
  libxcb-render-util0 \
  libxcb-shape0 \
  libxkbcommon-x11-0 \
  libgl1-mesa-glx

# Force XCB platform backend if on Wayland
export QT_QPA_PLATFORM=xcb
./run.sh
```

---

### Scenario 2: `pysqlcipher3` Compilation Fails during `pip install`

**Symptom:** `pip install -r requirements.txt` fails building wheel for `pysqlcipher3` with `sqlcipher/sqlite3.h: No such file or directory`.

**Root Cause:** SQLCipher C header files (`libsqlcipher-dev`) are absent.

**Copy-Paste Solution:**
```bash
# Install SQLCipher development libraries and compilers
sudo apt-get install -y libsqlcipher-dev libsqlcipher0 build-essential python3-dev

# Rebuild in venv
source venv/bin/activate
pip install --no-cache-dir pysqlcipher3
```

---

### Scenario 3: Golang Security Tools Missing from PATH

**Symptom:** Scanners such as `subfinder`, `httpx`, `ffuf`, or `dalfox` fail with `SMP-2002: Required security tool binary missing`.

**Root Cause:** Go binaries installed to `~/go/bin` or project-local `bin/` are not exported in the system `$PATH`.

**Copy-Paste Solution:**
```bash
# 1. Export Go paths into current shell and profile
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:$(pwd)/bin
echo 'export PATH=$PATH:$HOME/go/bin:$(pwd)/bin' >> ~/.bashrc

# 2. Re-run automated self-healing to install missing tools
python3 tools/troubleshoot.py --fix
```

---

### Scenario 4: Node.js Tools Missing (`wscat`, `ppmap`)

**Symptom:** WebSocket or prototype pollution scanners report binary not found.

**Root Cause:** Node.js package manager global path is not in environment.

**Copy-Paste Solution:**
```bash
# Install Node.js 18+ and npm
sudo apt-get install -y nodejs npm

# Install required tools globally
sudo npm install -g wscat ppmap

# Verify installation
which wscat && which ppmap
```

---

### Scenario 5: Native Architecture Incompatibility on ARM64 / Apple Silicon (`SMP-4041`)

**Symptom:** Scanner execution returns `Exec format error` or `SMP-4041: binary_incompatibility`.

**Root Cause:** An x86_64 precompiled binary was downloaded on an ARM64 (aarch64) system.

**Copy-Paste Solution:**
```bash
# Force native recompilation using Go on host architecture
export GOARCH=$(dpkg --print-architecture | sed 's/arm64/arm64/' | sed 's/amd64/amd64/')
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest

# Copy newly compiled binaries into project bin/
cp $HOME/go/bin/* bin/
```

---

### Scenario 6: Docker Container Network Capabilities (`CAP_NET_RAW`)

**Symptom:** Nmap or network probes fail inside Docker container with `socket: Operation not permitted`.

**Root Cause:** Container lacks Linux raw socket capabilities required for SYN scanning (`-sS`) or OS detection (`-O`).

**Copy-Paste Solution:**
Launch Docker with `cap_add: [NET_RAW, NET_ADMIN]` in `docker-compose.yml`:

```yaml
services:
  smp:
    image: smp:v9.5
    cap_add:
      - NET_RAW
      - NET_ADMIN
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./database:/app/database
```
```bash
docker compose up -d
```

---

### Scenario 7: Network Route Pre-Flight Failure (`SMP-9001`)

**Symptom:** Installation stops during pre-flight checks with `SMP-9001: network_route_failure`.

**Root Cause:** The `verify_network_routes()` function failed to probe `github.com`, `raw.githubusercontent.com`, `pypi.org`, or `go.dev`.

**Copy-Paste Solution:**
```bash
# Verify your proxy and firewall settings allowing outbound HTTPS to these domains
export HTTP_PROXY="http://your-proxy:8080"
export HTTPS_PROXY="http://your-proxy:8080"
python3 tools/troubleshoot.py --fix
```

---

### Scenario 8: Binary Download Integrity Failure (`SMP-9005`)

**Symptom:** Setup fails stating a downloaded file has a SHA-256 mismatch.

**Root Cause:** The binary download was partial or corrupted during transit.

**Copy-Paste Solution:**
```bash
# The setup process is idempotent. Simply re-run the installer and it will resume/retry.
./setup.sh
```
