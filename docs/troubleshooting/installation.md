# 🔧 Installation Troubleshooting — SMP V7

## pysqlcipher3 fails to install

SMP V7 will not start without SQLCipher. This is a hard requirement.

```bash
# Step 1: system library
sudo apt install libsqlcipher-dev libsqlcipher0 build-essential python3-dev

# Step 2: pip
source venv/bin/activate
pip install pysqlcipher3

# Step 3: verify
python3 -c "from pysqlcipher3 import dbapi2; print('SQLCipher OK')"
```

If pip fails with `_sqlite3.h not found`:
```bash
sudo apt install libsqlite3-dev
pip install pysqlcipher3 --no-binary pysqlcipher3
```

---

## setup.sh binary download failed

The prebuilt binary `curl` download failed (network issue or GitHub rate limit).

**What happens:** setup.sh falls back to `go install` (compiles from source, ~5 min per tool).

**Fix for fast path:**
```bash
# Wait for GitHub rate limit to clear, then re-run
./setup.sh
# Already-installed tools are skipped (command -v guard)
```

**Manual binary install:**
```bash
# Example: nuclei v3.3.7 AMD64
curl -fsSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip \
  -o /tmp/nuclei.zip
unzip /tmp/nuclei.zip -d bin/
chmod +x bin/nuclei
```

---

## Go not found after installation

```bash
# If Go was installed to /usr/local/go by setup.sh
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

---

## Python venv not activating

```bash
# If venv creation failed, recreate it
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pysqlcipher3
```

---

## WPScan Docker wrapper not created

setup.sh creates the Docker wrapper at `bin/wpscan` only if Docker is available and `gem install wpscan` failed.

```bash
# Check Docker
docker --version

# Create wrapper manually
mkdir -p bin
cat > bin/wpscan << 'EOF'
#!/usr/bin/env bash
exec docker run --rm --network=host wpscanteam/wpscan "$@"
EOF
chmod +x bin/wpscan
docker pull wpscanteam/wpscan
```

---

## Permission denied on setup.sh

```bash
chmod +x setup.sh
./setup.sh
```

---

## apt packages not installing (non-root)

```bash
# setup.sh uses sudo internally — ensure sudo is configured
sudo echo "sudo works"

# If in a container without sudo
apt-get update && apt-get install -y libsqlcipher-dev libsqlcipher0 nmap
```
