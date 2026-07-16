#!/bin/bash
# SMP V6.0 - Auto Setup for Linux/macOS with Fallbacks
echo "🚀 Starting SMP V6.0 Auto-Setup for Linux/macOS..."

# Helper: Command runner with ONE fallback
run_cmd() {
    local cmd="$1"
    local fallback="$2"
    local msg="$3"
    echo "======================================"
    echo "🛠️  $msg"
    eval "$cmd"
    if [ $? -ne 0 ]; then
        if [ -n "$fallback" ]; then
            echo "⚠️  Primary failed. Falling back to redundancy..."
            eval "$fallback"
        else
            echo "❌ Failed to execute: $cmd"
        fi
    fi
}

echo "🛠️ 1. Installing System Dependencies..."

# --- 1. Python Backup ---
if ! command -v python3 &> /dev/null; then
    run_cmd "sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip python3-venv" \
            "wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O miniconda.sh && bash miniconda.sh -b -p $HOME/miniconda && export PATH=\"$HOME/miniconda/bin:$PATH\" && echo 'export PATH=\"$HOME/miniconda/bin:$PATH\"' >> ~/.bashrc" \
            "Installing Python"
fi

# --- 2. Go Backup ---
if ! command -v go &> /dev/null; then
    run_cmd "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y golang-go" \
            "wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz -O go.tar.gz && sudo tar -C /usr/local -xzf go.tar.gz && export PATH=$PATH:/usr/local/go/bin && echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc" \
            "Installing Go"
fi

# --- 3. OS Tools Backup ---
run_cmd "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y nmap whatweb nikto sqlmap traceroute masscan wapiti ruby ruby-dev build-essential perl git" \
        "mkdir -p ~/smp_tools && cd ~/smp_tools && git clone --depth 1 https://github.com/sullo/nikto.git && sudo ln -sf \$(pwd)/nikto/program/nikto.pl /usr/local/bin/nikto && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev && sudo ln -sf \$(pwd)/sqlmap-dev/sqlmap.py /usr/local/bin/sqlmap && cd - >/dev/null" \
        "Installing OS Tools (Nmap, Nikto, SQLMap, Ruby, Git...)"

# --- 3.5 Manual Tools Setup (WPScan, SpiderFoot) ---
run_cmd "sudo gem install wpscan --no-user-install" "echo 'gem install failed'" "Installing WPScan via Ruby Gem"
run_cmd "mkdir -p bin/spiderfoot_src && git clone --depth 1 https://github.com/smicallef/spiderfoot.git bin/spiderfoot_src && echo '#!/usr/bin/env bash' > bin/sf && echo 'exec python3 \"\$(pwd)/bin/spiderfoot_src/sf.py\" \"\$@\"' >> bin/sf && chmod +x bin/sf" \
        "echo 'Spiderfoot clone failed'" "Installing SpiderFoot OSINT"

echo "📦 2. Setting up Python Virtual Environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv || python -m venv venv || { echo "❌ Venv failed."; exit 1; }
fi
source venv/bin/activate

echo "📥 3. Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install playwright

echo "📥 4. Installing ProjectDiscovery & Go Security Tools..."
export PATH=$PATH:$(go env GOPATH)/bin
grep -q 'export PATH=$PATH:$(go env GOPATH)/bin' ~/.bashrc || echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc

tools=(
    "nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    "subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    "httpx github.com/projectdiscovery/httpx/cmd/httpx"
    "katana github.com/projectdiscovery/katana/cmd/katana"
)

# --- 5. Go Tools Backup (Git clone + Go Build) ---
for entry in "${tools[@]}"; do
    read -r name repo <<< "$entry"
    if ! command -v $name &> /dev/null; then
        run_cmd "go install -v ${repo}@latest" \
                "git clone --depth 1 https://${repo%%/cmd/*} /tmp/$name && cd /tmp/$name && if [ -d cmd/$name ]; then cd cmd/$name; fi && go build -o $name . && mv $name \$(go env GOPATH)/bin/ && cd - >/dev/null && rm -rf /tmp/$name" \
                "Installing $name"
    fi
done

chmod +x run.sh
echo "======================================"
echo "✅ Setup Complete! To start SMP, run: ./run.sh"
