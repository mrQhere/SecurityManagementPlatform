# Security Management Platform (SMP) V9
# ========================================
# Self-contained Docker image bundling all required system tools,
# Go security tools, Python dependencies, and the SMP API.
#
# Build:   docker build -t smp:v9 .
# Run API: docker run -p 8000:8000 smp:v9
# Shell:   docker run -it smp:v9 /bin/bash

FROM ubuntu:22.04

LABEL maintainer="@mrQhere <https://github.com/mrQhere/SecurityManagementPlatform>"
LABEL description="Security Management Platform V9 — Local-first vulnerability scanning and correlation platform"
LABEL version="9.4.0"

# Suppress interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV SMP_API_HOST=0.0.0.0

# ── 1. System dependencies ────────────────────────────────────────────────────

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
        # Python runtime
        python3.11 \
        python3-pip \
        python3-venv \
        python3-dev \
        # Build tools
        build-essential \
        git \
        curl \
        wget \
        unzip \
        # Security scanning tools (apt-installable)
        nmap \
        gobuster \
        dirb \
        nikto \
        sqlmap \
        whatweb \
        wapiti \
        traceroute \
        masscan \
        # Network utilities
        dnsutils \
        whois \
        netcat-openbsd \
        net-tools \
        # SQLCipher for encrypted database
        libsqlcipher-dev \
        sqlcipher \
        # PDF generation dependencies
        wkhtmltopdf \
        fonts-liberation \
        libpangocairo-1.0-0 \
        libpango-1.0-0 \
        libgdk-pixbuf2.0-0 \
        libffi-dev \
        # Ruby for WPScan
        ruby \
        ruby-dev \
        # Perl for Nikto
        perl \
        # MAC changer (for OPSEC scanning)
        macchanger \
        jq \
        ripgrep \
        nodejs \
        npm \
    && apt-get autoremove -y \
    && apt-get autoclean \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Go runtime (for ProjectDiscovery tools) ────────────────────────────────

ENV GOVERSION=1.22.4
RUN wget -q https://go.dev/dl/go${GOVERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH=/root/go

# ── 3. Go security tools (ProjectDiscovery) ───────────────────────────────────

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/zricethezav/gitleaks/v8@latest && \
    go install -v github.com/s0md3v/smap/cmd/smap@latest

RUN wget -q https://github.com/The-Z-Labs/race-the-web/releases/download/v1.0.3/race-the-web-linux-amd64 -O /usr/local/bin/race-the-web && \
    chmod +x /usr/local/bin/race-the-web

# ── 4. Node.js Tools ──────────────────────────────────────────────────────────

RUN npm install -g wscat@5.2.1 && \
    git clone https://github.com/kleiton0x00/ppmap.git /usr/local/share/ppmap && \
    chmod +x /usr/local/share/ppmap/ppmap.sh && \
    ln -s /usr/local/share/ppmap/ppmap.sh /usr/local/bin/ppmap

# ── 4. Ruby tools ─────────────────────────────────────────────────────────────

RUN gem install wpscan --no-user-install

# ── 5. WPScan update its database ─────────────────────────────────────────────

RUN wpscan --update || true

# ── 6. Python application setup ───────────────────────────────────────────────

WORKDIR /app

# Copy requirements first for Docker layer caching
COPY requirements.txt .

# Install Python dependencies (headless — no PySide6 GUI in Docker)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        APScheduler \
        requests \
        cryptography \
        pyee \
        reportlab \
        Jinja2 \
        weasyprint \
        sslyze \
        fastapi \
        uvicorn \
        python-jose[cryptography] \
        slowapi \
        pydantic \
        pysqlcipher3 \
        shodan \
        python-dateutil \
        colorama \
        netaddr \
        pycryptodomex \
        certifi \
        ujson \
        dnspython \
        aiohttp \
        aiodns \
        PyYAML \
        beautifulsoup4 \
        httpx \
        cyclonedx-python-lib \
        psutil \
        aiosqlite \
        loguru

# Copy the full SMP source code
COPY . .

# ── 7. Create required runtime directories ────────────────────────────────────

RUN mkdir -p \
    database \
    logs/narrative \
    reports/pdf \
    reports/sbom \
    reports/evidence/screenshots \
    cache \
    backup

# ── 8. Create non-root user ───────────────────────────────────────────────────

RUN useradd -m -s /bin/bash -u 1000 smpuser && \
    chown -R smpuser:smpuser /app

USER smpuser

# ── 9. Expose API port ────────────────────────────────────────────────────────

EXPOSE 8000

# ── 10. Health check ──────────────────────────────────────────────────────────

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v6/health || exit 1

# ── 11. Default entrypoint: headless API mode ─────────────────────────────────

CMD ["python3", "main.py", "--api"]
