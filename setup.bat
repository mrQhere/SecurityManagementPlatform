@echo off
setlocal EnableDelayedExpansion
title SMP Setup - Windows Installer
echo =======================================================
echo 🚀 Starting SMP V7 Auto-Setup for Windows (Batch) with Fallbacks...
echo © mrQhere
echo =======================================================

where winget >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARN] winget is not installed. Relying purely on fallback direct downloads.
)

:: --- 1. Python Backup ---
echo ---------------------------------------------------
echo 🛠️ Installing Python...
winget install -e --id Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements 2>nul
python --version >nul 2>&1
if !errorlevel! neq 0 (
    echo [WARN] Winget failed. FALLBACK: Downloading Python installer...
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -OutFile 'python-installer.exe'"
    start /wait python-installer.exe /quiet InstallAllUsers=1 PrependPath=1
)

:: --- 2. Go Backup ---
echo ---------------------------------------------------
echo 🛠️ Installing Go...
winget install -e --id GoLang.Go --silent --accept-package-agreements --accept-source-agreements 2>nul
go version >nul 2>&1
if !errorlevel! neq 0 (
    echo [WARN] Winget failed. FALLBACK: Downloading Go installer...
    powershell -Command "Invoke-WebRequest -Uri 'https://go.dev/dl/go1.22.4.windows-amd64.msi' -OutFile 'go.msi'"
    start /wait msiexec.exe /i go.msi /quiet
)

:: --- 3. Git Backup ---
echo ---------------------------------------------------
echo 🛠️ Installing Git...
winget install -e --id Git.Git --silent --accept-package-agreements --accept-source-agreements 2>nul
git --version >nul 2>&1
if !errorlevel! neq 0 (
    echo [WARN] Winget failed. FALLBACK: Downloading Git installer...
    powershell -Command "Invoke-WebRequest -Uri 'https://github.com/git-for-windows/git/releases/download/v2.45.2.windows.1/Git-2.45.2-64-bit.exe' -OutFile 'git.exe'"
    start /wait git.exe /VERYSILENT /NORESTART
)

:: --- 4. OS Tools (Nmap) Backup ---
echo ---------------------------------------------------
echo 🛠️ Installing Nmap...
winget install -e --id Insecure.Nmap --silent --accept-package-agreements --accept-source-agreements 2>nul
if !errorlevel! neq 0 (
    echo [WARN] Winget failed for Nmap. FALLBACK: Direct download...
    powershell -Command "Invoke-WebRequest -Uri 'https://nmap.org/dist/nmap-7.94-setup.exe' -OutFile 'nmap-setup.exe'"
    start /wait nmap-setup.exe /S
)

:: --- 5. Ruby & Manual Tools Backup ---
echo ---------------------------------------------------
echo 🛠️ Installing Ruby, WPScan and SpiderFoot...
winget install -e --id RubyInstallerTeam.Ruby --silent --accept-package-agreements --accept-source-agreements 2>nul
gem install wpscan 2>nul

if not exist "bin\spiderfoot_src\" (
    mkdir bin\spiderfoot_src 2>nul
    git clone --depth 1 https://github.com/smicallef/spiderfoot.git bin\spiderfoot_src
    echo @echo off > bin\sf.bat
    echo python "%cd%\bin\spiderfoot_src\sf.py" %%* >> bin\sf.bat
)

echo =======================================================
echo 📦 2. Setting up Python Virtual Environment...
if not exist "venv\" (
    python -m venv venv
    if !errorlevel! neq 0 (
        echo [WARN] Failed to create venv with 'python'. FALLBACK: Retrying with 'py'...
        py -m venv venv
    )
)
call venv\Scripts\activate.bat

echo =======================================================
echo 📥 3. Installing Python dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install playwright

echo =======================================================
echo 📥 4. Installing Go Security Tools...
set PATH=%PATH%;%USERPROFILE%\go\bin

:: Array of Tool Name and Repo URL
set "t1=nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
set "t2=subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
set "t3=httpx github.com/projectdiscovery/httpx/cmd/httpx"
set "t4=katana github.com/projectdiscovery/katana/cmd/katana"

:: --- 5. Go Tools Backup (Git clone + Go Build) ---
for %%I in (1 2 3 4) do (
    for /F "tokens=1,2" %%A in ("!t%%I!") do (
        echo ---------------------------------------------------
        echo 🛠️ Installing %%A via go install...
        go install %%B@latest
        if !errorlevel! neq 0 (
            echo [WARN] go install failed. FALLBACK: Building %%A from source...
            for /f "tokens=1,2,3 delims=/" %%X in ("%%B") do set "repo_url=https://%%X/%%Y/%%Z"
            git clone --depth 1 !repo_url! C:\temp\%%A
            cd C:\temp\%%A
            if exist "cmd\%%A" cd "cmd\%%A"
            go build -o %%A.exe .
            move /Y %%A.exe %USERPROFILE%\go\bin\
            cd %~dp0
            rmdir /s /q C:\temp\%%A
        )
    )
)

echo @echo off > run.bat
echo echo 🚀 Starting Security Management Platform V7.0.4... >> run.bat
echo call venv\Scripts\activate.bat >> run.bat
echo python main.py %%* >> run.bat

echo =======================================================
echo ✅ Setup Complete! To start SMP, run: run.bat
echo =======================================================
pause
