Write-Host "🚀 Starting SMP V7 Auto-Setup for Windows (PowerShell) with Fallbacks..." -ForegroundColor Cyan
Write-Host "© mrQhere" -ForegroundColor DarkCyan
Write-Host "=======================================================" -ForegroundColor Cyan

function Run-WithFallback {
    param([string]$Primary, [string]$Fallback, [string]$Message)
    Write-Host "-------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "🛠️ $Message" -ForegroundColor Yellow
    Invoke-Expression $Primary
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null) {
        if (-not [string]::IsNullOrEmpty($Fallback)) {
            Write-Host "⚠️ Primary failed. Falling back to redundancy..." -ForegroundColor DarkYellow
            Invoke-Expression $Fallback
        } else {
            Write-Host "❌ Failed." -ForegroundColor Red
        }
    } else {
        Write-Host "✅ Success!" -ForegroundColor Green
    }
}

Write-Host "🛠️ 1. Installing System Dependencies..." -ForegroundColor Yellow

# --- 1. Python Backup ---
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Run-WithFallback -Primary "Start-Process winget -ArgumentList 'install -e --id Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements' -Wait -NoNewWindow" -Fallback "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -OutFile 'python-installer.exe'; Start-Process 'python-installer.exe' -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait" -Message "Installing Python"
}

# --- 2. Go Backup ---
if (-not (Get-Command "go" -ErrorAction SilentlyContinue)) {
    Run-WithFallback -Primary "Start-Process winget -ArgumentList 'install -e --id GoLang.Go --silent --accept-package-agreements --accept-source-agreements' -Wait -NoNewWindow" -Fallback "Invoke-WebRequest -Uri 'https://go.dev/dl/go1.22.4.windows-amd64.msi' -OutFile 'go.msi'; Start-Process msiexec.exe -ArgumentList '/i go.msi /quiet' -Wait" -Message "Installing Go"
}

# --- 3. Git Backup ---
if (-not (Get-Command "git" -ErrorAction SilentlyContinue)) {
    Run-WithFallback -Primary "Start-Process winget -ArgumentList 'install -e --id Git.Git --silent --accept-package-agreements --accept-source-agreements' -Wait -NoNewWindow" -Fallback "Invoke-WebRequest -Uri 'https://github.com/git-for-windows/git/releases/download/v2.45.2.windows.1/Git-2.45.2-64-bit.exe' -OutFile 'git.exe'; Start-Process 'git.exe' -ArgumentList '/VERYSILENT /NORESTART' -Wait" -Message "Installing Git"
}

# --- 4. OS Tools (Nmap) Backup ---
Run-WithFallback -Primary "Start-Process winget -ArgumentList 'install -e --id Insecure.Nmap --silent --accept-package-agreements --accept-source-agreements' -Wait -NoNewWindow" -Fallback "Invoke-WebRequest -Uri 'https://nmap.org/dist/nmap-7.94-setup.exe' -OutFile 'nmap-setup.exe'; Start-Process 'nmap-setup.exe' -ArgumentList '/S' -Wait" -Message "Installing Nmap"

# --- 5. Ruby & Manual Tools Backup ---
Run-WithFallback -Primary "Start-Process winget -ArgumentList 'install -e --id RubyInstallerTeam.Ruby --silent --accept-package-agreements --accept-source-agreements' -Wait -NoNewWindow" -Fallback "echo 'Skipping Ruby Fallback'" -Message "Installing Ruby"
gem install wpscan 2>$null

if (-not (Test-Path "bin\spiderfoot_src")) {
    New-Item -ItemType Directory -Force -Path "bin\spiderfoot_src" | Out-Null
    git clone --depth 1 https://github.com/smicallef/spiderfoot.git bin\spiderfoot_src
    $sfScript = "@echo off`npython `"$PWD\bin\spiderfoot_src\sf.py`" %*"
    $sfScript | Out-File "bin\sf.bat" -Encoding ascii
}
# Refresh environment variables
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "📦 2. Setting up Python Virtual Environment..." -ForegroundColor Yellow
if (-not (Test-Path "venv")) {
    Run-WithFallback -Primary "python -m venv venv" -Fallback "py -m venv venv" -Message "Creating venv"
}
.\venv\Scripts\Activate.ps1

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "📥 3. Installing Python dependencies..." -ForegroundColor Yellow
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install playwright

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "📥 4. Installing Go Security Tools..." -ForegroundColor Yellow
$env:Path += ";$HOME\go\bin"
$gotools = @(
    @("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"),
    @("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
    @("httpx", "github.com/projectdiscovery/httpx/cmd/httpx"),
    @("katana", "github.com/projectdiscovery/katana/cmd/katana")
)

# --- 5. Go Tools Backup (Git clone + Go Build) ---
foreach ($toolPair in $gotools) {
    $binName = $toolPair[0]
    $repo = $toolPair[1]
    
    $repoUrl = "https://" + $repo.Split("/cmd")[0]
    $fallbackScript = "git clone --depth 1 $repoUrl C:\temp\$binName; Set-Location C:\temp\$binName; if (Test-Path cmd\$binName) { Set-Location cmd\$binName }; go build -o $binName.exe .; Move-Item $binName.exe `$HOME\go\bin\ -Force; Set-Location `$PSScriptRoot; Remove-Item C:\temp\$binName -Recurse -Force"
    
    Run-WithFallback -Primary "go install $($repo)@latest" -Fallback $fallbackScript -Message "Installing $binName"
}

$runScript = @"
Write-Host "🚀 Starting Security Management Platform V7.0.6..." -ForegroundColor Cyan
if (`$env:VIRTUAL_ENV -eq `$null) { .\venv\Scripts\Activate.ps1 }
python main.py
"@
$runScript | Out-File run.ps1 -Encoding utf8

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "✅ Setup Complete! To start SMP, run: .\run.ps1" -ForegroundColor Green
