# recon-agent installer for Windows
# Run as Administrator in PowerShell 5.1+ or PowerShell Core 7+
#
# Usage:
#   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
#   .\install.ps1
#
# Optional flags:
#   .\install.ps1 -SkipGo      # Skip Go tool installation
#   .\install.ps1 -SkipScoop   # Skip Scoop package manager

param(
    [switch]$SkipGo,
    [switch]$SkipScoop
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # faster Invoke-WebRequest

$CONFIG_DIR = Join-Path $env:USERPROFILE ".recon-agent"
$TOOLS_DIR  = Join-Path $env:USERPROFILE ".recon-agent\bin"

function Write-Step($msg) { Write-Host "`n[+] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    WARN: $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "    FAIL: $msg" -ForegroundColor Red }

Write-Host @"
╔══════════════════════════════════════╗
║   recon-agent installer (Windows)   ║
╚══════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ── 1. Python ────────────────────────────────────────────────────────────────
Write-Step "Checking Python..."
try {
    $pyver = & python --version 2>&1
    if ($pyver -match "Python 3\.(\d+)") {
        $minor = [int]$Matches[1]
        if ($minor -lt 11) {
            Write-Warn "Python $pyver found but 3.11+ is required."
            Write-Warn "Download from https://python.org/downloads/"
        } else {
            Write-Ok $pyver
        }
    }
} catch {
    Write-Fail "Python not found. Download from https://python.org/downloads/ and re-run."
    exit 1
}

# ── 2. pipx ───────────────────────────────────────────────────────────────────
Write-Step "Installing pipx..."
try {
    python -m pip install --user pipx --quiet
    python -m pipx ensurepath --force | Out-Null
    Write-Ok "pipx ready"
} catch {
    Write-Warn "pipx installation failed: $_"
}

# ── 3. Scoop (package manager) ───────────────────────────────────────────────
if (-not $SkipScoop) {
    Write-Step "Setting up Scoop..."
    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        Write-Ok "Scoop already installed"
    } else {
        try {
            Invoke-RestMethod get.scoop.sh | Invoke-Expression
            Write-Ok "Scoop installed"
        } catch {
            Write-Warn "Scoop installation failed. Install manually from https://scoop.sh"
            $SkipScoop = $true
        }
    }

    if (-not $SkipScoop) {
        Write-Step "Installing system tools via Scoop..."
        $scoopTools = @("nmap", "go", "git")
        foreach ($tool in $scoopTools) {
            try {
                scoop install $tool 2>&1 | Out-Null
                Write-Ok $tool
            } catch {
                Write-Warn "Could not install $tool via scoop"
            }
        }
    }
}

# ── 4. Go-based recon tools ──────────────────────────────────────────────────
if (-not $SkipGo) {
    Write-Step "Installing Go-based recon tools..."
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Warn "Go not found — skipping Go tools. Install Go from https://golang.org/dl/"
    } else {
        New-Item -ItemType Directory -Force -Path $TOOLS_DIR | Out-Null

        $goTools = @(
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "github.com/projectdiscovery/katana/cmd/katana@latest",
            "github.com/ffuf/ffuf/v2@latest",
            "github.com/hahwul/dalfox/v2@latest",
            "github.com/trufflesecurity/trufflehog/v3@latest",
            "github.com/gitleaks/gitleaks/v8@latest",
            "github.com/OJ/gobuster/v3@latest",
            "github.com/owasp-amass/amass/v4/...@master"
        )

        $env:GOPATH = Join-Path $env:USERPROFILE "go"
        $env:PATH   = "$env:PATH;$env:GOPATH\bin"

        foreach ($tool in $goTools) {
            $name = ($tool -split "/")[-1] -replace "@.*$", ""
            Write-Host "  -> $name" -NoNewline
            try {
                go install $tool 2>&1 | Out-Null
                Write-Host " OK" -ForegroundColor Green
            } catch {
                Write-Host " WARN (failed)" -ForegroundColor Yellow
            }
        }
    }
}

# ── 5. Python tools ──────────────────────────────────────────────────────────
Write-Step "Installing Python-based tools..."
$pythonTools = @("arjun", "theHarvester", "wafw00f", "sqlmap")
foreach ($tool in $pythonTools) {
    Write-Host "  -> $tool" -NoNewline
    try {
        python -m pipx install $tool --quiet 2>&1 | Out-Null
        Write-Host " OK" -ForegroundColor Green
    } catch {
        try {
            python -m pip install --user $tool --quiet 2>&1 | Out-Null
            Write-Host " OK (pip)" -ForegroundColor Green
        } catch {
            Write-Host " WARN (failed)" -ForegroundColor Yellow
        }
    }
}

# ── 6. nuclei templates ──────────────────────────────────────────────────────
Write-Step "Updating nuclei templates..."
try {
    nuclei -update-templates -silent 2>&1 | Out-Null
    Write-Ok "nuclei templates updated"
} catch {
    Write-Warn "Could not update nuclei templates (nuclei may not be in PATH yet)"
}

# ── 7. Add Go bin to PATH (permanent) ───────────────────────────────────────
Write-Step "Configuring PATH..."
$goBin = Join-Path $env:USERPROFILE "go\bin"
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*$goBin*") {
    [Environment]::SetEnvironmentVariable(
        "PATH",
        "$currentPath;$goBin",
        "User"
    )
    Write-Ok "Added $goBin to user PATH"
} else {
    Write-Ok "Go bin already in PATH"
}

# ── 8. Install recon-agent ───────────────────────────────────────────────────
Write-Step "Installing recon-agent..."
try {
    python -m pipx install "git+https://github.com/baneplayss/recon-agent.git" --force 2>&1 | Out-Null
    Write-Ok "recon-agent installed"
} catch {
    Write-Warn "pipx install failed, trying pip..."
    python -m pip install --user "git+https://github.com/baneplayss/recon-agent.git"
}

# ── 9. Config directory ──────────────────────────────────────────────────────
Write-Step "Setting up config directory..."
New-Item -ItemType Directory -Force -Path $CONFIG_DIR | Out-Null

$envFile = Join-Path $CONFIG_DIR ".env"
if (-not (Test-Path $envFile)) {
    @"
# recon-agent configuration

# Required: Gemini Flash — get at https://aistudio.google.com/
GEMINI_API_KEY=

# Optional: Claude API — enables deep analysis on critical/high findings
# Get at https://console.anthropic.com/
ANTHROPIC_API_KEY=

# Optional: HackerOne API credentials — enables live program discovery
# Get at https://hackerone.com/settings/api_token/edit
# H1_USERNAME=your_h1_handle
# H1_API_TOKEN=your_api_token

# Optional: Telegram alerts
# TELEGRAM_BOT_TOKEN=123456:ABCdef...
# TELEGRAM_CHAT_ID=987654321

# Optional: WPScan vuln database
# WPSCAN_API_TOKEN=
"@ | Set-Content $envFile -Encoding UTF8
    Write-Ok "Config created at $envFile"
} else {
    Write-Ok "Config already exists at $envFile"
}

# ── 10. Windows Task Scheduler (optional daemon) ─────────────────────────────
Write-Step "Creating Windows Task Scheduler entry (optional)..."
$taskName = "recon-agent-scheduler"
try {
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $existing) {
        $action  = New-ScheduledTaskAction -Execute "recon-agent" -Argument "scheduler-start --interval 6 --top 5"
        $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 6) -Once -At (Get-Date)
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RestartOnIdle
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Limited -Force | Out-Null
        Write-Ok "Task '$taskName' created (every 6h). Manage in Task Scheduler."
        Write-Warn "Edit the task to add GEMINI_API_KEY to the environment first."
    } else {
        Write-Ok "Task '$taskName' already exists"
    }
} catch {
    Write-Warn "Could not create scheduled task: $_"
    Write-Warn "Run manually: nohup recon-agent scheduler-start (or use Task Scheduler manually)"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host @"

╔══════════════════════════════════════╗
║  recon-agent installation complete  ║
╚══════════════════════════════════════╝
"@ -ForegroundColor Green

Write-Host @"
Next steps:
  1. Close and reopen PowerShell (to pick up new PATH)
  2. Edit $envFile
     Set GEMINI_API_KEY (required) and other optional keys
  3. Verify tools:
     recon-agent tools
  4. Run:
     recon-agent

Note: Some tools (masscan, nikto, wpscan, testssl) are Linux-only.
They will show as unavailable — the agent skips them automatically.
For full tool coverage use WSL2 (install.sh) or Kali Linux.
"@ -ForegroundColor White
