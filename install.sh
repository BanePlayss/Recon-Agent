#!/usr/bin/env bash
# recon-agent installer for Kali Linux Live
set -euo pipefail

REPO_URL="https://github.com/baneplayss/recon-agent.git"
CONFIG_DIR="$HOME/.recon-agent"

echo "▶ recon-agent installer (Kali Live)"
echo

# ── 1. System packages ──────────────────────────────────────────────────────
echo "[1/7] Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3 python3-pip python3-venv pipx \
    golang-go git curl \
    nmap nikto wpscan sqlmap commix \
    masscan testssl.sh wafw00f \
    gobuster dirb

# ── 2. Python tools ──────────────────────────────────────────────────────────
echo "[2/7] Installing Python-based tools..."
pipx_install() {
    echo "  → $1"
    pipx install "$1" 2>/dev/null || pip install --user "$1" 2>/dev/null || echo "  [WARN] Failed: $1"
}
pipx_install arjun
pipx_install theHarvester
pipx_install trivy       # fallback — prefer binary below
pipx_install prowler

# ── 3. Go tools ───────────────────────────────────────────────────────────────
echo "[3/7] Installing Go-based recon tools..."

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

go_install() {
    echo "  → $1"
    go install -v "$1" 2>/dev/null || echo "  [WARN] Failed to install $1"
}

go_install github.com/owasp-amass/amass/v4/...@master
go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go_install github.com/projectdiscovery/httpx/cmd/httpx@latest
go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go_install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go_install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go_install github.com/projectdiscovery/katana/cmd/katana@latest
go_install github.com/ffuf/ffuf/v2@latest
go_install github.com/hahwul/dalfox/v2@latest
go_install github.com/trufflesecurity/trufflehog/v3@latest
go_install github.com/gitleaks/gitleaks/v8@latest
go_install github.com/OJ/gobuster/v3@latest

# ── 4. Trivy binary (preferred over pip) ────────────────────────────────────
echo "[4/7] Installing Trivy..."
TRIVY_VER="0.51.1"
TRIVY_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-64bit.tar.gz"
if ! command -v trivy &>/dev/null; then
    curl -sfL "$TRIVY_URL" | tar -xz -C /tmp trivy 2>/dev/null && \
        sudo mv /tmp/trivy /usr/local/bin/trivy || \
        echo "  [WARN] Failed to install trivy binary"
fi

# ── 5. Add Go bin to PATH permanently ───────────────────────────────────────
if ! grep -q 'GOPATH/bin\|go/bin' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> "$HOME/.bashrc"
fi

# ── 6. Nuclei templates ──────────────────────────────────────────────────────
echo "[5/7] Updating nuclei templates..."
nuclei -update-templates -silent 2>/dev/null || echo "[WARN] Could not update nuclei templates"

# ── 7. Install recon-agent ───────────────────────────────────────────────────
echo "[6/7] Installing recon-agent..."
pipx install "git+$REPO_URL" --force

# ── 8. Config directory ──────────────────────────────────────────────────────
echo "[7/7] Setting up config directory..."
mkdir -p "$CONFIG_DIR"

if [[ ! -f "$CONFIG_DIR/.env" ]]; then
    cat > "$CONFIG_DIR/.env" << 'EOF'
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

# Optional: WPScan vuln database
# WPSCAN_API_TOKEN=

# Optional limits (override defaults)
# RECON_AGENT_MAX_ITERATIONS=100
# RECON_AGENT_MAX_HOURS=4
# RECON_AGENT_MAX_COST_USD=10.0
EOF
    echo "  Config created at $CONFIG_DIR/.env"
fi

# ── Verify ───────────────────────────────────────────────────────────────────
echo
echo "╔══════════════════════════════════════╗"
echo "║  recon-agent installation complete   ║"
echo "╚══════════════════════════════════════╝"
echo

MISSING=()
for bin in subfinder httpx nuclei naabu dnsx dalfox trufflehog gitleaks; do
    if ! command -v "$bin" &>/dev/null; then
        MISSING+=("$bin")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "⚠  Missing in PATH (run: source ~/.bashrc): ${MISSING[*]}"
    echo
fi

echo "Check what's available:"
echo "  recon-agent tools"
echo
echo "Next steps:"
echo "  1. Edit $CONFIG_DIR/.env — set GEMINI_API_KEY (required) and ANTHROPIC_API_KEY (optional)"
echo "  2. Run: recon-agent"
echo
echo "  Or inline: GEMINI_API_KEY=your_key recon-agent"
