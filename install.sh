#!/usr/bin/env bash
# recon-agent installer for Kali Linux Live
set -euo pipefail

REPO_URL="https://github.com/baneplayss/recon-agent.git"
CONFIG_DIR="$HOME/.recon-agent"

echo "▶ recon-agent installer (Kali Live)"
echo

# ── 1. System packages ──────────────────────────────────────────────────────
echo "[1/6] Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3.12 python3-pip python3-venv pipx \
    golang-go git curl \
    nmap nikto wpscan sqlmap

# ── 2. Go tools (projectdiscovery + others) ─────────────────────────────────
echo "[2/6] Installing Go-based recon tools..."

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

# ── 3. Add Go bin to PATH permanently ───────────────────────────────────────
if ! grep -q 'GOPATH/bin' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> "$HOME/.bashrc"
fi

# ── 4. Nuclei templates ──────────────────────────────────────────────────────
echo "[3/6] Updating nuclei templates..."
nuclei -update-templates -silent || echo "[WARN] Could not update nuclei templates"

# ── 5. Install recon-agent ───────────────────────────────────────────────────
echo "[4/6] Installing recon-agent..."
pipx install "git+$REPO_URL" --force

# ── 6. Config directory ──────────────────────────────────────────────────────
echo "[5/6] Setting up config directory..."
mkdir -p "$CONFIG_DIR"

if [[ ! -f "$CONFIG_DIR/.env" ]]; then
    cat > "$CONFIG_DIR/.env" << 'EOF'
# recon-agent configuration
# Required: get your key at https://aistudio.google.com/
GEMINI_API_KEY=

# Optional limits (override defaults)
# RECON_AGENT_MAX_ITERATIONS=100
# RECON_AGENT_MAX_HOURS=4
# RECON_AGENT_MAX_COST_USD=10.0
EOF
    echo "  Config created at $CONFIG_DIR/.env"
fi

# ── 7. Verify ────────────────────────────────────────────────────────────────
echo "[6/6] Verifying installation..."
MISSING=()
for bin in subfinder httpx nuclei; do
    if ! command -v "$bin" &>/dev/null; then
        MISSING+=("$bin")
    fi
done

echo
echo "╔══════════════════════════════════════╗"
echo "║  recon-agent installation complete   ║"
echo "╚══════════════════════════════════════╝"
echo

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "⚠  Missing tools (add ~/go/bin to PATH): ${MISSING[*]}"
    echo "   Run: source ~/.bashrc"
    echo
fi

echo "Next steps:"
echo "  1. Edit $CONFIG_DIR/.env and set GEMINI_API_KEY"
echo "  2. Run: recon-agent"
echo
echo "  Or export the key inline:"
echo "  GEMINI_API_KEY=your_key recon-agent"
