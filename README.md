# recon-agent

Autonomous pentest agent for bug bounty programs. Receives a program URL and in-scope domains, then runs a ReAct loop (planner → action → observer) using Gemini Flash to decide which recon tools to run, analyze outputs, and generate a prioritized findings report.

## Quick Start (Kali Live)

```bash
curl -fsSL https://raw.githubusercontent.com/baneplayss/recon-agent/main/install.sh | bash
export GEMINI_API_KEY=your_key_here
recon-agent
```

## What It Does

1. **Wizard** — enter program URL, in-scope domains, and limits
2. **Planner (Gemini)** — decides the next best recon action at each iteration
3. **Tool Executor** — runs `subfinder`, `httpx`, `nuclei` safely via subprocess
4. **Observer (Gemini)** — parses tool output, extracts findings, updates state
5. **Reporter** — generates a Markdown report with findings + PoCs

## Architecture

```
Agent Loop (ReAct):
  State → Planner LLM → Policy Check → [Manual Approval?] → Tool → Observer LLM → State
                                  ↕
                           Guardrails (iter / time / cost)
                                  ↓
                        Report (Markdown + JSON)
```

### Guard-rails (non-negotiable)

- Policy gate validates every target against in/out-of-scope before execution
- Max iterations: 100 (configurable)
- Max time: 4h (configurable)
- Max API cost: $10 (configurable)
- Tool allowlist — LLM can only invoke registered tools
- Argument sanitization before subprocess execution
- Active actions (recon_active category in adaptive mode) require manual approval
- Full audit log in JSONL format with content hashes

## Requirements

- Python 3.12+
- `GEMINI_API_KEY` (Gemini 1.5 Flash)
- External tools: `subfinder`, `httpx`, `nuclei` (installed by `install.sh`)

## Installation (manual)

```bash
git clone https://github.com/baneplayss/recon-agent.git
cd recon-agent
pip install -e ".[dev]"
```

## Configuration

`~/.recon-agent/.env`:
```
GEMINI_API_KEY=your_key_here
```

## Depth Modes

| Mode     | Time  | Tools                        |
|----------|-------|------------------------------|
| fast     | ~15m  | subfinder + nuclei (crit/high) |
| standard | ~45m  | full recon + web scan        |
| deep     | ~3h   | all tools + fuzzing          |

## Agent Modes

| Mode        | Description                                    |
|-------------|------------------------------------------------|
| adaptive    | LLM decides; manual approval for active scans  |
| conservative| Passive only, no active recon or exploits       |

## Output

Results saved to `/tmp/recon-agent/runs/<timestamp>/`:
- `report.md` — full Markdown report with findings
- `findings.json` — structured findings (Pydantic models)
- `state.json` — full agent state snapshot
- `audit.jsonl` — tamper-evident audit log

## Phase 1 Tools

- `subfinder` — passive subdomain enumeration
- `httpx` — HTTP probing (alive hosts, tech detection)
- `nuclei` — template-based vulnerability scanning

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Legal

This tool is intended for authorized security testing only. Only use against programs you have explicit permission to test (e.g., bug bounty programs with defined scope). Unauthorized use is illegal.

## License

MIT
