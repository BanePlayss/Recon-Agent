# recon-agent

Autonomous bug bounty recon agent for HackerOne programs.

Runs a ReAct loop (plan → scan → observe → repeat), covers 35+ programs/week
unattended, and sends Telegram alerts when it finds something worth submitting.

```
Scheduler roda  ─────►  Telegram alert  ─────►  Você revisa (5min)
(sem interação)                                  └─► recon-agent draft <id>
                                                 └─► Submete no H1
                                                 └─► 💰
```

---

## Índice

1. [Requisitos](#requisitos)
2. [Instalação](#instalação)
3. [Configuração](#configuração)
4. [Quick Start](#quick-start)
5. [Modos de uso](#modos-de-uso)
   - [Hunt Mode (recomendado)](#hunt-mode)
   - [Scheduler automático](#scheduler-automático)
   - [Batch — lista de programas](#batch)
6. [Gerar report para H1](#gerar-report-para-h1)
7. [Referência de comandos](#referência-de-comandos)
8. [Arquitetura](#arquitetura)
9. [Ferramentas incluídas](#ferramentas-incluídas-30)

---

## Requisitos

- Python 3.11+
- [GEMINI_API_KEY](https://aistudio.google.com/) — obrigatório (grátis no tier básico)
- [ANTHROPIC_API_KEY](https://console.anthropic.com/) — opcional, melhora análise de findings críticos
- Linux (Kali recomendado), Windows 10/11, ou macOS

---

## Instalação

### Linux / Kali (recomendado — cobertura de ferramentas completa)

```bash
# 1. Instala todas as dependências (nmap, nuclei, subfinder, etc.)
bash <(curl -fsSL https://raw.githubusercontent.com/baneplayss/recon-agent/main/install.sh)

# 2. Instale o agente
pipx install git+https://github.com/baneplayss/recon-agent.git

# 3. Verifique
recon-agent tools
```

### Windows 10/11

```powershell
# 1. Abra PowerShell como Administrador e habilite scripts:
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# 2. Baixe e execute o installer:
Invoke-WebRequest -Uri https://raw.githubusercontent.com/baneplayss/recon-agent/main/install.ps1 -OutFile install.ps1
.\install.ps1

# 3. Reabra o PowerShell e verifique:
recon-agent tools
```

O `install.ps1` instala via **Scoop** (nmap, go) e **go install** (subfinder, httpx, nuclei,
katana, dnsx, dalfox, trufflehog, gitleaks, ffuf, gobuster, amass).

> **Ferramentas não disponíveis no Windows nativamente:**
> `masscan`, `nikto`, `wpscan`, `testssl` — o agente as ignora automaticamente.
> Para cobertura total, use [WSL2](https://docs.microsoft.com/windows/wsl/) e execute `install.sh` dentro do WSL.

### Scheduler no Windows (daemon automático)

O `install.ps1` cria uma tarefa no **Agendador de Tarefas** do Windows (`recon-agent-scheduler`)
que roda o hunt a cada 6 horas. Para gerenciar:

```powershell
# Ver status
recon-agent scheduler-status

# Parar / iniciar manualmente
Stop-ScheduledTask  -TaskName "recon-agent-scheduler"
Start-ScheduledTask -TaskName "recon-agent-scheduler"
```

Também funciona com `nohup` no WSL ou **Git Bash**:
```bash
nohup recon-agent scheduler-start --interval 6 --top 5 &
```

---

## Configuração

Edite `~/.recon-agent/.env`:

```env
# Obrigatório
GEMINI_API_KEY=sua_chave_aqui

# Recomendado: deep analysis de findings críticos/high via Claude
ANTHROPIC_API_KEY=sua_chave_aqui

# Para o scheduler buscar programas automaticamente no H1
# Gere em: https://hackerone.com/settings/api_token/edit
H1_USERNAME=seu_handle
H1_API_TOKEN=seu_token

# Para alertas Telegram (veja seção Scheduler abaixo)
TELEGRAM_BOT_TOKEN=123456:ABCdef...
TELEGRAM_CHAT_ID=987654321

# WPScan (opcional)
# WPSCAN_API_TOKEN=seu_token
```

---

## Quick Start

```bash
# Ver top 10 programas rankeados por ROI automatizado
recon-agent programs

# Escanear os top 5 programas em hunt mode
recon-agent hunt --top 5

# Scan manual de um programa específico (abre wizard)
recon-agent

# Listar findings encontrados
recon-agent findings

# Gerar report pronto para submeter no H1
recon-agent draft <id-do-finding>
```

---

## Modos de uso

### Hunt Mode

Modo otimizado para ROI automatizado. Prioriza os tipos de finding com maior
payout médio no H1 sem necessidade de análise manual:

| Tipo | Ferramenta | Payout médio |
|------|-----------|-------------|
| Secrets em JS (AWS, Stripe, GitHub) | `jssecrets` | $500–$2.000 |
| Subdomain takeover | `takeover` | $200–$1.000 |
| CVEs críticos (nuclei templates) | `nuclei` | $300–$1.500 |
| Admin panels expostos | `nuclei` | $300–$1.000 |

**Pipeline automático (ordem de execução):**
```
crtsh → dnsx → httpx → takeover → jssecrets → nuclei (critical+high)
```

```bash
# Scan em hunt mode de um programa específico
recon-agent

# Na tela do wizard, selecione:
# > Hunt (~45min, secrets + takeovers + critical CVEs) [RECOMENDADO]
```

```bash
# Ou direto pela linha de comando (sem wizard)
recon-agent hunt --top 5           # top 5 programas por ROI score
recon-agent hunt --top 10 --max-cost 3.0  # até $3 de API por programa
```

---

### Scheduler automático

Roda o hunt a cada N horas sem nenhuma interação. Detecta novos programas e
mudanças de scope automaticamente.

#### 1. Configurar Telegram

```bash
# Crie um bot via @BotFather no Telegram → copie o token
# Envie qualquer mensagem pro seu bot, depois:
curl https://api.telegram.org/bot<SEU_TOKEN>/getUpdates
# → copie o "chat_id" da resposta

# Adicione no ~/.recon-agent/.env:
TELEGRAM_BOT_TOKEN=123456:ABCdef...
TELEGRAM_CHAT_ID=987654321
```

#### 2. Iniciar scheduler

```bash
# Foreground (Ctrl+C para parar)
recon-agent scheduler-start

# Background com nohup
nohup recon-agent scheduler-start --interval 6 --top 5 &

# Como serviço systemd (persiste após reboot)
sudo cp recon-agent-scheduler.service /etc/systemd/system/recon-agent-scheduler@$USER.service
systemctl --user enable --now recon-agent-scheduler@$USER
```

**Opções do scheduler:**

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--interval` | `6` | Horas entre ciclos |
| `--top` | `5` | Programas por ciclo |
| `--notify` | `critical,high` | Severidades para alertar |
| `--max-cost` | `5.0` | Máximo de custo de API por programa (USD) |
| `--max-hours` | `0.75` | Máximo de tempo por programa |

```bash
# Ver status e fila de programas
recon-agent scheduler-status

# Parar
recon-agent scheduler-stop
```

**O que chega no Telegram:**
```
🔴 [CRITICAL] New Finding
Program: `shopify`
Title: AWS Access Key Exposed in CDN JavaScript
Asset: `https://cdn.shopify.com/app.min.js`
Tool: `jssecrets` | Confidence: 97%

✅ Scan complete: `shopify`
New findings: 2 | Cost: $0.0342 | Time: 38.2min
```

---

### Batch

Escaneie uma lista de programas de um arquivo:

```bash
# Formato do arquivo (um programa por linha):
# url  in-scope  out:out-of-scope
cat > ~/programs.txt << 'EOF'
https://hackerone.com/acme     acme.com,*.acme.com         out:legacy.acme.com
https://hackerone.com/beta     beta.com,api.beta.com
https://hackerone.com/gamma    *.gamma.io
EOF

recon-agent batch ~/programs.txt --depth hunt
```

---

## Gerar report para H1

O workflow do dinheiro:

```bash
# 1. Ver findings do último ciclo
recon-agent findings --severity critical,high

# Saída:
# ID        Severity  Title                          Asset                  Conf%
# abc12345  CRITICAL  AWS Key Exposed in CDN JS      cdn.shopify.com/app.js  97
# def67890  HIGH      Subdomain Takeover Possible    old.beta.com            89

# 2. Gerar o report pronto para submeter
recon-agent draft abc12345

# 3. Revisar e abrir no editor para ajustes finais
recon-agent draft abc12345 --edit

# 4. Salvar em arquivo específico
recon-agent draft abc12345 --output ~/reports/shopify-aws-key.md
```

O report gerado segue exatamente o formato preferido do H1 com:
- Título claro
- CVSS + CWE
- Steps to Reproduce numerados
- Evidence snippet do output da ferramenta
- Impact statement específico por tipo de finding
- Remediation

**Revise sempre antes de submeter** — confirme que o finding é real (5–10 min)
antes de abrir o report no H1.

---

## Referência de comandos

```bash
recon-agent                      # Wizard interativo + scan
recon-agent programs             # Top programas H1 por ROI score
recon-agent hunt [--top N]       # Scan automático dos top N programas
recon-agent batch <arquivo>      # Scan de lista de programas
recon-agent findings             # Listar findings de todas as runs
recon-agent draft <id>           # Gerar report H1 de um finding
recon-agent runs                 # Histórico de runs
recon-agent report <run-id>      # Ver report de uma run (md/json/h1)
recon-agent tools                # Listar ferramentas e disponibilidade
recon-agent scheduler-start      # Iniciar scheduler automático
recon-agent scheduler-stop       # Parar scheduler
recon-agent scheduler-status     # Ver estado do scheduler
```

---

## Arquitetura

```
recon-agent
├── core/
│   ├── orchestrator.py     # ReAct loop principal
│   ├── policy_engine.py    # Validação de scope e categorias
│   ├── guardrails.py       # Limites de custo/tempo/iterações
│   ├── correlator.py       # Identifica attack chains entre findings
│   └── state.py            # AgentState, Finding, AttackChain (Pydantic)
│
├── llm/
│   ├── gemini.py           # Planner + Observer (Gemini Flash)
│   ├── claude.py           # Deep analysis de findings críticos (Claude)
│   └── router.py           # Roteia plan/observe/deep_analyze
│
├── tools/                  # 30 ferramentas organizadas por categoria
│   ├── recon/              # subfinder, amass, crtsh, dnsx, httpx, takeover
│   ├── web/                # nuclei, katana, ffuf, nikto, wpscan, gobuster...
│   ├── secrets/            # trufflehog, gitleaks, secretfinder, jssecrets
│   ├── exploit/            # sqlmap, dalfox, xsstrike, nosqlmap, commix
│   └── cloud/              # trivy, prowler
│
├── h1/
│   ├── program_scanner.py  # Busca e rankeia programas H1 por ROI
│   └── monitor.py          # Detecta novos programas e mudanças de scope
│
├── scheduler/
│   └── scheduler.py        # Loop automático a cada N horas
│
├── notifications/
│   └── telegram.py         # Alertas via Telegram Bot API
│
├── reporting/
│   ├── drafter.py          # Gera report H1 pronto para submeter
│   ├── h1_json.py          # Formato JSON do H1
│   └── markdown.py         # Report completo em Markdown
│
└── storage/
    └── db.py               # SQLite: runs, findings, scheduler state
```

---

## Ferramentas incluídas (30)

| Categoria | Ferramentas |
|-----------|-----------|
| `recon_passive` | subfinder, amass, theHarvester, crtsh |
| `recon_active` | httpx, dnsx, wafw00f, **takeover** |
| `infra_scan` | nmap, naabu, masscan |
| `web_scan` | nuclei, ffuf, katana, nikto, wpscan, testssl, arjun, gobuster |
| `exploit` ⚠️ | sqlmap, dalfox, xsstrike, nosqlmap, commix |
| `secrets` | trufflehog, gitleaks, secretfinder, **jssecrets** |
| `cloud_scan` | trivy, prowler |

> ⚠️ Ferramentas de exploit requerem aprovação manual em modo `adaptive`.
> Em modo `conservative`, nunca são executadas.

---

## Custo estimado de API

Por ciclo de 5 programas em hunt mode:

| Item | Custo estimado |
|------|---------------|
| Planner (Gemini Flash) | ~$0.02/programa |
| Observer (Gemini Flash) | ~$0.03/programa |
| Deep analysis críticos (Claude) | ~$0.05–$0.15/finding |
| **Total por ciclo (5 programas)** | **~$0.30–$1.00** |

Com Gemini Flash gratuito (tier básico) + sem Claude, o custo cai para próximo de $0.
