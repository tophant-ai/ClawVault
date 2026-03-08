# Claw-Vault

**[English](./README.md)** | **[中文](./README.zh-CN.md)**

> AI Security Vault — Protect your AI workflows, credentials, and interactions

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## What is Claw-Vault?

Claw-Vault is an open-source **security vault for AI workflows** that protects your AI tools, credentials, and interactions:

- **Sensitive Data Detection** — API keys, passwords, PII, credit cards, and 15+ pattern types
- **Prompt Injection Defense** — Block role hijacking, instruction override, data exfiltration
- **Dangerous Command Guard** — Intercept `rm -rf`, `curl|bash`, privilege escalation
- **Auto-Sanitization** — Replace secrets with placeholders, restore on response
- **Token Budget Control** — Daily/monthly limits with cost alerts
- **Real-time Dashboard** — Web UI with per-agent config, detection details, quick tests

The vault includes a **transparent proxy gateway module** that intercepts traffic between your AI tools and external APIs (OpenAI, Anthropic, etc.).

## Quick Start

```bash
# Install
pip install -e .

# Start (proxy + dashboard)
claw-vault start

# Scan text
claw-vault scan "password=MySecret key=sk-proj-abc123"

# Interactive demo
claw-vault demo
```

## Deploy to Server

```bash
# One command: pack, upload, install
./scripts/deploy.sh <server-ip> root

# On server: setup integration + start
./scripts/setup.sh
./scripts/start.sh
```

## Scripts

| Script | Usage |
|--------|-------|
| `scripts/deploy.sh <ip> [user]` | Deploy to cloud server |
| `scripts/start.sh` | Start Claw-Vault (add `--with-openclaw` to also start OpenClaw) |
| `scripts/stop.sh` | Stop all services |
| `scripts/test.sh` | Run CLI + API tests |
| `scripts/setup.sh` | Setup OpenClaw proxy integration |
| `scripts/uninstall.sh` | Uninstall and restore original state |

## Architecture

```
AI Tools / OpenClaw
       │
       ▼
┌─────────────────────────────────┐
│      Claw-Vault (Security)      │
├─────────────────────────────────┤
│ Gateway Module                  │
│  • Transparent Proxy  :8765     │
│  • Traffic Interception         │
├─────────────────────────────────┤
│ Detection Engine                │
│  • Sensitive data               │
│  • Injection patterns           │
│  • Dangerous commands           │
├─────────────────────────────────┤
│ Guard / Sanitizer               │
│  • Allow / Block / Sanitize     │
├─────────────────────────────────┤
│ Audit + Monitor                 │
│  • SQLite storage               │
│  • Token budget tracking        │
├─────────────────────────────────┤
│ Dashboard                       │
│  • Web UI :8766                 │
│  • Agent config & tests         │
└─────────────────────────────────┘
```

## Configuration

```yaml
# ~/.claw-vault/config.yaml
proxy:
  port: 8765
  intercept_hosts: ["api.openai.com", "api.anthropic.com"]

guard:
  mode: "interactive"  # interactive | strict | permissive

monitor:
  daily_token_budget: 50000
```

## Development

```bash
git clone https://github.com/spai-lab/claw-vault.git
cd claw-vault
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Documentation

| Document | Description |
|----------|-------------|
| [Development Setup](doc/INSTALL_DEV.md) | Local dev environment |
| [Production Deployment](doc/INSTALL_PRODUCTION.md) | Deploy to server |
| [OpenClaw Integration](doc/OPENCLAW_INTEGRATION.md) | Connect with OpenClaw |
| [Architecture](doc/architecture.md) | System design & modules |
| [Guard Modes](doc/GUARD_MODE.md) | strict / interactive / permissive |
| [Scenarios](doc/scenes.md) | Use cases & roadmap |

See [doc/](doc/) for the full documentation index.

## License

MIT
