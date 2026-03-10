# ClawVault

**[English](./README.md)** | **[中文](./README.zh-CN.md)**

> OpenClaw Security Vault — Atomic "claw" control: every AI reach, within your sight.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## What is ClawVault?

ClawVault is an open-source security vault for OpenClaw Agent runtime.  
The core goal is to provide **visual monitoring, atomic control, and generative policies** for Agents, model invocations, and file assets.

### Core Capabilities

#### 1. Visual Monitoring
Users can configure their own "vault" and lock in Agents, Skills, credentials, and files they care about.  
When someone touches these assets, the "Security Lobster" will notify you via IM: who touched what in your vault yesterday.

**Technical Implementation**:
- Event collection based on API gateway and file-side monitoring (invocation records, file access, change tracking)
- Supports periodic change notifications and real-time alerts

#### 2. Atomic Control

Fine-grained control at the Agent level, using composable "atomic capabilities" as the smallest unit:
- Agent interaction and invocation policies
- Model routing, whitelists, and quota control
- Security detection (sensitive info recognition, credential detection, prompt injection protection, etc.)
- File access permission constraints

Users can combine these atomic capabilities like "building blocks" to create reusable policy configurations.

#### 3. Generative Capabilities
Each "storage chamber" in the vault includes built-in basic security scenarios and allows users to add detection scenarios and Skills via natural language by mobilizing atomic capabilities.

**Example**:  
Tell the system via chat interface:
```
For customer service Agent, if a user uploads a PDF containing 'contract',
it must first go through sensitive information desensitization,
and only GPT-4o-mini is allowed, with a single call limit of 2000 tokens.
```
The system will automatically generate and execute the corresponding policy rules.

---

### Features

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
| `scripts/start.sh` | Start ClawVault (add `--with-openclaw` to also start OpenClaw) |
| `scripts/stop.sh` | Stop all services |
| `scripts/test.sh` | Run CLI + API tests |
| `scripts/setup.sh` | Setup OpenClaw proxy integration |
| `scripts/uninstall.sh` | Uninstall and restore original state |

## Architecture

```
    OpenClaw
       │
       ▼
┌─────────────────────────────────┐
│    ClawVault (Security Vault)    │
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

### Development Progress

| Capability Module | Status | Notes |
|---------|------|------|
| API Gateway Monitoring & Interception | ✅ Implemented | V1 core capability |
| File-side Monitoring | 🚧 In Progress | Gradual integration |
| Agent-level Atomic Control | 🚧 In Progress | Gateway-side available, expanding to other scenarios |
| Generative Policy Orchestration | 🚧 In Progress | Gradual integration |

---

## Documentation

| Document | Description |
|------|------|
| [Development Setup](doc/INSTALL_DEV.md) | Local dev environment |
| [Production Deployment](doc/INSTALL_PRODUCTION.md) | Deploy to server |
| [OpenClaw Integration](doc/OPENCLAW_INTEGRATION.md) | Connect with OpenClaw |
| [Architecture](doc/architecture.md) | System design & modules |
| [Guard Modes](doc/GUARD_MODE.md) | strict / interactive / permissive |
| [Scenarios](doc/scenes.md) | Use cases & roadmap |

See [doc/](doc/) for the full documentation index.

## Development

```bash
git clone https://github.com/tophant-ai/ClawVault.git
cd ClawVault
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT
