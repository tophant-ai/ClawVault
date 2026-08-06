<div align="center">
  <img src="./doc/images/logo1.png" alt="ClawVault Logo" width="200"/>
  <p><strong>OpenClaw Security Vault — Atomic "claw" control: every AI reach, within your sight.</strong></p>
  <p>
    <a href="https://github.com/tophant-ai/ClawVault/blob/master/LICENSE">
      <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"/>
    </a>
    <a href="https://www.python.org/downloads/">
      <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+"/>
    </a>
    <a href="https://github.com/tophant-ai/ClawVault/stargazers">
      <img src="https://img.shields.io/github/stars/tophant-ai/ClawVault?style=social" alt="Stars"/>
    </a>
  </p>
</div>

**[English](./README.md)** | **[中文](./README.zh-CN.md)**

<div align="center">
  <img src="./doc/images/cartoon_en.png" alt="ClawVault Cartoon" width="800"/>
</div>

## 🎯 ClawVault is for you if

- ✅ You’re concerned about leaking personal private data when interacting with AI agents
- ✅ You want to prevent AI agents from accessing API keys, private files, and credentials
- ✅ You need to stop AI agents from mishandling sensitive or confidential files
- ✅ You want to keep logs of how AI interacts with your private data
- ✅ You need to detect AI injection attacks and dangerous commands

Activate your personal AI Vault:
- 1️⃣ Load private files
- 2️⃣ Set up and customize your secure storage
- 3️⃣ Create remote management skills

https://github.com/user-attachments/assets/2098b271-f844-4db5-b44a-f836e36d314c

### Effect

<div align="center">

| Interception | Interception Record |
|:-------------------:|:----------------:|
| <img src="doc/images/block-tui.png" width="400"> | <img src="doc/images/block-web.png" width="400"> |

</div>

https://github.com/user-attachments/assets/d580cfa1-8410-4095-90cb-3d693413a24e

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

## ✨ Features

- **🔍 Sensitive Data Detection** — API keys, passwords, PII, credit cards, and 15+ pattern types
- **🛡️ Prompt Injection Defense** — Block role hijacking, instruction override, data exfiltration
- **⚠️ Dangerous Command Guard** — Intercept `rm -rf`, `curl|bash`, privilege escalation
- **🔄 Auto-Sanitization** — Replace secrets with placeholders, restore on response
- **💰 Token Budget Control** — Daily/monthly limits with cost alerts
- **📊 Real-time Dashboard** — Web UI with Audit Log, Protection Monitor, per-agent config, and quick tests
- **🤖 Agent Integrations** — OpenClaw session/runtime protection and Claude Code prompt/tool hooks

ClawVault combines a **transparent proxy gateway**, local agent hooks, and dashboard monitoring to protect AI provider traffic, OpenClaw sessions, and Claude Code prompt/tool activity.


## 🚀 Quick Start

https://github.com/user-attachments/assets/1f424172-8833-4ccc-b0d2-abf67c1758dd

### Option 1: Install as OpenClaw Skill (Recommended)

```bash
# Install the dedicated installer from ClawHub
openclaw skills install tophant-clawvault-installer --version=0.2.9 --force

# Or install via clawhub CLI
clawhub install tophant-clawvault-installer --version 0.2.9
```

**ClawHub:** https://clawhub.ai/Martin2877/tophant-clawvault-installer

The installer skill provides AI-guided installation and management:
- `/tophant-clawvault-installer install --mode quick` - Quick setup
- `/tophant-clawvault-installer health` - Check status
- `/tophant-clawvault-installer generate-rule "Block AWS credentials"` - Create security rules
- `/tophant-clawvault-installer test --category all` - Run detection tests

See [skills/tophant-clawvault-installer/](skills/tophant-clawvault-installer/) for skill documentation.

Operational commands after installation are provided by [skills/tophant-clawvault-operator/](skills/tophant-clawvault-operator/).

### Option 2: Install as Python Package

```bash
# Install
pip install -e .

# Start (proxy + dashboard)
clawvault start

# Scan text
clawvault scan "password=[PASSWORD_EXAMPLE] key=[SYNTHETIC_API_KEY]"

# Interactive demo
clawvault demo
```

## 🚀 Deploy to Server

```bash
# One command: pack, upload, install
./scripts/deploy.sh <server-ip> root

# On server: setup integration + start
./scripts/setup.sh
./scripts/start.sh
```

## 📜 Scripts

| Script | Usage |
|--------|-------|
| `scripts/deploy.sh <ip> [user]` | Deploy to cloud server |
| `scripts/start.sh` | Start ClawVault (add `--with-openclaw` to also start OpenClaw) |
| `scripts/stop.sh` | Stop all services |
| `scripts/test.sh` | Run CLI + API tests |
| `scripts/setup.sh` | Setup OpenClaw proxy integration |
| `scripts/setup-claude-code.sh` | Setup Claude Code prompt and tool hooks (dry-run by default) |
| `scripts/uninstall.sh` | Uninstall and restore original state |

## 🏗️ Architecture

```
    OpenClaw
       │
       ▼
┌─────────────────────────────────┐
│    ClawVault (Security Vault)   │
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

## ⚙️ Configuration

```yaml
# ~/.ClawVault/config.yaml
proxy:
  port: 8765
  intercept_hosts: ["api.openai.com", "api.anthropic.com"]

guard:
  mode: "interactive"  # interactive | strict | permissive

monitor:
  daily_token_budget: 50000
```

### OpenClaw OpenAI-Compatible Adapter

For OpenClaw deployments, prefer the direct OpenAI-compatible adapter over a transparent proxy when you want `@clawvault sanitize` prompts to continue to the model after local sanitization.

OpenClaw provider configuration:

```text
base_url = http://127.0.0.1:8766/v1
```

Keep the existing OpenClaw model and provider API key unchanged. Configure ClawVault to forward adapter traffic to the real upstream provider:

```yaml
# ~/.ClawVault/config.yaml
provider_adapter:
  enabled: true
  upstream_base_url: https://api.example.com/v1
  request_timeout_seconds: 60.0
```

Do not set `provider_adapter.upstream_base_url` to `http://127.0.0.1:8766/v1`; that would route ClawVault back into itself.

When the latest OpenAI-compatible user message is a valid command such as `@clawvault sanitize email=alice@example.test`, ClawVault locally rewrites the provider request so the upstream model sees only the sanitized body, for example `email=[EMAIL_1]`. The upstream provider does not see the original sensitive value or the `@clawvault` control prefix. This flow is sanitize-only: placeholders in the model response are not restored.

Security boundary: sensitive data does not leave the local machine and does not enter the upstream model/provider. Because this mode does not modify OpenClaw runtime storage, local OpenClaw TUI, session, or transcript files may still contain the user's original local input.

### Claude Code Hooks

ClawVault can protect Claude Code at both prompt and tool-execution stages:

- `UserPromptSubmit`: scans user prompts before they are sent to the model.
- `PreToolUse`: scans Claude Code tool calls before execution.

Both hooks use the same ClawVault/OpenClaw detector, RuleEngine, guard mode, audit store, and dashboard semantics.

Preview the setup without changing Claude Code settings:

```bash
./scripts/setup-claude-code.sh --dry-run
```

Install after reviewing the planned change:

```bash
./scripts/setup-claude-code.sh --yes
```

The installer safely merges `~/.claude/settings.json`: it preserves existing hooks, MCP servers, permissions, model settings, status line configuration, and OpenClaw configuration. It creates a backup before writing, is idempotent, and can remove only ClawVault hooks:

```bash
clawvault claude-code status
clawvault claude-code uninstall --yes
```

Keep ClawVault running while Claude Code hooks are installed. The hooks fail closed if the local guard API is unavailable.

Manual checks:

- Safe prompt: allowed.
- Synthetic API key prompt: blocked before model submission.
- Dangerous command prompt: blocked or reviewed according to guard mode.
- Safe tool call such as `pwd`: allowed and audited.
- Dashboard Audit Log and Protection Monitor show the events.

## 📊 Development Progress

| Capability Module | Status | Notes |
|---------|------|------|
| API Gateway Monitoring & Interception | ✅ Implemented | V1 core capability |
| File-side Monitoring | 🚧 In Progress | Gradual integration |
| Agent-level Atomic Control | 🚧 In Progress | Gateway-side available, expanding to other scenarios |
| Generative Policy Orchestration | 🚧 In Progress | Gradual integration |

---

## 📚 Documentation

| Document | Description |
|------|------|
| [Development Setup](doc/INSTALL_DEV.md) | Local dev environment |
| [Production Deployment](doc/INSTALL_PRODUCTION.md) | Deploy to server |
| [OpenClaw Integration](doc/OPENCLAW_INTEGRATION.md) | Connect with OpenClaw |
| [Architecture](doc/architecture.md) | System design & modules |
| [Guard Modes](doc/GUARD_MODE.md) | strict / interactive / permissive |
| [Scenarios](doc/scenes.md) | Use cases & roadmap |

See [doc/](doc/) for the full documentation index.

## 🛠️ Development

```bash
git clone https://github.com/tophant-ai/ClawVault.git
cd ClawVault
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
pytest
```

## 📄 License

MIT © 2026 [Tophant](https://www.tophant.com/)

---

## 🤝 Community

**How to join us:**

- Discord: Join our Discord server for real-time chat and collaboration: https://discord.gg/P4pQCQgZ

- WeChat: Add the WeChat scan the QR code below and send the keyword clawvault to join the group.

<img width="1440" height="2988" alt="微信图片_20260518115512_35_192" src="https://github.com/user-attachments/assets/217329b1-537a-4a1f-8717-baaa2554ad92" />

- [GitHub Issues](https://github.com/tophant-ai/ClawVault/issues) — Bug reports and feature requests
- [Security Issues](https://github.com/tophant-ai/ClawVault/security/advisories) — Security vulnerability reports

🌟 Leave us a star! It helps the project get discovered by others and keeps us motivated to build awesome open-source tools!

---




<div align="center">
  <p><strong>🦞 Built for people who want to secure AI, not babysit agents.</strong></p>
  <p><a href="#top">Back to top ↑</a></p>
</div>
