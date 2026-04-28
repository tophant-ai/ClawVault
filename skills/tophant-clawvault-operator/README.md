# ClawVault Operator Skill

Day-to-day operations skill for ClawVault — start/stop services, manage configuration, apply vault presets, and scan text/files directly from OpenClaw agents.

**Complements** [`tophant-clawvault-installer`](https://clawhub.ai/Martin2877/tophant-clawvault-installer) (install/health/test/uninstall) with the full operational surface of ClawVault.

See `SECURITY.md` for the full capability and risk disclosure before installing.

## Prerequisites

ClawVault must be installed first via the installer skill:

```bash
openclaw skills install tophant-clawvault-installer
/tophant-clawvault-installer install --mode quick
```

This creates the `~/.clawvault-env/` venv that the operator skill depends on.

## Installation

**From ClawHub (recommended):**

```bash
openclaw skills install tophant-clawvault-operator --version=0.2.5 --force

# Or via clawhub CLI
clawhub install tophant-clawvault-operator --version 0.2.5
```

**ClawHub:** https://clawhub.ai/Martin2877/tophant-clawvault-operator

**From local repo:**

```bash
cp -r skills/tophant-clawvault-operator ~/.openclaw/skills/
openclaw restart
```

## Quick Start

```bash
# Start proxy + dashboard
/tophant-clawvault-operator start --mode interactive

# Check service status
/tophant-clawvault-operator status

# Scan text for threats
/tophant-clawvault-operator scan "my api key is sk-proj-abc123"

# Apply a vault preset
/tophant-clawvault-operator vault-apply developer-workflow

# Configure on the fly
/tophant-clawvault-operator config-set guard.mode strict

# Stop everything
/tophant-clawvault-operator stop
```

## Capability Overview

| Category | Commands |
|---|---|
| **Service lifecycle** | `start`, `stop`, `status` |
| **Threat scanning** | `scan`, `scan-file` |
| **Configuration** | `config-show`, `config-get`, `config-set` |
| **Vault presets** | `vault-list`, `vault-show`, `vault-apply` |

11 commands total. See [SKILL.md](./SKILL.md) for complete reference with examples.

## Vault Presets

Apply a one-click security posture with `vault-apply <id>`. Built-in presets:

**General:** `file-protection` 📁 · `photo-protection` 📷 · `account-secrets` 🔐 · `privacy-shield` 🛡️ · `full-lockdown` 🔒

**Engineering:** `developer-workflow` 💻 · `source-code-repo` 📦 · `ci-cd-pipelines` 🔧 · `mobile-dev` 📱 · `cloud-infra` ☁️ · `database-protection` 🗄️

**Compliance:** `crypto-wallet` 💰 · `financial-strict` 💳 · `healthcare-hipaa` 🏥 · `gdpr-compliance` 🇪🇺 · `legal-contracts` 📜 · `hr-recruiting` 👔 · `backup-archive` 🗜️

**Organization:** `enterprise-internal` 🏢 · `communication-logs` 💬 · `audit-only` 📝

Each preset bundles detection toggles + guard mode + file-monitor patterns + enforcement rules into a single reusable configuration.

## Hot-patching

`config-set` and `vault-apply` detect a running dashboard and hot-patch the live configuration via the REST API — no restart required. When the dashboard is not running, they fall back to editing `~/.ClawVault/config.yaml` directly.

## Requirements

- Python 3.10+
- OpenClaw installed
- ClawVault installed via `tophant-clawvault-installer` skill
- Optional: dashboard running on port 8766 for hot-patching

## Support

- **Repository:** https://github.com/tophant-ai/ClawVault
- **Issues:** https://github.com/tophant-ai/ClawVault/issues
- **Installer skill:** https://clawhub.ai/Martin2877/tophant-clawvault-installer

## License

MIT © 2026 Tophant SPAI Lab
