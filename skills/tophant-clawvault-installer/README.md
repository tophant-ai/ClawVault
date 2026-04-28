# ClawVault Installer Skill

AI security system for OpenClaw — protect your AI agents from prompt injection, data leakage, and dangerous commands.

## Before Installing

This skill installs and operates a local HTTPS-inspection proxy. Capabilities, defaults, and risks are documented in [SECURITY.md](./SECURITY.md) — please review it before installing.

## Quick Start

### Installation

**Option 1: Install from ClawHub (Recommended)**

```bash
# Install from ClawHub
openclaw skills install tophant-clawvault-installer

# Or use clawhub CLI
clawhub install tophant-clawvault-installer
```

**ClawHub:** https://clawhub.ai/Martin2877/tophant-clawvault-installer

**Option 2: Install from Local Repository**

```bash
# Copy to OpenClaw skills directory
cp -r skills/tophant-clawvault-installer ~/.openclaw/skills/

# Or create symbolic link
ln -s /path/to/ClawVault/skills/tophant-clawvault-installer ~/.openclaw/skills/tophant-clawvault-installer

# Restart OpenClaw
openclaw restart
```

### Basic Usage

```bash
# Install ClawVault
/tophant-clawvault-installer install --mode quick

# Check health
/tophant-clawvault-installer health

# Generate security rule
/tophant-clawvault-installer generate-rule "Block all AWS credentials" --apply

# Run tests
/tophant-clawvault-installer test --category all
```

## Features

- **AI-guided installation** - Quick, standard, or advanced setup modes
- **Dedicated virtualenv** - Installs into `~/.clawvault-env` instead of the system Python
- **Pinned install sources** - Uses `clawvault>=0.1.0,<1.0.0` and pinned GitHub fallback `v0.1.0`
- **Failure-aware setup** - Reports configuration initialization failures as installation failures
- **Secure dashboard defaults** - Binds the dashboard to `127.0.0.1` by default
- **OpenClaw proxy integration** - Can configure OpenClaw gateway proxy settings, with `--no-proxy` opt-out
- **Rule generation** - Create security rules from natural language
- **Scenario templates** - Pre-configured policies (customer_service, development, production, finance)
- **Detection testing** - Built-in test suites for validation
- **Health monitoring** - Real-time service status

## Documentation

- **Security Guide**: [SECURITY.md](./SECURITY.md) ⚠️ **Read this first**
- **Skill Reference**: [SKILL.md](./SKILL.md)
- **Complete Guide**: [../../doc/OPENCLAW_SKILL.md](../../doc/OPENCLAW_SKILL.md)
- **中文文档**: [../../doc/zh/OPENCLAW_SKILL.md](../../doc/zh/OPENCLAW_SKILL.md)

## Requirements

- Python 3.10+
- OpenClaw installed
- Ports 8765, 8766 available

## Support

- **Repository**: https://github.com/tophant-ai/ClawVault
- **Issues**: https://github.com/tophant-ai/ClawVault/issues
- **Documentation**: https://github.com/tophant-ai/ClawVault/tree/main/doc

## License

MIT © 2026 Tophant SPAI Lab
