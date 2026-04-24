---
name: tophant-clawvault-installer
version: 0.2.5
description: Install, configure, test, and uninstall ClawVault AI security proxy
homepage: https://github.com/tophant-ai/ClawVault
user-invocable: true
disable-model-invocation: false
---

# ClawVault Installer

Install, configure, test, and uninstall ClawVault — the AI security proxy that protects agents from prompt injection, data leakage, and dangerous commands.

**Protection Against:**
- Prompt injection attacks
- Data leakage (PII, credentials, API keys)
- Dangerous command execution
- Jailbreak attempts

## What This Skill Does

Installs ClawVault into a dedicated venv at `~/.clawvault-env/` and writes config under `~/.ClawVault/`. See `SECURITY.md` for the full capability, risk, and design-intent disclosure.

## How to Run

**IMPORTANT: All commands MUST be executed using the Python script bundled with this skill.**

Do NOT run `pip install`, `clawvault`, or any other command directly. Always use:

```bash
python3 SKILL_DIR/clawvault_manager.py <command> [options]
```

Where `SKILL_DIR` is the directory containing this SKILL.md file (typically `~/.openclaw/workspace/skills/tophant-clawvault-installer/` or `~/.openclaw/skills/tophant-clawvault-installer/`).

Add `--json` to any command for machine-readable JSON output.

## Commands

### /tophant-clawvault-installer install

Install ClawVault. The script handles everything automatically: creates a Python virtual environment, installs from GitHub, generates config, integrates OpenClaw proxy, and starts services. **No pip or system package manager needed.**

```bash
# Recommended: one command does everything
python3 SKILL_DIR/clawvault_manager.py install --mode quick --json

# Interactive setup
python3 SKILL_DIR/clawvault_manager.py install --mode standard --json

# Full control (strict mode)
python3 SKILL_DIR/clawvault_manager.py install --mode advanced --json

# Install without starting services
python3 SKILL_DIR/clawvault_manager.py install --mode quick --no-start --json

# Skip OpenClaw proxy integration
python3 SKILL_DIR/clawvault_manager.py install --mode quick --no-proxy --json
```

### /tophant-clawvault-installer health

Check service health and status.

```bash
python3 SKILL_DIR/clawvault_manager.py health --json
```

### /tophant-clawvault-installer generate-rule

Generate security rules from natural language.

```bash
python3 SKILL_DIR/clawvault_manager.py generate-rule "Block all AWS credentials" --json
python3 SKILL_DIR/clawvault_manager.py generate-rule --scenario customer_service --apply --json
```

**Scenarios:** `customer_service`, `development`, `production`, `finance`

### /tophant-clawvault-installer test

Run detection tests.

```bash
python3 SKILL_DIR/clawvault_manager.py test --category all --json
python3 SKILL_DIR/clawvault_manager.py test --category sensitive --json
```

**Categories:** `all`, `sensitive`, `injection`, `commands`

### /tophant-clawvault-installer uninstall

Remove ClawVault completely (stops services, removes proxy, deletes venv and config).

```bash
python3 SKILL_DIR/clawvault_manager.py uninstall --json
python3 SKILL_DIR/clawvault_manager.py uninstall --keep-config --json
```

## Quick Examples

```bash
# Set the skill directory path
CV="python3 ~/.openclaw/workspace/skills/tophant-clawvault-installer/clawvault_manager.py"

# Install (one command handles everything)
$CV install --mode quick --json

# Check health
$CV health --json

# Generate rule
$CV generate-rule "Detect database passwords" --apply --json

# Apply scenario
$CV generate-rule --scenario customer_service --apply --json

# Run tests
$CV test --category all --json

# Uninstall
$CV uninstall --json
```

## Requirements

- Python 3.10+ (with venv module)
- Ports 8765, 8766 available
- No pip or system packages needed — the install script creates its own virtual environment

## Permissions

- `execute_command` - Run installation and ClawVault commands
- `write_files` - Create configuration files
- `read_files` - Read configurations
- `network` - Download packages and API calls

## Security Considerations

See [SECURITY.md](./SECURITY.md) for capability disclosure, threat model, and deployment guidance.

## Documentation

- **Full Guide**: https://github.com/tophant-ai/ClawVault/blob/main/doc/OPENCLAW_SKILL.md
- **中文文档**: https://github.com/tophant-ai/ClawVault/blob/main/doc/zh/OPENCLAW_SKILL.md
- **Repository**: https://github.com/tophant-ai/ClawVault

## License

MIT © 2026 Tophant SPAI Lab
