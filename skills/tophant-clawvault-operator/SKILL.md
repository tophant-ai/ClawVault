---
name: tophant-clawvault-operator
version: 0.2.4
description: Operate ClawVault services, configuration, vault presets, and scanning from OpenClaw
homepage: https://github.com/tophant-ai/ClawVault
user-invocable: true
disable-model-invocation: false
metadata:
  openclaw:
    requires:
      bins: ["python3", "pgrep"]
      skills: ["tophant-clawvault-installer"]
---

# ClawVault Operator

Operate ClawVault services, manage configuration, apply vault presets, scan text/files, and schedule local filesystem security scans — all from OpenClaw agents.

**Complements** the `tophant-clawvault-installer` skill (install/health/generate-rule/test/uninstall) by covering day-to-day operational commands.

## What This Skill Does

This operator skill installs no software and opens no outbound network connections except to `127.0.0.1:8766`. See `SECURITY.md` for the full capability list.

## Prerequisites

This skill requires ClawVault to be installed via the `tophant-clawvault-installer` skill first:

```bash
openclaw skills install tophant-clawvault-installer
/tophant-clawvault-installer install --mode quick
```

## How to Run

**IMPORTANT: All commands MUST be executed using the Python script bundled with this skill.**

Do NOT run `clawvault` or any other command directly. Always use:

```bash
python3 SKILL_DIR/clawvault_ops.py <command> [options]
```

Where `SKILL_DIR` is the directory containing this SKILL.md file (typically `~/.openclaw/workspace/skills/tophant-clawvault-operator/` or `~/.openclaw/skills/tophant-clawvault-operator/`).

Add `--json` to any command for machine-readable JSON output.

## Commands

### /tophant-clawvault-operator start

Start ClawVault proxy and dashboard services.

```bash
python3 SKILL_DIR/clawvault_ops.py start --json
python3 SKILL_DIR/clawvault_ops.py start --mode strict --json
python3 SKILL_DIR/clawvault_ops.py start --port 9000 --json
python3 SKILL_DIR/clawvault_ops.py start --no-dashboard --json
```

### /tophant-clawvault-operator stop

Stop running ClawVault services.

```bash
python3 SKILL_DIR/clawvault_ops.py stop --json
python3 SKILL_DIR/clawvault_ops.py stop --force --json
```

### /tophant-clawvault-operator status

Check if ClawVault services are running.

```bash
python3 SKILL_DIR/clawvault_ops.py status --json
```

### /tophant-clawvault-operator scan

Scan text for sensitive data, prompt injection, and dangerous commands.

```bash
python3 SKILL_DIR/clawvault_ops.py scan "sk-proj-abc123" --json
```

### /tophant-clawvault-operator scan-file

Scan a local file for hardcoded secrets and sensitive data.

```bash
python3 SKILL_DIR/clawvault_ops.py scan-file /path/to/.env --json
```

### /tophant-clawvault-operator config-show

Show current ClawVault configuration.

```bash
python3 SKILL_DIR/clawvault_ops.py config-show --json
```

### /tophant-clawvault-operator config-get

Get a specific configuration value.

```bash
python3 SKILL_DIR/clawvault_ops.py config-get guard.mode --json
python3 SKILL_DIR/clawvault_ops.py config-get detection.pii --json
```

### /tophant-clawvault-operator config-set

Set a configuration value (auto-detects type: bool/int/float/string). If dashboard is running, changes to `file_monitor`, `guard`, and `detection` sections are hot-patched immediately.

```bash
python3 SKILL_DIR/clawvault_ops.py config-set guard.mode strict --json
python3 SKILL_DIR/clawvault_ops.py config-set detection.pii true --json
```

### /tophant-clawvault-operator config-append

Append a value to a list configuration field. Use this for adding watch paths, intercept hosts, etc. If dashboard is running, changes are hot-patched immediately (no restart needed).

```bash
python3 SKILL_DIR/clawvault_ops.py config-append file_monitor.watch_paths /home/cs/password --json
python3 SKILL_DIR/clawvault_ops.py config-append proxy.intercept_hosts api.deepseek.com --json
```

### /tophant-clawvault-operator config-remove

Remove a value from a list configuration field.

```bash
python3 SKILL_DIR/clawvault_ops.py config-remove file_monitor.watch_paths /home/cs/password --json
python3 SKILL_DIR/clawvault_ops.py config-remove proxy.intercept_hosts api.deepseek.com --json
```

### /tophant-clawvault-operator vault-list

List all vault presets.

```bash
python3 SKILL_DIR/clawvault_ops.py vault-list --json
```

### /tophant-clawvault-operator vault-show

Show detailed configuration of a vault preset.

```bash
python3 SKILL_DIR/clawvault_ops.py vault-show full-lockdown --json
```

### /tophant-clawvault-operator vault-apply

Apply a vault preset to the active configuration. If the dashboard is running, changes are hot-patched immediately (no restart needed).

```bash
python3 SKILL_DIR/clawvault_ops.py vault-apply full-lockdown --json
python3 SKILL_DIR/clawvault_ops.py vault-apply privacy-shield --json
```

### /tophant-clawvault-operator vault-create

Create a custom vault preset from the current active configuration.

```bash
python3 SKILL_DIR/clawvault_ops.py vault-create "My Custom Preset" --json
python3 SKILL_DIR/clawvault_ops.py vault-create "Dev Mode" --id dev-mode --description "Relaxed settings" --json
```

### /tophant-clawvault-operator vault-update

Update a custom vault preset's metadata. Builtin presets cannot be modified.

```bash
python3 SKILL_DIR/clawvault_ops.py vault-update my-preset --name "Renamed" --json
python3 SKILL_DIR/clawvault_ops.py vault-update my-preset --from-current --json
```

### /tophant-clawvault-operator vault-delete

Delete a custom vault preset. Builtin presets cannot be deleted.

```bash
python3 SKILL_DIR/clawvault_ops.py vault-delete my-preset --json
```

### /tophant-clawvault-operator vault-active

Show which vault preset is currently active.

```bash
python3 SKILL_DIR/clawvault_ops.py vault-active --json
```

### /tophant-clawvault-operator local-scan

Run an on-demand local filesystem security scan.

```bash
python3 SKILL_DIR/clawvault_ops.py local-scan --json
python3 SKILL_DIR/clawvault_ops.py local-scan --type vulnerability --path /srv --json
python3 SKILL_DIR/clawvault_ops.py local-scan --type skill_audit --max-files 50 --json
```

Scan types: `credential`, `vulnerability`, `skill_audit`

### /tophant-clawvault-operator scan-schedule-add

Add a cron-scheduled local scan.

```bash
python3 SKILL_DIR/clawvault_ops.py scan-schedule-add --cron "0 2 * * *" --type credential --json
```

### /tophant-clawvault-operator scan-schedule-list

List all configured scan schedules.

```bash
python3 SKILL_DIR/clawvault_ops.py scan-schedule-list --json
```

### /tophant-clawvault-operator scan-schedule-remove

Remove a scheduled scan by ID.

```bash
python3 SKILL_DIR/clawvault_ops.py scan-schedule-remove <schedule_id> --json
```

### /tophant-clawvault-operator scan-history

Show recent local scan results.

```bash
python3 SKILL_DIR/clawvault_ops.py scan-history --json
python3 SKILL_DIR/clawvault_ops.py scan-history --limit 50 --json
```

### /tophant-clawvault-operator agent-list

List all registered agents and their detection configurations.

```bash
python3 SKILL_DIR/clawvault_ops.py agent-list --json
```

### /tophant-clawvault-operator agent-set

Create or update per-agent configuration. Use `--no-*` flags to disable specific detection categories.

```bash
python3 SKILL_DIR/clawvault_ops.py agent-set "MyAgent" --guard-mode permissive --json
python3 SKILL_DIR/clawvault_ops.py agent-set "TrustedAgent" --disabled --json
python3 SKILL_DIR/clawvault_ops.py agent-set "OpenClaw" --guard-mode permissive --no-prompt-injection --no-dangerous-commands --json
```

### /tophant-clawvault-operator agent-remove

Remove an agent configuration by ID or name.

```bash
python3 SKILL_DIR/clawvault_ops.py agent-remove <agent_id> --json
```

## Quick Examples

```bash
# Set the skill directory path
CV="python3 ~/.openclaw/workspace/skills/tophant-clawvault-operator/clawvault_ops.py"

# Start services and verify
$CV start --mode interactive --json
$CV status --json

# Manage configuration
$CV config-get guard.mode --json
$CV config-set guard.mode strict --json

# Add/remove watch paths (hot-patches if dashboard running)
$CV config-append file_monitor.watch_paths /home/cs/password --json
$CV config-remove file_monitor.watch_paths /home/cs/password --json

# Apply a security preset (hot-patches if dashboard running)
$CV vault-list --json
$CV vault-apply file-protection --json
$CV vault-active --json

# Create and manage custom presets
$CV vault-create "My Security Profile" --description "Customized for our team" --json
$CV vault-delete my-security-profile --json

# Schedule daily credential scan
$CV scan-schedule-add --cron "0 2 * * *" --type credential --json

# Stop services
$CV stop --json
```

## Requirements

- Python 3.10+
- ClawVault installed via `tophant-clawvault-installer` skill
- pyyaml (`pip install pyyaml` if not available)

## Permissions

- `execute_command` - Start/stop services, run scans
- `write_files` - Write configuration changes to ~/.ClawVault/
- `read_files` - Read configuration, vault presets, scan history
- `network` - Probe service ports, dashboard API calls

## License

MIT (c) 2026 Tophant SPAI Lab
