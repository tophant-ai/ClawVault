# Security Notes for ClawVault Operator

This document explains the capability surface of the `tophant-clawvault-operator` skill so you can decide whether it fits your threat model before installing.

## What it touches

- Configuration and state under `~/.ClawVault/` (config.yaml, vault presets, scan history, schedules)
- ClawVault proxy and dashboard processes (starts/stops processes that the installer skill created)
- Local dashboard REST API at `127.0.0.1:8766` for hot-patching live config
- Files and directories you supply as arguments to `scan-file` or `local-scan`
- Cron entries added by `scan-schedule-add` (one entry per schedule, all under your user crontab)

## What it does not touch

- No system-wide paths (`/etc`, `/usr`, `/var`, `/opt`)
- No systemd units
- No other OpenClaw skill configurations, except when you explicitly run `local-scan --type skill_audit`
- No outbound network traffic, except to `127.0.0.1:8766`
- No environment variables
- No credentials or secrets of its own

## Runtime prerequisite

The script refuses to run unless `~/.clawvault-env/bin/python3` exists, which is created by the `tophant-clawvault-installer` skill. The `python3` binary listed in `requires.bins` launches `clawvault_ops.py`; all ClawVault operations dispatch into the installer's venv.

## Sensitive command modes

A few commands have broad read access. They are all user-initiated and read-only — the operator never opens files you haven't pointed it at.

- `scan-file <path>` — reads the file at `<path>`.
- `local-scan --path <dir>` — walks `<dir>` and reads text files under it, bounded by `--max-files`.
- `local-scan --type skill_audit` — reads files under `~/.openclaw/skills/*`. Run this only if you are comfortable with the scan output seeing the contents of your other installed skills.
- `scan-schedule-add` — adds a cron entry to your user crontab that re-runs a `local-scan` on the schedule you specify. The cron entry persists until you remove it with `scan-schedule-remove`.

## Permissions requested

| Permission | Why |
|---|---|
| `execute_command` | Start/stop ClawVault services, run `pgrep` for status, run subprocess calls into the installer venv |
| `read_files` | Read ClawVault config and, when requested, paths supplied to `scan-file` / `local-scan` |
| `write_files` | Write ClawVault config, schedules, and scan history under `~/.ClawVault/` |
| `network` | Talk to the local dashboard at `127.0.0.1:8766`. No remote endpoints. |

## Before installing

Run in a disposable VM or container if any of the following are true:

- You store secrets in other installed OpenClaw skills and do not want them scanned
- You rely on the user crontab being under strict change control
- You need strong read-file isolation guarantees from the operator skill
