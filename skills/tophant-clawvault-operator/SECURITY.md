# Security Notes for ClawVault Operator

This document explains the capability surface of the `tophant-clawvault-operator` skill so you can decide whether it fits your threat model before installing.

## What it touches

- Configuration and state under `~/.ClawVault/` (config.yaml and vault presets)
- ClawVault proxy and dashboard processes (starts/stops processes that the installer skill created)
- Local dashboard REST API at `127.0.0.1:8766` for hot-patching live config
- Files you supply as arguments to `scan-file`

## What it does not touch

- No system-wide paths (`/etc`, `/usr`, `/var`, `/opt`)
- No systemd units
- No other OpenClaw skill configurations
- No outbound network traffic, except to `127.0.0.1:8766`
- No environment variables
- No credentials or secrets of its own
- No user crontab changes

## Runtime prerequisite

The script refuses to run unless `~/.clawvault-env/bin/python3` exists, which is created by the `tophant-clawvault-installer` skill. The `python3` binary listed in `requires.bins` launches `clawvault_ops.py`; all ClawVault operations dispatch into the installer's venv.

## Sensitive command modes

A few commands have broad read access. They are all user-initiated and read-only — the operator never opens files you haven't pointed it at.

- `scan-file <path>` — reads the file at `<path>`.

## Permissions requested

| Permission | Why |
|---|---|
| `execute_command` | Start/stop ClawVault services, run `pgrep` for status, run subprocess calls into the installer venv |
| `read_files` | Read ClawVault config and, when requested, paths supplied to `scan-file` |
| `write_files` | Write ClawVault config under `~/.ClawVault/` |
| `network` | Talk to the local dashboard at `127.0.0.1:8766`. No remote endpoints. |

## Before installing

Run in a disposable VM or container if any of the following are true:

- You need strong read-file isolation guarantees from the operator skill
