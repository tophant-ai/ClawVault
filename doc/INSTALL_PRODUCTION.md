# Production Deployment

> [中文版](./zh/INSTALL_PRODUCTION.md)

## Prerequisites

- Linux server (Debian/Ubuntu or CentOS/RHEL)
- Python 3.10+
- SSH access with root or sudo privileges

## One-Command Deploy

From your **local machine** (where the source code is):

```bash
./scripts/deploy.sh <server-ip> [user]
# Example: ./scripts/deploy.sh 123.45.67.89 root
```

This script will:

1. Package the project (excluding `__pycache__`, `.pyc`)
2. Upload to the server via SCP
3. Create a Python virtual environment on the server
4. Install ClawVault in the venv

## First-Time Setup (on server)

```bash
ssh root@<server-ip>
cd ~/prj/claw-vault
source venv/bin/activate

# Initialize config (creates ~/.ClawVault/config.yaml)
claw-vault config init
```

### Recommended Production Config

Edit `~/.ClawVault/config.yaml`:

```yaml
proxy:
  port: 8765
  ssl_verify: false # Set true if you have proper CA certs

guard:
  mode: "interactive" # or "strict" for maximum protection
  auto_sanitize: true

monitor:
  daily_token_budget: 100000
  monthly_token_budget: 3000000
  cost_alert_usd: 100.0

dashboard:
  enabled: true
  host: "127.0.0.1" # Bind to localhost; use SSH tunnel for remote access
  port: 8766
```

## Start / Stop

```bash
./scripts/start.sh         # Start ClawVault (background)
./scripts/stop.sh          # Stop all services
```

Services after start:

- **Proxy**: `http://127.0.0.1:8765`
- **Dashboard**: `http://127.0.0.1:8766`
- **Log**: `/tmp/claw-vault.log`

## Remote Dashboard Access

The dashboard binds to `127.0.0.1` by default for security. Use an SSH tunnel:

```bash
# From your local machine
ssh -L 8766:localhost:8766 root@<server-ip>
# Then visit http://localhost:8766
```

## Update

```bash
# From local machine: re-deploy
./scripts/deploy.sh <server-ip> root

# On server: restart
./scripts/start.sh
```

## Verify

```bash
./scripts/test.sh          # Run CLI + API tests
```

Or test via the Dashboard web UI: open the **Test** tab and run any test case.

## Uninstall

```bash
./scripts/uninstall.sh               # Full cleanup
./scripts/uninstall.sh --keep-config  # Keep config files
```

## Scripts Reference

| Script                          | Description                                          |
| ------------------------------- | ---------------------------------------------------- |
| `scripts/deploy.sh <ip> [user]` | Pack, upload, and install on server                  |
| `scripts/start.sh`              | Start ClawVault (add `--with-openclaw` for OpenClaw) |
| `scripts/stop.sh`               | Stop all services                                    |
| `scripts/test.sh`               | Run CLI + API tests                                  |
| `scripts/setup.sh`              | Configure OpenClaw proxy integration                 |
| `scripts/uninstall.sh`          | Uninstall and restore                                |

## Troubleshooting

**pip install fails (proxy conflict)**:

```bash
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
pip install -e .
```

**HTTPS/SSL errors**: Set `ssl_verify: false` in `~/.ClawVault/config.yaml`.

**Dashboard not accessible remotely**: Use SSH tunnel (see above).

**Check logs**:

```bash
tail -f /tmp/claw-vault.log
```
