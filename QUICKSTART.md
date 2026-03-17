# ClawVault Quick Start

**[English](./QUICKSTART.md)** | **[中文](./QUICKSTART.zh-CN.md)**

## 1. Deploy to Server

```bash
# From local machine — packs, uploads, and installs in one command
./scripts/deploy.sh <server-ip> root
```

## 2. First-time Setup (on server)

```bash
ssh root@<server-ip>
cd ~/prj/clawvault
source venv/bin/activate

# Configure OpenClaw proxy integration
./scripts/setup.sh
```

## 3. Start

```bash
./scripts/start.sh                  # Start ClawVault only
./scripts/start.sh --with-openclaw  # Start ClawVault + OpenClaw
```

Services:
- **Proxy**: `http://127.0.0.1:8765`
- **Dashboard**: `http://<server-ip>:8766`
- **Log**: `/tmp/clawvault.log`

## 4. Test

```bash
./scripts/test.sh
```

Or test in the Dashboard web UI: go to the **Test** tab and click any test case.

## 5. Stop

```bash
./scripts/stop.sh
```

## 6. Update Code

```bash
# From local machine
./scripts/deploy.sh <server-ip> root

# On server: restart
./scripts/stop.sh && ./scripts/start.sh
```

## 7. Uninstall

```bash
./scripts/uninstall.sh              # Full cleanup
./scripts/uninstall.sh --keep-config # Keep config files
```

---

## CLI Commands

```bash
clawvault --version          # Version
clawvault start              # Start proxy + dashboard
clawvault scan "text"        # Scan text for threats
clawvault demo               # Interactive demo
clawvault config show        # Show config
clawvault skill list         # List skills
```

## Troubleshooting

**pip install fails (proxy conflict)**:
```bash
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
pip install -e .
```

**HTTPS/SSL errors**: Set `ssl_verify: false` in `~/.ClawVault/config.yaml`

**OpenClaw not using proxy**: Restart OpenClaw after setting env vars:
```bash
source ~/.openclaw/.env && openclaw
```

**Dashboard not accessible remotely**: Use SSH tunnel:
```bash
ssh -L 8766:localhost:8766 root@<server-ip>
# Then visit http://localhost:8766
```

---

**Last updated**: 2026-03-09
