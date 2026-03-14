#!/bin/bash
# Start ClawVault services and configure OpenClaw proxy
# Usage: ./scripts/start.sh [--with-openclaw]

set -e

CLAW_VAULT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="/tmp/claw-vault.log"
SERVICE_FILE="$HOME/.config/systemd/user/openclaw-gateway.service"

# Find venv
VENV=""
for v in venv .venv env; do
    [ -d "$CLAW_VAULT_DIR/$v" ] && VENV="$CLAW_VAULT_DIR/$v" && break
done
[ -z "$VENV" ] && [ -n "$VIRTUAL_ENV" ] && VENV="$VIRTUAL_ENV"
if [ -z "$VENV" ]; then
    echo "❌ No virtualenv found. Run: python3 -m venv venv && source venv/bin/activate && pip install -e ."
    exit 1
fi

echo "🛡️  Starting ClawVault"
echo "========================"

start_claw_vault() {
    cd "$CLAW_VAULT_DIR"
    source "$VENV/bin/activate"

    # Ensure ssl_verify is false for dev
    CONF="$HOME/.ClawVault/config.yaml"
    if [ -f "$CONF" ] && grep -q "ssl_verify: true" "$CONF"; then
        sed -i 's/ssl_verify: true/ssl_verify: false/' "$CONF" 2>/dev/null || \
        sed -i '' 's/ssl_verify: true/ssl_verify: false/' "$CONF"
    fi

    nohup claw-vault start --dashboard-host 0.0.0.0 > "$LOG" 2>&1 &
    sleep 3

    if curl -s http://127.0.0.1:8766/api/health > /dev/null 2>&1; then
        echo "✓ ClawVault started (PID: $!)"
    else
        echo "❌ Failed to start. Check: tail -f $LOG"
        exit 1
    fi
}

inspect_redaction_status() {
    python3 - "$1" <<'PY'
import json
import sys

try:
    payload = json.loads(sys.argv[1])
except json.JSONDecodeError:
    print("missing\t")
    raise SystemExit(0)

info = payload.get("openclaw_session_redaction")
if not isinstance(info, dict):
    print("missing\t")
    raise SystemExit(0)

enabled = info.get("enabled")
running = info.get("running")
root = info.get("sessions_root", "")

if enabled is False:
    state = "disabled"
elif enabled is True and running is True:
    state = "running"
else:
    state = "inactive"

print(f"{state}\t{root}")
PY
}

# 1. Start claw-vault
HEALTH_PAYLOAD="$(curl -fsS http://127.0.0.1:8766/api/health 2>/dev/null || true)"
if [ -n "$HEALTH_PAYLOAD" ]; then
    IFS=$'\t' read -r REDACTION_STATE REDACTION_ROOT <<< "$(inspect_redaction_status "$HEALTH_PAYLOAD")"
    if [ "$REDACTION_STATE" = "running" ]; then
        echo "✓ ClawVault already running"
        echo "✓ OpenClaw transcript redaction active: ${REDACTION_ROOT:-unknown}"
    elif [ "$REDACTION_STATE" = "disabled" ]; then
        echo "✓ ClawVault already running"
        echo "⚠️  OpenClaw transcript redaction is disabled in config"
    else
        echo "⚠️  ClawVault dashboard is reachable, but OpenClaw transcript redaction is inactive"
        if command -v pkill > /dev/null 2>&1; then
            pkill -f "claw-vault start" 2>/dev/null || true
            sleep 2
            start_claw_vault
        else
            echo "❌ Cannot restart existing ClawVault process automatically"
            exit 1
        fi
    fi
else
    start_claw_vault
fi

echo ""
echo "  Proxy:     http://127.0.0.1:8765"
echo "  Dashboard: http://127.0.0.1:8766"
echo "  Log:       $LOG"

# 2. Ensure proxy is configured in openclaw-gateway systemd service
if [ -f "$SERVICE_FILE" ]; then
    echo ""
    echo "🔗 Configuring OpenClaw proxy..."

    # Check if proxy already configured
    if grep -q "Environment=HTTP_PROXY=http://127.0.0.1:8765" "$SERVICE_FILE" 2>/dev/null; then
        echo "✓ Proxy already configured in systemd service"
    else
        # Run setup to inject proxy
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        bash "$SCRIPT_DIR/setup.sh" 2>/dev/null || true
    fi

    # Restart openclaw-gateway to pick up proxy
    echo "→ Restarting openclaw-gateway..."
    systemctl --user restart openclaw-gateway 2>/dev/null && \
        echo "✓ openclaw-gateway restarted with proxy" || \
        echo "⚠️  Could not restart openclaw-gateway"
fi

# Optionally start OpenClaw (non-systemd, e.g. TUI mode)
if [ "$1" = "--with-openclaw" ]; then
    echo ""
    echo "🚀 Starting OpenClaw..."
    export ALL_PROXY=socks5://127.0.0.1:1080
    export HTTP_PROXY=http://127.0.0.1:8765
    export HTTPS_PROXY=http://127.0.0.1:8765
    export NO_PROXY=localhost,127.0.0.1
    if command -v openclaw &> /dev/null; then
        openclaw "${@:2}"
    else
        echo "❌ openclaw not found"
        exit 1
    fi
fi
