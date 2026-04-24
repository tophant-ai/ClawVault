#!/bin/bash
# Stop ClawVault services and remove proxy from OpenClaw
# Usage: ./scripts/stop.sh

set -e

SERVICE_FILE="$HOME/.config/systemd/user/openclaw-gateway.service"

echo "🛑 Stopping ClawVault"
echo "========================"

# 1. Stop clawvault
PIDS=$(pgrep -f "clawvault start" 2>/dev/null || true)
if [ -n "$PIDS" ]; then
    kill $PIDS 2>/dev/null || true
    sleep 2
    # Force kill if still running
    pgrep -f "clawvault start" > /dev/null 2>&1 && kill -9 $(pgrep -f "clawvault start") 2>/dev/null
    echo "✓ ClawVault stopped"
else
    echo "✓ ClawVault not running"
fi

# 2. Stop gost (SOCKS5 proxy) if running
GOST_PIDS=$(pgrep -f "gost.*1080" 2>/dev/null || true)
if [ -n "$GOST_PIDS" ]; then
    kill $GOST_PIDS 2>/dev/null || true
    echo "✓ SOCKS5 proxy stopped"
fi

# 3. Remove proxy from openclaw-gateway systemd service
if [ -f "$SERVICE_FILE" ] && grep -q "Environment=HTTP_PROXY=" "$SERVICE_FILE" 2>/dev/null; then
    echo "→ Removing proxy from openclaw-gateway service..."
    sed -i '/^Environment=ALL_PROXY=/d' "$SERVICE_FILE" 2>/dev/null || \
    sed -i '' '/^Environment=ALL_PROXY=/d' "$SERVICE_FILE"
    sed -i '/^Environment=HTTP_PROXY=/d' "$SERVICE_FILE" 2>/dev/null || \
    sed -i '' '/^Environment=HTTP_PROXY=/d' "$SERVICE_FILE"
    sed -i '/^Environment=HTTPS_PROXY=/d' "$SERVICE_FILE" 2>/dev/null || \
    sed -i '' '/^Environment=HTTPS_PROXY=/d' "$SERVICE_FILE"
    sed -i '/^Environment=NO_PROXY=/d' "$SERVICE_FILE" 2>/dev/null || \
    sed -i '' '/^Environment=NO_PROXY=/d' "$SERVICE_FILE"
    sed -i '/^Environment=NODE_TLS_REJECT_UNAUTHORIZED=/d' "$SERVICE_FILE" 2>/dev/null || \
    sed -i '' '/^Environment=NODE_TLS_REJECT_UNAUTHORIZED=/d' "$SERVICE_FILE"

    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user restart openclaw-gateway 2>/dev/null && \
        echo "✓ openclaw-gateway restarted without proxy" || \
        echo "⚠️  Could not restart openclaw-gateway"
fi

# 4. Verify ports released
for port in 8765 8766; do
    if ss -tlnp 2>/dev/null | grep -q ":$port " || lsof -i :$port > /dev/null 2>&1; then
        echo "⚠️  Port $port still in use"
    else
        echo "✓ Port $port released"
    fi
done

echo ""
echo "✅ Done."
