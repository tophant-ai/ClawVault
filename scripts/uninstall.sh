#!/bin/bash
# Uninstall ClawVault and restore OpenClaw to original state
# Usage: ./scripts/uninstall.sh [--keep-config]

KEEP_CONFIG=false
[ "$1" = "--keep-config" ] && KEEP_CONFIG=true

SERVICE_FILE="$HOME/.config/systemd/user/openclaw-gateway.service"

echo "🔄 Uninstall ClawVault"
echo "========================"
echo ""

# 1. Stop services (also removes proxy from systemd)
echo "[1/3] Stopping services..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SCRIPT_DIR/stop.sh" ] && bash "$SCRIPT_DIR/stop.sh" 2>/dev/null || {
    pkill -f "clawvault start" 2>/dev/null || true
    pkill -f "gost.*1080" 2>/dev/null || true
}
echo ""

# 2. Remove proxy from systemd service (if stop.sh didn't handle it)
echo "[2/3] Cleaning proxy config..."
if [ -f "$SERVICE_FILE" ] && grep -q "Environment=HTTP_PROXY=" "$SERVICE_FILE" 2>/dev/null; then
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
    systemctl --user restart openclaw-gateway 2>/dev/null || true
    echo "  ✓ Proxy removed from openclaw-gateway service"
else
    echo "  ✓ No proxy config in systemd service"
fi

# Restore service backup if available
if [ "$KEEP_CONFIG" = false ] && [ -f "${SERVICE_FILE}.bak" ]; then
    cp "${SERVICE_FILE}.bak" "$SERVICE_FILE"
    systemctl --user daemon-reload 2>/dev/null || true
    echo "  ✓ Restored original service file from backup"
fi

# 3. Clean clawvault config
echo "[3/3] Cleaning clawvault config..."
if [ "$KEEP_CONFIG" = true ]; then
    echo "  ✓ Keeping config (--keep-config)"
else
    CONF_DIR="$HOME/.ClawVault"
    if [ -d "$CONF_DIR" ]; then
        echo "  ✓ Config at $CONF_DIR (not removed, use rm -rf to delete manually)"
    fi
fi

echo ""
echo "========================"
echo "✅ Uninstall complete."
echo ""
echo "Re-enable: ./scripts/setup.sh && ./scripts/start.sh"
