#!/bin/bash
# Setup OpenClaw + ClawVault integration
# Configures proxy in openclaw-gateway systemd service
# Usage: ./scripts/setup.sh

set -e

# Auto-activate virtualenv so clawvault CLI is available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ -z "$VIRTUAL_ENV" ]; then
    for v in venv .venv env; do
        if [ -f "$PROJECT_DIR/$v/bin/activate" ]; then
            source "$PROJECT_DIR/$v/bin/activate"
            break
        fi
    done
fi

SERVICE_FILE="$HOME/.config/systemd/user/openclaw-gateway.service"

echo "🔗 OpenClaw + ClawVault Setup"
echo "========================"
echo ""

# Check clawvault installed
echo "[1/3] Checking installation..."
if ! command -v clawvault &> /dev/null; then
    echo "❌ clawvault not found. Install first:"
    echo "   cd $(pwd) && source venv/bin/activate && pip install -e ."
    exit 1
fi
echo "  ✓ clawvault $(clawvault --version 2>/dev/null || echo 'installed')"

if [ ! -f "$SERVICE_FILE" ]; then
    echo "  ⚠️  openclaw-gateway.service not found at $SERVICE_FILE"
    echo "     Install OpenClaw first, then re-run this script."
else
    echo "  ✓ openclaw-gateway.service found"
fi

# Configure proxy in systemd service
echo "[2/3] Configuring proxy in systemd service..."
if [ -f "$SERVICE_FILE" ]; then
    # Backup
    cp "$SERVICE_FILE" "${SERVICE_FILE}.bak"

    # Remove old proxy env lines (if any)
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

    # Insert proxy env after [Service]
    awk '
    /^\[Service\]/ {
        print $0
        print "Environment=HTTP_PROXY=http://127.0.0.1:8765"
        print "Environment=HTTPS_PROXY=http://127.0.0.1:8765"
        print "Environment=NO_PROXY=localhost,127.0.0.1"
        print "Environment=NODE_TLS_REJECT_UNAUTHORIZED=0"
        next
    }
    { print }
    ' "$SERVICE_FILE" > "${SERVICE_FILE}.tmp"
    mv "${SERVICE_FILE}.tmp" "$SERVICE_FILE"

    # Reload systemd
    systemctl --user daemon-reload 2>/dev/null || true
    echo "  ✓ Proxy configured in $SERVICE_FILE"
    echo "  ✓ systemd daemon reloaded"
else
    echo "  ⚠️  Skipped (service file not found)"
fi

# Init clawvault config
echo "[3/3] Initializing clawvault config..."
CONF="$HOME/.ClawVault/config.yaml"
if [ ! -f "$CONF" ]; then
    clawvault config init 2>/dev/null || true
fi
# Set ssl_verify: false for dev
if [ -f "$CONF" ] && grep -q "ssl_verify: true" "$CONF"; then
    sed -i 's/ssl_verify: true/ssl_verify: false/' "$CONF" 2>/dev/null || \
    sed -i '' 's/ssl_verify: true/ssl_verify: false/' "$CONF"
fi
echo "  ✓ Config ready: $CONF"

echo ""
echo "========================"
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Restart OpenClaw:  systemctl --user restart openclaw-gateway"
echo "  2. Start ClawVault:   ./scripts/start.sh"
echo "  3. Test:              ./scripts/test.sh"
echo "  4. Visit:             http://<server-ip>:8766"
