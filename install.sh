#!/bin/bash
#
# ClawVault One-line Installer
# Usage: curl -sSL https://raw.githubusercontent.com/tophant-ai/ClawVault/main/install.sh | bash
# Or: bash install.sh
#

set -e

# Configuration
REPO_URL="https://github.com/tophant-ai/ClawVault"
RAW_URL="${REPO_URL}/raw/main/install.sh"
VERSION="0.2.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    else
        echo "unknown"
    fi
}

# Check Python installation
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        log_error "Python not found. Please install Python 3.10+ first."
        echo "Download: https://www.python.org/downloads/"
        exit 1
    fi

    # Check Python version
    PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    PYTHON_MAJOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info[0])')
    PYTHON_MINOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info[1])')

    if [[ $PYTHON_MAJOR -lt 3 ]] || ([[ $PYTHON_MAJOR -eq 3 ]] && [[ $PYTHON_MINOR -lt 10 ]]); then
        log_error "Python version too old: $PYTHON_VERSION, requires 3.10+"
        exit 1
    fi

    log_info "Detected Python $PYTHON_VERSION"
}

# Check pip installation
check_pip() {
    if $PYTHON_CMD -m pip --version &> /dev/null; then
        PIP_CMD="$PYTHON_CMD -m pip"
    elif command -v pip3 &> /dev/null; then
        PIP_CMD="pip3"
    elif command -v pip &> /dev/null; then
        PIP_CMD="pip"
    else
        log_warn "pip not found, attempting to install..."
        install_pip
    fi
    log_info "Detected pip"
}

# Install pip
install_pip() {
    log_info "Installing pip..."
    if [[ $(detect_os) == "macos" ]]; then
        brew install python3-pip 2>/dev/null || $PYTHON_CMD -m ensurepip --upgrade
    else
        $PYTHON_CMD -m ensurepip --upgrade || curl -sSL https://bootstrap.pypa.io/get-pip.py | $PYTHON_CMD
    fi

    if $PYTHON_CMD -m pip --version &> /dev/null; then
        PIP_CMD="$PYTHON_CMD -m pip"
    else
        log_error "Failed to install pip"
        exit 1
    fi
}

# Upgrade pip
upgrade_pip() {
    log_info "Upgrading pip..."
    $PIP_CMD install --upgrade pip --quiet 2>/dev/null || true
}

# Create virtual environment
setup_venv() {
    INSTALL_DIR="$HOME/.clawvault-env"
    log_info "Creating virtual environment at $INSTALL_DIR ..."

    if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/bin/activate" ]; then
        log_info "Virtual environment already exists"
    else
        $PYTHON_CMD -m venv "$INSTALL_DIR"
    fi

    # Switch to venv pip
    source "$INSTALL_DIR/bin/activate"
    PIP_CMD="$PYTHON_CMD -m pip"
    log_info "Virtual environment ready"
}

# Install ClawVault
install_clawvault() {
    log_info "Installing ClawVault from GitHub..."

    # Try latest version
    if $PIP_CMD install "git+${REPO_URL}.git" --quiet 2>/dev/null; then
        log_info "Successfully installed from GitHub!"
        return 0
    fi

    # Try specific version
    log_info "Trying v$VERSION..."
    if $PIP_CMD install "git+${REPO_URL}.git@v$VERSION" --quiet 2>/dev/null; then
        log_info "Successfully installed from GitHub (v$VERSION)!"
        return 0
    fi

    log_error "Installation failed. Check network connection or install manually."
    log_info "Manual install: pip install git+${REPO_URL}.git"
    exit 1
}

# Verify installation
verify_install() {
    log_info "Verifying installation..."

    if command -v clawvault &> /dev/null; then
        log_info "clawvault command installed"
    elif $PYTHON_CMD -m claw_vault --version &> /dev/null; then
        log_info "clawvault module installed"
    else
        log_warn "Unable to verify installation. Run 'clawvault --help' to check."
    fi
}

# Initialize config from template
initialize_config() {
    CONF_DIR="$HOME/.ClawVault"
    CONF="$CONF_DIR/config.yaml"

    if [ -f "$CONF" ]; then
        log_info "Config already exists: $CONF"
        return 0
    fi

    log_info "Initializing configuration..."

    # Try to find config.example.yaml from installed package
    EXAMPLE=$($PYTHON_CMD -c "
import importlib.resources, pathlib, sys
try:
    pkg = importlib.resources.files('claw_vault')
    p = pathlib.Path(str(pkg)) / 'config.example.yaml'
    if p.exists(): print(p); sys.exit(0)
    # fallback: walk parents
    for parent in pathlib.Path(str(pkg)).parents:
        c = parent / 'config.example.yaml'
        if c.exists(): print(c); sys.exit(0)
except: pass
" 2>/dev/null)

    mkdir -p "$CONF_DIR"

    if [ -n "$EXAMPLE" ] && [ -f "$EXAMPLE" ]; then
        cp "$EXAMPLE" "$CONF"
        # Set ssl_verify: false for dev
        sed -i 's/ssl_verify: true/ssl_verify: false/' "$CONF" 2>/dev/null || \
        sed -i '' 's/ssl_verify: true/ssl_verify: false/' "$CONF"
        log_info "Config created from template: $CONF"
    else
        # Fallback: use clawvault config init
        clawvault config init 2>/dev/null || true
        if [ -f "$CONF" ] && grep -q "ssl_verify: true" "$CONF"; then
            sed -i 's/ssl_verify: true/ssl_verify: false/' "$CONF" 2>/dev/null || \
            sed -i '' 's/ssl_verify: true/ssl_verify: false/' "$CONF"
        fi
        log_info "Config initialized: $CONF"
    fi
}

# Integrate with OpenClaw proxy (if openclaw-gateway service exists)
integrate_openclaw_proxy() {
    SERVICE_FILE="$HOME/.config/systemd/user/openclaw-gateway.service"

    if [ ! -f "$SERVICE_FILE" ]; then
        log_info "OpenClaw gateway service not found, skipping proxy integration"
        return 0
    fi

    log_info "Integrating with OpenClaw gateway..."

    # Backup
    cp "$SERVICE_FILE" "${SERVICE_FILE}.bak"

    # Remove old proxy env lines
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
    log_info "Proxy configured in OpenClaw gateway service"
}

# Show welcome message
show_welcome() {
    echo ""
    echo "========================================"
    echo "     ClawVault Installation Complete!"
    echo "========================================"
    echo ""
    echo "Quick start:"
    echo "  source $INSTALL_DIR/bin/activate"
    echo "  clawvault start            Start proxy + dashboard"
    echo ""
    echo "Commands:"
    echo "  clawvault --help           Show help"
    echo "  clawvault scan 'text'      Scan text for secrets"
    echo "  clawvault demo             Run interactive demo"
    echo "  clawvault status           Check service status"
    echo ""
    echo "Config: ~/.ClawVault/config.yaml"
    echo "Dashboard: http://127.0.0.1:8766"
    echo "Docs: https://ClawVault.dev"
    echo ""
}

# Main function
main() {
    echo "ClawVault One-line Installer v$VERSION"
    echo "================================"
    echo ""

    # Parse arguments
    case "${1:-}" in
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --help        Show this help"
            exit 0
            ;;
    esac

    check_python
    setup_venv
    check_pip
    upgrade_pip
    install_clawvault
    verify_install
    initialize_config
    integrate_openclaw_proxy
    show_welcome
}

main "$@"