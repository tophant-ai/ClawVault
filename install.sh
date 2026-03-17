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
VERSION="0.1.0"

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

# Install ClawVault
install_clawvault() {
    log_info "Installing ClawVault..."

    # Try installing from PyPI
    if $PIP_CMD install clawvault --quiet 2>/dev/null; then
        log_info "Successfully installed from PyPI!"
        return 0
    fi

    # PyPI failed, try GitHub
    log_warn "PyPI install failed, trying GitHub..."

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

# Show welcome message
show_welcome() {
    echo ""
    echo "========================================"
    echo "     ClawVault Installation Complete!"
    echo "========================================"
    echo ""
    echo "Usage:"
    echo "  clawvault --help           Show help"
    echo "  clawvault init             Initialize config"
    echo "  clawvault guard            Start guard mode"
    echo ""
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
        --pip-only)
            log_info "Using pip-only mode..."
            ;;
        --github)
            log_info "Using GitHub install mode..."
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --pip-only    Try PyPI install only"
            echo "  --github      Force GitHub install"
            echo "  --help        Show this help"
            exit 0
            ;;
    esac

    check_python
    check_pip
    upgrade_pip
    install_clawvault
    verify_install
    show_welcome
}

main "$@"