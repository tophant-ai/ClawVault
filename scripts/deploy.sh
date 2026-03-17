#!/bin/bash
# One-click deployment and installation script (includes server-side installation)
# Usage: ./deploy.sh <server-ip> [server_user]

set -e

SERVER_IP="$1"
SERVER_USER="${2:-root}"
SERVER_PATH="/root/prj/ClawVault"
VENV_PATH="$SERVER_PATH/venv"
ARCHIVE_NAME="clawvault.zip"

if [ -z "$SERVER_IP" ]; then
    echo "Error: Please provide server IP address"
    echo "Usage: $0 <server-ip> [server_user]"
    echo "Example: $0 123.45.67.89 root"
    exit 1
fi

echo "========================================"
echo "ClawVault One-Click Deploy & Install"
echo "========================================"
echo "Server: $SERVER_USER@$SERVER_IP"
echo "Target path: $SERVER_PATH"
echo "========================================"
echo ""

# Steps 1-4: Package and upload
echo "[1/6] Cleaning old package files..."
rm -f "$ARCHIVE_NAME"
rm -rf clawvault-deploy

echo "[2/6] Preparing project files..."
mkdir -p clawvault-deploy
cp -r src clawvault-deploy/
cp -r tests clawvault-deploy/
cp -r doc clawvault-deploy/
cp -r scripts clawvault-deploy/
chmod +x clawvault-deploy/scripts/*.sh 2>/dev/null || true
cp pyproject.toml clawvault-deploy/
cp install.sh clawvault-deploy/
cp README.md clawvault-deploy/
cp LICENSE clawvault-deploy/
cp config.example.yaml clawvault-deploy/
[ -f .gitignore ] && cp .gitignore clawvault-deploy/

find clawvault-deploy -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find clawvault-deploy -name "*.pyc" -delete 2>/dev/null || true

echo "[3/6] Packaging project..."
cd clawvault-deploy && zip -r "../$ARCHIVE_NAME" . -x "*.DS_Store" -x "__MACOSX/*" && cd ..

echo "[4/6] Uploading to server..."
scp "$ARCHIVE_NAME" "$SERVER_USER@$SERVER_IP:/tmp/"

# Steps 5-6: Extract on server, create venv and install
echo "[5/6] Extracting on server..."
ssh "$SERVER_USER@$SERVER_IP" << ENDSSH
set -e
echo "→ Creating directory and extracting..."
mkdir -p $SERVER_PATH
cd $SERVER_PATH
unzip -q -o /tmp/$ARCHIVE_NAME
rm /tmp/$ARCHIVE_NAME
echo "✓ Extraction complete"
ENDSSH

echo "[6/6] Installing on server..."
ssh "$SERVER_USER@$SERVER_IP" << 'ENDSSH'
set -e
cd /root/prj/ClawVault

echo "→ Checking Python version..."
python3 --version

echo "→ Checking system dependencies..."
# Detect OS type
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    if ! dpkg -l | grep -q python3-venv; then
        echo "  Installing python3-venv..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y python3-venv python3-pip > /dev/null 2>&1
        echo "✓ System dependencies installed"
    else
        echo "✓ System dependencies satisfied"
    fi
elif [ -f /etc/redhat-release ]; then
    # CentOS/RHEL
    if ! rpm -q python3-virtualenv > /dev/null 2>&1; then
        echo "  Installing python3-virtualenv..."
        yum install -y python3-virtualenv > /dev/null 2>&1
        echo "✓ System dependencies installed"
    else
        echo "✓ System dependencies satisfied"
    fi
fi

echo "→ Creating virtual environment..."
# Check if venv exists and is complete
if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
    echo "  Virtual environment already exists and is complete"
else
    if [ -d "venv" ]; then
        echo "  Detected corrupted venv, recreating..."
        rm -rf venv
    fi
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi

echo "→ Activating venv and installing..."
source venv/bin/activate

echo "→ Upgrading pip..."
pip install --upgrade pip setuptools wheel -q

echo "→ Installing ClawVault (dev mode)..."
pip install -e . -q

echo "→ Verifying installation..."
clawvault --version

echo ""
echo "✅ Installation complete!"
echo ""
echo "Available commands:"
echo "  clawvault --version"
echo "  clawvault scan 'test text'"
echo "  clawvault demo"
echo "  clawvault start"
ENDSSH

# Clean up local temp files
echo ""
echo "[Cleanup] Removing local temp files..."
rm -rf clawvault-deploy
rm -f "$ARCHIVE_NAME"

echo ""
echo "========================================"
echo "✅ Deploy & Install Complete!"
echo "========================================"
echo ""
echo "Login to server and test:"
echo "  ssh $SERVER_USER@$SERVER_IP"
echo "  cd $SERVER_PATH"
echo "  source venv/bin/activate"
echo "  clawvault --version"
echo ""
echo "Run quick test:"
echo "  ./scripts/test.sh"
echo ""
