#!/usr/bin/env bash
# Watchtower Setup Script (Linux/macOS)
# Run from the project root: bash scripts/setup.sh

set -e

echo "================================"
echo "  Watchtower Setup (Linux/Mac)  "
echo "================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed."
    echo "Install with: sudo apt install python3 python3-venv python3-pip  (Debian/Ubuntu)"
    echo "         or:  brew install python3  (macOS)"
    exit 1
fi

PY_VERSION=$(python3 --version)
echo "Found: $PY_VERSION"

# Check Node.js
HAS_NODE=false
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo "Found: Node.js $NODE_VERSION"
    HAS_NODE=true
else
    echo "WARNING: Node.js not found. Dashboard build will be skipped."
fi

# Check libpcap
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if ! dpkg -s libpcap-dev &> /dev/null 2>&1; then
        echo "WARNING: libpcap-dev not found. Install with: sudo apt install libpcap-dev"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS ships with libpcap
    echo "macOS detected — libpcap is built-in."
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

# Install backend
echo "Installing Python dependencies..."
pip install -e . --quiet

# Setup environment
if [ ! -f ".env" ]; then
    echo "Creating .env from template..."
    cp .env.example .env
fi

# Ensure data directory
mkdir -p data

# Build frontend
if [ "$HAS_NODE" = true ]; then
    echo ""
    echo "Installing frontend dependencies..."
    cd flow-insights
    npm install --quiet
    echo "Building dashboard..."
    npm run build
    cd ..
fi

echo ""
echo "================================"
echo "  Setup Complete!               "
echo "================================"
echo ""
echo "To get started:"
echo "  1. Activate the venv:  source venv/bin/activate"
echo "  2. Launch Watchtower:  tower"
echo ""
echo "NOTE: Packet capture requires root privileges."
echo "Use: sudo $(which tower) start"
