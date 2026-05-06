# Watchtower Setup Script (Windows)
# Run from the project root: .\scripts\setup.ps1

Write-Host "================================" -ForegroundColor Cyan
Write-Host "  Watchtower Setup (Windows)    " -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "Please install Python 3.9+ from https://python.org" -ForegroundColor Yellow
    exit 1
}

$pyVersion = python --version 2>&1
Write-Host "Found: $pyVersion" -ForegroundColor Green

# Check Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "WARNING: Node.js is not installed. Dashboard build will be skipped." -ForegroundColor Yellow
    $hasNode = $false
} else {
    $nodeVersion = node --version 2>&1
    Write-Host "Found: Node.js $nodeVersion" -ForegroundColor Green
    $hasNode = $true
}

# Create virtual environment
Write-Host ""
Write-Host "Creating virtual environment..." -ForegroundColor Cyan
if (-not (Test-Path "venv")) {
    python -m venv venv
}
& .\venv\Scripts\Activate.ps1

# Install backend
Write-Host "Installing Python dependencies..." -ForegroundColor Cyan
pip install -e . --quiet

# Setup environment
if (-not (Test-Path ".env")) {
    Write-Host "Creating .env from template..." -ForegroundColor Cyan
    Copy-Item ".env.example" ".env"
}

# Ensure data directory
if (-not (Test-Path "data")) {
    New-Item -ItemType Directory -Path "data" | Out-Null
}

# Build frontend
if ($hasNode) {
    Write-Host ""
    Write-Host "Installing frontend dependencies..." -ForegroundColor Cyan
    Push-Location flow-insights
    npm install --quiet
    Write-Host "Building dashboard..." -ForegroundColor Cyan
    npm run build
    Pop-Location
}

Write-Host ""
Write-Host "================================" -ForegroundColor Green
Write-Host "  Setup Complete!               " -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host ""
Write-Host "To get started:" -ForegroundColor White
Write-Host "  1. Activate the venv:  .\venv\Scripts\Activate.ps1" -ForegroundColor Gray
Write-Host "  2. Launch Watchtower:  tower" -ForegroundColor Gray
Write-Host ""
Write-Host "NOTE: Packet capture requires Administrator privileges." -ForegroundColor Yellow
Write-Host "Right-click PowerShell -> 'Run as Administrator' before using 'tower start'" -ForegroundColor Yellow
