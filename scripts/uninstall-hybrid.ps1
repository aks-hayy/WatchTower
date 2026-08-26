[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SensorHome = Join-Path $env:LOCALAPPDATA "WatchTower\hybrid-sensor"
$RuntimeRoot = Join-Path $env:LOCALAPPDATA "WatchTower"
$GeneratedPaths = @(
    (Join-Path $Root ".venv"),
    (Join-Path $Root ".deps"),
    (Join-Path $Root "rust\watchtower-sensor\target"),
    (Join-Path $Root "ui\node_modules"),
    (Join-Path $Root "ui\.output"),
    (Join-Path $Root "watchtower_engine.egg-info"),
    $RuntimeRoot,
    (Join-Path $Root "deploy\container\.env.container"),
    (Join-Path $Root "deploy\container\secrets")
)

if (-not $Force) {
    Write-Host "This stops WatchTower and removes its containers, volumes, local sensor state, and generated dependencies." -ForegroundColor Yellow
    Write-Host "Source files and the Git repository are preserved." -ForegroundColor DarkGray
    $confirmation = Read-Host "Type UNINSTALL to continue"
    if ($confirmation -cne "UNINSTALL") {
        Write-Host "Uninstall cancelled." -ForegroundColor Yellow
        exit 2
    }
}

Write-Host "Stopping WatchTower-owned services..." -ForegroundColor Cyan
try {
    & (Join-Path $Root "scripts\run-hybrid.ps1") stop
    if ($LASTEXITCODE -ne 0) { throw "Hybrid runtime stop returned exit code $LASTEXITCODE" }
} catch {
    Write-Warning "The normal runtime stop did not complete: $($_.Exception.Message)"
}

try {
    # Runtime files can be removed while an orphaned Python multiprocessing
    # child still holds them open. Only target processes whose command line
    # points at this checkout and a WatchTower-owned entry point.
    $rootPattern = [regex]::Escape($Root)
    $owned = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe' OR Name='watchtower-sensor.exe'" |
        Where-Object {
            $_.CommandLine -and
            $_.CommandLine -match $rootPattern -and
            $_.CommandLine -match 'core\\daemon\\server\.py|core\.mesh\.runtime|watchtower-sensor\.exe'
        }
    foreach ($process in @($owned)) {
        Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction SilentlyContinue
    }
    if ($owned) { Start-Sleep -Milliseconds 500 }
} catch {
    Write-Warning "Could not enumerate stale repository processes: $($_.Exception.Message)"
}

$container = Join-Path $Root "scripts\container.ps1"
if (Test-Path -LiteralPath $container) {
    try {
        & $container reset -WithMesh -MeshBindAddress "127.0.0.1" -HybridBridge
        if ($LASTEXITCODE -ne 0) { throw "Container reset returned exit code $LASTEXITCODE" }
    } catch {
        Write-Warning "Container cleanup was not completed: $($_.Exception.Message)"
    }
}

foreach ($path in $GeneratedPaths) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    try {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        Write-Host "Removed $path" -ForegroundColor DarkGray
    } catch {
        Write-Warning "Could not remove ${path}: $($_.Exception.Message)"
    }
}

Write-Host "WatchTower runtime has been uninstalled. Source files remain available for a future reinstall." -ForegroundColor Green
