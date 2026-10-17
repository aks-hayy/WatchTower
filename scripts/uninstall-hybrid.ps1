[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$KeepData = $true,
    [switch]$Purge
)

$ErrorActionPreference = "Stop"
$Purge = $Purge.IsPresent
if ($Purge) { $KeepData = $false }
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SensorHome = Join-Path $env:LOCALAPPDATA "WatchTower\hybrid-sensor"
$RuntimeRoot = Join-Path $env:LOCALAPPDATA "WatchTower"
$runtimeOverride = $env:WATCHTOWER_HOME
$runtimeOverrideKind = "WATCHTOWER_HOME"
if (-not $runtimeOverride) {
    $runtimeOverride = $env:WATCHTOWER_DATA_DIR
    $runtimeOverrideKind = "WATCHTOWER_DATA_DIR"
}
if ($runtimeOverride) {
    $RuntimeRoot = [IO.Path]::GetFullPath($runtimeOverride)
    if ($Purge) {
        $filesystemRoot = [IO.Path]::GetPathRoot($RuntimeRoot)
        $trimmedRuntimeRoot = $RuntimeRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        $trimmedFilesystemRoot = $filesystemRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        if ($trimmedRuntimeRoot -eq $trimmedFilesystemRoot) {
            throw "Refusing to purge WatchTower runtime override '$RuntimeRoot': it is a filesystem root."
        }
        $requiredRuntimeDirectories = if ($runtimeOverrideKind -eq "WATCHTOWER_HOME") {
            @("data", "config", "cache", "logs")
        } else {
            @("config", "cache", "logs")
        }
        $hasExpectedRuntimeLayout = $true
        foreach ($directory in $requiredRuntimeDirectories) {
            if (-not (Test-Path -LiteralPath (Join-Path $RuntimeRoot $directory) -PathType Container)) {
                $hasExpectedRuntimeLayout = $false
                break
            }
        }
        if (-not $hasExpectedRuntimeLayout) {
            throw "Refusing to purge WatchTower runtime override '$RuntimeRoot': expected WatchTower runtime directories were not found."
        }
    }
}
$containerEnvFile = Join-Path $Root "deploy\container\.env.container"
$containerMasterKey = Join-Path $Root "deploy\container\secrets\watchtower_master_key"
$containerDeploymentConfigured = (Test-Path -LiteralPath $containerEnvFile) -or
    (Test-Path -LiteralPath $containerMasterKey)
$GeneratedPaths = @(
    (Join-Path $Root ".venv"),
    (Join-Path $Root ".deps"),
    (Join-Path $Root "rust\watchtower-sensor\target"),
    (Join-Path $Root "ui\node_modules"),
    (Join-Path $Root "ui\.output"),
    (Join-Path $Root "watchtower_engine.egg-info")
)
if (-not $KeepData) {
    $GeneratedPaths += @(
        $RuntimeRoot,
        (Join-Path $Root "deploy\container\.env.container"),
        (Join-Path $Root "deploy\container\secrets")
    )
}
$cleanupFailures = [System.Collections.Generic.List[string]]::new()

if (-not $Force) {
    Write-Host "This stops WatchTower and removes its containers, local sensor state, and generated dependencies." -ForegroundColor Yellow
    if ($KeepData) {
        Write-Host "Stored evidence and local configuration will be kept under $RuntimeRoot." -ForegroundColor DarkGray
    } else {
        Write-Host "Stored evidence and local configuration will also be removed." -ForegroundColor DarkGray
    }
    Write-Host "Source files and the Git repository are preserved." -ForegroundColor DarkGray
    $confirmation = Read-Host "Type UNINSTALL to continue"
    if ($confirmation -cne "UNINSTALL") {
        Write-Host "Uninstall cancelled." -ForegroundColor Yellow
        exit 2
    }
}

Write-Host "Stopping WatchTower-owned services..." -ForegroundColor Cyan
if ($containerDeploymentConfigured) {
    try {
        & (Join-Path $Root "scripts\run-hybrid.ps1") stop
        if ($LASTEXITCODE -ne 0) { throw "Hybrid runtime stop returned exit code $LASTEXITCODE" }
    } catch {
        Write-Warning "The normal runtime stop did not complete: $($_.Exception.Message)"
    }
} else {
    Write-Host "No container deployment configuration found; skipping hybrid shutdown." -ForegroundColor DarkGray
}

try {
    # Runtime files can be removed while an orphaned Python multiprocessing
    # child still holds them open. Only target processes whose command line
    # points at this checkout and a WatchTower-owned entry point.
    $rootPattern = [regex]::Escape($Root)
    $processFilter = "Name='python.exe' OR Name='pythonw.exe' OR Name='node.exe' OR Name='cmd.exe' OR Name='tower.exe' OR Name='watchtower-sensor.exe'"
    $isOwnedWatchTowerProcess = {
            $_.CommandLine -and
            $_.CommandLine -match $rootPattern -and
            $_.CommandLine -match 'core[\\/]daemon[\\/]server\.py|core\.mesh\.runtime|core\.api\.server:app|ui[\\/]\.output[\\/]server[\\/]index\.mjs|tower(?:\.exe)?["'']?\s+(?:ui|open)\b|watchtower-sensor\.exe'
        }
    $owned = @(Get-CimInstance Win32_Process -Filter $processFilter | Where-Object $isOwnedWatchTowerProcess)
    foreach ($process in $owned) {
        Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction SilentlyContinue
    }
    if ($owned.Count -gt 0) {
        Start-Sleep -Milliseconds 500
        $remaining = @(Get-CimInstance Win32_Process -Filter $processFilter | Where-Object $isOwnedWatchTowerProcess)
        foreach ($process in $remaining) {
            $cleanupFailures.Add("WatchTower process PID $($process.ProcessId)")
        }
    }
} catch {
    if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match "(?i)access is denied|access denied") {
        Write-Warning "Windows denied process inspection. Rerun PowerShell as Administrator, or close WatchTower UI, CLI, and sensor processes before retrying."
    } else {
        Write-Warning "Could not verify whether WatchTower processes remain. Close WatchTower UI, CLI, and sensor processes, then retry uninstall."
    }
    $cleanupFailures.Add("WatchTower process cleanup/verification")
}

$container = Join-Path $Root "scripts\container.ps1"
if ($containerDeploymentConfigured -and (Test-Path -LiteralPath $container)) {
    try {
        $containerCommand = if ($KeepData) { "down" } else { "reset" }
        $containerArguments = @{
            Command = $containerCommand
            WithMesh = $true
            WithOllama = $true
            LinuxSensor = $true
            MeshBindAddress = "127.0.0.1"
            HybridBridge = $true
        }
        if (Test-Path -LiteralPath $containerEnvFile) {
            $containerEnv = Get-Content -LiteralPath $containerEnvFile -Raw
            if ($containerEnv -match "(?m)^\s*WATCHTOWER_NEO4J_PASSWORD_FILE\s*=\s*(.+?)\s*$") {
                $neo4jSecretPath = $Matches[1].Trim().Trim('"').Trim("'")
                if (-not [IO.Path]::IsPathRooted($neo4jSecretPath)) {
                    $neo4jSecretPath = Join-Path $Root $neo4jSecretPath
                }
                if (-not (Test-Path -LiteralPath $neo4jSecretPath)) {
                    throw "Neo4j cleanup configuration exists but its password file is missing: $neo4jSecretPath"
                }
                $containerArguments.WithNeo4j = $true
            }
        }
        & $container @containerArguments
        if ($LASTEXITCODE -ne 0) { throw "Container reset returned exit code $LASTEXITCODE" }
    } catch {
        Write-Warning "Container cleanup was not completed: $($_.Exception.Message)"
        $cleanupFailures.Add("Container cleanup")
    }
}

if ($cleanupFailures.Count -gt 0) {
    Write-Warning "Uninstall incomplete. Cleanup failed or WatchTower resources remain: $($cleanupFailures -join ', '). Generated files and stored data were left untouched."
    exit 1
}

foreach ($path in $GeneratedPaths) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    try {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        Write-Host "Removed $path" -ForegroundColor DarkGray
    } catch {
        Write-Warning "Could not remove ${path}: $($_.Exception.Message)"
        $cleanupFailures.Add($path)
    }
}

$remainingPaths = @($GeneratedPaths | Where-Object { Test-Path -LiteralPath $_ })
foreach ($path in $remainingPaths) {
    if (-not $cleanupFailures.Contains($path)) { $cleanupFailures.Add($path) }
}
if ($cleanupFailures.Count -gt 0) {
    Write-Warning "Uninstall incomplete. Cleanup failed or WatchTower resources remain: $($cleanupFailures -join ', ')"
    exit 1
}

if ($KeepData) {
    Write-Host "WatchTower application files were removed. Stored data was kept at $RuntimeRoot." -ForegroundColor Green
} else {
    Write-Host "WatchTower runtime and stored data have been removed. Source files remain available for a future reinstall." -ForegroundColor Green
}
