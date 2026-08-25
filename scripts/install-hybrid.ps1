[CmdletBinding()]
param(
    [switch]$InstallPrerequisites,
    [switch]$WithSysmon,
    [switch]$WithNeo4j,
    [switch]$DisableAuth,
    [string]$SysmonExecutable = "",
    [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Tower = Join-Path $Root ".venv\Scripts\tower.exe"
$SensorHome = Join-Path $env:LOCALAPPDATA "WatchTower\hybrid-sensor"

function Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Refresh-Path {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machine;$user;$env:USERPROFILE\.cargo\bin"
}

function Resolve-DockerDesktop {
    Refresh-Path
    if (Get-Command docker -ErrorAction SilentlyContinue) { return }
    $candidates = @(
        (Join-Path ${env:ProgramFiles} "Docker\Docker\resources\bin\docker.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Docker\Docker\resources\bin\docker.exe"),
        (Join-Path $env:LOCALAPPDATA "Docker\Docker\resources\bin\docker.exe")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    if ($candidates) {
        $env:Path = "$(Split-Path -Parent $candidates[0]);$env:Path"
    }
}

function Require-DockerDesktop {
    Resolve-DockerDesktop
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        if (-not $InstallPrerequisites) {
            throw "Docker Desktop is required. Install and start it, or rerun with -InstallPrerequisites."
        }
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw "Docker Desktop is required and winget is unavailable. Install Docker Desktop, start it, then rerun this command."
        }
        Step "Installing Docker Desktop"
        & winget install --id Docker.DockerDesktop --exact --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) { throw "Docker Desktop installation failed." }
        throw "Docker Desktop was installed. Start Docker Desktop once, wait until it is running, then rerun this command."
    }
    & docker compose version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Desktop is installed but not ready. Start Docker Desktop and rerun this command."
    }
}

function Invoke-NativeSetup {
    $rustBinary = Join-Path $Root "rust\watchtower-sensor\target\release\watchtower-sensor.exe"
    if ((Test-Path $Tower) -and (Test-Path $rustBinary)) { return }

    Step "Installing the native Rust sensor"
    $previousHome = $env:WATCHTOWER_HOME
    $env:WATCHTOWER_HOME = $SensorHome
    try {
        $arguments = @("-SkipUI", "-DisableAuth")
        if ($InstallPrerequisites) { $arguments += "-InstallPrerequisites" }
        if ($WithSysmon) { $arguments += "-WithSysmon" }
        if ($WithNeo4j) { $arguments += "-WithNeo4j" }
        if ($DisableAuth) { $arguments += "-DisableAuth" }
        if ($SysmonExecutable) { $arguments += @("-SysmonExecutable", $SysmonExecutable) }
        & (Join-Path $Root "scripts\setup.ps1") @arguments
        if ($LASTEXITCODE -ne 0) { throw "Native sensor installation failed." }
    } finally {
        if ($null -eq $previousHome) { Remove-Item Env:WATCHTOWER_HOME -ErrorAction SilentlyContinue } else { $env:WATCHTOWER_HOME = $previousHome }
    }
}

function Initialize-SensorRuntime {
    # The sensor keeps separate local state and has no browser or exposed API.
    # Disabling its private CLI gate avoids an unattended mesh agent being
    # blocked by the operator session that protects the controller/UI.
    if (Test-Path (Join-Path $SensorHome "data\watchtower.db")) { return }
    $previousHome = $env:WATCHTOWER_HOME
    $env:WATCHTOWER_HOME = $SensorHome
    try {
        & $Tower auth setup --disable
        if ($LASTEXITCODE -ne 0) { throw "Could not configure the local sensor runtime." }
    } finally {
        if ($null -eq $previousHome) { Remove-Item Env:WATCHTOWER_HOME -ErrorAction SilentlyContinue } else { $env:WATCHTOWER_HOME = $previousHome }
    }
}

Set-Location $Root
Require-DockerDesktop
Invoke-NativeSetup
Initialize-SensorRuntime

Step "Preparing and building the local controller image"
& (Join-Path $Root "scripts\container.ps1") init -WithMesh -MeshBindAddress "127.0.0.1" -HybridBridge -WithNeo4j:$WithNeo4j
& (Join-Path $Root "scripts\container.ps1") build -WithMesh -MeshBindAddress "127.0.0.1" -HybridBridge -WithNeo4j:$WithNeo4j

Write-Host "`nHybrid installation is ready." -ForegroundColor Green
Write-Host "Start WatchTower: .\watchtower.ps1 start$(if ($WithNeo4j) { ' -WithNeo4j' })"
Write-Host "Select and start a capture interface from the UI or the tower CLI window."
if ($OpenBrowser) {
    & (Join-Path $Root "watchtower.ps1") start
}
