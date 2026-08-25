[CmdletBinding()]
param(
    [ValidateSet("start", "stop", "restart", "status", "logs", "repair")]
    [string]$Command = "start",
    [string]$Interface = "",
    [string]$NodeName = $env:COMPUTERNAME,
    [int]$AgentInterval = 5,
    [switch]$OpenBrowser,
    [switch]$StartCapture,
    [switch]$SkipCapture,
    [switch]$NoCli,
    [switch]$WithNeo4j
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Tower = Join-Path $Root ".venv\Scripts\tower.exe"
$SensorHome = Join-Path $env:LOCALAPPDATA "WatchTower\hybrid-sensor"
$BridgeState = Join-Path $SensorHome "bridge.json"
$CliState = Join-Path $SensorHome "controller-cli.json"
$ContainerEnv = Join-Path $Root "deploy\container\.env.container"

function Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Require-HybridInstallation {
    $candidates = @(
        (Join-Path ${env:ProgramFiles} "Docker\Docker\resources\bin\docker.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Docker\Docker\resources\bin\docker.exe"),
        (Join-Path $env:LOCALAPPDATA "Docker\Docker\resources\bin\docker.exe")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue) -and $candidates) {
        $env:Path = "$(Split-Path -Parent $candidates[0]);$env:Path"
    }
    if (-not (Test-Path $Tower)) {
        throw "The native sensor is not installed. Run .\scripts\install-hybrid.ps1 first."
    }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "Docker Desktop is required. Start it, then retry."
    }
    & docker compose version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Docker Desktop is not ready. Start it, then retry." }
}

function Invoke-Tower([string[]]$Arguments) {
    $previousHome = $env:WATCHTOWER_HOME
    $env:WATCHTOWER_HOME = $SensorHome
    try {
        & $Tower @Arguments
        if ($LASTEXITCODE -ne 0) { throw "Native sensor command failed: tower $($Arguments -join ' ')" }
    } finally {
        if ($null -eq $previousHome) { Remove-Item Env:WATCHTOWER_HOME -ErrorAction SilentlyContinue } else { $env:WATCHTOWER_HOME = $previousHome }
    }
}

function Invoke-Container([string]$Action) {
    $arguments = @($Action, "-WithMesh", "-MeshBindAddress", "127.0.0.1", "-HybridBridge")
    if ($WithNeo4j) { $arguments += "-WithNeo4j" }
    if ($Action -eq "up") { $arguments += "-NoBuild" }
    & (Join-Path $Root "scripts\container.ps1") @arguments
    if ($LASTEXITCODE -ne 0) { throw "Container action '$Action' failed." }
}

function Start-OperatorCli {
    if ($NoCli) { return }
    $existing = $null
    if (Test-Path $CliState) {
        try { $existing = Get-Content -LiteralPath $CliState -Raw | ConvertFrom-Json } catch { $existing = $null }
    }
    if ($existing -and $existing.pid -and (Get-Process -Id $existing.pid -ErrorAction SilentlyContinue)) { return }

    $command = "title WatchTower CLI & cd /d `"$Root`" & docker compose --env-file deploy\container\.env.container -f compose.yaml -f deploy\compose.mesh.yaml exec controller tower"
    $process = Start-Process -FilePath $env:ComSpec -ArgumentList "/k", $command -PassThru
    @{ pid = $process.Id; started_at = [DateTimeOffset]::UtcNow.ToString("o") } |
        ConvertTo-Json | Set-Content -LiteralPath $CliState -Encoding utf8
}

function Get-DefaultInterface {
    $adapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq "Up" } |
        Sort-Object -Property ifIndex |
        Select-Object -First 1
    if (-not $adapter) {
        throw "No active physical network adapter was found. Pass -Interface with a name from 'tower sources'."
    }
    return [string]$adapter.Name
}

function Get-JoinPackage {
    $compose = @("compose", "--env-file", $ContainerEnv, "-f", "compose.yaml", "-f", "deploy/compose.mesh.yaml")
    $output = & docker @compose exec -T controller python -m core.mesh.bootstrap provision-local-controller `
        --data-dir /var/lib/watchtower/data --address 127.0.0.1 --node-name $NodeName --ttl 900
    if ($LASTEXITCODE -ne 0) { throw "Could not provision the local mesh controller." }
    try {
        return (($output | Out-String).Trim() | ConvertFrom-Json)
    } catch {
        throw "Controller bootstrap returned an invalid response: $($output | Out-String)"
    }
}

function Ensure-LocalController {
    $compose = @("compose", "--env-file", $ContainerEnv, "-f", "compose.yaml", "-f", "deploy/compose.mesh.yaml")
    & docker @compose exec -T controller python -m core.mesh.bootstrap ensure-local-controller `
        --data-dir /var/lib/watchtower/data --address 127.0.0.1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not start the local mesh controller." }
}

function Wait-ForController {
    $compose = @("compose", "--env-file", $ContainerEnv, "-f", "compose.yaml", "-f", "deploy/compose.mesh.yaml")
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        & docker @compose exec -T controller python /opt/watchtower-healthcheck.py 2>$null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Milliseconds 750
    }
    throw "The WatchTower controller did not become healthy within 60 seconds. Run .\scripts\run-hybrid.ps1 logs."
}

function Read-BridgeState {
    if (-not (Test-Path $BridgeState)) { return $null }
    try { return Get-Content -LiteralPath $BridgeState -Raw | ConvertFrom-Json } catch { return $null }
}

function Write-BridgeState([object]$State) {
    New-Item -ItemType Directory -Force -Path $SensorHome | Out-Null
    $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $BridgeState -Encoding utf8
}

function Join-LocalController {
    $state = Read-BridgeState
    $agentDir = Join-Path $SensorHome "data\mesh\agent"
    $credentialsPresent = (Test-Path (Join-Path $agentDir "agent.json")) -and
        (Test-Path (Join-Path $agentDir "client.pem")) -and
        (Test-Path (Join-Path $agentDir "ca.pem"))
    if ($state -and $state.enrolled -and $credentialsPresent) { return }
    if ($credentialsPresent) {
        try {
            $agentConfig = Get-Content -LiteralPath (Join-Path $agentDir "agent.json") -Raw | ConvertFrom-Json
            if ($agentConfig.controller -eq "127.0.0.1") {
                Write-BridgeState ([ordered]@{
                    enrolled = $true; node_name = $agentConfig.name; controller = $agentConfig.controller
                    enrolled_at = [DateTimeOffset]::UtcNow.ToString("o")
                })
                return
            }
            throw "This native sensor is enrolled with $($agentConfig.controller). Run .\scripts\run-hybrid.ps1 repair before using the local bridge."
        } catch {
            if ($_.Exception.Message -like "This native sensor is enrolled*") { throw }
        }
    }
    Remove-Item -LiteralPath $BridgeState -Force -ErrorAction SilentlyContinue
    Step "Enrolling the native sensor with the local controller"
    $package = Get-JoinPackage
    Invoke-Tower @("mesh", "agent", "join", $package.join_code, "--name", $NodeName, "--yes")
    Write-BridgeState ([ordered]@{
        enrolled = $true
        node_name = $NodeName
        controller = $package.controller
        ca_fingerprint = $package.ca_fingerprint
        enrolled_at = [DateTimeOffset]::UtcNow.ToString("o")
    })
}

function Start-Hybrid {
    Require-HybridInstallation
    if (-not (Test-Path $ContainerEnv)) {
        & (Join-Path $Root "scripts\container.ps1") init -WithMesh -MeshBindAddress "127.0.0.1" -HybridBridge
    }
    Step "Starting the WatchTower controller and UI"
    Invoke-Container "up"
    Wait-ForController
    Ensure-LocalController
    Join-LocalController

    if ($StartCapture -and -not $SkipCapture) {
        $selected = if ($Interface) { $Interface } else { Get-DefaultInterface }
        Step "Starting Rust capture on $selected"
        Invoke-Tower @("daemon", "start")
        Invoke-Tower @("start", "--interface", $selected, "--backend", "rust", "--background")
    }
    Step "Starting secure sensor-to-controller telemetry"
    Invoke-Tower @("mesh", "agent", "start", "--interval", ([Math]::Max(1, $AgentInterval)).ToString())
    Write-Host "`nWatchTower is ready at http://127.0.0.1:4173" -ForegroundColor Green
    Write-Host "Select a capture source in the UI or use the companion tower CLI window." -ForegroundColor DarkGray
    Start-OperatorCli
    if ($OpenBrowser) { Start-Process "http://127.0.0.1:4173" }
}

function Stop-Hybrid {
    if (Test-Path $Tower) {
        Step "Stopping sensor capture and flushing telemetry"
        try { Invoke-Tower @("mesh", "agent", "stop") } catch { Write-Warning $_.Exception.Message }
        try { Invoke-Tower @("stop") } catch { Write-Warning $_.Exception.Message }
        try { Invoke-Tower @("daemon", "stop") } catch { Write-Warning $_.Exception.Message }
    }
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        Step "Stopping the controller and UI"
        Invoke-Container "down"
    }
}

function Repair-Hybrid {
    Step "Resetting only the local bridge enrollment"
    if (Test-Path $Tower) {
        try { Invoke-Tower @("mesh", "agent", "leave", "--force", "--reason", "Hybrid runtime repair") } catch { Write-Warning $_.Exception.Message }
    }
    Remove-Item -LiteralPath $BridgeState -Force -ErrorAction SilentlyContinue
    Start-Hybrid
}

Set-Location $Root
switch ($Command) {
    "start" { Start-Hybrid }
    "stop" { Stop-Hybrid }
    "restart" { Stop-Hybrid; Start-Hybrid }
    "repair" { Repair-Hybrid }
    "status" {
        Require-HybridInstallation
        Invoke-Container "status"
        Invoke-Tower @("daemon", "status")
        Invoke-Tower @("mesh", "agent", "status")
    }
    "logs" {
        Require-HybridInstallation
        Write-Host "Native sensor logs: $SensorHome\data\mesh\agent\runtime.log" -ForegroundColor DarkGray
        Invoke-Container "logs"
    }
}
