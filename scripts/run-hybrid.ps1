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
$SensorHome = if ($env:WATCHTOWER_SENSOR_HOME) {
    [System.IO.Path]::GetFullPath($env:WATCHTOWER_SENSOR_HOME)
} else {
    Join-Path $env:LOCALAPPDATA "WatchTower\hybrid-sensor"
}
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
        (Join-Path $env:LOCALAPPDATA "Docker\Docker\resources\bin\docker.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe")
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
    $previousSensorService = $env:WATCHTOWER_SENSOR_SERVICE
    $previousDaemonPort = $env:WATCHTOWER_DAEMON_PORT
    $env:WATCHTOWER_HOME = $SensorHome
    # The native bridge is a managed sensor service, not a second operator
    # session. Its mesh and capture lifecycle commands must remain headless;
    # controller/UI authentication continues to be enforced normally.
    $env:WATCHTOWER_SENSOR_SERVICE = "1"
    # Keep the native bridge isolated from any standalone tower daemon left on
    # the legacy port by an interrupted development run. Set this on every
    # invocation: an inherited WATCHTOWER_DAEMON_PORT must not silently bind
    # the hybrid sensor to another runtime's key and data root.
    $env:WATCHTOWER_DAEMON_PORT = "10099"
    try {
        & $Tower @Arguments
        if ($LASTEXITCODE -ne 0) {
            $safeArguments = @($Arguments | ForEach-Object {
                if ($_ -is [string] -and ($_ -like "WTJ1-*" -or $_ -match "^(--token|--secret|--password)$")) {
                    "[REDACTED]"
                } else {
                    $_
                }
            })
            throw "Native sensor command failed: tower $($safeArguments -join ' ')"
        }
    } finally {
        if ($null -eq $previousHome) { Remove-Item Env:WATCHTOWER_HOME -ErrorAction SilentlyContinue } else { $env:WATCHTOWER_HOME = $previousHome }
        if ($null -eq $previousSensorService) { Remove-Item Env:WATCHTOWER_SENSOR_SERVICE -ErrorAction SilentlyContinue } else { $env:WATCHTOWER_SENSOR_SERVICE = $previousSensorService }
        if ($null -eq $previousDaemonPort) { Remove-Item Env:WATCHTOWER_DAEMON_PORT -ErrorAction SilentlyContinue } else { $env:WATCHTOWER_DAEMON_PORT = $previousDaemonPort }
    }
}

function Invoke-Container([string]$Action) {
    $arguments = @{
        Command = $Action
        WithMesh = $true
        MeshBindAddress = "127.0.0.1"
        HybridBridge = $true
    }
    if ($WithNeo4j) { $arguments.WithNeo4j = $true }
    if ($Action -eq "up") { $arguments.NoBuild = $true }
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

function Stop-ManagedMeshAgents {
    # A previous interrupted wrapper can leave an agent whose PID record was
    # overwritten. Reap only Python mesh agents using this installation's
    # sensor data directory; never match by a broad process name alone.
    $dataDirPattern = [regex]::Escape((Join-Path $SensorHome "data"))
    $agents = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^python(\.exe)?$' -and
            $_.CommandLine -match 'core\.mesh\.runtime\s+agent-run' -and
            $_.CommandLine -match $dataDirPattern
        }
    foreach ($agent in $agents) {
        if ($agent.ProcessId -and $agent.ProcessId -ne $PID) {
            Stop-Process -Id ([int]$agent.ProcessId) -Force -ErrorAction SilentlyContinue
        }
    }
}

function Join-LocalController {
    $agentDir = Join-Path $SensorHome "data\mesh\agent"
    $credentialsPresent = (Test-Path (Join-Path $agentDir "agent.json")) -and
        (Test-Path (Join-Path $agentDir "client.pem")) -and
        (Test-Path (Join-Path $agentDir "ca.pem"))
    if ($credentialsPresent) {
        try {
            $agentConfig = Get-Content -LiteralPath (Join-Path $agentDir "agent.json") -Raw | ConvertFrom-Json
            if ($agentConfig.controller -eq "127.0.0.1") {
                # A controller rebuild rotates its CA. Do not accept a stale
                # local enrollment just because its files still exist.
                $package = Get-JoinPackage
                $localFingerprint = [string]$agentConfig.controller_ca_fingerprint
                $controllerFingerprint = [string]$package.ca_fingerprint
                if ($localFingerprint -and $localFingerprint -eq $controllerFingerprint) {
                    Write-BridgeState ([ordered]@{
                        enrolled = $true; node_name = $agentConfig.name; controller = $agentConfig.controller
                        ca_fingerprint = $controllerFingerprint
                        enrolled_at = [DateTimeOffset]::UtcNow.ToString("o")
                    })
                    return
                }
                Write-Warning "Local mesh enrollment does not match the current controller CA; creating a fresh enrollment."
                Remove-Item -LiteralPath $agentDir -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $BridgeState -Force -ErrorAction SilentlyContinue
            } else {
                throw "This native sensor is enrolled with $($agentConfig.controller). Run .\scripts\run-hybrid.ps1 repair before using the local bridge."
            }
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

    Step "Starting the native capture control daemon"
    Invoke-Tower @("daemon", "start")

    if ($StartCapture -and -not $SkipCapture) {
        $selected = if ($Interface) { $Interface } else { Get-DefaultInterface }
        Step "Starting Rust capture on $selected"
        Invoke-Tower @("start", "--interface", $selected, "--backend", "rust", "--background")
    }
    Step "Starting secure sensor-to-controller telemetry"
    Stop-ManagedMeshAgents
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
        Stop-ManagedMeshAgents
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
