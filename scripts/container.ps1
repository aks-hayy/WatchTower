[CmdletBinding()]
param(
    [ValidateSet("init", "build", "up", "down", "status", "logs", "config", "reset")]
    [string]$Command = "up",
    [switch]$WithOllama,
    [switch]$WithNeo4j,
    [switch]$WithMesh,
    [switch]$LinuxSensor,
    [string]$MeshBindAddress = "",
    [switch]$HybridBridge,
    [switch]$NoBuild,
    [switch]$Prune
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ContainerDir = Join-Path $Root "deploy\container"
$EnvFile = Join-Path $ContainerDir ".env.container"
$SecretDir = Join-Path $ContainerDir "secrets"
$MasterKey = Join-Path $SecretDir "watchtower_master_key"
$Neo4jKey = Join-Path $SecretDir "watchtower_neo4j_password"

function Require-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        $candidates = @(
            (Join-Path ${env:ProgramFiles} "Docker\Docker\resources\bin\docker.exe"),
            (Join-Path ${env:ProgramFiles(x86)} "Docker\Docker\resources\bin\docker.exe"),
            (Join-Path $env:LOCALAPPDATA "Docker\Docker\resources\bin\docker.exe"),
            (Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe")
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
        if ($candidates) { $env:Path = "$(Split-Path -Parent $candidates[0]);$env:Path" }
    }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "Docker Desktop with Docker Compose is required. Install and start Docker Desktop, then retry."
    }
    & docker compose version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose is unavailable. Start Docker Desktop and retry." }
}

function New-Secret([string]$Path, [int]$Bytes = 32) {
    if (Test-Path -LiteralPath $Path) { return }
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    $encoded = [Convert]::ToBase64String($buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [IO.File]::WriteAllText($Path, $encoded, [Text.UTF8Encoding]::new($false))
}

function Ensure-EnvValue([string]$Name, [string]$Value) {
    $pattern = "(?m)^$([regex]::Escape($Name))=.*$"
    $content = Get-Content -LiteralPath $EnvFile -Raw
    if ($content -match $pattern) { return }
    $suffix = if ($content.EndsWith("`n")) { "" } else { "`r`n" }
    [IO.File]::AppendAllText($EnvFile, "$suffix$Name=$Value`r`n", [Text.UTF8Encoding]::new($false))
}

function Set-EnvValue([string]$Name, [string]$Value) {
    $pattern = "(?m)^$([regex]::Escape($Name))=.*$"
    $content = Get-Content -LiteralPath $EnvFile -Raw
    if ($content -match $pattern) {
        $content = [regex]::Replace($content, $pattern, "$Name=$Value")
        [IO.File]::WriteAllText($EnvFile, $content, [Text.UTF8Encoding]::new($false))
    } else {
        Ensure-EnvValue $Name $Value
    }
}

function Initialize-ContainerState {
    New-Item -ItemType Directory -Force -Path $SecretDir | Out-Null
    if (-not (Test-Path -LiteralPath $EnvFile)) {
        Copy-Item (Join-Path $ContainerDir ".env.container.example") $EnvFile
    }
    New-Secret $MasterKey
    if ($WithNeo4j) {
        New-Secret $Neo4jKey 36
        Ensure-EnvValue "WATCHTOWER_NEO4J_PASSWORD_FILE" "deploy/container/secrets/watchtower_neo4j_password"
    }
    Write-Host "Container configuration is ready: $EnvFile" -ForegroundColor Green
    Write-Host "The installation key stays in $SecretDir and is ignored by Git." -ForegroundColor DarkGray
}

function Compose-Arguments {
    $arguments = @("compose", "--env-file", $EnvFile, "-f", "compose.yaml")
    if ($WithNeo4j) { $arguments += @("-f", "deploy/compose.neo4j.yaml", "--profile", "graph") }
    if ($WithMesh) { $arguments += @("-f", "deploy/compose.mesh.yaml") }
    if ($WithOllama) { $arguments += @("--profile", "ai-local") }
    if ($LinuxSensor) { $arguments += @("--profile", "linux-sensor") }
    return $arguments
}

Set-Location $Root
if ($Command -eq "init") {
    Initialize-ContainerState
    return
}
Require-Docker
if (-not (Test-Path -LiteralPath $EnvFile) -or -not (Test-Path -LiteralPath $MasterKey)) {
    Initialize-ContainerState
}
if ($WithNeo4j) {
    New-Secret $Neo4jKey 36
    Ensure-EnvValue "WATCHTOWER_NEO4J_PASSWORD_FILE" "deploy/container/secrets/watchtower_neo4j_password"
}
if ($WithMesh -and $MeshBindAddress) {
    Set-EnvValue "WATCHTOWER_MESH_BIND_ADDRESS" $MeshBindAddress
}
if ($HybridBridge) {
    Set-EnvValue "WATCHTOWER_HYBRID_BRIDGE" "1"
}

$compose = Compose-Arguments
switch ($Command) {
    "build" { & docker @compose build }
    "up" {
        $upArguments = @("up", "--detach", "--remove-orphans")
        if (-not $NoBuild) { $upArguments += "--build" }
        & docker @compose @upArguments
    }
    "down" { & docker @compose down }
    "status" { & docker @compose ps }
    "logs" { & docker @compose logs --tail 200 --follow }
    "config" { & docker @compose config }
    "reset" {
        & docker @compose down --volumes --remove-orphans
        if ($Prune) { & docker system prune --force }
    }
}
if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose action '$Command' failed with exit code $LASTEXITCODE."
}
