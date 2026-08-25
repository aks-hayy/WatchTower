[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$WithOllama,
    [switch]$WithNeo4j,
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Project = "watchtower-acceptance-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
$RunRoot = if ($OutputRoot) { [IO.Path]::GetFullPath($OutputRoot) } else { Join-Path $Root ".acceptance-$Project" }
$SecretDir = Join-Path $RunRoot "secrets"
$EnvFile = Join-Path $RunRoot ".env"
$MasterKey = Join-Path $SecretDir "watchtower_master_key"
$Neo4jKey = Join-Path $SecretDir "watchtower_neo4j_password"
$UiPort = 43000 + (Get-Random -Minimum 100 -Maximum 800)
$Started = $false
$Results = [ordered]@{
    project = $Project
    started_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    checks = [ordered]@{}
    measurements = @()
    hashes = @()
}

function Resolve-Docker {
    if (Get-Command docker -ErrorAction SilentlyContinue) { return (Get-Command docker).Source }
    $candidates = @(
        (Join-Path $env:ProgramFiles "Docker\Docker\resources\bin\docker.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    if ($candidates) { return $candidates[0] }
    throw "Docker Desktop was not found. Start Docker Desktop or install it."
}

$Docker = Resolve-Docker
& $Docker compose version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker Compose is unavailable." }
$ComposeFiles = @("-f", (Join-Path $Root "compose.yaml"))
if ($WithNeo4j) { $ComposeFiles += @("-f", (Join-Path $Root "deploy/compose.neo4j.yaml")) }

function Invoke-Compose {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    & $Docker compose -p $Project --env-file $EnvFile @ComposeFiles @Args
    if ($LASTEXITCODE -ne 0) { throw "Compose command failed: $($Args -join ' ')" }
}

function Set-Check([string]$Name, [bool]$Passed, [string]$Detail) {
    $Results.checks[$Name] = [ordered]@{ passed = $Passed; detail = $Detail }
    if (-not $Passed) { throw "Acceptance check failed: $Name - $Detail" }
}

function New-State {
    New-Item -ItemType Directory -Force -Path $SecretDir | Out-Null
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [IO.File]::WriteAllText($MasterKey, ([Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')))
    if ($WithNeo4j) {
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        [IO.File]::WriteAllText($Neo4jKey, ([Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')))
    }
    @(
        "WATCHTOWER_MASTER_KEY_FILE=$MasterKey",
        $(if ($WithNeo4j) { "WATCHTOWER_NEO4J_PASSWORD_FILE=$Neo4jKey" }),
        "WATCHTOWER_UI_PORT=$UiPort",
        "WATCHTOWER_CONTROLLER_IMAGE=watchtower/controller:$Project",
        "WATCHTOWER_UI_IMAGE=watchtower/ui:$Project",
        "WATCHTOWER_NEO4J_IMAGE=watchtower/neo4j:$Project"
    ) | Set-Content -LiteralPath $EnvFile -Encoding ascii
}

function Wait-Healthy([string]$Service, [int]$TimeoutSeconds = 180) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $state = (& $Docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$Project-$Service-1" 2>$null)
        if ($state -in @("healthy", "running")) { return }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw "$Service did not become healthy. See $RunRoot\logs."
}

try {
    New-State
    if (-not $SkipBuild) {
        Invoke-Compose build
    }
    $upArgs = @()
    if ($WithOllama) { $upArgs += @("--profile", "ai-local") }
    if ($WithNeo4j) { $upArgs += @("--profile", "graph") }
    $upArgs += @("up", "--detach", "--remove-orphans")
    Invoke-Compose @upArgs
    $Started = $true

    Wait-Healthy "controller"
    Wait-Healthy "ui"
    Set-Check "controller_health" $true "controller reported healthy"
    Set-Check "ui_health" $true "UI reported healthy"

    $ui = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$UiPort/" -TimeoutSec 20
    Set-Check "ui_http" ($ui.StatusCode -eq 200) "HTTP $($ui.StatusCode)"

    & $Docker compose -p $Project --env-file $EnvFile @ComposeFiles exec -T controller test -x /opt/watchtower/bin/watchtower-sensor
    Set-Check "rust_sensor_present" ($LASTEXITCODE -eq 0) "Rust sensor binary exists in controller image"

    $doctor = & $Docker compose -p $Project --env-file $EnvFile @ComposeFiles exec -T controller python -W ignore -m core.packet_engine.main doctor --json 2>$null
    Set-Check "doctor_json" ($LASTEXITCODE -eq 0 -and $doctor) "container doctor returned JSON"
    $doctor | Set-Content -LiteralPath (Join-Path $RunRoot "doctor.json") -Encoding utf8

    $graph = & $Docker compose -p $Project --env-file $EnvFile @ComposeFiles exec -T controller python -W ignore -m core.packet_engine.main graph status 2>$null
    Set-Check "graph_status" ($LASTEXITCODE -eq 0) "graph status command completed"
    $graph | Set-Content -LiteralPath (Join-Path $RunRoot "graph-status.json") -Encoding utf8
    if ($WithNeo4j) {
        $seedCode = "from core.storage.database import WatchtowerDB; db=WatchtowerDB(); db.enqueue_graph_events([{'event_key':'acceptance:graph:identity:1','operation':'identity','payload':{'sensor_node_id':'acceptance-node','entity_ip':'198.51.100.7','identity_type':'hostname','identity_label':'acceptance-fixture','model_version':'v2','confidence':1.0}}]); db.close()"
        & $Docker compose -p $Project --env-file $EnvFile @ComposeFiles exec -T controller python -W ignore -c $seedCode 2>$null
        $graphEvent = $null
        $deadline = (Get-Date).AddSeconds(15)
        do {
            Start-Sleep -Seconds 2
            $graphEvent = & $Docker compose -p $Project --env-file $EnvFile @ComposeFiles exec -T controller python -W ignore -c "import json; from core.storage.database import WatchtowerDB; db=WatchtowerDB(); print(json.dumps(db.graph_outbox_status())); db.close()" 2>$null
            try { $graphEventObject = ($graphEvent -join "`n") | ConvertFrom-Json } catch { $graphEventObject = $null }
            if ($graphEventObject -and [int]$graphEventObject.pending -eq 0 -and $graphEventObject.last_materialized_at) { break }
        } while ((Get-Date) -lt $deadline)
        $graphEvent | Set-Content -LiteralPath (Join-Path $RunRoot "graph-materialization.json") -Encoding utf8
        Set-Check "graph_materializer" ($graphEventObject -and [int]$graphEventObject.pending -eq 0 -and $graphEventObject.last_materialized_at) "outbox event delivered by the controller worker"
    }

    New-Item -ItemType Directory -Force -Path (Join-Path $RunRoot "logs") | Out-Null
    Invoke-Compose logs --no-color | Set-Content -LiteralPath (Join-Path $RunRoot "logs\compose.log") -Encoding utf8
    $Results.measurements += (& $Docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' "$Project-controller-1" "$Project-ui-1" 2>$null)
    $Results.measurements | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $RunRoot "resources.json") -Encoding utf8
    $files = Get-ChildItem -LiteralPath $RunRoot -File -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName
        $Results.hashes += [ordered]@{ path = $file.FullName.Substring($RunRoot.Length + 1); sha256 = $hash.Hash.ToLowerInvariant() }
    }
    $Results.status = "passed"
}
catch {
    $Results.status = "failed"
    $Results.error = $_.Exception.Message
}
finally {
    if ($Started) {
        try {
            $downArgs = @()
            if ($WithOllama) { $downArgs += @("--profile", "ai-local") }
            if ($WithNeo4j) { $downArgs += @("--profile", "graph") }
            $downArgs += @("down", "--volumes", "--remove-orphans")
            Invoke-Compose @downArgs
        } catch {}
    }
    $Results.finished_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
    $Results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $RunRoot "acceptance.json") -Encoding utf8
    @(
        "# WatchTower Docker Acceptance",
        "",
        "- Project: $Project",
        "- Status: **$($Results.status)**",
        "- Started: $($Results.started_at)",
        "- Finished: $($Results.finished_at)",
        "",
        "## Checks",
        ($Results.checks.GetEnumerator() | ForEach-Object { "- **$($_.Key)**: $($_.Value.passed) - $($_.Value.detail)" }),
        "",
        "Generated artifacts: $RunRoot"
    ) | Set-Content -LiteralPath (Join-Path $RunRoot "acceptance.md") -Encoding utf8
}

if ($Results.status -ne "passed") { exit 1 }
Write-Output ($Results | ConvertTo-Json -Depth 8)
