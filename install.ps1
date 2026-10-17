[CmdletBinding()]
param(
    [ValidateSet("auto", "hybrid", "native")]
    [string]$Mode = "auto",
    [switch]$InstallPrerequisites = $true,
    [switch]$WithSysmon,
    [switch]$WithNeo4j,
    [switch]$DisableAuth,
    [string]$SysmonExecutable = ""
)

$Root = (Resolve-Path $PSScriptRoot).Path
$arguments = @{}
if ($InstallPrerequisites) { $arguments.InstallPrerequisites = $true }
if ($WithSysmon) { $arguments.WithSysmon = $true }
if ($WithNeo4j) { $arguments.WithNeo4j = $true }
if ($DisableAuth) { $arguments.DisableAuth = $true }
if ($SysmonExecutable) { $arguments.SysmonExecutable = $SysmonExecutable }

$ResolvedMode = $Mode
if ($Mode -eq "auto") {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        $candidates = @(
            (Join-Path $env:ProgramFiles "Docker\Docker\resources\bin\docker.exe"),
            (Join-Path ${env:ProgramFiles(x86)} "Docker\Docker\resources\bin\docker.exe"),
            (Join-Path $env:LOCALAPPDATA "Docker\Docker\resources\bin\docker.exe"),
            (Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe")
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
        if ($candidates) {
            $dockerDirectory = Split-Path -Parent $candidates[0]
            $env:Path = "$dockerDirectory;$env:Path"
            $docker = Get-Command docker -ErrorAction SilentlyContinue
        }
    }

    $dockerReady = $false
    $dockerHost = ""
    if ($docker -and -not $env:DOCKER_HOST) {
        $previousErrorAction = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $contextOutput = & docker context inspect 2>$null
            if ($LASTEXITCODE -eq 0) {
                $contextDetails = @(($contextOutput -join [Environment]::NewLine) | ConvertFrom-Json -ErrorAction Stop)
                if ($contextDetails.Count -eq 1) {
                    $dockerHost = [string]$contextDetails[0].Endpoints.docker.Host
                }
            }
            if ($dockerHost.StartsWith("npipe://", [StringComparison]::OrdinalIgnoreCase)) {
                & docker compose version *> $null
                $composeReady = $LASTEXITCODE -eq 0
                if ($composeReady) {
                    & docker info --format "{{.ServerVersion}}" *> $null
                    $dockerReady = $LASTEXITCODE -eq 0
                }
            }
        } catch {
            $dockerReady = $false
        } finally {
            $ErrorActionPreference = $previousErrorAction
        }
    }

    if ($dockerReady) {
        $ResolvedMode = "hybrid"
        Write-Host "Local Docker Desktop engine is ready; installing the hybrid controller and UI." -ForegroundColor Cyan
        Write-Host "For a single-host native install, run .\install.ps1 -Mode native."
    } else {
        $ResolvedMode = "native"
        Write-Host "A local Docker Desktop engine is unavailable or not selected; installing the native single-host edition." -ForegroundColor Yellow
        Write-Host "Auto mode avoids remote Docker contexts; remote Docker contexts are not selected automatically."
        Write-Host "No container runtime will be installed. For mesh/controller containers, start Docker Desktop and rerun with -Mode hybrid."
    }
}

if ($ResolvedMode -eq "native") {
    # Native mode is a first-class installation path, not a hybrid install
    # that fails early when Docker Desktop is absent.
    & (Join-Path $Root "scripts\setup.ps1") @arguments
} else {
    & (Join-Path $Root "scripts\install-hybrid.ps1") @arguments
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
