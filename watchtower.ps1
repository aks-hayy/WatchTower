[CmdletBinding()]
param(
    [ValidateSet("start", "stop", "ui", "open", "cli", "setup", "uninstall", "restart", "status", "logs", "repair", "doctor")]
    [string]$Command = "start",
    [string]$Interface = "",
    [string]$NodeName = $env:COMPUTERNAME,
    [int]$AgentInterval = 5,
    [switch]$StartCapture,
    [switch]$SkipCapture,
    [switch]$NoBrowser,
    [switch]$NoCli,
    [switch]$WithNeo4j,
    [switch]$Force,
    [switch]$KeepData,
    [switch]$Purge
)

$Root = (Resolve-Path $PSScriptRoot).Path
$Tower = Join-Path $Root ".venv\Scripts\tower.exe"
$directCommand = $Command -in @("setup", "doctor")

if ($directCommand) {
    if (-not (Test-Path -LiteralPath $Tower)) {
        Write-Error "The WatchTower CLI is not installed yet. Run .\scripts\setup.ps1 first."
        exit 2
    }
    & $Tower $Command
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    exit 0
}

$runtimeCommand = if ($Command -in @("ui", "cli")) { "start" } else { $Command }
$runtimeCommand = if ($Command -eq "open") { "start" } else { $runtimeCommand }
$arguments = @{ Command = $runtimeCommand }
if ($Interface) { $arguments.Interface = $Interface }
if ($NodeName) { $arguments.NodeName = $NodeName }
if ($AgentInterval -ne 5) { $arguments.AgentInterval = $AgentInterval }
if ($StartCapture) { $arguments.StartCapture = $true }
if ($SkipCapture) { $arguments.SkipCapture = $true }
if ($Command -in @("ui", "open") -or ($Command -eq "start" -and -not $NoBrowser)) { $arguments.OpenBrowser = $true }
if ($Command -eq "ui") { $arguments.NoCli = $true }
if ($NoCli) { $arguments.NoCli = $true }
if ($WithNeo4j) { $arguments.WithNeo4j = $true }
if ($Command -eq "uninstall") {
    $uninstallArguments = @{}
    if ($Force) { $uninstallArguments.Force = $true }
    if ($KeepData) { $uninstallArguments.KeepData = $true }
    if ($Purge) { $uninstallArguments.Purge = $true }
    & (Join-Path $Root "scripts\uninstall-hybrid.ps1") @uninstallArguments
} else {
    & (Join-Path $Root "scripts\run-hybrid.ps1") @arguments
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
