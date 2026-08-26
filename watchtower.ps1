[CmdletBinding()]
param(
    [ValidateSet("start", "stop", "ui", "cli", "uninstall", "restart", "status", "logs", "repair")]
    [string]$Command = "start",
    [string]$Interface = "",
    [string]$NodeName = $env:COMPUTERNAME,
    [int]$AgentInterval = 5,
    [switch]$StartCapture,
    [switch]$SkipCapture,
    [switch]$NoBrowser,
    [switch]$NoCli,
    [switch]$WithNeo4j
)

$Root = (Resolve-Path $PSScriptRoot).Path
$runtimeCommand = if ($Command -in @("ui", "cli")) { "start" } else { $Command }
$arguments = @{ Command = $runtimeCommand }
if ($Interface) { $arguments.Interface = $Interface }
if ($NodeName) { $arguments.NodeName = $NodeName }
if ($AgentInterval -ne 5) { $arguments.AgentInterval = $AgentInterval }
if ($StartCapture) { $arguments.StartCapture = $true }
if ($SkipCapture) { $arguments.SkipCapture = $true }
if ($Command -eq "ui" -or ($Command -eq "start" -and -not $NoBrowser)) { $arguments.OpenBrowser = $true }
if ($Command -eq "ui") { $arguments.NoCli = $true }
if ($NoCli) { $arguments.NoCli = $true }
if ($WithNeo4j) { $arguments.WithNeo4j = $true }
if ($Command -eq "uninstall") {
    & (Join-Path $Root "scripts\uninstall-hybrid.ps1")
} else {
    & (Join-Path $Root "scripts\run-hybrid.ps1") @arguments
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
