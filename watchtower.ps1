[CmdletBinding()]
param(
    [ValidateSet("start", "stop", "restart", "status", "logs", "repair")]
    [string]$Command = "start",
    [switch]$NoBrowser,
    [switch]$NoCli,
    [switch]$WithNeo4j
)

$Root = (Resolve-Path $PSScriptRoot).Path
$arguments = @($Command)
if ($Command -eq "start" -and -not $NoBrowser) { $arguments += "-OpenBrowser" }
if ($NoCli) { $arguments += "-NoCli" }
if ($WithNeo4j) { $arguments += "-WithNeo4j" }
& (Join-Path $Root "scripts\run-hybrid.ps1") @arguments
