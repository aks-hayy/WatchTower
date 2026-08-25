[CmdletBinding()]
param(
    [switch]$InstallPrerequisites = $true,
    [switch]$WithSysmon,
    [switch]$WithNeo4j,
    [switch]$DisableAuth,
    [string]$SysmonExecutable = ""
)

$Root = (Resolve-Path $PSScriptRoot).Path
$arguments = @()
if ($InstallPrerequisites) { $arguments += "-InstallPrerequisites" }
if ($WithSysmon) { $arguments += "-WithSysmon" }
if ($WithNeo4j) { $arguments += "-WithNeo4j" }
if ($DisableAuth) { $arguments += "-DisableAuth" }
if ($SysmonExecutable) { $arguments += @("-SysmonExecutable", $SysmonExecutable) }
& (Join-Path $Root "scripts\install-hybrid.ps1") @arguments
