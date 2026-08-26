[CmdletBinding()]
param(
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
& (Join-Path $Root "scripts\install-hybrid.ps1") @arguments
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
