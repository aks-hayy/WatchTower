param(
    [string]$NpcapSdk = $env:NPCAP_SDK,
    [switch]$Test
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Cargo = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
if (-not (Test-Path $Cargo)) { throw "Rust is not installed. Install rustup first." }
if (-not $NpcapSdk -or -not (Test-Path $NpcapSdk)) { throw "Set NPCAP_SDK to the extracted Npcap SDK directory." }
$NpcapSdk = (Resolve-Path -LiteralPath $NpcapSdk).Path
$VsWhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
$Install = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $Install) { throw "Visual C++ x64 build tools are not installed." }
$DevCmd = Join-Path $Install "Common7\Tools\VsDevCmd.bat"
$Manifest = Join-Path $Root "rust\watchtower-sensor\Cargo.toml"
$Lib = Join-Path $NpcapSdk "Lib\x64"
$Include = Join-Path $NpcapSdk "Include"
if (-not (Test-Path -LiteralPath (Join-Path $Lib "wpcap.lib"))) {
    throw "Npcap SDK import library is missing: $(Join-Path $Lib 'wpcap.lib'). Install/extract the Npcap SDK and set NPCAP_SDK to its root (the runtime driver alone is not sufficient)."
}
if (-not (Test-Path -LiteralPath (Join-Path $Include "pcap.h"))) {
    throw "Npcap SDK headers are missing: $(Join-Path $Include 'pcap.h'). Install/extract the Npcap SDK and set NPCAP_SDK to its root."
}
$WindowsKitRoot = "C:\Program Files (x86)\Windows Kits\10"
$WindowsKitVersion = Get-ChildItem (Join-Path $WindowsKitRoot "Lib") -Directory |
    Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name
if (-not $WindowsKitVersion) { throw "A Windows 10 or 11 SDK is required." }
$WindowsLibs = "$(Join-Path $WindowsKitRoot "Lib\$WindowsKitVersion\um\x64");$(Join-Path $WindowsKitRoot "Lib\$WindowsKitVersion\ucrt\x64")"
$WindowsIncludes = "$(Join-Path $WindowsKitRoot "Include\$WindowsKitVersion\um");$(Join-Path $WindowsKitRoot "Include\$WindowsKitVersion\ucrt");$(Join-Path $WindowsKitRoot "Include\$WindowsKitVersion\shared")"
$MsvcRoot = Get-ChildItem (Join-Path $Install "VC\Tools\MSVC") -Directory |
    Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $MsvcRoot) { throw "Visual C++ libraries are required." }
$MsvcLib = Join-Path $MsvcRoot "lib\x64"
$MsvcInclude = Join-Path $MsvcRoot "include"
$CargoCommand = if ($Test) { "test --manifest-path `"$Manifest`"" } else { "build --manifest-path `"$Manifest`" --release" }
$Command = "call `"$DevCmd`" -arch=x64 && set `"LIB=$Lib;$MsvcLib;$WindowsLibs;%LIB%`" && set `"INCLUDE=$Include;$MsvcInclude;$WindowsIncludes;%INCLUDE%`" && `"$Cargo`" $CargoCommand"
& $env:COMSPEC /d /s /c $Command
exit $LASTEXITCODE
