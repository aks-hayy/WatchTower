[CmdletBinding()]
param(
    [switch]$InstallPrerequisites,
    [switch]$WithSysmon,
    [switch]$WithNeo4j,
    [switch]$SkipUI,
    [switch]$SkipRust,
    [switch]$Development,
    [switch]$DisableAuth,
    [switch]$SkipDiagnostics,
    [string]$NpcapSdk = $env:NPCAP_SDK,
    [string]$SysmonExecutable = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Previous = Get-Location
$NpcapVersion = "1.88"
$NpcapSha256 = "A2F4EC1E5EA353FF67EFD24B2EBF081BA44532410FAE8D5E146AF0310AA4F56B"
$NpcapSdkVersion = "1.16"
$NpcapSdkSha256 = "F0A8BE7778EE3AE1B99BBBECB27A3FF0F6C111A4093F1C78C5C5A099607184DB"

function Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Refresh-Path {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machine;$user;$env:USERPROFILE\.cargo\bin"
}

function Require-Command([string]$Name, [string]$InstallHint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required. $InstallHint"
    }
}

function Invoke-Checked([scriptblock]$Operation, [string]$Failure) {
    & $Operation
    if ($LASTEXITCODE -ne 0) { throw $Failure }
}

function Invoke-Tower([string[]]$Arguments) {
    # Windows PowerShell promotes native stderr diagnostics to terminating
    # errors under Stop. tower uses stderr for informational logs, so the
    # process exit code is the authoritative success signal here.
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $Tower @Arguments
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if ($exitCode -ne 0) {
        throw "tower $($Arguments -join ' ') failed with exit code $exitCode."
    }
}

function Install-WingetPackage([string]$Id, [string]$Label, [string]$Override = "") {
    Require-Command "winget" "Install Microsoft App Installer, then rerun with -InstallPrerequisites."
    Step "Installing $Label"
    $arguments = @(
        "install", "--id", $Id, "--exact", "--silent",
        "--accept-package-agreements", "--accept-source-agreements"
    )
    if ($Override) { $arguments += @("--override", $Override) }
    & winget @arguments
    if ($LASTEXITCODE -ne 0) { throw "winget could not install $Label ($Id)." }
    Refresh-Path
}

function Ensure-Tool([string]$Command, [string]$PackageId, [string]$Label, [string]$Hint) {
    if (Get-Command $Command -ErrorAction SilentlyContinue) { return }
    if (-not $InstallPrerequisites) { throw "$Command is required. $Hint" }
    Install-WingetPackage $PackageId $Label
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "$Label was installed but $Command is not available in this shell. Open a new PowerShell and rerun setup."
    }
}

function Get-VerifiedDownload([string]$Uri, [string]$Destination, [string]$ExpectedSha256) {
    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination -TimeoutSec 120 -ErrorAction Stop
    } catch {
        # Windows PowerShell's web stack can time out against the official
        # Npcap endpoint even when the same URL is reachable by curl. Keep the
        # fallback pinned to the requested URL and verify the digest below.
        if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
            throw
        }
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        & curl.exe --fail --location --retry 3 --connect-timeout 15 --max-time 180 --output $Destination $Uri
        if ($LASTEXITCODE -ne 0) {
            throw "Download failed with both Invoke-WebRequest and curl.exe: $Uri"
        }
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash
    if ($actual -ne $ExpectedSha256) {
        Remove-Item -LiteralPath $Destination -Force
        throw "Integrity verification failed for $Uri. Expected $ExpectedSha256, received $actual."
    }
}

function Test-NpcapRuntime {
    $service = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
    $driver = Join-Path $env:WINDIR "System32\drivers\npcap.sys"
    $library = Join-Path $env:WINDIR "System32\Npcap\wpcap.dll"
    return $null -ne $service -or ((Test-Path $driver) -and (Test-Path $library))
}

function Ensure-NpcapRuntime {
    if (Test-NpcapRuntime) { return }
    if (-not $InstallPrerequisites) {
        throw "Npcap is required for Windows capture. Install it from https://npcap.com/#download or rerun with -InstallPrerequisites."
    }
    Step "Installing the Npcap packet-capture driver"
    Write-Host "Npcap's free license requires its visible installer. Review and accept the installer prompts." -ForegroundColor Yellow
    $bootstrap = Join-Path $env:TEMP "WatchTower-bootstrap"
    $installer = Join-Path $bootstrap "npcap-$NpcapVersion.exe"
    Get-VerifiedDownload "https://npcap.com/dist/npcap-$NpcapVersion.exe" $installer $NpcapSha256
    $process = Start-Process -FilePath $installer -Verb RunAs -Wait -PassThru
    if ($process.ExitCode -ne 0 -or -not (Test-NpcapRuntime)) {
        throw "Npcap installation was cancelled or did not complete successfully."
    }
}

function Ensure-NpcapSdk {
    if ($NpcapSdk -and (Test-Path $NpcapSdk)) {
        return (Resolve-Path -LiteralPath $NpcapSdk).Path
    }
    $sdkRoot = Join-Path $Root ".deps\npcap-sdk-$NpcapSdkVersion"
    if (-not (Test-Path $sdkRoot)) {
        if (-not $InstallPrerequisites) {
            throw "The Npcap SDK is required for the Rust sensor. Pass -NpcapSdk PATH or rerun with -InstallPrerequisites."
        }
        Step "Downloading the pinned Npcap SDK"
        $archive = Join-Path $Root ".deps\npcap-sdk-$NpcapSdkVersion.zip"
        Get-VerifiedDownload "https://npcap.com/dist/npcap-sdk-$NpcapSdkVersion.zip" $archive $NpcapSdkSha256
        New-Item -ItemType Directory -Force -Path $sdkRoot | Out-Null
        Expand-Archive -LiteralPath $archive -DestinationPath $sdkRoot -Force
        Remove-Item -LiteralPath $archive -Force
    }
    if (-not (Test-Path (Join-Path $sdkRoot "Include")) -or -not (Test-Path (Join-Path $sdkRoot "Lib\x64"))) {
        throw "Npcap SDK at $sdkRoot is incomplete."
    }
    return (Resolve-Path -LiteralPath $sdkRoot).Path
}

function Ensure-WindowsBuildTools {
    $vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($install) { return }
    }
    if (-not $InstallPrerequisites) {
        throw "Visual Studio 2022 Build Tools with the Desktop C++ workload are required. Rerun with -InstallPrerequisites or install them manually."
    }
    Install-WingetPackage "Microsoft.VisualStudio.2022.BuildTools" "Visual Studio C++ Build Tools" "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
}

try {
    Set-Location $Root
    Write-Host "WatchTower 2.0 setup" -ForegroundColor Cyan
    Write-Host "Repository: $Root"

    Refresh-Path
    Ensure-Tool "python" "Python.Python.3.12" "Python 3.12" "Install Python 3.12 or 3.13."
    $null = & python -c "import sys; raise SystemExit(0 if (sys.version_info >= (3,12) and sys.version_info < (3,14)) else 1)"
    if ($LASTEXITCODE -ne 0) { throw "WatchTower V2 requires Python 3.12 or 3.13." }

    if (-not $SkipRust) {
        Ensure-Tool "cargo" "Rustlang.Rustup" "Rust stable" "Install Rust stable with rustup."
        Ensure-WindowsBuildTools
        Ensure-NpcapRuntime
        $NpcapSdk = Ensure-NpcapSdk
    }

    if (-not $SkipUI) {
        Ensure-Tool "node" "OpenJS.NodeJS.LTS" "Node.js LTS" "Install Node.js 20 or newer."
        Require-Command "npm" "Install npm with Node.js."
        $nodeMajor = [int]((& node --version).TrimStart("v").Split(".")[0])
        if ($nodeMajor -lt 20) { throw "WatchTower requires Node.js 20 or newer; found $(& node --version)." }
    }

    Step "Creating the isolated Python environment"
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        Invoke-Checked { & python -m venv .venv } "Could not create the Python virtual environment."
    }
    $Python = Join-Path $Root ".venv\Scripts\python.exe"
    Invoke-Checked { & $Python -m pip install --upgrade pip } "pip upgrade failed."
    $InstallTarget = if ($Development) { ".[dev]" } else { "." }
    Invoke-Checked { & $Python -m pip install -c (Join-Path $Root "requirements\runtime.lock") -e $InstallTarget } "WatchTower Python installation failed."

    if (-not $SkipRust) {
        Step "Building the Rust capture and replay engine"
        & (Join-Path $Root "scripts\build_rust_sensor.ps1") -NpcapSdk $NpcapSdk
        if ($LASTEXITCODE -ne 0) { throw "Rust sensor build failed." }
    }

    if (-not $SkipUI) {
        Step "Building the production UI"
        Push-Location (Join-Path $Root "ui")
        try {
            Invoke-Checked { & npm ci } "UI dependency installation failed."
            Invoke-Checked { & npm run lint } "UI lint failed."
            Invoke-Checked { & npm run typecheck } "UI typecheck failed."
            Invoke-Checked { & npm run build } "UI production build failed."
        } finally {
            Pop-Location
        }
    }

    if ($WithSysmon) {
        Step "Installing the WatchTower Sysmon policy"
        if (-not $SysmonExecutable) {
            $candidate = Get-Command Sysmon64.exe, Sysmon.exe -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($candidate) { $SysmonExecutable = $candidate.Source }
        }
        if (-not $SysmonExecutable -or -not (Test-Path $SysmonExecutable)) {
            throw "Sysmon was requested but not found. Install Microsoft Sysmon and pass -SysmonExecutable PATH."
        }
        $config = Join-Path $Root "config\sysmon\watchtower-sysmon.xml"
        $installed = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1
        $action = if ($installed) { "-c" } else { "-i" }
        & $SysmonExecutable -accepteula $action $config
        if ($LASTEXITCODE -ne 0) { throw "Sysmon policy installation failed. Run setup from an elevated PowerShell." }
    }

    if ($WithNeo4j) {
        Step "Starting the optional loopback Neo4j evidence graph"
        Require-Command "docker" "Install Docker Desktop and start it."
        if (-not $env:WATCHTOWER_NEO4J_PASSWORD) {
            throw "Set WATCHTOWER_NEO4J_PASSWORD in this shell before using -WithNeo4j."
        }
        & docker compose -f (Join-Path $Root "deploy\neo4j.compose.yml") up -d
        if ($LASTEXITCODE -ne 0) { throw "Neo4j startup failed." }
        $ConfigRoot = & $Python -c "from core.runtime_paths import RuntimePaths; print(RuntimePaths.from_environment().config)"
        New-Item -ItemType Directory -Force -Path $ConfigRoot | Out-Null
        @"
neo4j:
  enabled: true
  uri: bolt://127.0.0.1:7687
  username: neo4j
  database: neo4j
"@ | Set-Content -Encoding UTF8 (Join-Path $ConfigRoot "evidence_graph.yaml")
    }

    $Tower = Join-Path $Root ".venv\Scripts\tower.exe"
    Step "Configuring local operator access"
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $authStatus = @(& $Tower auth status 2>&1)
        $authStatusExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    $authStatusText = $authStatus | Out-String
    if ($authStatusExit -eq 0 -and $authStatusText -notmatch "SETUP_REQUIRED") {
        Write-Host "Operator access is already configured; keeping the existing trust settings." -ForegroundColor DarkGray
    } elseif ($DisableAuth) {
        Invoke-Tower @("auth", "setup", "--disable")
    } else {
        Invoke-Tower @("auth", "setup")
    }

    if (-not $SkipDiagnostics) {
        Step "Running installation diagnostics"
        Invoke-Tower @("doctor")
    }

    Write-Host "`nWatchTower setup completed." -ForegroundColor Green
    Write-Host "Launch UI:  .\.venv\Scripts\tower.exe ui"
    Write-Host "CLI shell:  .\.venv\Scripts\tower.exe"
    Write-Host "List input devices: .\.venv\Scripts\tower.exe sources"
} finally {
    Set-Location $Previous
}
