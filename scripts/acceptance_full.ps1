[CmdletBinding()]
param(
    [ValidateSet("preflight", "source", "offline", "sigma", "docker", "live", "ui-ai", "all")]
    [string]$Stage = "all",
    [string]$OutputRoot = "",
    [switch]$Resume,
    [switch]$KeepArtifacts,
    [string]$SysmonExecutable = "",
    [switch]$RestoreSysmon,
    [switch]$ExcludeSigmaE2E,
    [string]$AuthorizedCaptureInterface = "",
    [string]$AuthorizedCaptureIPv4 = "",
    [switch]$RunAuthorizedLiveCapture,
    [switch]$FullPerformance
)

$ErrorActionPreference = "Stop"
$IsWindowsHost = ($env:OS -eq "Windows_NT")
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
. (Join-Path $PSScriptRoot "acceptance_network_scope.ps1")
$runName = "acceptance-full-$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$RunRoot = if ($OutputRoot) { [IO.Path]::GetFullPath($OutputRoot) } else { Join-Path $Root ".acceptance-$runName" }
$LogRoot = Join-Path $RunRoot "logs"
$ArtifactRoot = Join-Path $RunRoot "artifacts"
$AcceptanceHome = Join-Path $RunRoot "watchtower-home"
$AcceptanceTemp = Join-Path $env:TEMP ("wt-accept-" + [guid]::NewGuid().ToString("N").Substring(0, 10))
$StateFile = Join-Path $RunRoot "acceptance.json"
$StartedProcesses = @()
$StartedDocker = $false
$StartedOllama = $false
$SysmonWasInstalled = $false
$SysmonInitialService = $null
$SysmonInitialChannel = $false

New-Item -ItemType Directory -Force -Path $RunRoot, $LogRoot, $ArtifactRoot, $AcceptanceHome, $AcceptanceTemp | Out-Null
$env:WATCHTOWER_HOME = $AcceptanceHome
$env:TEMP = $AcceptanceTemp
$env:TMP = $AcceptanceTemp

$Results = [ordered]@{
    schema_version = 1
    run_id = $runName
    repository = $Root
    started_at = [DateTimeOffset]::UtcNow.ToString("o")
    scope = [ordered]@{
        sigma_end_to_end = ((-not $ExcludeSigmaE2E) -and ($Stage -in @("sigma", "offline", "all")))
        isolated_state = $true
        self_addressed_injection_only = $true
    }
    stages = [ordered]@{}
    checks = [ordered]@{}
    steps = @()
    measurements = @()
    blockers = @()
    warnings = @()
    sigma = $null
}

if ($Resume -and (Test-Path -LiteralPath $StateFile)) {
    try {
        $saved = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
        foreach ($property in $saved.psobject.Properties) {
            if ($property.Name -notin @("stages", "checks")) { $Results[$property.Name] = $property.Value }
        }
        $loadedStages = [ordered]@{}
        foreach ($property in $saved.stages.psobject.Properties) { $loadedStages[$property.Name] = $property.Value }
        $loadedChecks = [ordered]@{}
        foreach ($property in $saved.checks.psobject.Properties) { $loadedChecks[$property.Name] = $property.Value }
        $Results.stages = $loadedStages
        $Results.checks = $loadedChecks
    } catch {
        $Results.warnings += [ordered]@{ check = "resume_state"; detail = "Could not load prior acceptance state: $($_.Exception.Message)" }
    }
}

function Save-Results {
    $Results.finished_at = [DateTimeOffset]::UtcNow.ToString("o")
    $Results | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $StateFile -Encoding utf8
}

function Add-Log([string]$Name, [object]$Value) {
    $path = Join-Path $LogRoot $Name
    ($Value | Out-String -Width 240) | Set-Content -LiteralPath $path -Encoding utf8
    return $path
}

function Add-ResourceSample([string]$StageName) {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $process = Get-Process -Id $PID -ErrorAction Stop
        $Results.measurements += [ordered]@{
            stage = $StageName
            recorded_at = [DateTimeOffset]::UtcNow.ToString("o")
            process_working_set_bytes = [int64]$process.WorkingSet64
            process_cpu_seconds = [math]::Round([double]$process.CPU, 3)
            system_memory_total_bytes = [int64]$os.TotalVisibleMemorySize * 1KB
            system_memory_free_bytes = [int64]$os.FreePhysicalMemory * 1KB
            disk_free_bytes = [int64]$Results.machine.disk_free_bytes
        }
    } catch {
        try {
            $process = Get-Process -Id $PID -ErrorAction Stop
            $Results.measurements += [ordered]@{
                stage = $StageName
                recorded_at = [DateTimeOffset]::UtcNow.ToString("o")
                process_working_set_bytes = [int64]$process.WorkingSet64
                process_cpu_seconds = [math]::Round([double]$process.CPU, 3)
                system_memory_total_bytes = $null
                system_memory_free_bytes = $null
                disk_free_bytes = if ($Results.machine) { [int64]$Results.machine.disk_free_bytes } else { $null }
                resource_note = "System memory counters unavailable: $($_.Exception.Message)"
            }
        } catch {
            $Results.warnings += [ordered]@{ check = "resource:$StageName"; detail = $_.Exception.Message }
        }
    }
}

function Add-Check([string]$Name, [ValidateSet("passed", "failed", "blocked", "not_applicable", "warning")][string]$Status, [string]$Detail, [string]$StageName = "") {
    $item = [ordered]@{ status = $Status; detail = $Detail; stage = $StageName; recorded_at = [DateTimeOffset]::UtcNow.ToString("o") }
    $Results.checks[$Name] = $item
    if ($Status -eq "blocked") { $Results.blockers += [ordered]@{ check = $Name; detail = $Detail } }
    if ($Status -eq "warning") { $Results.warnings += [ordered]@{ check = $Name; detail = $Detail } }
    Save-Results
}

function Resolve-Executable([string]$Name, [string[]]$Candidates = @()) {
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    $commands = @(Get-Command $Name -All -ErrorAction SilentlyContinue)
    $command = $commands | Where-Object { $_.Source -match '\.(exe|cmd)$' } | Select-Object -First 1
    if (-not $command) { $command = $commands | Select-Object -First 1 }
    if ($command) { return $command.Source }
    return $null
}

function Resolve-NpcapSdk {
    if ($env:NPCAP_SDK -and (Test-NpcapSdkPath -Path $env:NPCAP_SDK)) {
        return (Resolve-Path -LiteralPath $env:NPCAP_SDK).Path
    }

    $pinnedSdk = Join-Path $Root ".deps\npcap-sdk-1.16"
    if (Test-NpcapSdkPath -Path $pinnedSdk) { return (Resolve-Path -LiteralPath $pinnedSdk).Path }

    $legacySdk = Join-Path $Root ".deps\NpcapSDK"
    if (Test-NpcapSdkPath -Path $legacySdk) { return (Resolve-Path -LiteralPath $legacySdk).Path }

    return $null
}

function Test-NpcapSdkPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $header = Join-Path $Path "Include\pcap.h"
    $library = Join-Path $Path "Lib\x64\wpcap.lib"
    return (Test-Path -LiteralPath $Path -PathType Container) -and
        (Test-Path -LiteralPath $header -PathType Leaf) -and
        (Test-Path -LiteralPath $library -PathType Leaf)
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 3600,
        [switch]$AllowFailure,
        [string]$StageName = ""
    )
    $stdoutPath = Join-Path $LogRoot "$Name.stdout.log"
    $stderrPath = Join-Path $LogRoot "$Name.stderr.log"
    $started = Get-Date
    $process = $null
    try {
        $version = (Get-Item -LiteralPath $FilePath -ErrorAction SilentlyContinue).VersionInfo
        $isPythonLauncher = $version -and ($version.InternalName -eq "py.exe" -or $version.FileDescription -eq "Python Launcher")
        if ($isPythonLauncher -or ($FilePath -match "\\python(?:\.exe)?$")) {
            # Invoke Python directly. Start-Process can observe a venv launcher
            # instead of the interpreter on Windows and report a blank exit code.
            Push-Location $Root
            try {
                $previousErrorAction = $ErrorActionPreference
                $ErrorActionPreference = "Continue"
                & $FilePath @Arguments 1> $stdoutPath 2> $stderrPath
                $exitCode = $LASTEXITCODE
                $ErrorActionPreference = $previousErrorAction
            } finally {
                Pop-Location
            }
            $status = if ($exitCode -eq 0) { "passed" } elseif ($AllowFailure) { "warning" } else { "failed" }
            $detail = "Exit code $exitCode"
        } else {
            $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -WorkingDirectory $Root -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
            $script:StartedProcesses += $process
            $deadline = $started.AddSeconds($TimeoutSeconds)
            while (-not $process.HasExited -and (Get-Date) -lt $deadline) {
                Start-Sleep -Milliseconds 250
                $process.Refresh()
            }
            if (-not $process.HasExited) {
                try { $process.Kill($true) } catch { try { $process.Kill() } catch {} }
                $exitCode = $null
                $status = if ($AllowFailure) { "warning" } else { "failed" }
                $detail = "Timed out after $TimeoutSeconds seconds; process was terminated."
            } else {
                $process.WaitForExit()
                $exitCode = $process.ExitCode
                $status = if ($exitCode -eq 0) { "passed" } elseif ($AllowFailure) { "warning" } else { "failed" }
                $detail = "Exit code $exitCode"
            }
        }
    } catch {
        $status = if ($AllowFailure) { "warning" } else { "failed" }
        $detail = $_.Exception.Message
        $exitCode = $null
    }
    $record = [ordered]@{
        name = $Name; status = $status; detail = $detail; exit_code = $exitCode
        seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 3)
        stdout = $stdoutPath; stderr = $stderrPath; command = @($FilePath) + $Arguments
    }
    if (-not $Results.steps) { $Results.steps = @() }
    $Results.steps += $record
    Add-Check $Name $status $detail $StageName
    return $record
}

function Invoke-PythonStep {
    param([string]$Name, [string[]]$Arguments, [int]$TimeoutSeconds = 3600, [switch]$AllowFailure, [string]$StageName = "")
    $python = Resolve-Python
    if (-not $python) {
        Add-Check $Name "blocked" "Python was not found. Create the project environment first." $StageName
        return $null
    }
    return Invoke-Step $Name $python $Arguments $TimeoutSeconds -AllowFailure:$AllowFailure -StageName $StageName
}

function Resolve-Python {
    $candidates = @(
        (Join-Path $Root ".venv\Scripts\python.exe"),
        (Join-Path $Root ".venv\bin\python")
    )
    $candidates += @(Get-Command python -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    foreach ($candidate in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        $version = (Get-Item -LiteralPath $candidate).VersionInfo
        if ($version.InternalName -ne "py.exe" -and $version.InternalName -ne "Python Launcher" -and $version.FileDescription -ne "Python Launcher") {
            return $candidate
        }
        $cfg = Join-Path (Split-Path -Parent (Split-Path -Parent $candidate)) "pyvenv.cfg"
        if (Test-Path -LiteralPath $cfg) {
            $homeLine = Get-Content -LiteralPath $cfg | Where-Object { $_ -match '^home\s*=\s*(.+)$' } | Select-Object -First 1
            if ($homeLine -and $homeLine -match '^home\s*=\s*(.+)$') {
                $basePython = Join-Path $Matches[1].Trim() "python.exe"
                if (Test-Path -LiteralPath $basePython) {
                    $sitePackages = Join-Path (Split-Path -Parent (Split-Path -Parent $candidate)) "Lib\site-packages"
                    if (Test-Path -LiteralPath $sitePackages) {
                        $separator = [IO.Path]::PathSeparator
                        $env:PYTHONPATH = "$Root$separator$sitePackages$separator$($env:PYTHONPATH)".TrimEnd($separator)
                    }
                    return $basePython
                }
            }
        }
    }
    return $null
}

function Invoke-NativeCommand([string]$Name, [string]$Command, [string]$StageName) {
    $shell = if ($IsWindows) { "cmd.exe" } else { "/bin/sh" }
    $args = if ($IsWindows) { @("/d", "/s", "/c", $Command) } else { @("-lc", $Command) }
    return Invoke-Step $Name $shell $args 3600 -StageName $StageName
}

function Test-Administrator {
    if (-not $IsWindowsHost) { return $true }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-InterfaceSnapshot {
    if ($IsWindowsHost) {
        $netsh = netsh interface show interface 2>&1 | Out-String
        Add-Log "interfaces-netsh.txt" $netsh | Out-Null
        $ipconfig = ipconfig /all 2>&1 | Out-String
        Add-Log "interfaces-ipconfig.txt" $ipconfig | Out-Null
        return $netsh
    }
    $result = (& ip -br link 2>&1 | Out-String)
    Add-Log "interfaces-ip.txt" $result | Out-Null
    return $result
}

function Start-OllamaIfNeeded {
    $ollama = Resolve-Executable "ollama" @(
        (Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"),
        (Join-Path $env:ProgramFiles "Ollama\ollama.exe")
    )
    if (-not $ollama) {
        Add-Check "ollama_installed" "blocked" "Ollama executable was not found." "ui-ai"
        return $null
    }
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 3 | Out-Null
        Add-Check "ollama_ready" "passed" "Existing Ollama server responded." "ui-ai"
        return $ollama
    } catch {}
    try {
        $process = Start-Process -FilePath $ollama -ArgumentList @("serve") -WorkingDirectory $RunRoot -RedirectStandardOutput (Join-Path $LogRoot "ollama.stdout.log") -RedirectStandardError (Join-Path $LogRoot "ollama.stderr.log") -PassThru -WindowStyle Hidden
        $script:StartedProcesses += $process
        $script:StartedOllama = $true
        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $deadline) {
            try {
                $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 3
                if ($response.StatusCode -eq 200) {
                    Add-Check "ollama_ready" "passed" "Ollama started by the acceptance runner." "ui-ai"
                    return $ollama
                }
            } catch {}
            Start-Sleep -Milliseconds 500
        }
        Add-Check "ollama_ready" "failed" "Ollama did not become ready within 30 seconds." "ui-ai"
    } catch {
        Add-Check "ollama_ready" "failed" $_.Exception.Message "ui-ai"
    }
    return $ollama
}

function Start-DockerIfNeeded {
    $docker = Resolve-Executable "docker" @(
        (Join-Path $env:ProgramFiles "Docker\Docker\resources\bin\docker.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Docker\Docker\resources\bin\docker.exe"),
        (Join-Path $env:LOCALAPPDATA "Docker\Docker\resources\bin\docker.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe")
    )
    if (-not $docker) {
        Add-Check "docker_installed" "blocked" "Docker Desktop was not found." "docker"
        return $null
    }
    $null = & $docker info 2>$null
    if ($LASTEXITCODE -eq 0) {
        Add-Check "docker_ready" "passed" "Docker engine was already running." "docker"
        return $docker
    }
    $desktop = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
    $desktopCandidates = @(
        $desktop,
        (Join-Path ${env:ProgramFiles(x86)} "Docker\Docker\Docker Desktop.exe"),
        (Join-Path $env:LOCALAPPDATA "Docker\Docker\Docker Desktop.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Docker Desktop\Docker Desktop.exe")
    )
    $desktop = $desktopCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not (Test-Path -LiteralPath $desktop)) {
        Add-Check "docker_ready" "blocked" "Docker engine is stopped and Docker Desktop executable was not found." "docker"
        return $docker
    }
    Start-Process -FilePath $desktop -WindowStyle Hidden | Out-Null
    $StartedDocker = $true
    $deadline = (Get-Date).AddSeconds(120)
    while ((Get-Date) -lt $deadline) {
        $null = & $docker info 2>$null
        if ($LASTEXITCODE -eq 0) {
            Add-Check "docker_ready" "passed" "Docker Desktop started by the acceptance runner." "docker"
            return $docker
        }
        Start-Sleep -Seconds 2
    }
    Add-Check "docker_ready" "failed" "Docker Desktop did not become ready within 120 seconds." "docker"
    return $docker
}

function Invoke-Preflight {
    $driveName = ((Split-Path -Path $Root -Qualifier) -replace ':$', '')
    $drive = [IO.DriveInfo]::GetDrives() | Where-Object { $_.Name -eq "$driveName`:\" } | Select-Object -First 1
    $Results.machine = [ordered]@{
        os = [Environment]::OSVersion.VersionString
        computer = $env:COMPUTERNAME
        processor_count = [Environment]::ProcessorCount
        interfaces = Get-InterfaceSnapshot
        powershell = $PSVersionTable.PSVersion.ToString()
        disk_free_bytes = if ($drive) { [int64]$drive.AvailableFreeSpace } else { $null }
    }
    $python = Resolve-Python
    $npcapSdkPath = Resolve-NpcapSdk
    $cargo = Resolve-Executable "cargo"
    $node = Resolve-Executable "node"
    $npm = Resolve-Executable "npm"
    $Results.tooling = [ordered]@{
        python = $python
        cargo = $cargo
        node = $node
        npm = $npm
        ollama = (Resolve-Executable "ollama" @((Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe")))
        docker = (Resolve-Executable "docker" @(
            (Join-Path $env:ProgramFiles "Docker\Docker\resources\bin\docker.exe"),
            (Join-Path ${env:ProgramFiles(x86)} "Docker\Docker\resources\bin\docker.exe"),
            (Join-Path $env:LOCALAPPDATA "Docker\Docker\resources\bin\docker.exe"),
            (Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe")
        ))
        sysmon = if ($SysmonExecutable) { $SysmonExecutable } else { (Resolve-Executable "Sysmon64.exe" @((Join-Path $env:USERPROFILE "Downloads\SYSMON\Sysmon64.exe"))) }
        npcap = Test-Path -LiteralPath "C:\Program Files\Npcap\npcap.sys"
        npcap_sdk = [bool]$npcapSdkPath
        npcap_sdk_path = $npcapSdkPath
    }
    Add-Check "source_tree_present" "passed" "Acceptance runner resolved repository root $Root." "preflight"
    if ($Results.machine.disk_free_bytes -and $Results.machine.disk_free_bytes -lt 20GB) {
        Add-Check "disk_headroom" "blocked" "At least 20 GiB free disk is required for the 1 GiB PCAP and Docker volumes." "preflight"
    } else { Add-Check "disk_headroom" "passed" "Sufficient disk headroom is available." "preflight" }
    if ($Results.tooling.npcap) { Add-Check "npcap_runtime" "passed" "Npcap runtime is installed." "preflight" } else { Add-Check "npcap_runtime" "blocked" "Npcap runtime is unavailable." "preflight" }
    if ($Results.tooling.npcap_sdk) {
        Add-Check "npcap_sdk" "passed" "Npcap SDK is available at $npcapSdkPath." "preflight"
    } else {
        Add-Check "npcap_sdk" "blocked" "Npcap SDK is missing; Windows Rust build/live capture cannot be verified until it is installed." "preflight"
    }
    if ($Results.tooling.sysmon -and (Test-Path -LiteralPath $Results.tooling.sysmon)) { Add-Check "sysmon_binary" "passed" "Sysmon resolved at $($Results.tooling.sysmon)." "preflight" } else { Add-Check "sysmon_binary" "blocked" "Sysmon was not found; pass -SysmonExecutable or put Sysmon64.exe on PATH." "preflight" }
    Save-Results
}

function Initialize-IsolatedAuth {
    if (-not $Results.tooling.python) { return }
    $helper = Join-Path $RunRoot "disable_acceptance_auth.py"
    @'
from core.storage.database import WatchtowerDB
from core.auth import OperatorAuthService

db = WatchtowerDB()
try:
    OperatorAuthService(db).disable_first_run()
finally:
    db.close()
'@ | Set-Content -LiteralPath $helper -Encoding utf8
    Invoke-Step "isolated_auth_disabled" $Results.tooling.python @($helper) 120 -StageName "preflight" | Out-Null
}

function Invoke-Source {
    $python = $Results.tooling.python
    if (-not $python) { Add-Check "source_python" "blocked" "Python unavailable." "source"; return }
    Invoke-Step "ruff" $python @("-m", "ruff", "check", "core", "tests", "scripts") 900 -StageName "source" | Out-Null
    Invoke-Step "compileall" $python @("-m", "compileall", "-q", "core", "scripts", "tests") 900 -StageName "source" | Out-Null
    if ($Results.tooling.cargo) {
        $buildScript = Join-Path $Root "scripts\build_rust_sensor.ps1"
        if ($Results.tooling.npcap_sdk -and (Test-Path -LiteralPath $buildScript)) {
            $rustTestArguments = @(
                "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $buildScript,
                "-NpcapSdk", $Results.tooling.npcap_sdk_path, "-Test"
            )
            Invoke-Step "rust_tests_windows" "powershell.exe" $rustTestArguments 1800 -StageName "source" | Out-Null
        } else {
            Add-Check "rust_tests_windows" "blocked" "Npcap SDK or the Windows Rust build wrapper is unavailable." "source"
        }
    } else { Add-Check "rust_tests_windows" "blocked" "Cargo unavailable." "source" }
    Invoke-Step "python_tests" $python @("-m", "pytest", "-q") 3600 -StageName "source" | Out-Null
    Invoke-Step "plugin_contracts" $python @("-m", "core.packet_engine.main", "plugins", "test") 900 -StageName "source" | Out-Null
    Invoke-Step "calibration_verify" $python @("-m", "core.packet_engine.main", "plugins", "calibration", "verify") 900 -StageName "source" | Out-Null
    Invoke-Step "release_tree" $python @("tools/check_release_tree.py", "--strict-workspace") 900 -AllowFailure -StageName "source" | Out-Null
    $uiDir = Join-Path $Root "ui"
    if ($Results.tooling.npm -and (Test-Path -LiteralPath (Join-Path $uiDir "package.json"))) {
        Invoke-Step "ui_npm_ci" $Results.tooling.npm @("--prefix", $uiDir, "ci", "--ignore-scripts") 1800 -AllowFailure -StageName "source" | Out-Null
        Invoke-Step "ui_lint" $Results.tooling.npm @("--prefix", $uiDir, "run", "lint") 900 -StageName "source" | Out-Null
        Invoke-Step "ui_typecheck" $Results.tooling.npm @("--prefix", $uiDir, "run", "typecheck") 900 -StageName "source" | Out-Null
        Invoke-Step "ui_build" $Results.tooling.npm @("--prefix", $uiDir, "run", "build") 1200 -StageName "source" | Out-Null
    } else { Add-Check "ui_tooling" "blocked" "npm or UI package manifest unavailable." "source" }
}

function Invoke-Offline {
    $python = $Results.tooling.python
    if (-not $python) { Add-Check "offline_python" "blocked" "Python unavailable." "offline"; return }
    $fixture = Join-Path $ArtifactRoot "acceptance-25MiB.pcap"
    Invoke-Step "generate_25m_pcap" $python @("scripts/generate_acceptance_pcaps.py", "--output", $fixture, "--size", "25MiB") 900 -StageName "offline" | Out-Null
    Invoke-Step "offline_rust_cli_analysis" $python @("scripts/acceptance_offline.py", "--pcap", $fixture) 1800 -StageName "offline" | Out-Null
    Invoke-Step "forensics_tests" $python @("-m", "pytest", "tests/forensics", "-q") 3600 -StageName "offline" | Out-Null
    Invoke-Step "rust_parity_tests" $python @("-m", "pytest", "tests/forensics/test_rust_analysis_parity.py", "tests/forensics/test_rust_fast_analysis.py", "-q") 1800 -StageName "offline" | Out-Null
    if ($ExcludeSigmaE2E) {
        $Results.sigma = [ordered]@{ status = "not_applicable"; reason = "Excluded by -ExcludeSigmaE2E." }
        Add-Check "sigma_e2e_result" "not_applicable" "Sigma end-to-end was explicitly excluded." "offline"
    } else {
        Invoke-Sigma "offline"
    }
    Invoke-Step "pcap_25m_benchmark" $python @("scripts/benchmark_large_pcap.py", "--size-gib", "0.025", "--path", (Join-Path $ArtifactRoot "benchmark-25m.pcap")) 1800 -AllowFailure -StageName "offline" | Out-Null
    if ($FullPerformance) {
        Invoke-Step "pcap_1g_benchmark" $python @("scripts/benchmark_large_pcap.py", "--size-gib", "1.0", "--path", (Join-Path $ArtifactRoot "benchmark-1g.pcap")) 7200 -AllowFailure -StageName "offline" | Out-Null
    } else { Add-Check "pcap_1g_benchmark" "not_applicable" "Pass -FullPerformance to run the multi-gigabyte benchmark." "offline" }
}

function Invoke-Sigma([string]$StageName = "sigma") {
    if ($ExcludeSigmaE2E) {
        $Results.sigma = [ordered]@{ status = "not_applicable"; reason = "Excluded by -ExcludeSigmaE2E." }
        Add-Check "sigma_e2e_result" "not_applicable" "Sigma end-to-end was explicitly excluded." $StageName
        return
    }
    $python = if ($Results.tooling -and $Results.tooling.python) { $Results.tooling.python } else { Resolve-Python }
    if (-not $python) {
        $Results.sigma = [ordered]@{ status = "blocked"; reason = "Python unavailable." }
        Add-Check "sigma_e2e_result" "blocked" "Python unavailable for the isolated Sigma engine check." $StageName
        return
    }
    $script = Join-Path $Root "scripts\acceptance_sigma.py"
    $step = Invoke-Step "sigma_e2e" $python @($script) 180 -StageName $StageName
    if ($step.status -ne "passed") {
        $Results.sigma = [ordered]@{ status = "failed"; reason = $step.detail }
        return
    }
    try {
        $summary = Get-Content -LiteralPath $step.stdout -Raw | ConvertFrom-Json
        $valid = ($summary.status -eq "passed") -and
            ($summary.match_count -eq 1) -and
            ($summary.rule_id -eq "c92ab6e7-9d55-4f33-80f1-4ce91010f998") -and
            ($summary.persisted_alert_count -eq 1)
        if (-not $valid) { throw "Sigma summary did not meet the one-match, one-alert scoped acceptance contract." }
        $Results.sigma = $summary
        Add-Check "sigma_e2e_result" "passed" "Bundled Sigma rule matched one synthetic flow in the selected session and persisted exactly one alert." $StageName
    } catch {
        $Results.sigma = [ordered]@{ status = "failed"; reason = $_.Exception.Message }
        Add-Check "sigma_e2e_result" "failed" $_.Exception.Message $StageName
    }
}

function Invoke-DockerStage {
    $docker = Start-DockerIfNeeded
    if (-not $docker) { return }
    $script = Join-Path $Root "scripts\acceptance_docker.ps1"
    if (-not (Test-Path -LiteralPath $script)) { Add-Check "docker_acceptance_script" "failed" "Docker acceptance script is missing." "docker"; return }
    Invoke-Step "docker_acceptance_neo4j" "powershell.exe" @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $script, "-WithNeo4j", "-OutputRoot", (Join-Path $ArtifactRoot "docker")) 3600 -AllowFailure -StageName "docker" | Out-Null
    Add-Check "mesh_two_node_matrix" "blocked" "The current Docker acceptance script does not yet provision two isolated sensor nodes; this remains a release blocker." "docker"
    Add-Check "ubuntu_install_matrix" "blocked" "Ubuntu installer acceptance requires an available Linux container host and is not run by the Windows-only stage." "docker"
}

function Invoke-Live {
    if (-not $IsWindowsHost) { Add-Check "windows_live_capture" "not_applicable" "Windows native capture stage only." "live"; return }
    if ([string]::IsNullOrWhiteSpace($AuthorizedCaptureInterface) -or [string]::IsNullOrWhiteSpace($AuthorizedCaptureIPv4)) {
        Add-Check "live_capture_scope" "blocked" "Pass -AuthorizedCaptureInterface and -AuthorizedCaptureIPv4 for the expressly approved adapter. No capture was started." "live"
        return
    }
    try {
        # Use the read-only .NET inventory instead of elevated NetAdapter/WMI
        # cmdlets so scope diagnostics work in a non-elevated preflight too.
        $networkInterface = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            Where-Object { $_.Name -ceq $AuthorizedCaptureInterface } |
            Select-Object -First 1
        $adapter = if ($networkInterface) {
            [pscustomobject]@{
                Name = $networkInterface.Name
                Id = $networkInterface.Id
                InterfaceIndex = $networkInterface.Id
                Status = $networkInterface.OperationalStatus.ToString()
                NetworkInterfaceType = $networkInterface.NetworkInterfaceType.ToString()
            }
        } else { $null }
        $addresses = if ($networkInterface) {
            @($networkInterface.GetIPProperties().UnicastAddresses |
                Where-Object { $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                ForEach-Object { [pscustomobject]@{ InterfaceId = $networkInterface.Id; IPAddress = $_.Address.ToString() } })
        } else { @() }
        $scope = Get-AcceptanceCaptureScope $adapter $addresses $AuthorizedCaptureInterface $AuthorizedCaptureIPv4
    } catch {
        $scope = [ordered]@{
            status = "blocked"
            detail = "Could not verify the approved physical capture adapter/address: $($_.Exception.Message). No capture was started."
        }
    }
    if ($scope.status -ne "passed") {
        Add-Check "live_capture_scope" "blocked" $scope.detail "live"
        return
    }
    $Results.live_capture_scope = $scope
    Add-Check "live_capture_scope" "passed" $scope.detail "live"
    $captureGate = Get-AcceptanceLiveCaptureGate ($scope.status -eq "passed") ([bool]$RunAuthorizedLiveCapture)
    if ($captureGate.status -ne "passed") {
        Add-Check "live_capture_opt_in" "blocked" $captureGate.detail "live"
        return
    }
    if (-not (Test-Administrator)) { Add-Check "live_privilege" "blocked" "Windows Rust capture requires an elevated PowerShell session. No capture was started." "live"; return }
    if (-not $Results.tooling.npcap) { Add-Check "live_npcap_runtime" "blocked" "Npcap runtime is unavailable; Rust live capture cannot start." "live"; return }
    if (-not $Results.tooling.python) { Add-Check "live_python" "blocked" "Python unavailable for the isolated Rust capture runner." "live"; return }

    $daemonPortListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $daemonPortListener.Start()
        $isolatedDaemonPort = ([Net.IPEndPoint]$daemonPortListener.LocalEndpoint).Port
    } finally { $daemonPortListener.Stop() }
    $previousHome = $env:WATCHTOWER_HOME
    $previousDaemonPort = $env:WATCHTOWER_DAEMON_PORT
    $previousLiveApproval = $env:WATCHTOWER_ACCEPTANCE_LIVE_APPROVED
    $env:WATCHTOWER_HOME = Join-Path $AcceptanceTemp "watchtower-home"
    $env:WATCHTOWER_DAEMON_PORT = [string]$isolatedDaemonPort
    $env:WATCHTOWER_ACCEPTANCE_LIVE_APPROVED = "1"
    try {
        $runner = Join-Path $Root "scripts\acceptance_live.py"
        Write-Host "Starting the isolated 30-minute Rust capture on $($scope.interface) ($($scope.ipv4)); WatchTower will stop and drain its own session." -ForegroundColor Cyan
        $step = Invoke-Step "live_capture_run" $Results.tooling.python @(
            $runner, "--interface", $scope.interface, "--ipv4", $scope.ipv4,
            "--duration-seconds", "1800"
        ) 3600 -AllowFailure -StageName "live"
    } finally {
        if ($null -eq $previousHome) { Remove-Item Env:\WATCHTOWER_HOME -ErrorAction SilentlyContinue }
        else { $env:WATCHTOWER_HOME = $previousHome }
        if ($null -eq $previousDaemonPort) { Remove-Item Env:\WATCHTOWER_DAEMON_PORT -ErrorAction SilentlyContinue }
        else { $env:WATCHTOWER_DAEMON_PORT = $previousDaemonPort }
        if ($null -eq $previousLiveApproval) { Remove-Item Env:\WATCHTOWER_ACCEPTANCE_LIVE_APPROVED -ErrorAction SilentlyContinue }
        else { $env:WATCHTOWER_ACCEPTANCE_LIVE_APPROVED = $previousLiveApproval }
    }

    try {
        $events = @(
            Get-Content -LiteralPath $step.stdout |
                ForEach-Object { try { $_ | ConvertFrom-Json -ErrorAction Stop } catch { $null } } |
                Where-Object { $_ -and $_.event -eq "complete" }
        )
        $summary = $events | Select-Object -Last 1
        if (-not $summary) { throw "The Rust capture runner did not emit a final JSON result." }
        $Results.live_capture = $summary
        if ($step.exit_code -eq 0 -and $summary.status -eq "passed") {
            Add-Check "live_capture_result" "passed" "Rust capture completed for $($summary.duration_seconds) seconds; session $($summary.session_id); processed $($summary.processed_packets) packets, dropped $($summary.dropped_packets)." "live"
        } elseif ($summary.status -eq "blocked") {
            Add-Check "live_capture_result" "blocked" ([string]$summary.error) "live"
        } else {
            Add-Check "live_capture_result" "failed" ([string]($summary.error ?? $summary.completion_reason ?? "Rust capture did not complete.")) "live"
        }
        Add-Check "sysmon_live_capture" "not_applicable" "Sysmon endpoint telemetry is a separate feature-path check and is not required to validate Rust packet capture." "live"
    } catch {
        Add-Check "live_capture_result" "failed" $_.Exception.Message "live"
    }
}

function Invoke-UiAi {
    $ollama = Start-OllamaIfNeeded
    if (-not $ollama) { return }
    $python = $Results.tooling.python
    if (-not $python) { Add-Check "ai_tests" "blocked" "Python unavailable." "ui-ai"; return }
    Invoke-Step "ai_tests" $python @("-m", "pytest", "tests/ai", "-q") 1800 -StageName "ui-ai" | Out-Null
    Invoke-Step "identity_tests" $python @("-m", "pytest", "tests/identity", "-q") 2400 -StageName "ui-ai" | Out-Null
    Invoke-Step "ollama_live_model" $python @("-W", "ignore", "scripts/acceptance_ollama.py") 600 -AllowFailure -StageName "ui-ai" | Out-Null
    Add-Check "playwright_ui_matrix" "blocked" "No Playwright acceptance project is currently present; route/control coverage requires the UI browser harness." "ui-ai"
    Invoke-Step "web_research_live" $python @("-W", "ignore", "scripts/acceptance_research_live.py") 300 -AllowFailure -StageName "ui-ai" | Out-Null
}

function Invoke-Stage([string]$Name) {
    if ($Results.stages.Contains($Name) -and $Resume -and $Results.stages[$Name].status -eq "passed") {
        Write-Host "Reusing completed stage: $Name" -ForegroundColor DarkGray
        return
    }
    $Results.stages[$Name] = [ordered]@{ status = "running"; started_at = [DateTimeOffset]::UtcNow.ToString("o") }
    Save-Results
    try {
        if ($Name -notin @("preflight", "sigma") -and -not $Results.Contains("tooling")) {
            Invoke-Preflight
        }
        if ($Name -ne "preflight") { Initialize-IsolatedAuth }
        switch ($Name) {
            "preflight" { Invoke-Preflight }
            "source" { Invoke-Source }
            "offline" { Invoke-Offline }
            "sigma" { Invoke-Sigma "sigma" }
            "docker" { Invoke-DockerStage }
            "live" { Invoke-Live }
            "ui-ai" { Invoke-UiAi }
        }
        $stageChecks = @($Results.checks.Values | Where-Object { $_.stage -eq $Name })
        $failed = @($stageChecks | Where-Object { $_.status -eq "failed" }).Count
        $blocked = @($stageChecks | Where-Object { $_.status -eq "blocked" }).Count
        $Results.stages[$Name].status = if ($failed) { "failed" } elseif ($blocked) { "blocked" } else { "passed" }
        Add-ResourceSample $Name
    } catch {
        $Results.stages[$Name].status = "failed"
        $Results.stages[$Name].error = $_.Exception.Message
        Add-Check "stage:$Name" "failed" $_.Exception.Message $Name
    }
    $Results.stages[$Name].finished_at = [DateTimeOffset]::UtcNow.ToString("o")
    Save-Results
}

function Write-Report {
    $statusValues = @($Results.checks.Values | ForEach-Object { $_.status })
    $Results.status = if ($statusValues -contains "failed") { "failed" } elseif ($statusValues -contains "blocked") { "blocked" } else { "passed" }
    $junitPath = Join-Path $RunRoot "acceptance.junit.xml"
    $xml = New-Object System.Text.StringBuilder
    [void]$xml.AppendLine('<?xml version="1.0" encoding="utf-8"?>')
    [void]$xml.AppendLine(('<testsuite name="WatchTower comprehensive acceptance" tests="{0}">' -f $Results.checks.Count))
    foreach ($entry in $Results.checks.GetEnumerator()) {
        $check = $entry.Value
        $name = [Security.SecurityElement]::Escape([string]$entry.Key)
        $detail = [Security.SecurityElement]::Escape([string]$check.detail)
        if ($check.status -eq "failed" -or $check.status -eq "blocked") {
            [void]$xml.AppendLine(('  <testcase classname="acceptance" name="{0}"><failure message="{1}">{1}</failure></testcase>' -f $name, $detail))
        } elseif ($check.status -eq "not_applicable") {
            [void]$xml.AppendLine(('  <testcase classname="acceptance" name="{0}"><skipped message="{1}" /></testcase>' -f $name, $detail))
        } else {
            [void]$xml.AppendLine(('  <testcase classname="acceptance" name="{0}" />' -f $name))
        }
    }
    [void]$xml.AppendLine('</testsuite>')
    $xml.ToString() | Set-Content -LiteralPath $junitPath -Encoding utf8
    $hashes = @()
    Get-ChildItem -LiteralPath $RunRoot -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "artifact-manifest.json" } | ForEach-Object {
        $hashes += [ordered]@{ path = $_.FullName.Substring($RunRoot.Length + 1); sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant() }
    }
    $hashes | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $RunRoot "artifact-manifest.json") -Encoding utf8
    $lines = @(
        "# WatchTower Comprehensive Acceptance",
        "",
        "- Run: **$($Results.run_id)**",
        "- Status: **$($Results.status)**",
        "- Sigma end-to-end excluded: **$($ExcludeSigmaE2E)**",
        "- Isolated state: **true**",
        "",
        "## Stage Results",
        ($Results.stages.GetEnumerator() | ForEach-Object { "- **$($_.Key)**: $($_.Value.status)" }),
        "",
        "## Checks",
        ($Results.checks.GetEnumerator() | ForEach-Object { "- **$($_.Key)**: $($_.Value.status) - $($_.Value.detail)" }),
        "",
        "Artifacts: $RunRoot",
        "JUnit: $junitPath"
    )
    $lines | Set-Content -LiteralPath (Join-Path $RunRoot "acceptance.md") -Encoding utf8
    Save-Results
}

try {
    $requested = if ($Stage -eq "all") { @("preflight", "source", "offline", "docker", "live", "ui-ai") } else { @($Stage) }
    foreach ($item in $requested) { Invoke-Stage $item }
}
finally {
    foreach ($process in @($StartedProcesses)) {
        try { if (-not $process.HasExited) { $process.Kill($true); $process.WaitForExit(5000) } } catch {}
    }
    if (-not $KeepArtifacts) {
        try { Remove-Item -LiteralPath $AcceptanceTemp -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
    if ($RestoreSysmon) {
        Add-Check "sysmon_restore" "warning" "Sysmon restoration is recorded as required; execute the elevated live stage to perform the vendor uninstall/reapply operation." "live"
    }
    Write-Report
}

if ($Results.status -ne "passed") { exit 1 }
Write-Output ($Results | ConvertTo-Json -Depth 12)
