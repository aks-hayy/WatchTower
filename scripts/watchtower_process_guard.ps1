function Find-WatchTowerRuntimeProcesses {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][object[]]$Processes
    )

    $root = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\') + '\'
    $runtimeMarkers = @(
        '\ui\.output\server\index.mjs',
        '\ui\node_modules\.bin\vite',
        '\ui\node_modules\vite\bin\vite.js',
        'core.api.server',
        'core.daemon.server',
        '\.venv\scripts\tower.exe',
        '\rust\watchtower-sensor\target\',
        '\watchtower-sensor.exe'
    )
    $runtimeNames = @('node.exe', 'python.exe', 'pythonw.exe', 'tower.exe', 'watchtower-sensor.exe')

    @(
        foreach ($process in $Processes) {
            $name = [string]$process.Name
            $commandLine = [string]$process.CommandLine
            if ([string]::IsNullOrWhiteSpace($commandLine)) { continue }
            if ($runtimeNames -notcontains $name.ToLowerInvariant()) { continue }

            $normalized = $commandLine.Replace('/', '\')
            if ($normalized.IndexOf($root, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
            $hasRuntimeMarker = $false
            foreach ($marker in $runtimeMarkers) {
                if ($normalized.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $hasRuntimeMarker = $true
                    break
                }
            }
            if ($hasRuntimeMarker) { $process }
        }
    ) | Sort-Object { [int]$_.ProcessId }
}

function Assert-WatchTowerStoppedForSetup {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [object[]]$Processes
    )

    if ($null -eq $Processes) {
        try {
            $Processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
        } catch {
            throw "Setup could not safely inspect running processes ($($_.Exception.Message)). Close WatchTower and rerun setup from an elevated PowerShell if process inspection is restricted. Setup made no changes."
        }
    }

    $root = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\') + '\'
    foreach ($process in $Processes) {
        $name = [string]$process.Name
        $commandLine = [string]$process.CommandLine
        $executablePath = [string]$process.ExecutablePath
        if (
            [string]::IsNullOrWhiteSpace($commandLine) -and
            @('node.exe', 'python.exe', 'pythonw.exe', 'tower.exe', 'watchtower-sensor.exe') -contains $name.ToLowerInvariant() -and
            -not [string]::IsNullOrWhiteSpace($executablePath) -and
            $executablePath.Replace('/', '\').StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)
        ) {
            throw "Setup could not safely identify a running process from this checkout (PID: $($process.ProcessId)); its command line is unavailable. Close WatchTower and rerun setup. Setup made no changes."
        }
    }

    $matching = @(Find-WatchTowerRuntimeProcesses -RepositoryRoot $RepositoryRoot -Processes $Processes)
    if ($matching.Count -gt 0) {
        $ids = ($matching | ForEach-Object { [int]$_.ProcessId }) -join ', '
        throw "WatchTower processes from this checkout are still running (PID(s): $ids). Close WatchTower and rerun setup. Setup made no changes."
    }
}
