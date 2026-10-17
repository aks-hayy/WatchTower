function Get-CommandJsonResult {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [string[]]$Output = @(),
        [Parameter(Mandatory = $true)]
        [int]$ExitCode
    )

    $jsonText = ($Output -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($jsonText)) {
        return [pscustomobject]@{
            IsValid = $false
            ExitCode = $ExitCode
            Report = $null
            Error = "Command produced no JSON output."
        }
    }

    try {
        $report = ConvertFrom-Json -InputObject $jsonText -ErrorAction Stop
        return [pscustomobject]@{
            IsValid = $true
            ExitCode = $ExitCode
            Report = $report
            Error = $null
        }
    } catch {
        return [pscustomobject]@{
            IsValid = $false
            ExitCode = $ExitCode
            Report = $null
            Error = $_.Exception.Message
        }
    }
}
