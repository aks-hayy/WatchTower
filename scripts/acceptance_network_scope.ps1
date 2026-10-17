function Get-AcceptanceCaptureScope {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Adapter,
        [object[]]$Addresses = @(),
        [Parameter(Mandatory = $true)][string]$ExpectedInterface,
        [Parameter(Mandatory = $true)][string]$ExpectedIPv4
    )

    if (-not $Adapter) {
        return [ordered]@{
            status = "blocked"
            detail = "Authorized capture interface '$ExpectedInterface' was not found. No capture was started."
        }
    }
    if ([string]$Adapter.Name -ne $ExpectedInterface) {
        return [ordered]@{
            status = "blocked"
            detail = "Resolved interface '$($Adapter.Name)' does not match authorized interface '$ExpectedInterface'. No capture was started."
        }
    }
    if ([string]$Adapter.NetworkInterfaceType -notin @("Ethernet", "Wireless80211")) {
        return [ordered]@{
            status = "blocked"
            detail = "Resolved adapter '$ExpectedInterface' is not a physical Ethernet or Wi-Fi interface. No capture was started."
        }
    }
    if ([string]$Adapter.Status -ne "Up") {
        return [ordered]@{
            status = "blocked"
            detail = "Authorized interface '$ExpectedInterface' is '$($Adapter.Status)', not Up. No capture was started."
        }
    }

    $observed = @(
        $Addresses |
            Where-Object {
                ([string]$_.InterfaceIndex -eq [string]$Adapter.InterfaceIndex) -or
                ([string]$_.InterfaceId -and [string]$_.InterfaceId -eq [string]$Adapter.Id)
            } |
            ForEach-Object { [string]$_.IPAddress } |
            Where-Object { $_ }
    )
    if ($ExpectedIPv4 -notin $observed) {
        $observedText = if ($observed.Count) { $observed -join ", " } else { "none" }
        return [ordered]@{
            status = "blocked"
            detail = "Authorized interface '$ExpectedInterface' does not have expected IPv4 '$ExpectedIPv4' (current IPv4: $observedText). No capture was started."
        }
    }

    return [ordered]@{
        status = "passed"
        detail = "Authorized interface and address are present and connected."
        interface = $ExpectedInterface
        interface_index = [string]$Adapter.InterfaceIndex
        adapter_type = [string]$Adapter.NetworkInterfaceType
        ipv4 = $ExpectedIPv4
    }
}

function Get-AcceptanceLiveCaptureGate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][bool]$ScopeVerified,
        [Parameter(Mandatory = $true)][bool]$ExplicitOptIn
    )

    if (-not $ScopeVerified) {
        return [ordered]@{ status = "blocked"; detail = "The authorized interface/address is not verified. No capture was started." }
    }
    if (-not $ExplicitOptIn) {
        return [ordered]@{ status = "blocked"; detail = "Pass -RunAuthorizedLiveCapture to explicitly start the approved 30-minute capture. No capture was started." }
    }
    return [ordered]@{ status = "passed"; detail = "Verified capture scope and explicit live-capture opt-in." }
}
