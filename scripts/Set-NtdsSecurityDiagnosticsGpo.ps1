#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    Manages a GPO that sets NTDS diagnostics "2 Security Events" = 1 on all domain controllers
    (variant B: toggle by link state, value is removed when the GPO no longer applies).

.DESCRIPTION
    Install : creates the GPO (user part disabled), links it to the Domain Controllers OU with the
              link DISABLED, adds a GPP registry item (action Replace) and enables
              "Remove this item when it is no longer applied" by setting removePolicy="1" in Registry.xml
              (this option is not exposed by Set-GPPrefRegistryValue). Waits until the patched
              Registry.xml has replicated (SYSVOL/DFSR) to every writable DC.
    Enable  : verifies SYSVOL replication of the patched item on every writable DC, then enables the link.
    Disable : disables the link. GPP removes the value on the next policy refresh of each DC.
    Status  : shows link state, SYSVOL state per DC and the effective registry value per DC.

    Events 3095 (policy load), 3097 (audit) and 3098 (enforced block) of Entra Cloud Sync AD object
    enforcement are written to the Directory Service log only when "2 Security Events" >= 1.

.PARAMETER Action
    Install | Enable | Disable | Status

.PARAMETER GpoName
    Display name of the GPO. Default: 'DC - NTDS Diagnostics - Security Events'

.PARAMETER Refresh
    After Enable/Disable, run "gpupdate /target:computer /force" on all writable DCs via WinRM.

.EXAMPLE
    .\Set-NtdsSecurityDiagnosticsGpo.ps1 -Action Install
    .\Set-NtdsSecurityDiagnosticsGpo.ps1 -Action Enable  -Refresh
    .\Set-NtdsSecurityDiagnosticsGpo.ps1 -Action Disable -Refresh
    .\Set-NtdsSecurityDiagnosticsGpo.ps1 -Action Status

.NOTES
    Toolkit: cloudsync-ad-enforcement-toolkit 1.0.0 (2026-10-19)
    Run as Domain Admin from a host with RSAT. All GPO operations target the PDC emulator.
    WinRM (TCP 5985) to the DCs is only needed for -Refresh and Status.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Install', 'Enable', 'Disable', 'Status')]
    [string] $Action,

    [string] $GpoName = 'DC - NTDS Diagnostics - Security Events',

    [switch] $Refresh
)

$ErrorActionPreference = 'Stop'

#region --- Context ---------------------------------------------------------------------------------
$domain  = Get-ADDomain
$dnsRoot = $domain.DNSRoot
$pdc     = $domain.PDCEmulator
$dcOu    = $domain.DomainControllersContainer
$regKey  = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
$valName = '2 Security Events'
$dcs     = @((Get-ADDomainController -Filter * -Server $pdc | Where-Object { -not $_.IsReadOnly } | Sort-Object HostName).HostName)
#endregion

#region --- Helpers ---------------------------------------------------------------------------------
function Get-TargetGpo {
    try { Get-GPO -Name $GpoName -Domain $dnsRoot -Server $pdc }
    catch { $null }
}

function Get-RegistryXmlPath([string]$Server, [guid]$GpoId) {
    "\\$Server\SYSVOL\$dnsRoot\Policies\{$GpoId}\Machine\Preferences\Registry\Registry.xml"
}

# Returns the writable DCs whose SYSVOL copy does not yet contain the patched registry item
function Get-SysvolPending([guid]$GpoId) {
    @($dcs | Where-Object {
        $p = Get-RegistryXmlPath $_ $GpoId
        try   { -not ((Get-Content -LiteralPath $p -Raw) -match 'removePolicy="1"') }
        catch { $true }
    })
}

function Wait-SysvolReplication([guid]$GpoId, [int]$TimeoutMinutes = 15) {
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    do {
        $pending = Get-SysvolPending $GpoId
        if ($pending.Count -eq 0) { Write-Host 'Patched Registry.xml is present on all writable DCs.' -ForegroundColor Green; return $true }
        Write-Host ("Waiting for SYSVOL replication to: {0}" -f ($pending -join ', ')) -ForegroundColor Yellow
        Start-Sleep -Seconds 20
    } while ((Get-Date) -lt $deadline)
    Write-Warning ("SYSVOL replication not complete after {0} min. Pending: {1}" -f $TimeoutMinutes, ($pending -join ', '))
    return $false
}

function Get-LinkState([guid]$GpoId) {
    $link = (Get-GPInheritance -Target $dcOu -Domain $dnsRoot -Server $pdc).GpoLinks |
            Where-Object { $_.GpoId -eq $GpoId } | Select-Object -First 1
    if ($link) { $link.Enabled } else { $null }
}

function Invoke-DcRefresh {
    Write-Host 'Running gpupdate on all writable DCs ...'
    Invoke-Command -ComputerName $dcs -ScriptBlock { gpupdate.exe /target:computer /force | Out-Null }
}

function Show-DcValues {
    Invoke-Command -ComputerName $dcs -ScriptBlock {
        $p = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ErrorAction SilentlyContinue
        $v = if ($p -and ($p.PSObject.Properties.Name -contains '2 Security Events')) { $p.'2 Security Events' } else { '(not set)' }
        [pscustomobject]@{ DC = $env:COMPUTERNAME; SecurityEvents = $v }
    } | Sort-Object DC | Format-Table DC, SecurityEvents -AutoSize | Out-Host
}
#endregion

switch ($Action) {

    'Install' {
        if (Get-TargetGpo) { throw "GPO '$GpoName' already exists. Use -Action Status / Enable / Disable." }

        # 1. GPO with user part disabled, linked to the DC OU with the link DISABLED (nothing applies yet)
        $gpo = New-GPO -Name $GpoName -Domain $dnsRoot -Server $pdc `
                       -Comment "Sets NTDS\Diagnostics '$valName'=1 (SOA enforcement events 3095/3097/3098). Toggle via link state; value is removed when the GPO no longer applies."
        $gpo.GpoStatus = 'UserSettingsDisabled'
        New-GPLink -Guid $gpo.Id -Target $dcOu -LinkEnabled No -Domain $dnsRoot -Server $pdc | Out-Null
        Write-Host "Created GPO '$GpoName' ($($gpo.Id)) and linked it to $dcOu (link disabled)."

        # 2. GPP registry item, action Replace (required for "remove when no longer applied")
        Set-GPPrefRegistryValue -Guid $gpo.Id -Domain $dnsRoot -Server $pdc -Context Computer -Action Replace `
                                -Key $regKey -ValueName $valName -Type DWord -Value 1 | Out-Null

        # 3. Enable "Remove this item when it is no longer applied" (removePolicy="1") in Registry.xml on the PDCe
        $path = Get-RegistryXmlPath $pdc $gpo.Id
        [xml]$xml = Get-Content -LiteralPath $path -Raw
        $items = @($xml.SelectNodes("//Registry[Properties[@name='$valName']]"))
        if ($items.Count -ne 1) { throw "Expected exactly one registry item for '$valName' in $path, found $($items.Count)." }
        $items[0].SetAttribute('removePolicy', '1')
        $items[0].SetAttribute('bypassErrors', '1')

        $ws = New-Object System.Xml.XmlWriterSettings
        $ws.Encoding = New-Object System.Text.UTF8Encoding($false)
        $writer = [System.Xml.XmlWriter]::Create($path, $ws)
        try { $xml.Save($writer) } finally { $writer.Close() }
        Write-Host "Patched $path (removePolicy=1)."

        # 4. Wait for SYSVOL replication before the link may be enabled
        [void](Wait-SysvolReplication $gpo.Id)
        Write-Host ''
        Write-Host "Done. Verify once in GPMC (Preferences > Registry > item > Common tab: 'Remove this item when it is no longer applied' checked)," -ForegroundColor Cyan
        Write-Host "then run: .\Set-NtdsSecurityDiagnosticsGpo.ps1 -Action Enable -Refresh" -ForegroundColor Cyan
    }

    'Enable' {
        $gpo = Get-TargetGpo
        if (-not $gpo) { throw "GPO '$GpoName' not found. Run -Action Install first." }

        # Never enable before every DC has the patched item - a DC applying an unpatched copy
        # would not remove the value later when the link is disabled.
        $pending = Get-SysvolPending $gpo.Id
        if ($pending.Count) { throw ("Patched Registry.xml not yet replicated to: {0}. Link not enabled." -f ($pending -join ', ')) }

        Set-GPLink -Guid $gpo.Id -Target $dcOu -LinkEnabled Yes -Domain $dnsRoot -Server $pdc | Out-Null
        Write-Host "Link enabled on $dcOu." -ForegroundColor Green

        if ($Refresh) {
            Write-Host 'Waiting 30 s for AD replication of the link ...'
            Start-Sleep -Seconds 30
            Invoke-DcRefresh
            Show-DcValues
        } else {
            Write-Host 'DCs apply the setting at their next background refresh (default 5 min on DCs).'
        }
    }

    'Disable' {
        $gpo = Get-TargetGpo
        if (-not $gpo) { throw "GPO '$GpoName' not found." }

        Set-GPLink -Guid $gpo.Id -Target $dcOu -LinkEnabled No -Domain $dnsRoot -Server $pdc | Out-Null
        Write-Host "Link disabled on $dcOu. GPP removes '$valName' at the next policy refresh." -ForegroundColor Yellow

        if ($Refresh) {
            Write-Host 'Waiting 30 s for AD replication of the link ...'
            Start-Sleep -Seconds 30
            Invoke-DcRefresh
            Show-DcValues
        }
    }

    'Status' {
        $gpo = Get-TargetGpo
        if (-not $gpo) { Write-Host "GPO '$GpoName' not found." -ForegroundColor Yellow; break }

        $linkState = Get-LinkState $gpo.Id
        $pending   = Get-SysvolPending $gpo.Id
        Write-Host ("GPO          : {0} ({1})" -f $gpo.DisplayName, $gpo.Id)
        Write-Host ("GPO status   : {0}" -f $gpo.GpoStatus)
        Write-Host ("Link on DC OU: {0}" -f $(if ($null -eq $linkState) { 'NOT LINKED' } elseif ($linkState) { 'ENABLED' } else { 'disabled' }))
        Write-Host ("SYSVOL       : {0}" -f $(if ($pending.Count) { "patched item missing on $($pending -join ', ')" } else { 'patched item present on all writable DCs' }))
        Write-Host ''
        Show-DcValues
    }
}
