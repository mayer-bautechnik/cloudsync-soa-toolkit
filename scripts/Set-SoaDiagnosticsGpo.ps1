#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Manages the GPO that sets NTDS diagnostics "2 Security Events" = 1 on all domain controllers, which makes the
    AD object enforcement events 3095 (policy load), 3097 (audit) and 3098 (blocked) visible.

.DESCRIPTION
    The value is set by a Group Policy Preferences registry item (action Replace) with
    "Remove this item when it is no longer applied" (removePolicy="1"), so disabling the link or deleting the GPO
    removes the value from the DCs again. Set-GPPrefRegistryValue does not expose that option, therefore the script
    patches Registry.xml on the PDC emulator and waits for SYSVOL replication before the link may be enabled.

    Microsoft's documentation calls the value "Security Diagnostics"; the registry value name is
    "2 Security Events" below HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics (upstream finding F5).

    Install : creates the GPO (user part disabled, marker comment), link DISABLED, patched GPP item (removePolicy and
              a short marker in the item description, GPMC tab Common)
    Enable  : verifies SYSVOL replication of the patched item on every writable DC, then enables the link. Refuses a
              GPO without the SOA Toolkit marker (a GPO of the same name that the toolkit did not create) unless -Force.
              Adds the item marker to toolkit GPOs created by older versions.
    Disable : disables the link - the DCs remove the value at their next policy refresh
    Status  : link state, SYSVOL state per DC and the effective value per DC
    Remove  : disables the link, optionally refreshes the DCs (-Refresh), then deletes the GPO (used by Uninstall)

    Usable on its own (without the rest of the toolkit): omit -ConfigPath and pass -GpoName if needed. The marker is
    set in this case too (with the project URL of the toolkit).

    Where the marker is: the GPO comment (stored by Group Policy in SYSVOL, read with Get-GPO .Description) and the
    description of the GPP registry item. The GPO link and the registry value on the DCs cannot carry a marker;
    Install-SoaToolkit.ps1 records the GPO in its manifest.

.EXAMPLE
    .\Set-SoaDiagnosticsGpo.ps1 -Action Install
    .\Set-SoaDiagnosticsGpo.ps1 -Action Enable -Refresh
    .\Set-SoaDiagnosticsGpo.ps1 -Action Status

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.1.1 (2026-10-23)
    Run as Domain Admin with RSAT. All GPO operations target the PDC emulator. WinRM to the DCs for -Refresh / Status.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Install', 'Enable', 'Disable', 'Status', 'Remove')]
    [string] $Action,

    [string] $GpoName,

    [switch] $Refresh,

    [string] $ConfigPath,

    [switch] $Force          # Enable / Remove: also act on a GPO of this name without the SOA Toolkit marker
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
Import-Module (Join-Path $ScriptRoot 'SoaToolkit.psm1') -Force -DisableNameChecking

#region --- Context ---------------------------------------------------------------------------------
$cfg = $null
if ($ConfigPath) { $cfg = Import-SoaConfig -Path $ConfigPath }
else {
    $found = Resolve-SoaConfigPath -ScriptRoot $ScriptRoot -Optional
    if ($found) { try { $cfg = Import-SoaConfig -Path $found } catch { Write-Warning "Configuration $found not loaded ($($_.Exception.Message)) - using defaults."; $cfg = $null } }
}
if (-not $GpoName) { $GpoName = if ($cfg) { $cfg.DiagnosticsGpoName } else { 'SOA Toolkit - DC - NTDS Security Diagnostics' } }
$ctx     = Get-SoaContext
$pdc     = $ctx.Pdc
$regKey  = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
$valName = '2 Security Events'
$dcs     = $ctx.WritableDcs
$purpose = "Sets NTDS\Diagnostics '2 Security Events'=1 (AD object enforcement events 3095/3097/3098). Toggle with Set-SoaDiagnosticsGpo.ps1; the value is removed when the GPO no longer applies"
$itemMarker = Get-SoaMarker -Config $cfg -Short -Purpose 'Keep the option Remove this item when it is no longer applied'
#endregion

#region --- Helpers ---------------------------------------------------------------------------------
function Get-TargetGpo { Get-SoaGpo -Name $GpoName -Context $ctx }
function Get-RegistryXmlPath([string]$Server, [guid]$GpoId) { "\\$Server\SYSVOL\$($ctx.DnsRoot)\Policies\{$GpoId}\Machine\Preferences\Registry\Registry.xml" }

# Patches the GPP item on the PDC emulator: removePolicy / bypassErrors (install) and the marker in desc
function Set-ItemAttributes([guid]$GpoId, [hashtable]$Attributes) {
    $path = Get-RegistryXmlPath $pdc $GpoId
    [xml]$xml = Get-Content -LiteralPath $path -Raw
    $items = @($xml.SelectNodes("//Registry[Properties[@name='$valName']]"))
    if ($items.Count -ne 1) { throw "Expected exactly one registry item for '$valName' in $path, found $($items.Count)." }
    foreach ($k in $Attributes.Keys) { $items[0].SetAttribute($k, $Attributes[$k]) }
    $ws = New-Object System.Xml.XmlWriterSettings
    $ws.Encoding = New-Object System.Text.UTF8Encoding($false)
    $writer = [System.Xml.XmlWriter]::Create($path, $ws)
    try { $xml.Save($writer) } finally { $writer.Close() }
    $path
}

function Get-SysvolPending([guid]$GpoId) {
    @($dcs | Where-Object {
        $p = Get-RegistryXmlPath $_ $GpoId
        try { -not ((Get-Content -LiteralPath $p -Raw) -match 'removePolicy="1"') } catch { $true }
    })
}

function Wait-SysvolReplication([guid]$GpoId, [int]$TimeoutMinutes = 15) {
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    do {
        $pending = Get-SysvolPending $GpoId
        if ($pending.Count -eq 0) { Write-SoaLine PASS 'Patched Registry.xml is present on all writable DCs.'; return $true }
        Write-Host ("Waiting for SYSVOL replication to: {0}" -f ($pending -join ', ')) -ForegroundColor Yellow
        Start-Sleep -Seconds 20
    } while ((Get-Date) -lt $deadline)
    Write-Warning ("SYSVOL replication not complete after {0} min. Pending: {1}" -f $TimeoutMinutes, ($pending -join ', '))
    $false
}

function Invoke-DcRefresh {
    Write-Host 'Waiting 30 s for AD replication of the link, then gpupdate on all writable DCs ...'
    Start-Sleep -Seconds 30
    foreach ($dc in $dcs) { [void](Invoke-SoaOnHost -ComputerName $dc -ScriptBlock { gpupdate.exe /target:computer /force | Out-Null }) }
}

function Show-DcValues {
    $rows = foreach ($dc in $dcs) {
        $r = Invoke-SoaOnHost -ComputerName $dc -ScriptBlock {
            $p = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ErrorAction SilentlyContinue
            if ($p -and ($p.PSObject.Properties.Name -contains '2 Security Events')) { $p.'2 Security Events' } else { '(not set)' }
        }
        [pscustomobject]@{ DC = $dc; SecurityEvents = $(if ($r.Ok) { $r.Result } else { "error: $($r.Error)" }) }
    }
    $rows | Format-Table DC, SecurityEvents -AutoSize | Out-Host
}
#endregion

switch ($Action) {

    'Install' {
        if (Get-TargetGpo) { Write-SoaLine SAME "GPO '$GpoName' already exists - use -Action Status / Enable / Disable."; break }
        if (-not $PSCmdlet.ShouldProcess($GpoName, 'Create GPO (link disabled) with GPP registry item')) { break }
        $comment = Get-SoaMarker -Config $cfg -Purpose $purpose
        $gpo = New-GPO -Name $GpoName -Domain $ctx.DnsRoot -Server $pdc -Comment $comment
        $gpo.GpoStatus = 'UserSettingsDisabled'
        New-GPLink -Guid $gpo.Id -Target $ctx.DcOu -LinkEnabled No -Domain $ctx.DnsRoot -Server $pdc | Out-Null
        Write-SoaLine ADD "GPO '$GpoName' ($($gpo.Id)) created and linked to $($ctx.DcOu) (link disabled)"

        Set-GPPrefRegistryValue -Guid $gpo.Id -Domain $ctx.DnsRoot -Server $pdc -Context Computer -Action Replace `
                                -Key $regKey -ValueName $valName -Type DWord -Value 1 | Out-Null

        [void](Set-ItemAttributes $gpo.Id @{ removePolicy = '1'; bypassErrors = '1'; desc = $itemMarker })
        Write-SoaLine ADD "Registry.xml patched (removePolicy=1, marker in the item description)"
        [void](Wait-SysvolReplication $gpo.Id)
        Write-Host "Next: .\Set-SoaDiagnosticsGpo.ps1 -Action Enable -Refresh" -ForegroundColor Cyan
    }

    'Enable' {
        $gpo = Get-TargetGpo
        if (-not $gpo) { throw "GPO '$GpoName' not found. Run -Action Install first." }
        if (-not (Test-SoaMarker $gpo.Description) -and -not $Force) {
            throw "GPO '$GpoName' exists but carries no SOA Toolkit marker - it was not created by the toolkit and is not changed. Rename or remove it, or use -Force."
        }
        # Item marker for toolkit GPOs created before 2.0.5 (cosmetic: the description is not evaluated by the DCs)
        $item = Get-SoaDiagnosticsItemState -RegistryXmlPath (Get-RegistryXmlPath $pdc $gpo.Id) -ValueName $valName
        if ($item.Count -eq 1 -and -not $item.Marked -and (Test-SoaMarker $gpo.Description) -and $PSCmdlet.ShouldProcess($GpoName, 'Add the marker to the description of the GPP registry item')) {
            [void](Set-ItemAttributes $gpo.Id @{ desc = $itemMarker })
            Write-SoaLine ADD 'marker added to the GPP item description'
        }
        # Never enable before every DC has the patched item - a DC applying an unpatched copy would keep the value later
        $pending = Get-SysvolPending $gpo.Id
        if ($pending.Count) { throw ("Patched Registry.xml not yet replicated to: {0}. Link not enabled." -f ($pending -join ', ')) }
        $state = Get-SoaGpoLinkState -Id $gpo.Id -Target $ctx.DcOu -Context $ctx
        if ($state.Linked -and $state.Enabled) { Write-SoaLine SAME "link on $($ctx.DcOu) already enabled" }
        elseif ($PSCmdlet.ShouldProcess($ctx.DcOu, "Enable link of '$GpoName'")) {
            if ($state.Linked) { Set-GPLink -Guid $gpo.Id -Target $ctx.DcOu -LinkEnabled Yes -Domain $ctx.DnsRoot -Server $pdc | Out-Null }
            else { New-GPLink -Guid $gpo.Id -Target $ctx.DcOu -LinkEnabled Yes -Domain $ctx.DnsRoot -Server $pdc | Out-Null }
            Write-SoaLine ADD "link enabled on $($ctx.DcOu)"
        }
        if ($Refresh) { Invoke-DcRefresh; Show-DcValues } else { Write-Host 'DCs apply the setting at their next background refresh (default 5 min on DCs).' }
    }

    'Disable' {
        $gpo = Get-TargetGpo
        if (-not $gpo) { throw "GPO '$GpoName' not found." }
        if ($PSCmdlet.ShouldProcess($ctx.DcOu, "Disable link of '$GpoName'")) {
            Set-GPLink -Guid $gpo.Id -Target $ctx.DcOu -LinkEnabled No -Domain $ctx.DnsRoot -Server $pdc | Out-Null
            Write-SoaLine DEL "link disabled on $($ctx.DcOu) - GPP removes '$valName' at the next policy refresh"
        }
        if ($Refresh) { Invoke-DcRefresh; Show-DcValues }
    }

    'Remove' {
        $gpo = Get-TargetGpo
        if (-not $gpo) { Write-SoaLine SKIP "GPO '$GpoName' not found."; break }
        if (-not (Test-SoaMarker $gpo.Description) -and -not $Force) { throw "GPO '$GpoName' carries no SOA Toolkit marker - not deleted (use -Force)." }
        if ($PSCmdlet.ShouldProcess($GpoName, 'Disable link, refresh the DCs (if -Refresh) and delete the GPO')) {
            $state = Get-SoaGpoLinkState -Id $gpo.Id -Target $ctx.DcOu -Context $ctx
            if ($state.Linked -and $state.Enabled) { Set-GPLink -Guid $gpo.Id -Target $ctx.DcOu -LinkEnabled No -Domain $ctx.DnsRoot -Server $pdc | Out-Null; Write-SoaLine DEL 'link disabled' }
            if ($Refresh) { Invoke-DcRefresh; Show-DcValues }
            Remove-GPO -Guid $gpo.Id -Domain $ctx.DnsRoot -Server $pdc
            Write-SoaLine DEL "GPO '$GpoName' deleted (DCs that did not refresh before remove the value when they process the deletion)"
        }
    }

    'Status' {
        $gpo = Get-TargetGpo
        if (-not $gpo) { Write-Host "GPO '$GpoName' not found." -ForegroundColor Yellow; break }
        $state   = Get-SoaGpoLinkState -Id $gpo.Id -Target $ctx.DcOu -Context $ctx
        $pending = Get-SysvolPending $gpo.Id
        Write-Host ("GPO          : {0} ({1})" -f $gpo.DisplayName, $gpo.Id)
        $item    = Get-SoaDiagnosticsItemState -RegistryXmlPath (Get-RegistryXmlPath $pdc $gpo.Id) -ValueName $valName
        Write-Host ("Managed      : {0}" -f $(if (Test-SoaMarker $gpo.Description) { 'yes (SOA Toolkit marker in the GPO comment)' } else { 'no marker' }))
        Write-Host ("GPP item     : {0}" -f $(if ($item.Count -ne 1) { "$($item.Count) item(s) for '$valName'" } else { "action $($item.Action), remove when no longer applied = $($item.RemovePolicy), marker = $($item.Marked)" }))
        Write-Host ("GPO status   : {0}" -f $gpo.GpoStatus)
        Write-Host ("Link on DC OU: {0}" -f $(if (-not $state.Linked) { 'NOT LINKED' } elseif ($state.Enabled) { 'ENABLED' } else { 'disabled' }))
        Write-Host ("SYSVOL       : {0}" -f $(if ($pending.Count) { "patched item missing on $($pending -join ', ')" } else { 'patched item present on all writable DCs' }))
        Write-Host ''
        Show-DcValues
    }
}
