#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Read-only pre-flight / troubleshooting check: Microsoft Entra Cloud Sync "AD object enforcement" on every
    writable DC, plus the prerequisites of the SOA Toolkit (topology, rolling, modules, OUs, test user).

.DESCRIPTION
    Part A - SOA Toolkit prerequisites (only with a configuration file; skipped with -EnforcementOnly)
        - RSAT modules on this host, KDS root key, ToolkitGroupOU / BreakGlassOU exist
        - domain functional level >= 2016 and msDS-ExpirePasswordsOnSmartCardOnlyAccounts (automatic rolling)
        - every agent host: WinRM, provisioning agent service + gMSA, RSAT AD PowerShell, OS (Server Core is not
          supported for the agent), domain controller or member server
        - Group Policy central store present (ADMX of the KIR package)
        - TestUser exists, is provisioned by Cloud Sync and marked
        - write scope (WriteScope = AgentScope -> containers where the agent gMSA holds write permissions)

    Part B - AD object enforcement, for every WRITABLE domain controller
      Host side (via WinRM, executed locally on each DC)
        - OS caption, build and UBR, last boot time, pending reboot indicators
        - ntdsai.dll file version vs. documented minimum (WS2022 10.0.20348.5257, WS2025 10.0.26100.32995)
        - Known Issue Rollback (KIR) feature override values written by the KIR Group Policy
              HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides
        - Resultant Set of Policy (gpresult /scope computer): is the KIR GPO really applied, or filtered out
          by WMI filter / security filtering?
        - Group Policy processing errors in the System log (last 24 h)
        - NTDS diagnostics value "2 Security Events" (controls events 3095/3097/3098)
        - events 3095 (policy load), 3097 (audit), 3098 (enforced block) - last 7 days
      Directory side (ADWS against each DC's own database copy)
        - PDC emulator as seen by each DC, CN=SOA-Policies / CN=Cloud, originating DC of the container
          (engine-created on the PDCe vs. script-created), inbound replication of the domain partition
      Domain level
        - KIR ADMX definitions (central store + local store), GPOs on the Domain Controllers OU with KIR settings

    Output: colored matrix + findings + diagnosis, and CSV / JSON / HTML report files.

.PARAMETER KirGpoName
    Display name of the GPO that deploys the KIR package. Optional (default: all GPOs effective on the DC OU are scanned).

.PARAMETER KirFeatureId
    FeatureManagement override IDs (ADMX valueName). Optional (derived from the KIR GPO / ADMX otherwise).

.PARAMETER EnforcementOnly
    Only part B (usable without the rest of the toolkit / without a configuration file).

.EXAMPLE
    .\Test-SoaPrerequisites.ps1
    .\Test-SoaPrerequisites.ps1 -EnforcementOnly -KirGpoName 'DC - KIR AD Object Enforcement'

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.0.5 (2026-10-21)
    Complements Microsoft's Check-CloudSyncSOAPolicy.ps1, which only reads the domain-wide objects and the local
    diagnostics value and does not verify the enforcement engine per DC (upstream finding F3).
    Run as Domain Admin from the admin workstation with RSAT. WinRM (5985) and ADWS (9389) to every writable DC.
    Read-only: nothing is changed in AD, GPOs or on any host.
#>
[CmdletBinding()]
param(
    [string]   $KirGpoName,
    [string[]] $KirFeatureId,
    [switch]   $EnforcementOnly,
    [string]   $ConfigPath,
    [string]   $OutputPath
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
Import-Module (Join-Path $ScriptRoot 'SoaToolkit.psm1') -Force -DisableNameChecking
$ConfigPath = Resolve-SoaConfigPath -ConfigPath $ConfigPath -ScriptRoot $ScriptRoot -Optional
$cfg = $null
if (-not $EnforcementOnly) {
    if ($ConfigPath) { $cfg = Import-SoaConfig -Path $ConfigPath; Assert-SoaAdminPaths -Config $cfg -ScriptRoot $ScriptRoot; Initialize-SoaReportPath -Config $cfg }
    else { Write-Warning "No configuration found (SoaToolkit.config.psd1) - only the AD object enforcement checks (part B) are run." }
}
if (-not $OutputPath) {
    $OutputPath = if ($cfg) { Join-Path $cfg.ReportPath ('Prerequisites\{0:yyyyMMdd_HHmm}' -f (Get-Date)) } else { Join-Path ([Environment]::GetFolderPath('Desktop')) ('SOA-Preflight_{0:yyyyMMdd_HHmm}' -f (Get-Date)) }
}

#region --- Constants ----------------------------------------------------------------------------
# Minimum ntdsai.dll versions documented by Microsoft for AD object enforcement (keyed by OS build)
$MinNtdsai = Get-SoaConstant 'MinNtdsai'     # WS2022 10.0.20348.5257, WS2025 10.0.26100.32995
# Heuristic to recognize the enforcement KIR policy if neither feature ID nor matching GPO setting is known
$KirNamePattern = '(?i)active directory|directory service|\bSOA\b|source of authority|enforcement|ntds|cloud sync'
# Registry key (below HKLM) that KIR policies write their feature overrides to
$OverridesKey   = 'SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides'

# Check names (rows of the result matrix, in display order)
$C = [ordered]@{
    WinRM   = 'WinRM reachable'
    OS      = 'OS supported'
    Ntdsai  = 'ntdsai.dll version'
    Pending = 'Pending reboot'
    KirReg  = 'KIR override (registry)'
    KirGpo  = 'KIR GPO applied (RSoP)'
    Restart = 'Restart after KIR change'
    GpErr   = 'GP errors (24h)'
    Diag    = 'SOA event logging'
    SoaEv   = 'SOA events (7d)'
    Adws    = 'ADWS reachable'
    Pdc     = 'PDCe view consistent'
    Cont    = 'SOA-Policies container'
    Pol     = 'Cloud policy object'
    Repl    = 'Replication (domain NC)'
}
$checkOrder = @($C.Values)
$colors     = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Gray' }
#endregion

#region --- Helpers ------------------------------------------------------------------------------
$Checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [string] $DC,
        [string] $Check,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string] $Status,
        [string] $Detail
    )
    $Checks.Add([pscustomobject]@{ DC = $DC; Check = $Check; Status = $Status; Detail = $Detail })
}

function Get-ShortName([string]$Fqdn) { ($Fqdn -split '\.')[0] }

function Get-ServerFromNtdsDn([string]$Dn) {
    if ($Dn -match 'CN=NTDS Settings,CN=([^,]+)') { $Matches[1] } else { $Dn }
}

function Write-Section([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 90) -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 90) -ForegroundColor DarkCyan
}

function ConvertTo-HtmlText($Value) { [System.Net.WebUtility]::HtmlEncode("$Value") }
#endregion

#region --- 1. Domain and DC inventory -----------------------------------------------------------
Write-Section '1. Domain and writable domain controllers'

$domain      = Get-ADDomain
$domainDN    = $domain.DistinguishedName
$dnsRoot     = $domain.DNSRoot
$pdcFqdn     = $domain.PDCEmulator
$dcGroupSid  = '{0}-516' -f $domain.DomainSID.Value          # Domain Controllers group
$containerDN = "CN=SOA-Policies,CN=System,$domainDN"
$policyDN    = "CN=Cloud,$containerDN"

$writableDCs = @(Get-ADDomainController -Filter * -Server $pdcFqdn |
                 Where-Object { -not $_.IsReadOnly } | Sort-Object HostName)
$dcNames     = @($writableDCs.HostName)

Write-Host "Domain           : $dnsRoot ($domainDN)"
Write-Host "Domain mode      : $($domain.DomainMode)"
Write-Host "PDC emulator     : $pdcFqdn"
Write-Host "Writable DCs     : $($dcNames -join ', ')"
Write-Host "Container DN     : $containerDN"

if ($dcNames -notcontains $pdcFqdn) {
    Add-Check '(domain)' 'PDCe in writable DC list' 'FAIL' "PDC emulator $pdcFqdn is not in the list of writable DCs."
}
#endregion

#region --- 1b. SOA Toolkit prerequisites (part A) ---------------------------------------------
if ($cfg) {
    Write-Section '1b. SOA Toolkit prerequisites'
    foreach ($m in 'ActiveDirectory', 'GroupPolicy') {
        Add-Check '(toolkit)' "Module $m (this host)" $(if (Get-Module -ListAvailable -Name $m) { 'PASS' } else { 'FAIL' }) 'RSAT on the admin workstation'
    }
    try { $kds = @(Get-KdsRootKey); Add-Check '(toolkit)' 'KDS root key' $(if ($kds.Count) { 'PASS' } else { 'FAIL' }) $(if ($kds.Count) { "$($kds.Count) key(s), effective $(($kds | Sort-Object EffectiveTime | Select-Object -First 1).EffectiveTime)" } else { 'missing - Add-KdsRootKey (gMSA prerequisite; never delete it later)' }) }
    catch { Add-Check '(toolkit)' 'KDS root key' 'INFO' "not checked: $($_.Exception.Message)" }
    foreach ($ou in @($cfg.ToolkitGroupOU, $cfg.BreakGlassOU) | Where-Object { $_ }) {
        $ok = $false; try { $ok = [bool](Get-ADObject -Identity $ou -Server $pdcFqdn) } catch { }
        Add-Check '(toolkit)' 'OU exists' $(if ($ok) { 'PASS' } else { 'FAIL' }) $ou
    }
    $root = Get-ADObject -Identity $domainDN -Server $pdcFqdn -Properties 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts', 'msDS-Behavior-Version'
    $dflv = [int]$root.'msDS-Behavior-Version'
    Add-Check '(toolkit)' 'Domain functional level' $(if ($dflv -ge 7) { 'PASS' } else { 'FAIL' }) "msDS-Behavior-Version $dflv (automatic rolling needs >= 7 = Windows Server 2016)"
    $rv = $root.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'
    Add-Check '(toolkit)' 'Automatic rolling attribute' $(if ($rv -eq $true) { 'PASS' } else { 'WARN' }) "msDS-ExpirePasswordsOnSmartCardOnlyAccounts = $(if ($null -eq $rv) { 'not set' } else { $rv }) $(if ($rv -ne $true) { '- Install-SoaToolkit.ps1 -Step EnableRolling sets it' })"
    $central = "\\$dnsRoot\SYSVOL\$dnsRoot\Policies\PolicyDefinitions"
    Add-Check '(toolkit)' 'Group Policy central store' $(if (Test-Path -LiteralPath $central) { 'PASS' } else { 'INFO' }) $(if (Test-Path -LiteralPath $central) { $central } else { 'not present - KIR ADMX would be copied to the local store of the admin workstation only (the toolkit never creates a central store)' })
    foreach ($h in @($cfg.AgentHosts)) {
        $r = Invoke-SoaOnHost -ComputerName $h -ScriptBlock {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='AADConnectProvisioningAgent'"
            $cv  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $cs  = Get-CimInstance -ClassName Win32_ComputerSystem
            [pscustomobject]@{
                Service = $(if ($svc) { "$($svc.State)" } else { $null }); StartName = $(if ($svc) { $svc.StartName } else { $null })
                Build = [int]$cv.CurrentBuild; Product = $cv.ProductName; InstallationType = $cv.InstallationType
                IsDc = ($cs.DomainRole -ge 4); AdModule = [bool](Get-Module -ListAvailable -Name ActiveDirectory)
            }
        }
        if (-not $r.Ok) { Add-Check $h 'Agent host reachable (WinRM)' 'FAIL' $r.Error; continue }
        $x = $r.Result
        Add-Check $h 'Agent host reachable (WinRM)' 'PASS' ("{0} build {1}, {2}, {3}" -f $x.Product, $x.Build, $x.InstallationType, $(if ($x.IsDc) { 'domain controller' } else { 'member server' }))
        Add-Check $h 'Provisioning agent service' $(if ($x.Service -eq 'Running') { 'PASS' } elseif ($x.Service) { 'WARN' } else { 'FAIL' }) $(if ($x.Service) { "$($x.Service) as $($x.StartName)" } else { 'service AADConnectProvisioningAgent not found' })
        if ($x.StartName -and $x.StartName -notmatch '\$$') { Add-Check $h 'Agent identity' 'WARN' "$($x.StartName) is not a gMSA - Entra -> AD provisioning requires the gMSA" }
        Add-Check $h 'RSAT AD PowerShell' $(if ($x.AdModule) { 'PASS' } else { 'FAIL' }) $(if ($x.AdModule) { 'present' } else { 'missing - Install-WindowsFeature RSAT-AD-PowerShell (toolkit tasks need it)' })
        if ($x.InstallationType -eq 'Server Core') { Add-Check $h 'Agent OS' 'WARN' 'Server Core: installing the provisioning agent on Server Core is not supported (Microsoft prerequisites)' }
        if ($x.Build -ge 26100) { Add-Check $h 'Agent OS support statement' 'INFO' 'Windows Server 2025: recommended for the agent, but the AD DS provisioning prerequisites list only 2016-2022 (inconsistent Microsoft statement - keep in mind for support cases)' }
    }
    if ($cfg.TestUser) {
        $tu = Get-ADUser -Filter "SamAccountName -eq '$($cfg.TestUser)'" -Server $pdcFqdn -Properties 'msDS-ExternalDirectoryObjectId', 'msDS-ObjectSoa'
        if (-not $tu) { Add-Check '(toolkit)' 'TestUser' 'WARN' "$($cfg.TestUser) not found - create it in Entra ID and provision it" }
        else {
            $prov = "$($tu.'msDS-ExternalDirectoryObjectId')" -like 'User_*'
            Add-Check '(toolkit)' 'TestUser' $(if ($prov -and $tu.'msDS-ObjectSoa') { 'PASS' } elseif ($prov) { 'WARN' } else { 'FAIL' }) ("provisioned: {0}, marked: {1}" -f $prov, (@($tu.'msDS-ObjectSoa') -join ','))
        }
    }
    try {
        $tctx = Get-SoaContext -Server $pdcFqdn
        $ws = @(Get-SoaWriteScope -Config $cfg -Context $tctx)
        Add-Check '(toolkit)' 'Write scope' $(if ($ws.Count) { 'PASS' } else { 'WARN' }) ("{0}: {1}" -f $cfg.WriteScope, ($ws -join '; '))
    } catch { Add-Check '(toolkit)' 'Write scope' 'WARN' $_.Exception.Message }
    $Checks | Where-Object { $_.DC -eq '(toolkit)' -or @($cfg.AgentHosts) -contains $_.DC } | Format-Table Status, DC, Check, Detail -AutoSize -Wrap | Out-Host
}
#endregion

#region --- 2. KIR ADMX discovery ----------------------------------------------------------------
Write-Section '2. KIR policy definitions (ADMX) writing FeatureManagement overrides'

$admxStores = @(
    "\\$dnsRoot\SYSVOL\$dnsRoot\Policies\PolicyDefinitions",   # central store
    (Join-Path $env:windir 'PolicyDefinitions')                 # local store of this management host
)

$kirAdmxRaw = foreach ($store in $admxStores) {
    if (-not (Test-Path -Path $store)) { continue }
    foreach ($file in Get-ChildItem -Path $store -Filter '*.admx' -File) {
        try { [xml]$admx = Get-Content -Path $file.FullName -Raw } catch { continue }
        # A KIR policy either writes one value (policy valueName) or several values via <enabledList>
        # (e.g. "Feature Preview" packages that switch on multiple feature IDs at once)
        $pols = @($admx.SelectNodes("//*[local-name()='policy']") | Where-Object {
            ($_.GetAttribute('key') -like '*FeatureManagement\Overrides*') -or
            (@($_.SelectNodes("./*[local-name()='enabledList']/*[local-name()='item']") |
               Where-Object { $_.GetAttribute('key') -like '*FeatureManagement\Overrides*' }).Count -gt 0)
        })
        if ($pols.Count -eq 0) { continue }

        # Resolve display names from the en-US ADML (if present)
        $strings = @{}
        $adml = Join-Path $store ('en-US\{0}.adml' -f $file.BaseName)
        if (Test-Path -Path $adml) {
            try {
                [xml]$admlXml = Get-Content -Path $adml -Raw
                foreach ($s in $admlXml.SelectNodes("//*[local-name()='string']")) { $strings[$s.GetAttribute('id')] = $s.InnerText }
            } catch { }
        }

        foreach ($p in $pols) {
            $ref         = $p.GetAttribute('displayName') -replace '^\$\(string\.(.+)\)$', '$1'
            $displayName = if ($strings.ContainsKey($ref)) { $strings[$ref] } else { $p.GetAttribute('displayName') }
            $policyKey   = $p.GetAttribute('key')

            # Collect (FeatureId, EnabledValue, DisabledValue) tuples from both ADMX patterns
            $ids = @()
            if ($p.GetAttribute('valueName')) {
                $en = $p.SelectSingleNode("./*[local-name()='enabledValue']/*[local-name()='decimal']")
                $di = $p.SelectSingleNode("./*[local-name()='disabledValue']/*[local-name()='decimal']")
                $ids += [pscustomobject]@{
                    Id = $p.GetAttribute('valueName')
                    En = $(if ($en) { $en.GetAttribute('value') } else { '1' })
                    Di = $(if ($di) { $di.GetAttribute('value') } else { '0' })
                }
            }
            $disabledMap = @{}
            foreach ($it in $p.SelectNodes("./*[local-name()='disabledList']/*[local-name()='item']")) {
                $dv = $it.SelectSingleNode(".//*[local-name()='decimal']")
                $disabledMap[$it.GetAttribute('valueName')] = $(if ($dv) { $dv.GetAttribute('value') } else { '0' })
            }
            foreach ($it in $p.SelectNodes("./*[local-name()='enabledList']/*[local-name()='item']")) {
                $itemKey = $it.GetAttribute('key'); if (-not $itemKey) { $itemKey = $policyKey }
                if ($itemKey -notlike '*FeatureManagement\Overrides*') { continue }
                $ev = $it.SelectSingleNode(".//*[local-name()='decimal']")
                $vn = $it.GetAttribute('valueName')
                $ids += [pscustomobject]@{
                    Id = $vn
                    En = $(if ($ev) { $ev.GetAttribute('value') } else { '1' })
                    Di = $(if ($disabledMap.ContainsKey($vn)) { $disabledMap[$vn] } else { '0' })
                }
            }

            foreach ($i in $ids) {
                [pscustomobject]@{
                    Store          = $store
                    InCentralStore = ($store -like '\\*')
                    AdmxFile       = $file.Name
                    PolicyName     = $p.GetAttribute('name')
                    DisplayName    = $displayName
                    FeatureId      = $i.Id
                    EnabledValue   = $i.En
                    DisabledValue  = $i.Di
                }
            }
        }
    }
}
# One entry per feature ID, central store preferred (enumerated first)
$kirAdmx = @($kirAdmxRaw | Group-Object FeatureId | ForEach-Object { $_.Group | Select-Object -First 1 })

if ($kirAdmx.Count) {
    $kirAdmx | Format-Table FeatureId, EnabledValue, InCentralStore, AdmxFile, DisplayName -AutoSize -Wrap | Out-Host
} else {
    Write-Host 'No ADMX with FeatureManagement overrides found (central store or local PolicyDefinitions).' -ForegroundColor Yellow
    Add-Check '(domain)' 'KIR ADMX' 'WARN' 'No KIR ADMX found. Install-SoaToolkit.ps1 -Step KirGpo -KirMsi2022/-KirMsi2025 copies them from the Microsoft package.'
}

$localOnly = @($kirAdmx | Where-Object { -not $_.InCentralStore })
if ((Test-Path $admxStores[0]) -and $localOnly.Count) {
    Add-Check '(domain)' 'KIR ADMX' 'INFO' ("KIR ADMX only in local store of this host, not in central store: {0}" -f (($localOnly.AdmxFile | Select-Object -Unique) -join ', '))
}

$expected = @{}
foreach ($k in $kirAdmx) { $expected[$k.FeatureId] = "$($k.EnabledValue)" }
function Get-ExpectedValue([string]$Id) { if ($expected.ContainsKey($Id)) { $expected[$Id] } else { '1' } }
#endregion

#region --- 3. GPOs effective on the Domain Controllers OU ---------------------------------------
Write-Section '3. KIR GPOs effective on the Domain Controllers OU'

$dcOu        = $domain.DomainControllersContainer
$inheritance = Get-GPInheritance -Target $dcOu -Domain $dnsRoot
if ($inheritance.GpoInheritanceBlocked) {
    Add-Check '(domain)' 'DC OU inheritance' 'WARN' 'Inheritance is blocked on the Domain Controllers OU - domain-linked GPOs only apply if enforced.'
}

$allLinks = @(@($inheritance.GpoLinks) + @($inheritance.InheritedGpoLinks) |
              Where-Object { $_ } | Sort-Object GpoId -Unique)

$kirGpos = @(foreach ($link in $allLinks) {
    $gpo = Get-GPO -Guid $link.GpoId -Domain $dnsRoot
    [xml]$rep = Get-GPOReport -Guid $link.GpoId -ReportType Xml -Domain $dnsRoot
    $text = $rep.OuterXml

    if ($KirGpoName) {
        $isKir = ($gpo.DisplayName -eq $KirGpoName)
    } else {
        $isKir = ($text -match '(?i)Known Issue Rollback|FeatureManagement') -or
                 (@($kirAdmx | Where-Object { $_.DisplayName -and $text.Contains($_.DisplayName) }).Count -gt 0)
    }
    if (-not $isKir) { continue }

    $settings = @(foreach ($pn in $rep.SelectNodes("//*[local-name()='Policy']")) {
        $n = $pn.SelectSingleNode("./*[local-name()='Name']")
        $s = $pn.SelectSingleNode("./*[local-name()='State']")
        if ($n) { [pscustomobject]@{ Name = $n.InnerText; State = $(if ($s) { $s.InnerText }) } }
    })

    $perm      = @(Get-GPPermission -Guid $gpo.Id -All -DomainName $dnsRoot)
    $applySids = @($perm | Where-Object { "$($_.Permission)" -eq 'GpoApply' } | ForEach-Object { $_.Trustee.Sid.Value })
    $dcApply   = ($applySids -contains 'S-1-5-11') -or ($applySids -contains 'S-1-5-9') -or ($applySids -contains $dcGroupSid)

    [pscustomobject]@{
        Name                  = $gpo.DisplayName
        Id                    = $gpo.Id
        LinkTarget            = $link.Target
        LinkEnabled           = $link.Enabled
        LinkEnforced          = $link.Enforced
        GpoStatus             = "$($gpo.GpoStatus)"
        ModificationTime      = $gpo.ModificationTime
        ComputerDSVersion     = $gpo.Computer.DSVersion
        ComputerSysvolVersion = $gpo.Computer.SysvolVersion
        WmiFilter             = $(if ($gpo.WmiFilter) { $gpo.WmiFilter.Name } else { '' })
        ApplyForDCs           = $dcApply
        Settings              = (($settings | ForEach-Object { "$($_.Name) = $($_.State)" }) -join '; ')
        SettingNames          = @($settings | ForEach-Object { $_.Name })
    }
})

if ($KirGpoName -and $kirGpos.Count -eq 0) {
    $exists = $null
    try { $exists = Get-GPO -Name $KirGpoName -Domain $dnsRoot } catch { }
    if ($exists) { Add-Check '(domain)' 'KIR GPO' 'FAIL' "GPO '$KirGpoName' exists but is not linked to / effective on the Domain Controllers OU." }
    else         { Add-Check '(domain)' 'KIR GPO' 'FAIL' "GPO '$KirGpoName' not found in $dnsRoot." }
} elseif ($kirGpos.Count -eq 0) {
    Add-Check '(domain)' 'KIR GPO' 'FAIL' 'No GPO with Known Issue Rollback / FeatureManagement settings is effective on the Domain Controllers OU.'
}

foreach ($g in $kirGpos) {
    if (-not $g.LinkEnabled) { Add-Check '(domain)' 'KIR GPO' 'FAIL' "'$($g.Name)': link to $($g.LinkTarget) is disabled." }
    if ($g.GpoStatus -in 'AllSettingsDisabled', 'ComputerSettingsDisabled') { Add-Check '(domain)' 'KIR GPO' 'FAIL' "'$($g.Name)': GPO status is $($g.GpoStatus)." }
    if ($g.ComputerDSVersion -ne $g.ComputerSysvolVersion) {
        Add-Check '(domain)' 'KIR GPO' 'WARN' ("'{0}': computer version AD={1} vs. SYSVOL={2} - SYSVOL (DFSR) replication or edit in progress." -f $g.Name, $g.ComputerDSVersion, $g.ComputerSysvolVersion)
    }
    if (-not $g.ApplyForDCs) { Add-Check '(domain)' 'KIR GPO' 'FAIL' "'$($g.Name)': no 'Apply group policy' permission for Authenticated Users / Domain Controllers / Enterprise DCs." }
    if ($g.WmiFilter)        { Add-Check '(domain)' 'KIR GPO' 'INFO' "'$($g.Name)': WMI filter '$($g.WmiFilter)' - verify it matches the OS build of every DC (2022 vs. 2025 package)." }
    if (-not $g.Settings)    { Add-Check '(domain)' 'KIR GPO' 'WARN' "'$($g.Name)': no administrative template settings found in the GPO report." }
}

if ($kirGpos.Count) {
    $kirGpos | Format-List Name, LinkTarget, LinkEnabled, LinkEnforced, GpoStatus, ModificationTime,
                           ComputerDSVersion, ComputerSysvolVersion, WmiFilter, ApplyForDCs, Settings | Out-Host
}

# Determine the feature IDs to verify on the DCs
if ($KirFeatureId) {
    $effectiveIds = @($KirFeatureId)
    $idSource     = 'parameter -KirFeatureId'
} else {
    $gpoSettingNames = @($kirGpos | ForEach-Object { $_.SettingNames })
    $fromGpo = @($kirAdmx | Where-Object { $_.DisplayName -and ($gpoSettingNames -contains $_.DisplayName) })
    if ($fromGpo.Count) {
        $effectiveIds = @($fromGpo.FeatureId)
        $idSource     = 'KIR GPO settings matched to ADMX'
    } else {
        $effectiveIds = @($kirAdmx | Where-Object { $_.DisplayName -match $KirNamePattern -or $_.AdmxFile -match $KirNamePattern } |
                          ForEach-Object { $_.FeatureId })
        $idSource     = 'ADMX name heuristic'
    }
}
$effectiveIds = @($effectiveIds | Where-Object { $_ } | Select-Object -Unique)

# Group the IDs by the policy that sets them (a DC needs all IDs of one policy, e.g. its OS package)
$idGroups = @{}
foreach ($id in $effectiveIds) {
    $row = $kirAdmx | Where-Object { $_.FeatureId -eq $id } | Select-Object -First 1
    $grp = if ($row -and -not $KirFeatureId) { $row.DisplayName } else { 'parameter -KirFeatureId' }
    if (-not $idGroups.ContainsKey($grp)) { $idGroups[$grp] = New-Object System.Collections.Generic.List[string] }
    $idGroups[$grp].Add($id)
}
Write-Host ("Feature IDs to verify : {0}  (source: {1})" -f $(if ($effectiveIds.Count) { $effectiveIds -join ', ' } else { 'none' }), $idSource)
if (-not $effectiveIds.Count) {
    Add-Check '(domain)' 'KIR feature ID' 'WARN' 'KIR feature ID could not be determined - pass -KirFeatureId (ADMX valueName) for a definitive registry check.'
}

$lastKirChange = $kirGpos | Sort-Object ModificationTime -Descending | Select-Object -First 1 -ExpandProperty ModificationTime
$kirNames      = @($kirAdmx | ForEach-Object { $_.DisplayName }) + @($kirGpos | ForEach-Object { $_.SettingNames })
#endregion

#region --- 4. Host-side data from every DC (WinRM) ----------------------------------------------
Write-Section '4. Collecting host-side data from every writable DC (WinRM)'

$remoteBlock = {
    param([string]$OverridesKey)

    function Get-ChildText($Node, [string]$Name) {
        $n = $Node.SelectSingleNode("./*[local-name()='$Name']")
        if ($n) { $n.InnerText } else { $null }
    }
    function Get-Short([string]$Text, [int]$Max = 240) {
        if (-not $Text) { return $null }
        $t = $Text -replace '\s+', ' '
        if ($t.Length -gt $Max) { $t.Substring(0, $Max) + '...' } else { $t }
    }

    $out = [ordered]@{}

    # OS and boot state
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $out.OSCaption = $os.Caption
    $out.Build     = [int]$cv.CurrentBuild
    $out.UBR       = [int]$cv.UBR
    $out.LastBoot  = $os.LastBootUpTime

    # ntdsai.dll version (as string - System.Version does not survive remoting deserialization)
    $vi = (Get-Item -Path (Join-Path $env:windir 'System32\ntdsai.dll')).VersionInfo
    $out.NtdsaiVersion = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart

    # Pending reboot indicators
    $pending = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'CBS' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'WindowsUpdate' }
    $out.PendingReboot = $pending -join ', '

    # KIR feature overrides (written by the KIR Group Policy)
    $ov  = @{}
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($OverridesKey)
    if ($key) {
        foreach ($n in $key.GetValueNames()) { $ov[$n] = "$($key.GetValue($n))" }
        $key.Close()
    }
    $out.KirOverrides = $ov

    # NTDS diagnostics level for SOA events 3095/3097/3098
    $diag = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ErrorAction SilentlyContinue
    $out.SecurityEventsLevel = $null
    if ($diag -and ($diag.PSObject.Properties.Name -contains '2 Security Events')) { $out.SecurityEventsLevel = [int]$diag.'2 Security Events' }

    # Resultant Set of Policy (computer part)
    $out.RsopTime = $null; $out.RsopGpos = @(); $out.RsopPolicies = @(); $out.RsopError = $null
    $tmp   = Join-Path $env:TEMP ('rsop_{0}.xml' -f [guid]::NewGuid())
    $gpOut = & gpresult.exe /scope computer /x $tmp /f 2>&1
    if (Test-Path -Path $tmp) {
        try {
            [xml]$x = Get-Content -Path $tmp -Raw
            $rt = $x.SelectSingleNode("//*[local-name()='ReadTime']")
            if ($rt) { $out.RsopTime = $rt.InnerText }
            $cr = $x.SelectSingleNode("//*[local-name()='ComputerResults']")
            if ($cr) {
                $out.RsopGpos = @(foreach ($g in $cr.SelectNodes("./*[local-name()='GPO']")) {
                    [pscustomobject]@{
                        Name          = Get-ChildText $g 'Name'
                        Enabled       = Get-ChildText $g 'Enabled'
                        IsValid       = Get-ChildText $g 'IsValid'
                        FilterAllowed = Get-ChildText $g 'FilterAllowed'
                        AccessDenied  = Get-ChildText $g 'AccessDenied'
                    }
                })
                $pols = @()
                foreach ($p in $cr.SelectNodes(".//*[local-name()='ExtensionData']//*[local-name()='Policy']")) {
                    $pols += [pscustomobject]@{ Name = Get-ChildText $p 'Name'; State = Get-ChildText $p 'State' }
                }
                # Settings without a resolvable ADMX appear as raw registry settings
                foreach ($rs in $cr.SelectNodes(".//*[local-name()='RegistrySetting']")) {
                    $kp = Get-ChildText $rs 'KeyPath'
                    if ($kp -like '*FeatureManagement\Overrides*') {
                        $vn = $rs.SelectSingleNode(".//*[local-name()='Value']/*[local-name()='Name']")
                        $vv = $rs.SelectSingleNode(".//*[local-name()='Value']/*[local-name()='Number']")
                        $pols += [pscustomobject]@{
                            Name  = '{0}\{1}' -f $kp, $(if ($vn) { $vn.InnerText })
                            State = $(if ($vv) { $vv.InnerText })
                        }
                    }
                }
                $out.RsopPolicies = $pols
            }
        } catch { $out.RsopError = $_.Exception.Message }
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    } else {
        $out.RsopError = Get-Short ($gpOut -join ' ')
    }

    # Group Policy processing errors (System log, last 24 h)
    $gpErr = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-GroupPolicy'; Level = 2; StartTime = (Get-Date).AddDays(-1) } -ErrorAction SilentlyContinue)
    $out.GpErrors24h      = $gpErr.Count
    $out.GpLastError      = $null
    $out.GpLastErrorTime  = $null
    if ($gpErr.Count) {
        $out.GpLastError     = '{0:yyyy-MM-dd HH:mm} ID {1}: {2}' -f $gpErr[0].TimeCreated, $gpErr[0].Id, (Get-Short $gpErr[0].Message)
        $out.GpLastErrorTime = $gpErr[0].TimeCreated
    }
    # Last successful computer policy processing (1500 = no changes, 1502 = new settings applied)
    $gpOk = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-GroupPolicy'; Id = 1500, 1502; StartTime = (Get-Date).AddDays(-1) } -MaxEvents 1 -ErrorAction SilentlyContinue
    $out.GpLastSuccessTime = $(if ($gpOk) { $gpOk.TimeCreated } else { $null })

    # SOA policy events (Directory Service log, last 7 days)
    $soa = @(Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 3095, 3097, 3098; StartTime = (Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue)
    $out.SoaEventCounts    = (($soa | Group-Object Id | ForEach-Object { '{0}x{1}' -f $_.Name, $_.Count }) -join ' ')
    $out.SoaLastPolicyLoad = $null
    $last3095 = $soa | Where-Object { $_.Id -eq 3095 } | Select-Object -First 1
    if ($last3095) { $out.SoaLastPolicyLoad = '{0:yyyy-MM-dd HH:mm} {1}' -f $last3095.TimeCreated, (Get-Short $last3095.Message) }

    [pscustomobject]$out
}

$remoteErrors = $null
$remote = @(Invoke-Command -ComputerName $dcNames -ScriptBlock $remoteBlock -ArgumentList $OverridesKey `
                           -ErrorAction SilentlyContinue -ErrorVariable remoteErrors)

$remoteByDc = @{}
foreach ($r in $remote) { $remoteByDc[$r.PSComputerName.ToLower()] = $r }
$remoteFail = @{}
foreach ($e in @($remoteErrors)) {
    $t = "$($e.TargetObject)"
    if (-not $t) { $t = "$($e.CategoryInfo.TargetName)" }
    if ($t) { $remoteFail[$t.ToLower()] = $e.Exception.Message }
}
Write-Host ("WinRM data received from {0} of {1} DC(s)." -f $remoteByDc.Count, $dcNames.Count)
#endregion

#region --- 5. Directory-side data from every DC (ADWS / LDAP) -----------------------------------
Write-Section '5. Querying each DC''s own directory copy (container, policy, PDCe view, replication)'

$adByDc = @{}
foreach ($dc in $dcNames) {
    $o = [ordered]@{
        DC = $dc; AdReachable = $false; AdError = $null; PdcSeen = $null
        ContainerPresent = $false; ContainerCreated = $null; ContainerOrigin = $null; ContainerOriginTime = $null
        PolicyPresent = $false; PolicyMode = $null; PolicySidCount = 0
        ReplPartners = 0; ReplFailures = @()
    }
    try {
        $o.PdcSeen     = (Get-ADDomain -Server $dc).PDCEmulator
        $o.AdReachable = $true

        try {
            $cObj = Get-ADObject -Server $dc -Identity $containerDN -Properties whenCreated
            $o.ContainerPresent = $true
            $o.ContainerCreated = $cObj.whenCreated
            $md = Get-ADReplicationAttributeMetadata -Server $dc -Object $containerDN -Properties objectClass | Select-Object -First 1
            if ($md) {
                $o.ContainerOrigin     = Get-ServerFromNtdsDn $md.LastOriginatingChangeDirectoryServerIdentity
                $o.ContainerOriginTime = $md.LastOriginatingChangeTime
            }
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { }

        try {
            $pObj = Get-ADObject -Server $dc -Identity $policyDN -Properties keywords, 'msDS-Settings'
            $o.PolicyPresent  = $true
            $o.PolicyMode     = (@($pObj.keywords) -join ',')
            $o.PolicySidCount = @($pObj.'msDS-Settings' | Where-Object { $_ }).Count
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { }

        try {
            $partners = @(Get-ADReplicationPartnerMetadata -Target $dc -Partition $domainDN -PartnerType Inbound)
            $o.ReplPartners = $partners.Count
            $o.ReplFailures = @($partners |
                Where-Object { $_.LastReplicationResult -ne 0 -or $_.ConsecutiveReplicationFailures -gt 0 } |
                ForEach-Object {
                    '{0}: result {1}, {2} consecutive failure(s), last success {3}' -f (Get-ServerFromNtdsDn $_.Partner),
                        $_.LastReplicationResult, $_.ConsecutiveReplicationFailures, $_.LastReplicationSuccess
                })
        } catch {
            $o.ReplFailures = @("Replication metadata not readable: $($_.Exception.Message)")
        }
    } catch {
        $o.AdError = $_.Exception.Message
    }
    $adByDc[$dc.ToLower()] = [pscustomobject]$o
}
Write-Host ("Directory data received from {0} of {1} DC(s)." -f @($adByDc.Values | Where-Object { $_.AdReachable }).Count, $dcNames.Count)
#endregion

#region --- 6. Evaluation ------------------------------------------------------------------------
foreach ($dcObj in $writableDCs) {
    $dc  = $dcObj.HostName
    $key = $dc.ToLower()
    $r   = $remoteByDc[$key]
    $a   = $adByDc[$key]

    # ---------- host side ----------
    if (-not $r) {
        Add-Check $dc $C.WinRM 'FAIL' ("No data via WinRM: {0}" -f $remoteFail[$key])
    } else {
        Add-Check $dc $C.WinRM 'PASS' ''

        $build     = [int]$r.Build
        $supported = $MinNtdsai.ContainsKey($build)
        Add-Check $dc $C.OS $(if ($supported) { 'PASS' } else { 'FAIL' }) ('{0} (build {1}.{2})' -f $r.OSCaption, $r.Build, $r.UBR)

        $ver = [version]$r.NtdsaiVersion
        if ($supported) {
            $min = $MinNtdsai[$build]
            Add-Check $dc $C.Ntdsai $(if ($ver -ge $min) { 'PASS' } else { 'FAIL' }) ('{0} (minimum {1})' -f $ver, $min)
        } else {
            Add-Check $dc $C.Ntdsai 'FAIL' ('{0} - OS not supported for AD object enforcement' -f $ver)
        }

        if ($r.PendingReboot) { Add-Check $dc $C.Pending 'WARN' "Reboot pending: $($r.PendingReboot)" }
        else                  { Add-Check $dc $C.Pending 'PASS' "Last boot $($r.LastBoot)" }

        # KIR registry override
        $ov = $r.KirOverrides
        if (-not $ov) { $ov = @{} }
        $allOv = if ($ov.Count) { (@($ov.Keys) | Sort-Object | ForEach-Object { "$_=$($ov[$_])" }) -join ', ' } else { 'none' }
        if ($effectiveIds.Count) {
            # A policy (e.g. the 2022 or the 2025 package) passes only if ALL of its feature IDs are at the enabled value
            $groupResults = @(foreach ($g in $idGroups.Keys) {
                $ids = @($idGroups[$g])
                $ok  = @($ids | Where-Object { $ov.ContainsKey($_) -and "$($ov[$_])" -eq (Get-ExpectedValue $_) })
                $bad = @($ids | Where-Object { $ok -notcontains $_ } | ForEach-Object {
                    if ($ov.ContainsKey($_)) { "$_=$($ov[$_]) (expected $(Get-ExpectedValue $_))" } else { "$_ missing" } })
                [pscustomobject]@{ Policy = $g; Total = $ids.Count; Ok = $ok.Count; Bad = $bad }
            })
            $full    = @($groupResults | Where-Object { $_.Ok -eq $_.Total })
            $partial = @($groupResults | Where-Object { $_.Ok -gt 0 -and $_.Ok -lt $_.Total })
            if ($full.Count) {
                Add-Check $dc $C.KirReg 'PASS' (($full | ForEach-Object { "All $($_.Total) feature ID(s) of '$($_.Policy)' enabled" }) -join ' | ')
            } elseif ($partial.Count) {
                Add-Check $dc $C.KirReg 'FAIL' (($partial | ForEach-Object { "'$($_.Policy)': $($_.Ok)/$($_.Total) enabled; not OK: $($_.Bad -join ', ')" }) -join ' | ')
            } else {
                Add-Check $dc $C.KirReg 'FAIL' ('None of the feature IDs {0} is at its enabled value. Overrides on this DC: {1}' -f ($effectiveIds -join ', '), $allOv)
            }
        } else {
            Add-Check $dc $C.KirReg $(if ($ov.Count) { 'WARN' } else { 'FAIL' }) ('Feature ID unknown (use -KirFeatureId). Overrides on this DC: {0}' -f $allOv)
        }

        # KIR GPO in RSoP
        if ($kirGpos.Count) {
            $states = @(foreach ($kg in $kirGpos) {
                $hit = $r.RsopGpos | Where-Object { $_.Name -eq $kg.Name } | Select-Object -First 1
                if (-not $hit) {
                    [pscustomobject]@{ Applied = $false; Text = "'$($kg.Name)': not in RSoP (out of scope or GP not processed yet)" }
                } else {
                    $applied = ($hit.Enabled -eq 'true' -and $hit.IsValid -eq 'true' -and $hit.FilterAllowed -eq 'true' -and $hit.AccessDenied -eq 'false')
                    $txt = if ($applied) { "'$($kg.Name)': applied" }
                           else { "'$($kg.Name)': NOT applied (Enabled=$($hit.Enabled), IsValid=$($hit.IsValid), WMI FilterAllowed=$($hit.FilterAllowed), AccessDenied=$($hit.AccessDenied))" }
                    [pscustomobject]@{ Applied = $applied; Text = $txt }
                }
            })
            $kirRsop = @($r.RsopPolicies | Where-Object { ($kirNames -contains $_.Name) -or ($_.Name -like '*FeatureManagement\Overrides*') } |
                         ForEach-Object { "$($_.Name) = $($_.State)" })
            $detail = ($states | ForEach-Object { $_.Text }) -join ' | '
            if ($kirRsop.Count)  { $detail += ' | Effective: ' + ($kirRsop -join '; ') }
            if ($r.RsopError)    { $detail += " | gpresult error: $($r.RsopError)" }
            $detail += " | RSoP read: $($r.RsopTime)"
            Add-Check $dc $C.KirGpo $(if (@($states | Where-Object { $_.Applied }).Count) { 'PASS' } else { 'FAIL' }) $detail
        } else {
            Add-Check $dc $C.KirGpo 'WARN' 'No KIR GPO identified on the Domain Controllers OU (use -KirGpoName).'
        }

        # Restart after last KIR GPO change (heuristic: GPO modification time vs. last boot)
        if ($lastKirChange) {
            if ($r.LastBoot -lt $lastKirChange) {
                Add-Check $dc $C.Restart 'WARN' ('Last boot {0} is older than last KIR GPO change {1} - gpupdate + restart required for activation.' -f $r.LastBoot, $lastKirChange)
            } else {
                Add-Check $dc $C.Restart 'PASS' ('Last boot {0} is after last KIR GPO change {1}.' -f $r.LastBoot, $lastKirChange)
            }
        } else {
            Add-Check $dc $C.Restart 'INFO' "Last boot $($r.LastBoot)"
        }

        if ($r.GpErrors24h -eq 0) {
            Add-Check $dc $C.GpErr 'PASS' 'No Group Policy errors in the last 24 h'
        } elseif ($r.GpLastSuccessTime -and $r.GpLastErrorTime -and $r.GpLastSuccessTime -gt $r.GpLastErrorTime) {
            Add-Check $dc $C.GpErr 'INFO' ("{0} error(s), resolved - successful computer policy processing at {1:yyyy-MM-dd HH:mm} after last error. Last error: {2}" -f
                $r.GpErrors24h, $r.GpLastSuccessTime, $r.GpLastError)
        } else {
            Add-Check $dc $C.GpErr 'WARN' ("{0} error(s), no successful computer policy processing since; last: {1}" -f $r.GpErrors24h, $r.GpLastError)
        }

        if ($r.SecurityEventsLevel -ge 1) { Add-Check $dc $C.Diag 'PASS' ("'2 Security Events' = {0}" -f $r.SecurityEventsLevel) }
        else { Add-Check $dc $C.Diag 'WARN' ("'2 Security Events' = {0} - events 3097/3098 are not logged" -f $(if ($null -eq $r.SecurityEventsLevel) { 'not set' } else { $r.SecurityEventsLevel })) }

        Add-Check $dc $C.SoaEv 'INFO' ('Counts: {0}; last policy load (3095): {1}' -f $(if ($r.SoaEventCounts) { $r.SoaEventCounts } else { 'none' }),
                                       $(if ($r.SoaLastPolicyLoad) { $r.SoaLastPolicyLoad } else { 'none' }))
    }

    # ---------- directory side ----------
    if (-not $a -or -not $a.AdReachable) {
        Add-Check $dc $C.Adws 'FAIL' $(if ($a) { $a.AdError } else { 'not queried' })
    } else {
        Add-Check $dc $C.Adws 'PASS' ''
        Add-Check $dc $C.Pdc $(if ($a.PdcSeen -eq $pdcFqdn) { 'PASS' } else { 'FAIL' }) ("PDCe according to this DC: {0}" -f $a.PdcSeen)

        if ($a.ContainerPresent) {
            Add-Check $dc $C.Cont 'PASS' ('whenCreated {0}; originating DC {1} at {2}' -f $a.ContainerCreated, $a.ContainerOrigin, $a.ContainerOriginTime)
        } else {
            Add-Check $dc $C.Cont 'FAIL' "Not present in this DC's copy of the domain partition"
        }

        if ($a.PolicyPresent) { Add-Check $dc $C.Pol 'PASS' ('Mode={0}; authorized SIDs={1}' -f $a.PolicyMode, $a.PolicySidCount) }
        elseif ($a.ContainerPresent) { Add-Check $dc $C.Pol 'INFO' 'CN=Cloud not present yet - expected until Install-SoaToolkit.ps1 -Step Policy has been run' }
        else                         { Add-Check $dc $C.Pol 'WARN' 'CN=Cloud not present (container missing as well)' }

        if ($a.ReplFailures.Count)     { Add-Check $dc $C.Repl 'FAIL' ($a.ReplFailures -join ' | ') }
        elseif ($a.ReplPartners -eq 0) { Add-Check $dc $C.Repl 'INFO' 'No inbound partners for the domain partition (single DC?)' }
        else                           { Add-Check $dc $C.Repl 'PASS' ('{0} inbound partner(s) healthy' -f $a.ReplPartners) }
    }
}
#endregion

#region --- 7. Console output --------------------------------------------------------------------
Write-Section '6. Result matrix (* = PDC emulator)'

$colNames = @($writableDCs | ForEach-Object { if ($_.HostName -eq $pdcFqdn) { "$($_.Name)*" } else { $_.Name } })
$firstW   = ($checkOrder | Measure-Object -Property Length -Maximum).Maximum + 2
$colW     = @{}
foreach ($n in $colNames) { $colW[$n] = [Math]::Max($n.Length, 4) + 3 }

Write-Host ('Check'.PadRight($firstW)) -NoNewline
foreach ($n in $colNames) { Write-Host $n.PadRight($colW[$n]) -NoNewline }
Write-Host ''
Write-Host ('-' * ($firstW + ($colW.Values | Measure-Object -Sum).Sum))

foreach ($chk in $checkOrder) {
    Write-Host $chk.PadRight($firstW) -NoNewline
    for ($i = 0; $i -lt $writableDCs.Count; $i++) {
        $hit = $Checks | Where-Object { $_.DC -eq $writableDCs[$i].HostName -and $_.Check -eq $chk } | Select-Object -First 1
        $st  = if ($hit) { $hit.Status } else { '-' }
        $fg  = if ($colors.ContainsKey($st)) { $colors[$st] } else { 'DarkGray' }
        Write-Host $st.PadRight($colW[$colNames[$i]]) -NoNewline -ForegroundColor $fg
    }
    Write-Host ''
}

Write-Section '7. Findings (WARN / FAIL)'
$findings = @($Checks | Where-Object { $_.Status -in 'WARN', 'FAIL' } | Sort-Object @{ e = { if ($_.Status -eq 'FAIL') { 0 } else { 1 } } }, DC, Check)
if ($findings.Count -eq 0) { Write-Host 'No warnings or failures.' -ForegroundColor Green }
foreach ($f in $findings) {
    $dcLabel = if ($f.DC -like '(*') { $f.DC } else { Get-ShortName $f.DC }
    Write-Host ('[{0}] {1} - {2}: {3}' -f $f.Status, $dcLabel, $f.Check, $f.Detail) -ForegroundColor $colors[$f.Status]
}

Write-Section '8. Diagnosis: SOA-Policies container'
$diag     = New-Object System.Collections.Generic.List[string]
$pdcAd    = $adByDc[$pdcFqdn.ToLower()]
$pdcShort = Get-ShortName $pdcFqdn
$withC    = @($adByDc.Values | Where-Object { $_.ContainerPresent })
$withoutC = @($adByDc.Values | Where-Object { $_.AdReachable -and -not $_.ContainerPresent })

if (-not $pdcAd -or -not $pdcAd.AdReachable) {
    $diag.Add("PDC emulator $pdcFqdn could not be queried via ADWS - container state on the PDCe is unknown.")
} elseif ($pdcAd.ContainerPresent) {
    if ($withoutC.Count -eq 0) {
        $diag.Add('Container is present on all reachable writable DCs.')
    } else {
        $diag.Add(("Container exists on the PDCe but is missing on: {0}. This is replication latency or a replication failure, not an enforcement engine problem - see 'Replication (domain NC)'." -f
                   (($withoutC | ForEach-Object { Get-ShortName $_.DC }) -join ', ')))
    }
    if ($pdcAd.ContainerOrigin -and $pdcAd.ContainerOrigin -ne $pdcShort) {
        $diag.Add("Container was originally written on '$($pdcAd.ContainerOrigin)', not on the PDCe '$pdcShort'. It was most likely created by Microsoft's Set-CloudSyncSOAPolicy.ps1 (creates it if missing, upstream finding F2). Its existence does NOT prove that the enforcement engine on the PDCe is active.")
    } else {
        $diag.Add("Container was originally written on the PDCe at $($pdcAd.ContainerOriginTime) - consistent with automatic creation by the enforcement engine.")
    }
} else {
    $diag.Add('Container is missing on the PDCe itself -> creation problem, not a replication problem.')
    if ($withC.Count) {
        $diag.Add(("Container is however present on: {0} (written elsewhere and not yet replicated to the PDCe)." -f (($withC | ForEach-Object { Get-ShortName $_.DC }) -join ', ')))
    }
    $relevant = @($C.WinRM, $C.OS, $C.Ntdsai, $C.Pending, $C.KirReg, $C.KirGpo, $C.Restart)
    $blockers = @($Checks | Where-Object { $_.DC -eq $pdcFqdn -and $_.Status -in 'FAIL', 'WARN' -and $relevant -contains $_.Check })
    $domainBlockers = @($Checks | Where-Object { $_.DC -eq '(domain)' -and $_.Status -eq 'FAIL' })
    if ($blockers.Count -or $domainBlockers.Count) {
        $diag.Add('Most likely causes:')
        foreach ($b in $blockers)       { $diag.Add("  - PDCe / $($b.Check): $($b.Detail)") }
        foreach ($b in $domainBlockers) { $diag.Add("  - Domain / $($b.Check): $($b.Detail)") }
    } else {
        $diag.Add('All checked prerequisites on the PDCe look fine. Allow a few minutes after the restart, check the Directory Service log on the PDCe and consider a support case (preview feature).')
    }
}
foreach ($line in $diag) { Write-Host $line }
#endregion

#region --- 8. Reports ---------------------------------------------------------------------------
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
$csvPath  = Join-Path $OutputPath 'checks.csv'
$jsonPath = Join-Path $OutputPath 'raw.json'
$htmlPath = Join-Path $OutputPath 'report.html'

$Checks | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

[pscustomobject]@{
    Generated           = (Get-Date).ToString('s')
    Domain              = $dnsRoot
    PDCe                = $pdcFqdn
    ContainerDN         = $containerDN
    EffectiveFeatureIds = $effectiveIds
    FeatureIdSource     = $idSource
    KirAdmx             = $kirAdmx
    KirGpos             = $kirGpos
    HostData            = $remote
    DirectoryData       = @($adByDc.Values)
    Checks              = $Checks
    Diagnosis           = $diag
} | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append(@"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>SOA enforcement pre-flight - $dnsRoot</title>
<style>
body{font-family:Calibri,'Segoe UI',sans-serif;margin:24px;color:#1b1b1b;font-size:14px}
h1,h2{color:#1f3864} table{border-collapse:collapse;margin-bottom:24px}
th{background:#1f3864;color:#fff;padding:6px 10px;text-align:left}
td{border:1px solid #c8c8c8;padding:5px 10px;vertical-align:top}
.PASS{background:#d4edda}.WARN{background:#fff3cd}.FAIL{background:#f8d7da}.INFO{background:#e7e9ec}
.box{border-left:4px solid #1f3864;background:#eef2f8;padding:10px 14px;margin-bottom:24px}
</style></head><body>
<h1>AD object enforcement &ndash; pre-flight</h1>
<p>Domain: <b>$(ConvertTo-HtmlText $dnsRoot)</b> &nbsp;|&nbsp; PDC emulator: <b>$(ConvertTo-HtmlText $pdcFqdn)</b>
&nbsp;|&nbsp; Feature IDs: <b>$(ConvertTo-HtmlText ($effectiveIds -join ', '))</b> ($(ConvertTo-HtmlText $idSource))
&nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>
<h2>Diagnosis</h2><div class="box">
"@)
foreach ($line in $diag) { [void]$sb.Append("<div>$(ConvertTo-HtmlText $line)</div>") }
[void]$sb.Append('</div><h2>Result matrix</h2><table><tr><th>Check</th>')
foreach ($n in $colNames) { [void]$sb.Append("<th>$(ConvertTo-HtmlText $n)</th>") }
[void]$sb.Append('</tr>')
foreach ($chk in $checkOrder) {
    [void]$sb.Append("<tr><td>$(ConvertTo-HtmlText $chk)</td>")
    foreach ($dcObj in $writableDCs) {
        $hit = $Checks | Where-Object { $_.DC -eq $dcObj.HostName -and $_.Check -eq $chk } | Select-Object -First 1
        if ($hit) { [void]$sb.Append("<td class=`"$($hit.Status)`" title=`"$(ConvertTo-HtmlText $hit.Detail)`">$($hit.Status)</td>") }
        else      { [void]$sb.Append('<td>-</td>') }
    }
    [void]$sb.Append('</tr>')
}
[void]$sb.Append('</table><p>* = PDC emulator. Hover a cell for details.</p><h2>All checks</h2><table><tr><th>Status</th><th>DC</th><th>Check</th><th>Detail</th></tr>')
foreach ($chkRow in ($Checks | Sort-Object DC, Check)) {
    [void]$sb.Append("<tr><td class=`"$($chkRow.Status)`">$($chkRow.Status)</td><td>$(ConvertTo-HtmlText $chkRow.DC)</td><td>$(ConvertTo-HtmlText $chkRow.Check)</td><td>$(ConvertTo-HtmlText $chkRow.Detail)</td></tr>")
}
[void]$sb.Append('</table><h2>KIR GPOs</h2><table><tr><th>Name</th><th>Link</th><th>Status</th><th>Modified</th><th>AD/SYSVOL</th><th>WMI filter</th><th>Apply for DCs</th><th>Settings</th></tr>')
foreach ($g in $kirGpos) {
    [void]$sb.Append(("<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}/{5}</td><td>{6}</td><td>{7}</td><td>{8}</td></tr>" -f
        (ConvertTo-HtmlText $g.Name), (ConvertTo-HtmlText "$($g.LinkTarget) (enabled=$($g.LinkEnabled))"), (ConvertTo-HtmlText $g.GpoStatus),
        (ConvertTo-HtmlText $g.ModificationTime), $g.ComputerDSVersion, $g.ComputerSysvolVersion, (ConvertTo-HtmlText $g.WmiFilter),
        $g.ApplyForDCs, (ConvertTo-HtmlText $g.Settings)))
}
[void]$sb.Append('</table><h2>KIR ADMX definitions</h2><table><tr><th>Feature ID</th><th>Enabled value</th><th>Central store</th><th>ADMX</th><th>Display name</th></tr>')
foreach ($k in $kirAdmx) {
    [void]$sb.Append(("<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>" -f
        (ConvertTo-HtmlText $k.FeatureId), (ConvertTo-HtmlText $k.EnabledValue), $k.InCentralStore, (ConvertTo-HtmlText $k.AdmxFile), (ConvertTo-HtmlText $k.DisplayName)))
}
[void]$sb.Append('</table></body></html>')
Set-Content -Path $htmlPath -Value $sb.ToString() -Encoding UTF8

Write-Section 'Reports'
Write-Host "CSV  : $csvPath"
Write-Host "JSON : $jsonPath"
Write-Host "HTML : $htmlPath"
Write-Host "       (contains names of your environment - share it only through Export-SoaReport.ps1)" -ForegroundColor DarkGray
#endregion
