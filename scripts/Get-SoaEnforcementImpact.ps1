#Requires -Version 5.1
#Requires -Modules ActiveDirectory
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Shows which AD users and groups are affected by Entra Cloud Sync AD object enforcement right now,
    and which identities changed them recently (= changes that would be BLOCKED in Enforced mode).

.DESCRIPTION
    Read-only. Evaluates:
      1. SOA policy CN=Cloud: present? mode (keywords)? allow-list (msDS-Settings) with resolved names
      2. Objects marked for enforcement (msDS-ObjectSoa set) - users, groups, anything else
         incl. origin heuristic: provisioned as cloud-native vs. pre-existing (SOA-converted)
      3. Objects provisioned by Cloud Sync (msDS-ExternalDirectoryObjectId User_/Group_) that are NOT marked
         (= not protected)
      4. Security-log evidence from every writable DC for the last -Days days: who modified / reset / unlocked /
         renamed / disabled the marked objects or changed membership of marked groups. Each writer is classified as
            Allowed (allow-list)      SID is in msDS-Settings
            System / DC-internal      SYSTEM / DC computer account (e.g. lockout) - effect under enforcement unverified
            WOULD BE BLOCKED          any other identity (admins, helpdesk, scripts, tools)
         Event IDs: 4722 4723 4724 4725 4738 4740 4767 4781 4728 4729 4732 4733 4756 4757 5136
         (5136 only where a SACL is configured; coverage per DC = oldest event in the Security log)

.PARAMETER Days
    Look-back window for the Security-log evidence (default 14).

.PARAMETER OutputPath
    Folder for CSV + HTML. Default: <ReportPath>\Impact\<timestamp> (or Desktop\SOA-Impact_<timestamp> without configuration)

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.1.1 (2026-10-23)
    Read-only. Run as Domain Admin from the admin workstation with RSAT. Requires WinRM (5985) to every writable DC.
    Usable without the rest of the toolkit (without a configuration file the toolkit gMSA is simply not labelled).
#>
[CmdletBinding()]
param(
    [int]    $Days = 14,
    [string] $ConfigPath,
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
Import-Module (Join-Path $ScriptRoot 'SoaToolkit.psm1') -Force -DisableNameChecking
$ConfigPath = Resolve-SoaConfigPath -ConfigPath $ConfigPath -ScriptRoot $ScriptRoot -Optional
$cfg = $null
if ($ConfigPath) { try { $cfg = Import-SoaConfig -Path $ConfigPath } catch { Write-Warning $_.Exception.Message } }
if ($cfg) { Assert-SoaAdminPaths -Config $cfg -ScriptRoot $ScriptRoot; Initialize-SoaReportPath -Config $cfg }
if (-not $OutputPath) {
    $OutputPath = if ($cfg) { Join-Path $cfg.ReportPath ('Impact\{0:yyyyMMdd_HHmm}' -f (Get-Date)) } else { Join-Path ([Environment]::GetFolderPath('Desktop')) ('SOA-Impact_{0:yyyyMMdd_HHmm}' -f (Get-Date)) }
}

#region --- Context / helpers ----------------------------------------------------------------------
$domain   = Get-ADDomain
$pdc      = $domain.PDCEmulator
$netbios  = $domain.NetBIOSName
$domainDN = $domain.DistinguishedName
$policyDN = "CN=Cloud,CN=SOA-Policies,CN=System,$domainDN"
$dcObjs   = @(Get-ADDomainController -Filter * -Server $pdc | Where-Object { -not $_.IsReadOnly } | Sort-Object HostName)
$dcs      = @($dcObjs.HostName)
$dcSids   = @($dcObjs | ForEach-Object { (Get-ADComputer -Identity $_.ComputerObjectDN -Server $pdc).SID.Value })
$since    = (Get-Date).AddDays(-$Days)

$EventNames = @{
    4722 = 'User enabled';               4723 = 'Password change attempt';   4724 = 'Password reset attempt'
    4725 = 'User disabled';              4738 = 'User account changed';      4740 = 'User locked out'
    4767 = 'User unlocked';              4781 = 'Account name changed';      4728 = 'Member added (global group)'
    4729 = 'Member removed (global)';    4732 = 'Member added (local group)'; 4733 = 'Member removed (local)'
    4756 = 'Member added (universal)';   4757 = 'Member removed (universal)'; 5136 = 'Directory object modified'
}

function Write-Section([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 100) -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 100) -ForegroundColor DarkCyan
}

function Resolve-SidName([string]$Sid) {
    try {
        $o = Get-ADObject -Server $pdc -LDAPFilter "(objectSid=$Sid)" -Properties sAMAccountName
        if ($o) { return "$netbios\$($o.sAMAccountName)" }
    } catch { }
    try { return ([Security.Principal.SecurityIdentifier]$Sid).Translate([Security.Principal.NTAccount]).Value } catch { return $null }
}

# Heuristic: anchor stamped within 10 min of object creation => object was created by provisioning (cloud-native).
# Anchor stamped later => pre-existing AD object matched by provisioning (SOA-converted).
function Get-OriginKind($Object) {
    try {
        $md = Get-ADReplicationAttributeMetadata -Object $Object.DistinguishedName -Server $pdc -Properties 'msDS-ExternalDirectoryObjectId' |
              Where-Object { $_.AttributeName -eq 'msDS-ExternalDirectoryObjectId' } | Select-Object -First 1
        if ((-not $md) -or (-not $md.LastOriginatingChangeTime)) { return 'unknown' }
        # The anchor is written once and never changed afterwards -> LastOriginatingChangeTime = time it was stamped
        if ([Math]::Abs(($md.LastOriginatingChangeTime - $Object.whenCreated).TotalMinutes) -le 10) { 'cloud-native (created by provisioning)' }
        else { 'SOA-converted / pre-existing' }
    } catch { 'unknown' }
}
#endregion

#region --- 1. SOA policy --------------------------------------------------------------------------
Write-Section '1. SOA policy (CN=Cloud)'
$policy = $null
try { $policy = Get-ADObject -Identity $policyDN -Server $pdc -Properties keywords, 'msDS-Settings', whenChanged } catch { }

$allowed = @()
if ($policy) {
    $allowed = @(foreach ($s in @($policy.'msDS-Settings' | Where-Object { $_ })) {
        $n = Resolve-SidName "$s"
        [pscustomobject]@{ Sid = "$s"; Name = $(if ($n) { $n } else { '!! NOT RESOLVABLE - policy will fail to load !!' }) }
    })
    Write-Host ("Mode (keywords) : {0}" -f (@($policy.keywords) -join ','))
    Write-Host ("Last changed    : {0}" -f $policy.whenChanged)
    $allowed | Format-Table Sid, Name -AutoSize | Out-Host
} else {
    Write-Host 'CN=Cloud does not exist yet - no enforcement active (Install-SoaToolkit.ps1 -Step Policy creates it in mode Audit).' -ForegroundColor Yellow
    Write-Host 'Writers are classified without an allow-list (Cloud Sync agent changes will show as "would be blocked").' -ForegroundColor Yellow
}
$allowedSet = @{}
foreach ($a in $allowed) { $allowedSet[$a.Sid] = $a.Name }
$toolkitSid = $null
if ($cfg) { try { $toolkitSid = (Get-ADServiceAccount -Identity $cfg.GmsaName -Server $pdc).SID.Value } catch { } }
#endregion

#region --- 2. Marked objects ----------------------------------------------------------------------
Write-Section '2. Objects marked for enforcement (msDS-ObjectSoa set)'
$markedObjs = @(Get-ADObject -Server $pdc -LDAPFilter '(msDS-ObjectSoa=*)' -ResultPageSize 500 `
                -Properties 'msDS-ObjectSoa', 'msDS-ExternalDirectoryObjectId', objectSid, sAMAccountName, whenCreated, userAccountControl, member)

$marked = @(foreach ($o in $markedObjs) {
    $isUser  = $o.ObjectClass -in 'user', 'inetOrgPerson'
    $isGroup = $o.ObjectClass -eq 'group'
    [pscustomobject]@{
        Class          = $o.ObjectClass
        Name           = $o.Name
        SamAccountName = $o.sAMAccountName
        ObjectSoa      = (@($o.'msDS-ObjectSoa') -join ',')
        Anchor         = $o.'msDS-ExternalDirectoryObjectId'
        Origin         = Get-OriginKind $o
        Enabled        = $(if ($isUser) { -not ($o.userAccountControl -band 2) } else { $null })
        Scril          = $(if ($isUser) { [bool]($o.userAccountControl -band 0x40000) } else { $null })
        Members        = $(if ($isGroup) { @($o.member).Count } else { $null })
        Sid            = $(if ($o.objectSid) { $o.objectSid.Value } else { $null })
        DistinguishedName = $o.DistinguishedName
    }
})

$mUsers  = @($marked | Where-Object { $_.Class -in 'user', 'inetOrgPerson' })
$mGroups = @($marked | Where-Object { $_.Class -eq 'group' })
$mOther  = @($marked | Where-Object { $_.Class -notin 'user', 'inetOrgPerson', 'group' })
Write-Host ("Marked users: {0}   marked groups: {1}   other marked objects: {2}" -f $mUsers.Count, $mGroups.Count, $mOther.Count)
if ($mUsers.Count)  { $mUsers  | Sort-Object Name | Format-Table Name, SamAccountName, ObjectSoa, Enabled, Scril, Origin -AutoSize | Out-Host }
if ($mGroups.Count) { $mGroups | Sort-Object Name | Format-Table Name, SamAccountName, ObjectSoa, Members, Origin -AutoSize | Out-Host }
if ($mOther.Count)  { $mOther  | Format-Table Class, Name, ObjectSoa, DistinguishedName -AutoSize | Out-Host }
$nonCloud = @($marked | Where-Object { $_.ObjectSoa -ne 'Cloud' })
if ($nonCloud.Count) { Write-Host ("Note: {0} object(s) carry an msDS-ObjectSoa value other than 'Cloud'." -f $nonCloud.Count) -ForegroundColor Yellow }
#endregion

#region --- 3. Provisioned but NOT marked ----------------------------------------------------------
Write-Section '3. Provisioned by Cloud Sync but NOT marked (not protected)'
$unmarked = @(Get-ADObject -Server $pdc -ResultPageSize 500 -Properties sAMAccountName, 'msDS-ExternalDirectoryObjectId' `
    -LDAPFilter '(&(|(msDS-ExternalDirectoryObjectId=User_*)(msDS-ExternalDirectoryObjectId=Group_*))(!(msDS-ObjectSoa=*)))' |
    ForEach-Object { [pscustomobject]@{ Class = $_.ObjectClass; Name = $_.Name; SamAccountName = $_.sAMAccountName; DistinguishedName = $_.DistinguishedName } })
if ($unmarked.Count) { $unmarked | Format-Table Class, Name, SamAccountName, DistinguishedName -AutoSize | Out-Host }
else { Write-Host 'None - every provisioned user/group is marked.' -ForegroundColor Green }
#endregion

#region --- 4. Security-log evidence: who writes to marked objects? --------------------------------
Write-Section ("4. Writers of marked objects in the last {0} day(s) (Security log of every writable DC)" -f $Days)

$sids = @($marked | Where-Object { $_.Sid } | ForEach-Object { $_.Sid })
$dns  = @($marked | ForEach-Object { $_.DistinguishedName })
$targetName = @{}
foreach ($m in $marked) { if ($m.Sid) { $targetName[$m.Sid] = $m.Name }; $targetName[$m.DistinguishedName.ToLower()] = $m.Name }

$remoteBlock = {
    param([string[]]$Sids, [string[]]$Dns, [datetime]$Since)
    $sidSet = @{}; foreach ($s in $Sids) { $sidSet[$s] = $true }
    $dnSet  = @{}; foreach ($d in $Dns)  { $dnSet[$d.ToLower()] = $true }
    $oldest = (Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue).TimeCreated
    $ids    = 4722, 4723, 4724, 4725, 4738, 4740, 4767, 4781, 4728, 4729, 4732, 4733, 4756, 4757, 5136
    $rows = foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = $Since } -ErrorAction SilentlyContinue)) {
        $d = @{}
        foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        $target = $null
        if ($e.Id -eq 5136) {
            if ($d.ObjectDN -and $dnSet.ContainsKey($d.ObjectDN.ToLower())) { $target = $d.ObjectDN.ToLower() }
        } elseif ($d.TargetSid -and $sidSet.ContainsKey($d.TargetSid)) {
            $target = $d.TargetSid
        }
        if (-not $target) { continue }
        [pscustomobject]@{
            DC         = $env:COMPUTERNAME
            Time       = $e.TimeCreated
            Id         = $e.Id
            SubjectSid = $d.SubjectUserSid
            Subject    = '{0}\{1}' -f $d.SubjectDomainName, $d.SubjectUserName
            Target     = $target
            Detail     = $(if ($e.Id -eq 5136) { '{0} ({1})' -f $d.AttributeLDAPDisplayName, $(if ($d.OperationType -eq '%%14674') { 'value added' } elseif ($d.OperationType -eq '%%14675') { 'value deleted' } else { $d.OperationType }) }
                           elseif ($d.MemberName) { "member: $($d.MemberName)" } else { '' })
        }
    }
    [pscustomobject]@{ DC = $env:COMPUTERNAME; Oldest = $oldest; Rows = @($rows) }
}

$remoteErrors = $null
$evidence = @(Invoke-Command -ComputerName $dcs -ScriptBlock $remoteBlock -ArgumentList $sids, $dns, $since `
                             -ErrorAction SilentlyContinue -ErrorVariable remoteErrors)
foreach ($err in @($remoteErrors)) { Write-Warning ("No Security-log data from {0}: {1}" -f $err.TargetObject, $err.Exception.Message) }

Write-Host 'Coverage (oldest event in the Security log):'
$evidence | ForEach-Object {
    $full = $_.Oldest -and $_.Oldest -le $since
    Write-Host ('  {0,-16} oldest {1}  {2}' -f $_.DC, $_.Oldest, $(if ($full) { '(full window)' } else { '(PARTIAL - log rolled over)' })) -ForegroundColor $(if ($full) { 'Gray' } else { 'Yellow' })
}

$events = @(foreach ($ev in $evidence) {
    foreach ($r in $ev.Rows) {
        $verdict = if ($r.SubjectSid -and $r.SubjectSid -eq $toolkitSid -and $allowedSet.ContainsKey($r.SubjectSid)) { 'Allowed (SOA Toolkit)' }
                   elseif ($r.SubjectSid -and $r.SubjectSid -eq $toolkitSid) { 'SOA Toolkit - NOT allow-listed, WOULD BE BLOCKED' }
                   elseif ($r.SubjectSid -and $allowedSet.ContainsKey($r.SubjectSid)) { 'Allowed (allow-list)' }
                   elseif ($r.SubjectSid -in 'S-1-5-18', 'S-1-5-19', 'S-1-5-20' -or $dcSids -contains $r.SubjectSid) { 'System / DC-internal (effect unverified)' }
                   else { 'WOULD BE BLOCKED' }
        [pscustomobject]@{
            Verdict = $verdict
            Time    = $r.Time
            DC      = $r.DC
            Event   = '{0} {1}' -f $r.Id, $EventNames[[int]$r.Id]
            Subject = $r.Subject
            Target  = $(if ($targetName.ContainsKey($r.Target)) { $targetName[$r.Target] } else { $r.Target })
            Detail  = $r.Detail
        }
    }
})

$summary = @($events | Group-Object Verdict, Subject | ForEach-Object {
    $g = $_.Group
    [pscustomobject]@{
        Verdict  = $g[0].Verdict
        Subject  = $g[0].Subject
        Count    = $g.Count
        Events   = (($g | Group-Object Event | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join '; ')
        Targets  = (($g.Target | Select-Object -Unique | Select-Object -First 6) -join ', ')
        LastSeen = ($g | Sort-Object Time -Descending | Select-Object -First 1).Time
    }
} | Sort-Object @{ e = { switch -Wildcard ($_.Verdict) { '*WOULD*' { 0 } 'System*' { 1 } default { 2 } } } }, Subject)

if ($summary.Count) {
    foreach ($s in $summary) {
        $color = switch -Wildcard ($s.Verdict) { '*WOULD*' { 'Red' } 'System*' { 'Yellow' } default { 'Green' } }
        Write-Host ('[{0}] {1}  ({2} change(s), last {3})' -f $s.Verdict, $s.Subject, $s.Count, $s.LastSeen) -ForegroundColor $color
        Write-Host ('      events : {0}' -f $s.Events)
        Write-Host ('      targets: {0}' -f $s.Targets)
    }
} else {
    Write-Host 'No changes to marked objects found in the Security logs for this window.' -ForegroundColor Green
}
#endregion

#region --- 5. What Enforced mode will do ----------------------------------------------------------
Write-Section '5. Effect of Enforced mode on the objects above'
@(
    'BLOCKED for every identity NOT in the allow-list (incl. Domain Admins):'
    '  - LDAP modify of any attribute (incl. password reset via LDAP, enable/disable, unlock, description, ...)'
    '  - group membership changes of marked groups'
    '  - rename / move (modify DN) and restore from the AD Recycle Bin'
    '  - security descriptor changes (ACL) on marked objects'
    'STILL ALLOWED (preview): delete; LDAP add; nesting a marked group into an unmarked group'
    'NOT COVERED by the toolkit tests: DC-internal writes and non-LDAP paths. Automatic secret rolling at'
    '  sign-in was observed to work (Test-SoaBehavior.ps1 -Suite RollingObserve). Validate the LDAP paths with'
    '  Test-SoaBehavior.ps1 -Suite Enforcement, Onboarding'
) | ForEach-Object { Write-Host $_ }
$blockedWriters = @($summary | Where-Object { $_.Verdict -like '*WOULD BE BLOCKED' })
Write-Host ''
if ($blockedWriters.Count) {
    Write-Host ("{0} identity/identities changed marked objects in the window and would be blocked:" -f $blockedWriters.Count) -ForegroundColor Red
    $blockedWriters | ForEach-Object { Write-Host "  - $($_.Subject)" -ForegroundColor Red }
    Write-Host 'Decide per identity: move the change to Entra ID (source of authority), or accept the block. Do not add admin accounts to the allow-list.' -ForegroundColor Red
} else {
    Write-Host 'No observed writer would be blocked (within the log coverage above).' -ForegroundColor Green
}
#endregion

#region --- Reports --------------------------------------------------------------------------------
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
$marked   | Export-Csv (Join-Path $OutputPath 'marked-objects.csv')   -NoTypeInformation -Encoding UTF8
$unmarked | Export-Csv (Join-Path $OutputPath 'unmarked-provisioned.csv') -NoTypeInformation -Encoding UTF8
$events   | Export-Csv (Join-Path $OutputPath 'writer-events.csv')    -NoTypeInformation -Encoding UTF8
$summary  | Export-Csv (Join-Path $OutputPath 'writer-summary.csv')   -NoTypeInformation -Encoding UTF8

$css = '<style>body{font-family:Calibri,Segoe UI,sans-serif;margin:24px;font-size:14px}h1,h2{color:#1f3864}' +
       'table{border-collapse:collapse;margin-bottom:22px}th{background:#1f3864;color:#fff;padding:6px 10px;text-align:left}' +
       'td{border:1px solid #c8c8c8;padding:4px 10px;vertical-align:top}</style>'
$html = @(
    "<h1>AD object enforcement - impact ($($domain.DNSRoot))</h1>"
    "<p>Policy mode: <b>$(if ($policy) { @($policy.keywords) -join ',' } else { 'no policy' })</b> | Window: $Days day(s) | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>"
    '<h2>Writers of marked objects</h2>'
    ($summary | ConvertTo-Html -Fragment -Property Verdict, Subject, Count, Events, Targets, LastSeen)
    '<h2>Allow-list (msDS-Settings)</h2>'
    ($allowed | ConvertTo-Html -Fragment -Property Sid, Name)
    '<h2>Marked users</h2>'
    ($mUsers | ConvertTo-Html -Fragment -Property Name, SamAccountName, ObjectSoa, Enabled, Scril, Origin)
    '<h2>Marked groups</h2>'
    ($mGroups | ConvertTo-Html -Fragment -Property Name, SamAccountName, ObjectSoa, Members, Origin)
    '<h2>Provisioned but not marked</h2>'
    ($unmarked | ConvertTo-Html -Fragment -Property Class, Name, SamAccountName, DistinguishedName)
)
ConvertTo-Html -Head $css -Body ($html -join "`n") -Title 'SOA enforcement impact' | Set-Content (Join-Path $OutputPath 'impact.html') -Encoding UTF8
Write-Host ''
Write-Host "Reports: $OutputPath" -ForegroundColor Cyan
Write-Host "         (contains names of your environment - share it only through Export-SoaReport.ps1)" -ForegroundColor DarkGray
#endregion
