#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Step-by-step rollback of everything Install-SoaToolkit.ps1 created or changed.

.DESCRIPTION
    Uses the install manifest (<ReportPath>\State\manifest.json; a copy is on every toolkit host) and the marker
    "[SoaToolkit]" on every object the toolkit created. Objects that existed before the installation
    (manifest action 'PreExisting', no marker) are NEVER removed unless -Force is given. Every step can be run on its
    own and supports -WhatIf.

    Steps (executed in this order when several are given):
      SetModeAudit          policy keywords -> Audit (marked objects become writable again; no effect on users)
      StopTasks             disables all toolkit tasks on all hosts (from here on the toolkit writes nothing)
      RevertUsers           OPTIONAL, never part of a preset: restores SCRIL / "password never expires" of the users
                            the toolkit changed, from the journals of all hosts. WARNING: without SCRIL the
                            automatic rolling stops - the (random, unknown) password expires and passwordless sign-in
                            fails with KDC_ERR_KEY_EXPIRED (0x17). Requires mode Audit.
      RemovePso             deletes the PSO (users fall back to the domain password policy; rolling continues with the
                            domain maxPwdAge)
      RemoveAllowList       removes the toolkit gMSA (and break-glass) SID from msDS-Settings - BEFORE RemoveGmsa,
                            because a stale SID makes the whole policy fail to load
      RemovePolicy          deletes CN=Cloud if the toolkit created it (= AD object enforcement off)
      RemoveTasks           collects journals / status / logs to <ReportPath>\Uninstall\<host>, then removes tasks,
                            task folder, scripts, data folder and the event log 'SoaToolkit' on every host
      RemoveAudit           removes the toolkit SACL entries (exact fingerprint, only where the manifest records them)
                            and the audit GPO (if created)
      RemoveDelegation      removes every ACE of the toolkit gMSA (and break-glass) and the Event Log Readers membership
      RemoveBatchLogonGpo   deletes the batch logon GPO(s); verifies the right on the hosts (-Refresh), cleans a
                            remaining local entry on member servers
      RemoveKirGpo          deletes the KIR GPO(s) and WMI filter(s) created by the toolkit (engine off after the next
                            DC restart); -RemoveAdmx also deletes the copied ADMX/ADML (only if unchanged)
      RemoveDiagnosticsGpo  deletes the diagnostics GPO ('2 Security Events' is removed from the DCs)
      RemoveGmsa            deletes the toolkit gMSA (refused while its SID is still allow-listed) and SOA-Toolkit-Hosts
      RemoveGroups          deletes SOA-CloudUsers-PSO, -Exclude, -Pilot
      RestoreRolling        restores msDS-ExpirePasswordsOnSmartCardOnlyAccounts if the toolkit changed it
      RemoveAccounts        deletes the break-glass account if the toolkit created it (the TestUser comes from Entra ID)
      Verify                lists everything that still carries the toolkit marker

    Presets:
      -Preset Decommission  remove the toolkit, KEEP the target state and Microsoft's feature:
                             StopTasks, RemoveAllowList, RemoveTasks, RemoveDelegation, RemoveBatchLogonGpo, RemoveGmsa, Verify
                             Existing users keep working (SCRIL + DC rolling + PSO are native AD functions); NEW users and
                             SOA conversions are no longer configured.
      -Preset Full          everything except RevertUsers:
                             SetModeAudit, StopTasks, RemovePso, RemoveAllowList, RemovePolicy, RemoveTasks, RemoveAudit,
                             RemoveDelegation, RemoveBatchLogonGpo, RemoveKirGpo, RemoveDiagnosticsGpo, RemoveGmsa,
                             RemoveGroups, RestoreRolling, RemoveAccounts, Verify

.EXAMPLE
    .\Uninstall-SoaToolkit.ps1 -Preset Decommission -WhatIf
    .\Uninstall-SoaToolkit.ps1 -Step SetModeAudit
    .\Uninstall-SoaToolkit.ps1 -Preset Full -Refresh
    .\Uninstall-SoaToolkit.ps1 -Step RevertUsers -WhatIf

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.0.2 (2026-10-21)
    Run as Domain Admin from the admin workstation (RSAT ActiveDirectory + GroupPolicy). WinRM to the toolkit hosts.
    Not handled (outside the toolkit): Cloud Sync configuration and attribute mappings, msDS-ObjectSoa on users and
    groups (without a policy it has no effect), Windows updates, the KDS root key (never delete it), pre-existing GPOs.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('SetModeAudit', 'StopTasks', 'RevertUsers', 'RemovePso', 'RemoveAllowList', 'RemovePolicy', 'RemoveTasks', 'RemoveAudit',
                 'RemoveDelegation', 'RemoveBatchLogonGpo', 'RemoveKirGpo', 'RemoveDiagnosticsGpo', 'RemoveGmsa', 'RemoveGroups',
                 'RestoreRolling', 'RemoveAccounts', 'Verify')]
    [string[]] $Step,

    [ValidateSet('Decommission', 'Full')]
    [string] $Preset,

    [switch] $RemoveAdmx,
    [switch] $Refresh,
    [switch] $Force,

    [string] $ConfigPath = (Join-Path $PSScriptRoot 'SoaToolkit.config.psd1')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SoaToolkit.psm1') -Force -DisableNameChecking

if (-not $Step -and -not $Preset) { throw 'Pass -Step and/or -Preset Decommission|Full.' }
$presets = @{
    Decommission = @('StopTasks', 'RemoveAllowList', 'RemoveTasks', 'RemoveDelegation', 'RemoveBatchLogonGpo', 'RemoveGmsa', 'Verify')
    Full         = @('SetModeAudit', 'StopTasks', 'RemovePso', 'RemoveAllowList', 'RemovePolicy', 'RemoveTasks', 'RemoveAudit', 'RemoveDelegation',
                     'RemoveBatchLogonGpo', 'RemoveKirGpo', 'RemoveDiagnosticsGpo', 'RemoveGmsa', 'RemoveGroups', 'RestoreRolling', 'RemoveAccounts', 'Verify')
}
$selected = @(@($Step) + @(if ($Preset) { $presets[$Preset] }) | Where-Object { $_ } | Select-Object -Unique)
$order = 'SetModeAudit', 'StopTasks', 'RevertUsers', 'RemovePso', 'RemoveAllowList', 'RemovePolicy', 'RemoveTasks', 'RemoveAudit', 'RemoveDelegation',
         'RemoveBatchLogonGpo', 'RemoveKirGpo', 'RemoveDiagnosticsGpo', 'RemoveGmsa', 'RemoveGroups', 'RestoreRolling', 'RemoveAccounts', 'Verify'

#region --- Context --------------------------------------------------------------------------------
$cfg      = Import-SoaConfig -Path $ConfigPath
$ctx      = Get-SoaContext
$pdc      = $ctx.Pdc
$Cmdlet   = $PSCmdlet
$Uac      = Get-SoaConstant 'Uac'
$S        = Get-SoaConstant 'Sid'
$drive    = Initialize-SoaAdDrive -Server $pdc
$manifest = Get-SoaManifest -Config $cfg
$hasManifest = Test-Path -LiteralPath (Get-SoaManifestPath -Config $cfg)
$roles    = @(Get-SoaHostRoles -Config $cfg -Context $ctx)
$deployedHosts = @(@(Get-SoaManifestEntry -Manifest $manifest -Kind 'HostDeployment' | ForEach-Object { $_.Key }) + @($roles | ForEach-Object { $_.Host }) | Select-Object -Unique)
$log = Join-Path (Join-Path $cfg.ReportPath 'State') ('uninstall_{0:yyyyMMdd}.log' -f (Get-Date))
New-Item -Path (Split-Path $log -Parent) -ItemType Directory -Force | Out-Null
function Write-UninstallLog([string]$Text) { Add-Content -Path $log -Value ('{0:s} {1} {2}' -f (Get-Date), [Security.Principal.WindowsIdentity]::GetCurrent().Name, $Text) -Encoding UTF8 }
function Save-Manifest { if (-not $WhatIfPreference -and $hasManifest) { Save-SoaManifest -Config $cfg -Manifest $manifest -Context $ctx } }

# May the toolkit remove this object? Created by the toolkit (manifest or marker) - or -Force.
function Test-Owned($Entry, [string]$MarkerText) {
    if ($Force) { return $true }
    if ($Entry -and $Entry.Action -in 'Created', 'Adopted') { return $true }
    if ($Entry -and $Entry.Action -eq 'PreExisting') { return $false }
    return (Test-SoaMarker $MarkerText)
}

$runId = [guid]::NewGuid().ToString('N').Substring(0, 8)
Write-UninstallLog ("RUN {0} START tool=Uninstall version={1} steps={2} preset={3} whatif={4}" -f $runId, (Get-SoaVersion).Version, (($order | Where-Object { $selected -contains $_ }) -join ','), $Preset, [bool]$WhatIfPreference)
Set-SoaLineLog -Path $log -Prefix "RUN $runId"

Write-SoaSection ("SOA Toolkit {0} - Uninstall - domain {1} - steps: {2}" -f (Get-SoaVersion).Version, $ctx.DnsRoot, (($order | Where-Object { $selected -contains $_ }) -join ', '))
if (-not $hasManifest) { Write-SoaLine WARN "No manifest at $(Get-SoaManifestPath -Config $cfg) - falling back to the marker '[SoaToolkit]' and the configured names (previous values cannot be restored)." }
#endregion

foreach ($current in ($order | Where-Object { $selected -contains $_ })) {
    Write-UninstallLog "Step $current started (WhatIf=$WhatIfPreference)"
    switch ($current) {

        'SetModeAudit' {
            Write-SoaSection 'SetModeAudit'
            $pol = Get-SoaPolicy -Context $ctx
            if (-not $pol) { Write-SoaLine SKIP 'no policy'; break }
            $mode = (@($pol.keywords) -join ',')
            if ($mode -eq 'Audit') { Write-SoaLine SAME 'mode already Audit'; break }
            if ($Cmdlet.ShouldProcess($ctx.PolicyDN, "keywords $mode -> Audit")) {
                Set-ADObject -Identity $ctx.PolicyDN -Server $pdc -Replace @{ keywords = 'Audit' }
                Write-SoaLine DEL "mode $mode -> Audit (replicates to all DCs within minutes)"
                $pe = Get-SoaManifestEntry -Manifest $manifest -Kind 'PolicyMode' -Key 'Cloud' | Select-Object -First 1
                if ($pe -and $pe.Previous -and $pe.Previous.Mode -eq 'Enforced') { Write-SoaLine INFO 'The policy was already Enforced before the toolkit was installed - switch it back manually if it should stay enforced.' }
            }
        }

        'StopTasks' {
            Write-SoaSection 'StopTasks'
            foreach ($h in $deployedHosts) {
                if (-not $Cmdlet.ShouldProcess($h, "Disable all tasks in $($cfg.TaskFolder)")) { continue }
                $res = Invoke-SoaOnHost -ComputerName $h -ArgumentList $cfg.TaskFolder -ScriptBlock {
                    param($Folder)
                    @(Get-ScheduledTask -TaskPath $Folder -ErrorAction SilentlyContinue | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $Folder | Out-Null; $_.TaskName })
                }
                if ($res.Ok) { Write-SoaLine DEL ("{0}: disabled {1}" -f $h, $(if (@($res.Result).Count) { @($res.Result) -join ', ' } else { 'nothing (no tasks)' })) } else { Write-SoaLine WARN "${h}: $($res.Error)" }
            }
        }

        'RevertUsers' {
            Write-SoaSection 'RevertUsers (optional)'
            Write-Host 'WARNING: removing SCRIL stops the automatic rolling of the users'' secret. Their AD password is random and unknown;' -ForegroundColor Red
            Write-Host '         it expires according to the password policy and passwordless sign-in (WHfB / FIDO2 via Cloud Kerberos Trust)' -ForegroundColor Red
            Write-Host '         then fails with KDC_ERR_KEY_EXPIRED (0x17) - the original problem returns. Only use this if the users get' -ForegroundColor Red
            Write-Host '         passwords again or "password never expires" from the journal is restored.' -ForegroundColor Red
            if ((Get-SoaPolicyMode -Context $ctx) -eq 'Enforced') { throw 'The policy is Enforced - run -Step SetModeAudit first (your writes would be blocked).' }
            $entries = New-Object System.Collections.Generic.List[object]
            foreach ($h in $deployedHosts) {
                $res = Invoke-SoaOnHost -ComputerName $h -ArgumentList $cfg.DataPath -ScriptBlock {
                    param($DataPath)
                    $dir = Join-Path $DataPath 'Journal'
                    if (Test-Path $dir) { Get-ChildItem -Path $dir -Filter 'journal-*.jsonl' | ForEach-Object { Get-Content -Path $_.FullName } }
                }
                if ($res.Ok) { foreach ($l in @($res.Result)) { try { $entries.Add(($l | ConvertFrom-Json)) } catch { } } }
                else { Write-SoaLine WARN "journal of $h not readable: $($res.Error)" }
            }
            $local = Join-Path $cfg.ReportPath 'Uninstall'
            if (Test-Path $local) { foreach ($f in Get-ChildItem -Path $local -Recurse -Filter 'journal-*.jsonl') { foreach ($l in Get-Content -Path $f.FullName) { try { $entries.Add(($l | ConvertFrom-Json)) } catch { } } } }
            $first = @{}
            foreach ($e in ($entries | Where-Object { $_.PSObject.Properties.Name -contains 'Before' -and $_.Before } | Sort-Object Time)) {
                $k = "$($e.ObjectGuid)"; if (-not $k) { $k = "$($e.Dn)".ToLower() }
                if (-not $first.ContainsKey($k)) { $first[$k] = $e }
            }
            Write-Host ("{0} user(s) with a recorded original state." -f $first.Count)
            foreach ($e in $first.Values) {
                $u = $null
                try { $u = if ($e.ObjectGuid) { Get-ADUser -Identity ([guid]$e.ObjectGuid) -Server $pdc -Properties userAccountControl } else { Get-ADUser -Identity $e.Dn -Server $pdc -Properties userAccountControl } } catch { }
                if (-not $u) { Write-SoaLine SKIP "$($e.User): no longer exists"; continue }
                $set = 0; $clr = 0
                if (-not $e.Before.Scril -and ([int]$u.userAccountControl -band $Uac.Scril)) { $clr = $clr -bor $Uac.Scril }
                if ($e.Before.Pne -and -not ([int]$u.userAccountControl -band $Uac.DontExpire)) { $set = $set -bor $Uac.DontExpire }
                if (-not ($set -or $clr)) { Write-SoaLine SAME "$($u.SamAccountName): already in the original state"; continue }
                $what = @(if ($clr) { 'clear SCRIL' }; if ($set) { "set 'password never expires'" }) -join ', '
                if ($Cmdlet.ShouldProcess($u.SamAccountName, $what)) {
                    $r = Set-SoaUacFlags -Dn $u.DistinguishedName -Server $pdc -SetBits $set -ClearBits $clr
                    Write-SoaLine DEL ("{0}: {1} (0x{2:X} -> 0x{3:X})" -f $u.SamAccountName, $what, $r.Old, $r.New)
                }
            }
        }

        'RemovePso' {
            Write-SoaSection "RemovePso: $($cfg.PsoName)"
            $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$($cfg.PsoName)'" -Server $pdc -Properties Description, ProtectedFromAccidentalDeletion
            if (-not $pso) { Write-SoaLine SKIP 'not found'; break }
            $entry = Get-SoaManifestEntry -Manifest $manifest -Kind 'Pso' -Key 'CloudUsers' | Select-Object -First 1
            if (-not (Test-Owned $entry $pso.Description)) { Write-SoaLine SKIP 'pre-existing / not created by the toolkit (use -Force)'; break }
            if ($Cmdlet.ShouldProcess($cfg.PsoName, 'Delete PSO (users fall back to the domain password policy)')) {
                if ($pso.ProtectedFromAccidentalDeletion) { Set-ADObject -Identity $pso.DistinguishedName -Server $pdc -ProtectedFromAccidentalDeletion $false }
                Remove-ADFineGrainedPasswordPolicy -Identity $pso -Server $pdc -Confirm:$false
                Write-SoaLine DEL "PSO $($cfg.PsoName) deleted"
                Remove-SoaManifestEntry -Manifest $manifest -Kind 'Pso' -Key 'CloudUsers'; Save-Manifest
            }
        }

        'RemoveAllowList' {
            Write-SoaSection 'RemoveAllowList'
            $pol = Get-SoaPolicy -Context $ctx
            if (-not $pol) { Write-SoaLine SKIP 'no policy'; break }
            $remove = @()
            $j = Get-SoaJobGmsa -Config $cfg -Context $ctx
            if ($j) { $remove += $j.SID.Value }
            if ($cfg.BreakGlassName) { $bg = Get-ADUser -Filter "SamAccountName -eq '$($cfg.BreakGlassName)'" -Server $pdc -Properties description; if ($bg -and (Test-SoaMarker $bg.description)) { $remove += $bg.SID.Value } }
            $cur = @($pol.'msDS-Settings' | ForEach-Object { "$_" })
            $remove = @($remove | Where-Object { $cur -contains $_ })
            if (-not $remove.Count) { Write-SoaLine SAME 'no toolkit SID in the allow-list'; break }
            if ($cur.Count - $remove.Count -lt 1) { Write-SoaLine WARN 'the allow-list would become empty - Cloud Sync agents would be blocked under Enforced' }
            if ($Cmdlet.ShouldProcess($ctx.PolicyDN, "Remove $($remove -join ', ') from msDS-Settings")) {
                Set-ADObject -Identity $ctx.PolicyDN -Server $pdc -Remove @{ 'msDS-Settings' = [string[]]$remove }
                Write-SoaLine DEL "removed from the allow-list: $($remove -join ', ')"
                Remove-SoaManifestEntry -Manifest $manifest -Kind 'AllowList'; Save-Manifest
            }
        }

        'RemovePolicy' {
            Write-SoaSection 'RemovePolicy: CN=Cloud'
            $pol = Get-SoaPolicy -Context $ctx
            if (-not $pol) { Write-SoaLine SKIP 'no policy'; break }
            $entry = Get-SoaManifestEntry -Manifest $manifest -Kind 'Policy' -Key 'Cloud' | Select-Object -First 1
            if (-not (Test-Owned $entry $pol.description)) { Write-SoaLine SKIP 'the policy existed before the toolkit (e.g. created by Set-CloudSyncSOAPolicy.ps1) - kept (use -Force)'; break }
            if ($Cmdlet.ShouldProcess($ctx.PolicyDN, 'Delete the AD object enforcement policy (enforcement off)')) {
                Remove-ADObject -Identity $ctx.PolicyDN -Server $pdc -Confirm:$false
                Write-SoaLine DEL 'CN=Cloud deleted - AD object enforcement is off on every DC after replication (the container CN=SOA-Policies belongs to the engine and stays)'
                Remove-SoaManifestEntry -Manifest $manifest -Kind 'Policy'; Remove-SoaManifestEntry -Manifest $manifest -Kind 'PolicyMode'; Save-Manifest
            }
        }

        'RemoveTasks' {
            Write-SoaSection 'RemoveTasks'
            foreach ($h in $deployedHosts) {
                if (-not $Cmdlet.ShouldProcess($h, 'Collect journal/status/logs, remove tasks, scripts, data and event log')) { continue }
                $dest = Join-Path (Join-Path $cfg.ReportPath 'Uninstall') (Get-SoaShortName $h)
                New-Item -Path $dest -ItemType Directory -Force | Out-Null
                $isLocal = ($h -eq (Get-SoaLocalFqdn)) -or ((Get-SoaShortName $h) -ieq $env:COMPUTERNAME)
                try {
                    $session = if ($isLocal) { $null } else { New-PSSession -ComputerName $h }
                    foreach ($sub in 'Journal', 'Status', 'Logs') {
                        $src = Join-Path $cfg.DataPath $sub
                        $exists = if ($session) { Invoke-Command -Session $session -ScriptBlock { param($Path) Test-Path -Path $Path } -ArgumentList $src } else { Test-Path $src }
                        if ($exists) {
                            if ($session) { Copy-Item -Path $src -Destination $dest -FromSession $session -Recurse -Force } else { Copy-Item -Path $src -Destination $dest -Recurse -Force }
                        }
                    }
                    $block = {
                        param($Folder, $InstallPath, $DataPath, $LogName)
                        $out = @()
                        foreach ($t in @(Get-ScheduledTask -TaskPath $Folder -ErrorAction SilentlyContinue)) { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $Folder -Confirm:$false; $out += "task $($t.TaskName) removed" }
                        try { $svc = New-Object -ComObject 'Schedule.Service'; $svc.Connect(); $svc.GetFolder('\').DeleteFolder($Folder.Trim('\'), 0); $out += "task folder $Folder removed" } catch { }
                        foreach ($p in @($InstallPath, $DataPath)) { if (Test-Path $p) { Remove-Item -Path $p -Recurse -Force; $out += "$p removed" } }
                        if ([Diagnostics.EventLog]::Exists($LogName)) { [Diagnostics.EventLog]::Delete($LogName); $out += "event log $LogName removed" }
                        $out
                    }
                    $a = @($cfg.TaskFolder, $cfg.ScriptInstallPath, $cfg.DataPath, $cfg.EventLogName)
                    $out = if ($session) { Invoke-Command -Session $session -ScriptBlock $block -ArgumentList $a } else { & $block @a }
                    foreach ($o in @($out)) { Write-SoaLine DEL "${h}: $o" }
                    Write-SoaLine INFO "${h}: journal/status/logs saved to $dest"
                    Remove-SoaManifestEntry -Manifest $manifest -Kind 'HostDeployment' -Key $h
                } catch { Write-SoaLine WARN "${h}: $($_.Exception.Message)" }
                finally { if ($session) { Remove-PSSession $session } }
            }
            Save-Manifest
        }

        'RemoveAudit' {
            Write-SoaSection 'RemoveAudit'
            $sacl = Get-SoaManifestEntry -Manifest $manifest -Kind 'Sacl' -Key 'msDS-ObjectSoa' | Select-Object -First 1
            if ($sacl) {
                $attr = [guid]$sacl.Data.AttributeGuid
                foreach ($dn in @($sacl.Data.Dns)) {
                    if (-not $Cmdlet.ShouldProcess($dn, 'Remove SACL entry (Everyone, Success, Write msDS-ObjectSoa)')) { continue }
                    $acl = Get-Acl -Path "$drive\$dn" -Audit
                    $hit = @($acl.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { Test-SoaSaclFingerprint -Rule $_ -AttributeGuid $attr })
                    foreach ($r in $hit) { [void]$acl.RemoveAuditRuleSpecific($r) }
                    if ($hit.Count) { Set-Acl -Path "$drive\$dn" -AclObject $acl; Write-SoaLine DEL "SACL entry removed on $dn" } else { Write-SoaLine SKIP "no toolkit SACL entry on $dn" }
                }
                Remove-SoaManifestEntry -Manifest $manifest -Kind 'Sacl'
            } else { Write-SoaLine SKIP 'no SACL entries recorded in the manifest' }
            $g = Get-SoaGpo -Name $cfg.AuditGpoName -Context $ctx
            if ($g) {
                $entry = Get-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key 'Audit' | Select-Object -First 1
                if ((Test-Owned $entry $g.Description) -and $Cmdlet.ShouldProcess($cfg.AuditGpoName, 'Delete GPO')) {
                    Remove-GPO -Guid $g.Id -Domain $ctx.DnsRoot -Server $pdc
                    Write-SoaLine DEL "GPO $($cfg.AuditGpoName) deleted (advanced audit settings revert to the remaining GPOs)"
                    Remove-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key 'Audit'
                }
            } else { Write-SoaLine SKIP "GPO $($cfg.AuditGpoName) not found (none was needed)" }
            Save-Manifest
        }

        'RemoveDelegation' {
            Write-SoaSection 'RemoveDelegation'
            $sids = @()
            $j = Get-SoaJobGmsa -Config $cfg -Context $ctx
            if ($j) { $sids += $j.SID.Value }
            if ($cfg.BreakGlassName) { $bg = Get-ADUser -Filter "SamAccountName -eq '$($cfg.BreakGlassName)'" -Server $pdc -Properties description; if ($bg -and (Test-SoaMarker $bg.description)) { $sids += $bg.SID.Value } }
            $targets = @(Get-SoaManifestEntry -Manifest $manifest -Kind 'Ace' | ForEach-Object { $_.Data.TargetDn })
            if (-not $targets.Count) {
                $targets = @(Get-SoaWriteScope -Config $cfg -Context $ctx) + $ctx.PscDN
                $pg = Get-ADGroup -Filter "Name -eq '$($cfg.PsoGroupName)'" -Server $pdc; if ($pg) { $targets += $pg.DistinguishedName }
                if ($cfg.TestUser) { $tu = Get-ADUser -Filter "SamAccountName -eq '$($cfg.TestUser)'" -Server $pdc; if ($tu) { $targets += $tu.DistinguishedName } }
            }
            foreach ($dn in @($targets | Select-Object -Unique)) {
                foreach ($sid in $sids) {
                    try {
                        $n = Remove-SoaTrusteeAces -TargetDn $dn -Sid $sid -WhatIf:$WhatIfPreference
                        if ($n) { Write-SoaLine DEL "$n ACE(s) of $sid removed on $dn" }
                    } catch { Write-SoaLine WARN "${dn}: $($_.Exception.Message) (marked object under Enforced? run SetModeAudit first)" }
                }
            }
            if ($j) {
                $elr = Get-ADGroup -Identity $S.EventLogReaders -Server $pdc -Properties member
                if (@($elr.member) -contains $j.DistinguishedName -and $Cmdlet.ShouldProcess('BUILTIN\Event Log Readers', "Remove $($cfg.GmsaName)")) {
                    Remove-ADGroupMember -Identity $elr -Members $j -Server $pdc -Confirm:$false
                    Write-SoaLine DEL "BUILTIN\Event Log Readers -= $($cfg.GmsaName)"
                }
            }
            Remove-SoaManifestEntry -Manifest $manifest -Kind 'Ace'; Remove-SoaManifestEntry -Manifest $manifest -Kind 'Membership'; Save-Manifest
        }

        'RemoveBatchLogonGpo' {
            Write-SoaSection 'RemoveBatchLogonGpo'
            foreach ($k in @(@{ Key = 'BatchLogonDc'; Name = $cfg.BatchLogonGpoNameDc }, @{ Key = 'BatchLogonAgent'; Name = $cfg.BatchLogonGpoNameAgent })) {
                $g = Get-SoaGpo -Name $k.Name -Context $ctx
                if (-not $g) { Write-SoaLine SKIP "GPO $($k.Name) not found"; continue }
                $entry = Get-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key $k.Key | Select-Object -First 1
                if (-not (Test-Owned $entry $g.Description)) { Write-SoaLine SKIP "GPO $($k.Name) not created by the toolkit"; continue }
                if ($Cmdlet.ShouldProcess($k.Name, 'Delete GPO')) {
                    Remove-GPO -Guid $g.Id -Domain $ctx.DnsRoot -Server $pdc
                    Write-SoaLine DEL "GPO $($k.Name) deleted - 'Log on as a batch job' reverts to the remaining GPOs"
                    Remove-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key $k.Key
                }
            }
            Save-Manifest
            $j = Get-SoaJobGmsa -Config $cfg -Context $ctx
            if ($Refresh -and $j -and -not $WhatIfPreference) {
                Start-Sleep -Seconds 30
                foreach ($r in $roles) {
                    [void](Invoke-SoaOnHost -ComputerName $r.Host -ScriptBlock { gpupdate.exe /target:computer /force | Out-Null })
                    $res = Invoke-SoaOnHost -ComputerName $r.Host -ScriptBlock (Get-SoaBatchRightBlock)
                    if ($res.Ok -and @($res.Result) -contains $j.SID.Value) {
                        if ($r.IsDc) { Write-SoaLine WARN "$($r.Host): gMSA still has the right - another GPO grants it?" }
                        else {
                            # Member server: remove a remaining (tattooed) local entry
                            $clean = Invoke-SoaOnHost -ComputerName $r.Host -ArgumentList $j.SID.Value -ScriptBlock {
                                param($Sid)
                                $tmp = Join-Path $env:TEMP ('soa_rm_{0}' -f [guid]::NewGuid().ToString('N'))
                                & secedit.exe /export /cfg "$tmp.inf" /areas USER_RIGHTS | Out-Null
                                $new = foreach ($l in (Get-Content -Path "$tmp.inf")) {
                                    if ($l -match '^\s*SeBatchLogonRight\s*=') { 'SeBatchLogonRight = ' + ((@((($l -split '=', 2)[1] -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne "*$Sid" })) -join ',') } else { $l }
                                }
                                Set-Content -Path "$tmp.inf" -Value $new -Encoding Unicode
                                & secedit.exe /configure /db "$tmp.sdb" /cfg "$tmp.inf" /areas USER_RIGHTS /quiet | Out-Null
                                Remove-Item -Path "$tmp.*" -Force -ErrorAction SilentlyContinue
                            }
                            Write-SoaLine $(if ($clean.Ok) { 'DEL' } else { 'WARN' }) "$($r.Host): remaining local entry $(if ($clean.Ok) { 'removed' } else { "not removed: $($clean.Error)" })"
                        }
                    } elseif ($res.Ok) { Write-SoaLine PASS "$($r.Host): gMSA no longer has 'Log on as a batch job'" }
                }
            }
        }

        'RemoveKirGpo' {
            Write-SoaSection 'RemoveKirGpo'
            foreach ($label in 'WS2022', 'WS2025') {
                $name = '{0} ({1})' -f $cfg.KirGpoNamePrefix, $label
                $entry = Get-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key "Kir$label" | Select-Object -First 1
                $g = Get-SoaGpo -Name $name -Context $ctx
                if ($g -and (Test-Owned $entry $g.Description)) {
                    if ($Cmdlet.ShouldProcess($name, 'Delete GPO (AD object enforcement engine off after the next DC restart)')) {
                        Remove-GPO -Guid $g.Id -Domain $ctx.DnsRoot -Server $pdc
                        Write-SoaLine DEL "GPO $name deleted - restart the $label DCs to deactivate the feature"
                        Remove-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key "Kir$label"
                    }
                } elseif ($entry -and $entry.Action -eq 'PreExisting') { Write-SoaLine SKIP "$label : pre-existing GPO '$($entry.Data.Name)' - kept" }
                else { Write-SoaLine SKIP "$label : no toolkit GPO" }
                $wf = Get-SoaManifestEntry -Manifest $manifest -Kind 'WmiFilter' -Key $label | Select-Object -First 1
                if ($wf -and $wf.Action -eq 'Created') {
                    $users = @(Get-ADObject -Server $pdc -SearchBase "CN=Policies,CN=System,$($ctx.DomainDN)" -LDAPFilter "(gPCWQLFilter=*$($wf.Data.Id)*)")
                    if ($users.Count) { Write-SoaLine SKIP "WMI filter $($wf.Data.Id) still used by $($users.Count) GPO(s)" }
                    elseif ($Cmdlet.ShouldProcess($wf.Data.Dn, 'Delete WMI filter')) {
                        Remove-ADObject -Identity $wf.Data.Dn -Server $pdc -Confirm:$false
                        Write-SoaLine DEL "WMI filter $($wf.Data.Id) deleted"
                        Remove-SoaManifestEntry -Manifest $manifest -Kind 'WmiFilter' -Key $label
                    }
                }
                if ($RemoveAdmx) {
                    $ad = Get-SoaManifestEntry -Manifest $manifest -Kind 'AdmxFiles' -Key $label | Select-Object -First 1
                    foreach ($f in @(if ($ad) { $ad.Data.Files })) {
                        if (-not (Test-Path -LiteralPath $f.Path)) { continue }
                        if ((Get-FileHash -LiteralPath $f.Path -Algorithm SHA256).Hash -ne $f.Sha256 -and -not $Force) { Write-SoaLine SKIP "$($f.Path) changed since the installation - kept"; continue }
                        if ($Cmdlet.ShouldProcess($f.Path, 'Delete policy definition')) { Remove-Item -LiteralPath $f.Path -Force; Write-SoaLine DEL "$($f.Path) deleted" }
                    }
                    if ($ad) { Remove-SoaManifestEntry -Manifest $manifest -Kind 'AdmxFiles' -Key $label }
                }
            }
            Save-Manifest
        }

        'RemoveDiagnosticsGpo' {
            Write-SoaSection 'RemoveDiagnosticsGpo'
            $g = Get-SoaGpo -Name $cfg.DiagnosticsGpoName -Context $ctx
            $entry = Get-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key 'Diagnostics' | Select-Object -First 1
            if (-not $g) { Write-SoaLine SKIP 'not found'; break }
            if (-not (Test-Owned $entry $g.Description)) { Write-SoaLine SKIP 'not created by the toolkit'; break }
            & (Join-Path $PSScriptRoot 'Set-SoaDiagnosticsGpo.ps1') -Action Remove -ConfigPath $ConfigPath -Refresh:$Refresh -WhatIf:$WhatIfPreference -Confirm:$false
            if (-not $WhatIfPreference) { Remove-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key 'Diagnostics'; Save-Manifest }
        }

        'RemoveGmsa' {
            Write-SoaSection 'RemoveGmsa'
            $j = Get-SoaJobGmsa -Config $cfg -Context $ctx
            if ($j) {
                $pol = Get-SoaPolicy -Context $ctx
                if ($pol -and @($pol.'msDS-Settings' | ForEach-Object { "$_" }) -contains $j.SID.Value) { throw "The gMSA SID is still in the allow-list - run -Step RemoveAllowList first (a stale SID would make the policy fail to load)." }
                $entry = Get-SoaManifestEntry -Manifest $manifest -Kind 'Gmsa' -Key 'Toolkit' | Select-Object -First 1
                if (-not (Test-Owned $entry $j.Description)) { Write-SoaLine SKIP 'gMSA not created by the toolkit' }
                elseif ($Cmdlet.ShouldProcess($cfg.GmsaName, 'Delete gMSA')) {
                    Remove-ADServiceAccount -Identity $j -Server $pdc -Confirm:$false
                    Write-SoaLine DEL "gMSA $($cfg.GmsaName) deleted"
                    Remove-SoaManifestEntry -Manifest $manifest -Kind 'Gmsa'
                }
            } else { Write-SoaLine SKIP 'gMSA not found' }
            $hg = Get-ADGroup -Filter "Name -eq '$($cfg.HostGroupName)'" -Server $pdc -Properties description
            if ($hg) {
                $entry = Get-SoaManifestEntry -Manifest $manifest -Kind 'Group' -Key 'HostGroup' | Select-Object -First 1
                if ((Test-Owned $entry $hg.description) -and $Cmdlet.ShouldProcess($cfg.HostGroupName, 'Delete group')) {
                    Remove-ADGroup -Identity $hg -Server $pdc -Confirm:$false
                    Write-SoaLine DEL "group $($cfg.HostGroupName) deleted"
                    Remove-SoaManifestEntry -Manifest $manifest -Kind 'Group' -Key 'HostGroup'
                }
            }
            Save-Manifest
        }

        'RemoveGroups' {
            Write-SoaSection 'RemoveGroups'
            foreach ($d in @(@{ Key = 'PsoGroup'; Name = $cfg.PsoGroupName }, @{ Key = 'ExcludeGroup'; Name = $cfg.ExcludeGroupName }, @{ Key = 'PilotGroup'; Name = $cfg.PilotGroupName })) {
                $g = Get-ADGroup -Filter "Name -eq '$($d.Name)'" -Server $pdc -Properties description
                if (-not $g) { Write-SoaLine SKIP "$($d.Name) not found"; continue }
                $entry = Get-SoaManifestEntry -Manifest $manifest -Kind 'Group' -Key $d.Key | Select-Object -First 1
                if (-not (Test-Owned $entry $g.description)) { Write-SoaLine SKIP "$($d.Name) not created by the toolkit"; continue }
                if ($Cmdlet.ShouldProcess($d.Name, 'Delete group')) {
                    Remove-ADGroup -Identity $g -Server $pdc -Confirm:$false
                    Write-SoaLine DEL "group $($d.Name) deleted"
                    Remove-SoaManifestEntry -Manifest $manifest -Kind 'Group' -Key $d.Key
                }
            }
            Save-Manifest
        }

        'RestoreRolling' {
            Write-SoaSection 'RestoreRolling'
            $entry = Get-SoaManifestEntry -Manifest $manifest -Kind 'Domain' -Key 'Rolling' | Select-Object -First 1
            if (-not $entry -or $entry.Action -ne 'Changed') { Write-SoaLine SKIP 'not changed by the toolkit (was already enabled) - kept'; break }
            $prev = $entry.Previous.Value
            if ($Cmdlet.ShouldProcess($ctx.DomainDN, "Restore msDS-ExpirePasswordsOnSmartCardOnlyAccounts = $(if ($null -eq $prev) { 'not set' } else { $prev })")) {
                if ($null -eq $prev) { Set-ADObject -Identity $ctx.DomainDN -Server $pdc -Clear 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' }
                else { Set-ADObject -Identity $ctx.DomainDN -Server $pdc -Replace @{ 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' = [bool]$prev } }
                Write-SoaLine DEL 'automatic rolling restored to the previous value (SCRIL users then keep their secret until it is changed otherwise)'
                Remove-SoaManifestEntry -Manifest $manifest -Kind 'Domain' -Key 'Rolling'; Save-Manifest
            }
        }

        'RemoveAccounts' {
            Write-SoaSection 'RemoveAccounts'
            if (-not $cfg.BreakGlassName) { Write-SoaLine SKIP 'no break-glass account configured'; break }
            $bg = Get-ADUser -Filter "SamAccountName -eq '$($cfg.BreakGlassName)'" -Server $pdc -Properties description
            $entry = Get-SoaManifestEntry -Manifest $manifest -Kind 'User' -Key 'BreakGlass' | Select-Object -First 1
            if (-not $bg) { Write-SoaLine SKIP 'not found'; break }
            if ((Test-Owned $entry $bg.description) -and $Cmdlet.ShouldProcess($cfg.BreakGlassName, 'Delete break-glass account')) {
                Remove-ADUser -Identity $bg -Server $pdc -Confirm:$false
                Write-SoaLine DEL "$($cfg.BreakGlassName) deleted"
                Remove-SoaManifestEntry -Manifest $manifest -Kind 'User' -Key 'BreakGlass'; Save-Manifest
            }
        }

        'Verify' {
            Write-SoaSection 'Verify: remaining objects with the SOA Toolkit marker'
            $tag = ConvertTo-SoaLdapValue (Get-SoaConstant 'Tag')
            $left = @(Get-ADObject -Server $pdc -LDAPFilter "(|(description=*$tag*)(msWMI-Parm1=*$tag*))" -SearchBase $ctx.DomainDN -Properties description, 'msWMI-Name' -ResultPageSize 500)
            foreach ($o in $left) { Write-SoaLine INFO ("{0}: {1}" -f $o.ObjectClass, $o.DistinguishedName) }
            $gpos = @(Get-GPO -All -Domain $ctx.DnsRoot -Server $pdc | Where-Object { Test-SoaMarker $_.Description })
            foreach ($g in $gpos) { Write-SoaLine INFO "GPO: $($g.DisplayName)" }
            $j = Get-SoaJobGmsa -Config $cfg -Context $ctx
            $pol = Get-SoaPolicy -Context $ctx
            if ($pol -and $j -and @($pol.'msDS-Settings' | ForEach-Object { "$_" }) -contains $j.SID.Value) { Write-SoaLine WARN 'toolkit gMSA is still allow-listed' }
            foreach ($h in $deployedHosts) {
                $res = Invoke-SoaOnHost -ComputerName $h -ArgumentList $cfg.TaskFolder, $cfg.ScriptInstallPath -ScriptBlock { param($F, $P) [pscustomobject]@{ Tasks = @(Get-ScheduledTask -TaskPath $F -ErrorAction SilentlyContinue).Count; Files = (Test-Path $P) } }
                if ($res.Ok -and ($res.Result.Tasks -or $res.Result.Files)) { Write-SoaLine INFO ("{0}: {1} task(s), scripts present: {2}" -f $h, $res.Result.Tasks, $res.Result.Files) }
            }
            if (-not $left.Count -and -not $gpos.Count) { Write-SoaLine PASS 'no AD object or GPO with the toolkit marker left' }
            else { Write-Host 'Objects listed above are either intentionally kept by the chosen steps/preset or pre-existing; remove them with the matching step.' -ForegroundColor DarkGray }
        }
    }
    Write-UninstallLog "Step $current finished"
}
Set-SoaLineLog
Write-UninstallLog "RUN $runId END"
Write-Host ''
Write-Host "Log: $log" -ForegroundColor Cyan
