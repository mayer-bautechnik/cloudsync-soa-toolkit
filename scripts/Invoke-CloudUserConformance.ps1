#Requires -Version 5.1
#Requires -Modules ActiveDirectory
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Brings users provisioned by Microsoft Entra Cloud Sync (Entra ID -> AD) into the passwordless target state.

.DESCRIPTION
    Scope (domain-wide, by attributes): msDS-ExternalDirectoryObjectId = User_*  AND  msDS-ObjectSoa = Cloud,
    minus members of the exclusion group, ExcludeOUs and the break-glass account (and, with PilotMode, only
    members of the pilot group).

    Target state per in-scope user:
      - "Smart card is required for interactive logon" (SCRIL, UAC 0x40000) = set
        -> the DC replaces the password with a random secret; with automatic rolling (DFL >= 2016,
           msDS-ExpirePasswordsOnSmartCardOnlyAccounts = TRUE) the DCs roll the secret at the first passwordless
           sign-in after expiry (rolling interval = MaxPasswordAge of the PSO)
      - "Password never expires" (UAC 0x10000) = cleared (it would disable the automatic rolling)
      - member of the PSO group (the fine-grained password policy applies)
    Out-of-scope members of the PSO group are removed (schedule / manual runs only). SCRIL is never removed.

    -Mode Analyze  (read-only, any admin) - report of all provisioned users: conform / what would change / why not
    -Mode Apply    (toolkit gMSA, from the scheduled tasks) - applies the target state
                   -Trigger Event    : started by the event trigger (4720 / 5136 by the agent) on a writable DC;
                                       re-runs while new events arrive during the run
                   -Trigger Schedule : reconcile task on the agent hosts
                   -Trigger Manual   : interactive / Install-SoaToolkit.ps1 -Step Conform
    -Mode Test -TestAction <action> - single controlled actions, ONLY on the configured TestUser
                   (used by Test-SoaBehavior.ps1 to write as the allow-listed identity)

    userAccountControl is written with an atomic compare-and-swap (LDAP delete old value + add new value in one
    request): a concurrent change by Cloud Sync (e.g. the 'disabled' bit) is never overwritten.

    Output: console, log (DataPath\Logs), journal of every change incl. previous flags (DataPath\Journal),
            status file (DataPath\Status\conformance.json), event log 'SoaToolkit'
            (1000 change, 1001 warning, 1002 error, 1010 run summary). Exit code 0 = OK, 1 = errors.

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.0.4 (2026-10-21)
    Reads and writes go to one DC per run: the local DC on a writable DC, otherwise a discovered writable DC.
#>
[CmdletBinding()]
param(
    [ValidateSet('Analyze', 'Apply', 'Test')]
    [string] $Mode = 'Analyze',

    [ValidateSet('Event', 'Schedule', 'Manual')]
    [string] $Trigger = 'Manual',

    [ValidateSet('ScrilOn', 'ScrilOff', 'ScrilRewrite', 'RandomReset', 'PneOn', 'PneOff', 'DenyChangeOn', 'DenyChangeOff',
                 'MustChangeOn', 'MustChangeOff', 'Unlock', 'ProbeWrite', 'GroupAdd', 'GroupRemove')]
    [string] $TestAction,

    [string] $Identity,

    [string] $Server,

    [string] $OutputPath,

    [switch] $IncludeAcl,

    [string] $ConfigPath
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
Import-Module (Join-Path $ScriptRoot 'SoaToolkit.psm1') -Force -DisableNameChecking
$ConfigPath = Resolve-SoaConfigPath -ConfigPath $ConfigPath -ScriptRoot $ScriptRoot

$cfg     = Import-SoaConfig -Path $ConfigPath
$server  = Select-SoaTargetDc -Preferred $Server
$Uac     = Get-SoaConstant 'Uac'
$Ucc     = Get-SoaConstant 'Ucc'
$G       = Get-SoaConstant 'Guid'
$EventId = Get-SoaConstant 'EventId'
$logName = 'Conformance'
$runAs   = [Security.Principal.WindowsIdentity]::GetCurrent().Name

# Deployment information written by Install-SoaToolkit.ps1 -Step DeployTasks (write scope, agent SIDs) - the gMSA
# cannot query the agent hosts itself. Interactive runs compute the values live.
$deployment = $null
$depFile = Join-Path $ScriptRoot 'deployment.json'
if (Test-Path -LiteralPath $depFile) { try { $deployment = Get-Content -LiteralPath $depFile -Raw | ConvertFrom-Json } catch { } }

function Write-RunLog([string]$Text, [string]$Level = 'INFO') {
    Write-SoaLog -DataPath $cfg.DataPath -Name $logName -Message $Text -Level $Level
    if ($Mode -ne 'Apply' -or [Environment]::UserInteractive) {
        $c = switch ($Level) { 'ERROR' { 'Red' } 'WARN' { 'Yellow' } default { 'Gray' } }
        Write-Host $Text -ForegroundColor $c
    }
}

function Get-WriteScope {
    if ($deployment -and $deployment.PSObject.Properties.Name -contains 'WriteScope' -and @($deployment.WriteScope).Count) { return @($deployment.WriteScope) }
    try { return @(Get-SoaWriteScope -Config $cfg -Context (Get-SoaContext -Server $server)) } catch { Write-RunLog "Write scope not determinable: $($_.Exception.Message)" 'WARN'; return @() }
}

function Get-AgentSids {
    if ($deployment -and $deployment.PSObject.Properties.Name -contains 'AgentSids') { return @($deployment.AgentSids) }
    try { return @(Get-SoaAgentGmsa -Config $cfg -Context (Get-SoaContext -Server $server) -Quiet | ForEach-Object { $_.Sid }) } catch { return @() }
}

#==================================================================================================
#  TEST MODE
#==================================================================================================
if ($Mode -eq 'Test') {
    $status = [ordered]@{ Mode = 'Test'; TestAction = $TestAction; Identity = $Identity; RunAs = $runAs; Server = $server; Start = (Get-Date).ToString('s'); End = $null; Success = $false; Errors = @(); Before = $null; After = $null }
    try {
        if (-not $TestAction) { throw '-TestAction is required in Test mode.' }
        if (-not $cfg.TestUser -or $Identity -ne $cfg.TestUser) { throw "Test actions are only allowed on the configured TestUser '$($cfg.TestUser)'." }
        $u = Get-ADUser -Identity $Identity -Server $server -Properties 'msDS-ExternalDirectoryObjectId', userAccountControl
        if ("$($u.'msDS-ExternalDirectoryObjectId')" -notlike 'User_*') { throw "TestUser '$Identity' is not provisioned by Cloud Sync." }
        $dn = $u.DistinguishedName
        $snap = {
            $x = Get-ADUser -Identity $dn -Server $server -Properties userAccountControl, pwdLastSet, lockoutTime, 'msDS-User-Account-Control-Computed', 'msDS-UserPasswordExpiryTimeComputed', 'msDS-ResultantPSO'
            $m = Get-SoaSecretMeta -Dn $dn -Server $server
            [ordered]@{ Uac = [int]$x.userAccountControl; Scril = [bool]($x.userAccountControl -band $Uac.Scril); Pne = [bool]($x.userAccountControl -band $Uac.DontExpire)
                        PwdLastSet = [int64]$x.pwdLastSet; SecretVersion = $m.SecretVersion; SecretTime = $(if ($m.SecretTime) { $m.SecretTime.ToString('s') } else { $null })
                        PeFlag = [bool]($x.'msDS-User-Account-Control-Computed' -band $Ucc.Expired); ResultantPso = "$($x.'msDS-ResultantPSO')" }
        }
        $status.Before = & $snap
        $drive = Initialize-SoaAdDrive -Server $server
        switch ($TestAction) {
            'ScrilOn'       { [void](Set-SoaUacFlags -Dn $dn -Server $server -SetBits $Uac.Scril) }
            'ScrilOff'      { [void](Set-SoaUacFlags -Dn $dn -Server $server -ClearBits $Uac.Scril) }
            'ScrilRewrite'  { Set-ADUser -Identity $dn -Server $server -Replace @{ userAccountControl = [int](Get-ADUser -Identity $dn -Server $server -Properties userAccountControl).userAccountControl } }
            'RandomReset'   { Set-ADAccountPassword -Identity $dn -Server $server -Reset -NewPassword (New-SoaRandomSecret) }
            'PneOn'         { [void](Set-SoaUacFlags -Dn $dn -Server $server -SetBits $Uac.DontExpire) }
            'PneOff'        { [void](Set-SoaUacFlags -Dn $dn -Server $server -ClearBits $Uac.DontExpire) }
            'DenyChangeOn'  {
                $acl = Get-Acl -Path "$drive\$dn"
                foreach ($s in 'S-1-1-0', 'S-1-5-10') { $acl.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule([Security.Principal.SecurityIdentifier]$s, 'ExtendedRight', 'Deny', $G.ChangePwd))) }
                Set-Acl -Path "$drive\$dn" -AclObject $acl
            }
            'DenyChangeOff' {
                $acl = Get-Acl -Path "$drive\$dn"
                foreach ($r in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
                    if ("$($r.AccessControlType)" -eq 'Deny' -and $r.ObjectType -eq $G.ChangePwd -and $r.IdentityReference.Value -in 'S-1-1-0', 'S-1-5-10') { [void]$acl.RemoveAccessRuleSpecific($r) }
                }
                Set-Acl -Path "$drive\$dn" -AclObject $acl
            }
            'MustChangeOn'  { Set-ADUser -Identity $dn -Server $server -Replace @{ pwdLastSet = 0 } }
            'MustChangeOff' { Set-ADUser -Identity $dn -Server $server -Replace @{ pwdLastSet = -1 } }
            'Unlock'        { Unlock-ADAccount -Identity $dn -Server $server }
            'ProbeWrite'    { Set-ADUser -Identity $dn -Server $server -Replace @{ info = "SOA Toolkit allow-list probe $(Get-Date -Format s)" }; Set-ADUser -Identity $dn -Server $server -Clear info }
            'GroupAdd'      { Add-ADGroupMember -Identity $cfg.PsoGroupName -Members $dn -Server $server }
            'GroupRemove'   { Remove-ADGroupMember -Identity $cfg.PsoGroupName -Members $dn -Server $server -Confirm:$false }
        }
        Start-Sleep -Seconds 1
        $status.After = & $snap
        $status.Success = $true
        Write-RunLog "Test action $TestAction on $Identity completed (as $runAs against $server)"
    } catch {
        $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }
        $status.Errors += $e.Message
        Write-RunLog "Test action $TestAction failed: $($e.Message)" 'ERROR'
    } finally {
        $status.End = (Get-Date).ToString('s')
        try { Save-SoaStatus -DataPath $cfg.DataPath -Name "test-$TestAction" -Status ([pscustomobject]$status) } catch { }
    }
    if ($status.Success) { exit 0 } else { exit 1 }
}

#==================================================================================================
#  ANALYZE / APPLY
#==================================================================================================
$psoMembers = Get-SoaGroupMemberSet -Name $cfg.PsoGroupName -Server $server
$excluded   = Get-SoaGroupMemberSet -Name $cfg.ExcludeGroupName -Server $server -Recursive
$pilot      = if ($cfg.PilotMode) { Get-SoaGroupMemberSet -Name $cfg.PilotGroupName -Server $server -Recursive } else { @{} }
$scope      = @(Get-WriteScope)
$psoGroup   = $null
try { $psoGroup = Get-ADGroup -Identity $cfg.PsoGroupName -Server $server } catch { }

function Get-Evaluation {
    $users = @(Get-SoaCloudUser -Server $server -Properties @('msDS-UserPasswordExpiryTimeComputed', 'msDS-User-Account-Control-Computed'))
    foreach ($u in $users) {
        $c = Get-SoaUserConformance -User $u -Config $cfg -PsoMembers $psoMembers -ExcludeMembers $excluded -PilotMembers $pilot -WriteScope $scope
        $c | Add-Member -NotePropertyName User -NotePropertyValue $u -PassThru
    }
}

#--------------------------------------------------------------------------------------------------
if ($Mode -eq 'Analyze') {
    if (-not $OutputPath) { $OutputPath = Join-Path $cfg.ReportPath 'Conformance' }
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    Write-SoaSection ("Conformance analysis (read-only) against {0} - PilotMode {1}" -f $server, $cfg.PilotMode)
    Write-Host ("Write scope: {0}" -f $(if ($scope.Count) { $scope -join '; ' } else { 'unknown' }))
    $drive = if ($IncludeAcl) { Initialize-SoaAdDrive -Server $server } else { $null }
    $evals = @(Get-Evaluation)
    $rows = foreach ($e in $evals) {
        $u = $e.User
        $md = $null; try { $md = Get-SoaSecretMeta -Dn $u.DistinguishedName -Server $server } catch { }
        $deny = $null
        if ($IncludeAcl) {
            try {
                $acl = Get-Acl -Path "$drive\$($u.DistinguishedName)"
                $deny = (@($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { "$($_.AccessControlType)" -eq 'Deny' -and $_.ObjectType -eq $G.ChangePwd }).Count -gt 0)
            } catch { }
        }
        $changes = @()
        if ($e.NeedScril)    { $changes += 'set SCRIL' }
        if ($e.NeedPneClear) { $changes += 'clear PNE' }
        if ($e.NeedGroupAdd) { $changes += "add to $($cfg.PsoGroupName)" }
        if ($e.NeedGroupRemove) { $changes += "remove from $($cfg.PsoGroupName)" }
        $category = if (-not $e.Marked) { 'Provisioned, not marked (out of scope - check the msDS-ObjectSoa mapping)' }
                    elseif ($e.Excluded) { "Excluded ($($e.ExcludeReason))" }
                    elseif ($e.PilotOut) { 'Not in pilot group (PilotMode)' }
                    elseif ($changes.Count -and -not $e.Writable) { 'NEEDS CHANGE - but outside the write scope (no permission)' }
                    elseif ($changes.Count) { 'Needs change' }
                    else { 'Conform' }
        $status = switch -Wildcard ($category) { 'Conform' { 'PASS' } 'Needs change' { 'WARN' } 'NEEDS CHANGE*' { 'FAIL' } 'Provisioned*' { 'WARN' } default { 'INFO' } }
        [pscustomobject]@{
            Status = $status; User = $e.Sam; Category = $category; WouldChange = ($changes -join ', ')
            Origin = $(if ($md) { Get-SoaOriginKind -WhenCreated $u.whenCreated -AnchorTime $md.AnchorTime } else { 'unknown' })
            Enabled = -not $e.Disabled; SCRIL = $e.Scril; PNE = $e.Pne; InPsoGroup = $e.InPsoGroup; DenyChangeAces = $deny
            PwdLastSet = $(if ($t = ConvertFrom-SoaFileTime $u.pwdLastSet) { $t.ToString('yyyy-MM-dd HH:mm') } else { "$($u.pwdLastSet)" })
            SecretChanged = $(if ($md -and $md.SecretTime) { $md.SecretTime.ToString('yyyy-MM-dd HH:mm') } else { '-' })
            PeFlag = [bool]([int]$u.'msDS-User-Account-Control-Computed' -band $Ucc.Expired)
            Dn = $u.DistinguishedName
        }
    }
    $rows = @($rows | Sort-Object @{ e = { Get-SoaStatusRank $_.Status }; Descending = $true }, User)
    $inScope = @($evals | Where-Object { $_.InScope }).Count
    $extra = @()
    if ($psoGroup) {
        $inScopeSet = @{}; foreach ($e in $evals) { if ($e.InScope) { $inScopeSet[$e.Dn.ToLower()] = $true } }
        $extra = @($psoMembers.Keys | Where-Object { -not $inScopeSet.ContainsKey($_) })
    }
    foreach ($r in $rows) {
        Write-Host ('[{0}] {1,-24} {2,-12} SCRIL={3,-5} PNE={4,-5} PSO-group={5,-5} {6}{7}' -f $r.Status, $r.User, $r.Origin, $r.SCRIL, $r.PNE, $r.InPsoGroup, $r.Category,
            $(if ($r.WouldChange) { " -> $($r.WouldChange)" } else { '' })) -ForegroundColor (Get-SoaStatusColor $r.Status)
    }
    if ($extra.Count) { Write-Host ''; Write-Host ("Members of {0} that are not in scope (would be removed by a schedule/manual run): {1}" -f $cfg.PsoGroupName, ($extra -join '; ')) -ForegroundColor Yellow }
    if (-not $psoGroup) { Write-Host "Group $($cfg.PsoGroupName) not found (Install-SoaToolkit.ps1 -Step Groups)." -ForegroundColor Yellow }
    Write-Host ''
    Write-Host ("Provisioned users: {0} | in scope: {1} | conform: {2} | need change: {3} | not writable: {4} | excluded/pilot: {5} | not marked: {6}" -f $rows.Count, $inScope,
        @($rows | Where-Object { $_.Category -eq 'Conform' }).Count, @($rows | Where-Object { $_.Category -eq 'Needs change' }).Count,
        @($rows | Where-Object { $_.Category -like 'NEEDS CHANGE*' }).Count, @($rows | Where-Object { $_.Status -eq 'INFO' }).Count,
        @($rows | Where-Object { $_.Category -like 'Provisioned*' }).Count) -ForegroundColor Cyan
    $stamp = Get-Date -Format 'yyyyMMdd_HHmm'
    $rows | Export-Csv -Path (Join-Path $OutputPath "conformance_$stamp.csv") -NoTypeInformation -Encoding UTF8
    $html = "<h1>Cloud user conformance &ndash; analysis</h1><p>DC: $server | PilotMode: $($cfg.PilotMode) | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>" +
            "<div class='box'>Note: SOA-converted users lose password-based sign-in when SCRIL is set (VPN/RADIUS, Wi-Fi PEAP-MSCHAPv2, LDAP bind, RDP or runas with password).</div>" +
            (ConvertTo-SoaHtmlTable -Rows $rows -Properties @('Status', 'User', 'Category', 'WouldChange', 'Origin', 'Enabled', 'SCRIL', 'PNE', 'InPsoGroup', 'DenyChangeAces', 'PwdLastSet', 'SecretChanged', 'PeFlag', 'Dn'))
    ConvertTo-Html -Head (Get-SoaHtmlStyle) -Body $html -Title 'Cloud user conformance' | Set-Content -Path (Join-Path $OutputPath "conformance_$stamp.html") -Encoding UTF8
    Write-Host "Report: $(Join-Path $OutputPath "conformance_$stamp.html")" -ForegroundColor Cyan
    exit 0
}

#--------------------------------------------------------------------------------------------------
# APPLY
$status = [ordered]@{
    Mode = 'Apply'; Trigger = $Trigger; Host = $env:COMPUTERNAME; Server = $server; RunAs = $runAs; Start = (Get-Date).ToString('s'); End = $null
    Passes = 0; Candidates = 0; Changed = 0; InScope = 0; Conform = 0; Success = $false; Changes = @(); Warnings = @(); Errors = @()
}
$mutex = $null
try { $mutex = New-Object System.Threading.Mutex($false, 'Global\SoaToolkit-CloudUserConformance') } catch { Write-RunLog "No host-wide lock available: $($_.Exception.Message)" 'WARN' }
$haveLock = $false
try {
    if ($mutex) {
        try { $haveLock = $mutex.WaitOne([TimeSpan]::FromMinutes(10)) } catch [System.Threading.AbandonedMutexException] { $haveLock = $true }
        if (-not $haveLock) { throw 'Another conformance run on this host did not finish within 10 minutes.' }
    }
    Write-RunLog "Run started as $runAs against $server (trigger $Trigger, PilotMode $($cfg.PilotMode))"
    if (-not $psoGroup) { throw "Group $($cfg.PsoGroupName) not found." }
    $agentSids = @(Get-AgentSids)

    $pass = 0
    do {
        $pass++
        $passStart = Get-Date
        $status.Passes = $pass
        if ($pass -gt 1) { $psoMembers = Get-SoaGroupMemberSet -Name $cfg.PsoGroupName -Server $server }
        $evals = @(Get-Evaluation)
        $status.InScope = @($evals | Where-Object { $_.InScope }).Count
        foreach ($e in $evals) {
            $needUac = $e.NeedScril -or $e.NeedPneClear
            if (-not ($needUac -or $e.NeedGroupAdd)) { if ($e.InScope) { $status.Conform++ }; continue }
            $status.Candidates++
            if (-not $e.Writable) {
                $msg = "$($e.Sam): outside the write scope ($($e.Dn)) - cannot apply: $(@(if ($e.NeedScril) { 'SCRIL' }; if ($e.NeedPneClear) { 'PNE' }; if ($e.NeedGroupAdd) { 'PSO group' }) -join ', ')"
                $status.Errors += $msg; Write-RunLog $msg 'ERROR'
                continue
            }
            $done = @()
            $entry = [ordered]@{ Time = (Get-Date).ToString('s'); Host = $env:COMPUTERNAME; Server = $server; Trigger = $Trigger; RunAs = $runAs
                                 User = $e.Sam; Dn = $e.Dn; ObjectGuid = "$($e.User.objectGUID)"; Before = [ordered]@{ Scril = $e.Scril; Pne = $e.Pne; InPsoGroup = $e.InPsoGroup }; Actions = @() }
            try {
                if ($needUac) {
                    $before = Get-SoaSecretMeta -Dn $e.Dn -Server $server
                    $set = if ($e.NeedScril) { $Uac.Scril } else { 0 }
                    $clr = if ($e.NeedPneClear) { $Uac.DontExpire } else { 0 }
                    $r = Set-SoaUacFlags -Dn $e.Dn -Server $server -SetBits $set -ClearBits $clr
                    if ($e.NeedScril) {
                        $after = Get-SoaSecretMeta -Dn $e.Dn -Server $server
                        if ($after.SecretVersion -gt $before.SecretVersion) { $done += 'SCRIL set (secret re-randomized by the DC)' }
                        else {
                            $done += 'SCRIL set'
                            $w = "$($e.Sam): SCRIL set but the secret was not re-randomized (unicodePwd metadata unchanged) - unexpected, check with Test-SoaBehavior.ps1 -Suite Scril"
                            $status.Warnings += $w; Write-RunLog $w 'WARN'
                            Write-SoaEvent -Id $EventId.ConformanceWarning -Level Warning -Message $w -Data @{ User = $e.Sam; Dn = $e.Dn } -LogName $cfg.EventLogName
                        }
                    }
                    if ($e.NeedPneClear) { $done += "'password never expires' cleared" }
                    $entry.Actions += "userAccountControl 0x{0:X} -> 0x{1:X} ({2})" -f $r.Old, $r.New, $r.Method
                }
                if ($e.NeedGroupAdd) {
                    try { Add-ADGroupMember -Identity $psoGroup -Members $e.Dn -Server $server; $done += "added to $($cfg.PsoGroupName)" }
                    catch { if ($_.Exception.Message -match 'already a member|bereits Mitglied') { $done += "already in $($cfg.PsoGroupName)" } else { throw } }
                    $entry.Actions += "member of $($cfg.PsoGroupName)"
                }
                $status.Changed++
                $line = "$($e.Sam): $($done -join '; ')"
                $status.Changes += $line
                Write-RunLog $line
                Add-SoaJournal -DataPath $cfg.DataPath -Entry $entry
                Write-SoaEvent -Id $EventId.ConformanceChanged -Message "Cloud user brought into the target state: $line" -Data @{ User = $e.Sam; Dn = $e.Dn; Trigger = $Trigger; Server = $server; Actions = $done; Before = $entry.Before } -LogName $cfg.EventLogName
            } catch {
                $x = $_.Exception; while ($x.InnerException) { $x = $x.InnerException }
                $msg = "$($e.Sam): FAILED - $($x.Message)"
                $status.Errors += $msg; Write-RunLog $msg 'ERROR'
                Write-SoaEvent -Id $EventId.ConformanceError -Level Error -Message $msg -Data @{ User = $e.Sam; Dn = $e.Dn; Trigger = $Trigger } -LogName $cfg.EventLogName
            }
        }

        # PSO group clean-up (not on event runs: the local DC may not have replicated a conversion yet)
        if ($Trigger -ne 'Event') {
            $inScopeSet = @{}; foreach ($e in $evals) { if ($e.InScope) { $inScopeSet[$e.Dn.ToLower()] = $true } }
            $current = Get-SoaGroupMemberSet -Name $cfg.PsoGroupName -Server $server
            foreach ($m in @($current.Keys | Where-Object { -not $inScopeSet.ContainsKey($_) })) {
                try {
                    $obj = Get-ADObject -Identity $m -Server $server -Properties userAccountControl, 'msDS-ObjectSoa', sAMAccountName
                    Remove-ADGroupMember -Identity $psoGroup -Members $obj.DistinguishedName -Server $server -Confirm:$false
                    $line = "$($obj.sAMAccountName): removed from $($cfg.PsoGroupName) (no longer in scope)"
                    $status.Changes += $line; $status.Changed++; Write-RunLog $line
                    Add-SoaJournal -DataPath $cfg.DataPath -Entry ([ordered]@{ Time = (Get-Date).ToString('s'); Host = $env:COMPUTERNAME; Server = $server; Trigger = $Trigger; RunAs = $runAs; User = $obj.sAMAccountName; Dn = $obj.DistinguishedName; Actions = @("removed from $($cfg.PsoGroupName)") })
                    Write-SoaEvent -Id $EventId.ConformanceChanged -Message $line -Data @{ User = $obj.sAMAccountName; Dn = $obj.DistinguishedName } -LogName $cfg.EventLogName
                    if ([int]$obj.userAccountControl -band $Uac.Scril) {
                        $w = "$($obj.sAMAccountName): no longer a cloud user in scope but SCRIL is still set - decide whether the user needs a password again (SCRIL is never removed automatically)."
                        $status.Warnings += $w; Write-RunLog $w 'WARN'
                        Write-SoaEvent -Id $EventId.ConformanceWarning -Level Warning -Message $w -Data @{ User = $obj.sAMAccountName; Dn = $obj.DistinguishedName } -LogName $cfg.EventLogName
                    }
                } catch {
                    $msg = "PSO group clean-up of ${m} FAILED - $($_.Exception.Message)"
                    $status.Errors += $msg; Write-RunLog $msg 'ERROR'
                }
            }
        }

        # Doorbell: more provisioning events on this DC during the pass -> another pass
        $again = $false
        if ($Trigger -eq 'Event' -and $agentSids.Count -and $pass -lt 5) {
            $subs = Get-SoaEventSubscription -AgentSids $agentSids
            $ms = [int64]((Get-Date) - $passStart).TotalMilliseconds + 1000
            foreach ($xp in @($subs.XPathUserCreated, $subs.XPathSoaWritten)) {
                try {
                    $q = $xp -replace '^\*\[System\[\(EventID=(\d+)\)\]\]', ('*[System[(EventID=$1) and TimeCreated[timediff(@SystemTime) <= ' + $ms + ']]]')
                    if (@(Get-WinEvent -LogName Security -FilterXPath $q -MaxEvents 1 -ErrorAction Stop).Count) { $again = $true }
                } catch { }
            }
            if ($again) { Write-RunLog "New provisioning events during pass $pass - running another pass"; Start-Sleep -Seconds ([Math]::Min(60, [int]$cfg.EventTriggerDelaySeconds)) }
        }
    } while ($again)
    $status.Success = (@($status.Errors).Count -eq 0)
} catch {
    $x = $_.Exception; while ($x.InnerException) { $x = $x.InnerException }
    $status.Errors += "Run failed: $($x.Message)"
    Write-RunLog "Run failed: $($x.Message)" 'ERROR'
    $status.Success = $false
} finally {
    if ($haveLock) { try { $mutex.ReleaseMutex() } catch { } }
    if ($mutex) { $mutex.Dispose() }
    $status.End = (Get-Date).ToString('s')
    try { Save-SoaStatus -DataPath $cfg.DataPath -Name 'conformance' -Status ([pscustomobject]$status) } catch { Write-RunLog "Status file not written: $($_.Exception.Message)" 'WARN' }
    $sum = "Conformance run ($Trigger) against ${server}: in scope $($status.InScope), conform $($status.Conform), changed $($status.Changed), warnings $(@($status.Warnings).Count), errors $(@($status.Errors).Count), passes $($status.Passes)"
    Write-RunLog $sum $(if ($status.Success) { 'INFO' } else { 'ERROR' })
    Write-SoaEvent -Id $EventId.ConformanceSummary -Level $(if ($status.Success) { 'Information' } else { 'Error' }) -Message $sum `
        -Data @{ Trigger = $Trigger; Server = $server; InScope = $status.InScope; Conform = $status.Conform; Changed = $status.Changed; Warnings = @($status.Warnings).Count; Errors = @($status.Errors); Passes = $status.Passes } -LogName $cfg.EventLogName
}
if ($status.Success) { exit 0 } else { exit 1 }
