#Requires -Version 5.1
#Requires -Modules ActiveDirectory
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Read-only monitoring of the passwordless target state of cloud users and of everything it depends on
    (AD object enforcement, automatic rolling, PSO, toolkit tasks and objects, Cloud Kerberos Trust).

.DESCRIPTION
    -Scope Local (scheduled task '\SoaToolkit\Monitor' on every toolkit host, runs as the toolkit gMSA)
        Checks what belongs to THIS host's role(s):
          writable DC : enforcement engine (ntdsai.dll, KIR feature overrides, '2 Security Events', policy load 3095,
                        audit / blocked events 3097 / 3098), onboarding task, Kerberos failures of cloud users on this DC
          agent host  : provisioning agent service, reconcile task + last run, and the domain-wide checks below
          every host  : monitor task, script integrity (hash / signature), conformance errors in the event log,
                        size / retention of the event log
        Writes the result to the event log 'SoaToolkit' (2000 heartbeat with summary, 2001 warning, 2002 failure -
        one event per check, affected objects listed) and to DataPath\Status\monitor.json.

    -Scope All (interactive from the admin workstation, as Domain Admin)
        Everything above for every writable DC and agent host (via WinRM) plus the effective audit policy and
        "Log on as a batch job" per host, lastLogon over all DCs and the results of Test-SoaBehavior.ps1.
        Console + CSV / JSON (+ HTML with -Html) in ReportPath\Monitor.

    Domain-wide checks: AD object enforcement policy (mode, allow-list, replication), automatic rolling, PSO values
    and target, toolkit objects (gMSA, groups, GPOs incl. marker / link / version), PSO group drift, the toolkit's
    SACL entry for msDS-ObjectSoa on every write-scope container (-Scope All only), every
    provisioned user (SCRIL, PNE, PSO, write scope, expired-but-not-rolled, lockout, Kerberos failures,
    AzureADKerberos password replication policy), AzureADKerberos object and krbtgt_AzureAD key age,
    provisioned objects that are not marked.

    Exit code: 0 = OK / INFO, 1 = WARN, 2 = FAIL (Nagios convention - usable by script sensors).

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.0.4 (2026-10-21)
    Never writes to AD. Writes only the event log / status files (Local) or report files (All).
#>
[CmdletBinding()]
param(
    [ValidateSet('Local', 'All')]
    [string] $Scope = 'All',

    [switch] $Html,

    [switch] $Quiet,

    [int] $EventHours = 24,

    [string] $OutputPath,

    [string] $ConfigPath
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
Import-Module (Join-Path $ScriptRoot 'SoaToolkit.psm1') -Force -DisableNameChecking
$ConfigPath = Resolve-SoaConfigPath -ConfigPath $ConfigPath -ScriptRoot $ScriptRoot

#region --- Context --------------------------------------------------------------------------------
$cfg      = Import-SoaConfig -Path $ConfigPath
if ($Scope -eq 'All') { Assert-SoaAdminPaths -Config $cfg -ScriptRoot $ScriptRoot; Initialize-SoaReportPath -Config $cfg }
$server   = Select-SoaTargetDc
$ctx      = Get-SoaContext -Server $server
$Ucc      = Get-SoaConstant 'Ucc'
$EventId  = Get-SoaConstant 'EventId'
$minNtdsai = Get-SoaConstant 'MinNtdsai'
$auditReq = Get-SoaConstant 'Audit'
$since    = (Get-Date).AddHours(-$EventHours)
$isInteractive = -not $Quiet

$deployment = $null
$depFile = Join-Path $ScriptRoot 'deployment.json'
if (Test-Path -LiteralPath $depFile) { try { $deployment = Get-Content -LiteralPath $depFile -Raw | ConvertFrom-Json } catch { } }
$manifest = $null
if ($Scope -eq 'All') { try { $manifest = Get-SoaManifest -Config $cfg } catch { } }

$KerbStatus = @{
    '0x6' = 'client unknown'; '0x12' = 'client revoked (disabled / locked / expired account)'; '0x17' = 'key (password) expired'
    '0x18' = 'pre-authentication failed (wrong password)'; '0x25' = 'clock skew'; '0xe' = 'encryption type not supported'
}

$Results  = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$CheckId, [string]$Area, [string]$Item, [string]$Status, [string]$Detail, [string[]]$Objects = @()) {
    $Results.Add([pscustomobject]@{ CheckId = $CheckId; Area = $Area; Item = $Item; Status = $Status; Detail = $Detail; Objects = ($Objects -join '; ') })
}
#endregion

#region --- Host roles ------------------------------------------------------------------------------
$allRoles = @(Get-SoaHostRoles -Config $cfg -Context $ctx)
if ($Scope -eq 'Local') {
    $local = Get-SoaLocalFqdn
    $me = $allRoles | Where-Object { $_.Host -eq $local -or (Get-SoaShortName $_.Host) -ieq $env:COMPUTERNAME } | Select-Object -First 1
    if (-not $me) {
        $isAgent = [bool](Get-Service -Name (Get-SoaConstant 'AgentService') -ErrorAction SilentlyContinue)
        $me = [pscustomobject]@{ Host = $local; IsDc = ($ctx.WritableDcs -contains $local); IsAgent = $isAgent; AgentIndex = -1 }
    }
    $hostsToCheck = @($me)
    $domainChecks = $me.IsAgent -or -not @($allRoles | Where-Object { $_.IsAgent }).Count
} else {
    $hostsToCheck = $allRoles
    $domainChecks = $true
}
#endregion

#region --- Cloud users (needed for host checks: Kerberos failures) ---------------------------------
$users = @(Get-SoaCloudUser -Server $server -Properties @('msDS-User-Account-Control-Computed', 'msDS-UserPasswordExpiryTimeComputed', 'msDS-ResultantPSO', 'lastLogonTimestamp', 'userPrincipalName'))
$userSams = @($users | ForEach-Object { $_.SamAccountName })
#endregion

#region --- Host checks -----------------------------------------------------------------------------
$hostBlock = {
    param($P)
    $o = [ordered]@{ Host = $env:COMPUTERNAME; Errors = @() }
    function Get-SafeValue([scriptblock]$Sb, [string]$What) { try { & $Sb } catch { $script:o.Errors += "${What}: $($_.Exception.Message)"; $null } }
    $script:o = $o

    # Tasks
    $o.Tasks = @(Get-SafeValue { Get-ScheduledTask -TaskPath $P.TaskFolder -ErrorAction Stop | ForEach-Object {
        $i = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $P.TaskFolder
        [pscustomobject]@{ Name = $_.TaskName; State = "$($_.State)"; LastRun = $i.LastRunTime; LastResult = [int64]$i.LastTaskResult }
    } } 'tasks')
    # Status files
    $o.Conformance = Get-SafeValue { $f = Join-Path $P.DataPath 'Status\conformance.json'; if (Test-Path $f) { Get-Content -Path $f -Raw } else { $null } } 'conformance status'
    # Event log + recent conformance errors
    $o.EventLog = [Diagnostics.EventLog]::SourceExists($P.EventLog)
    $o.EventLogConfig = Get-SafeValue { $l = Get-WinEvent -ListLog $P.EventLog -ErrorAction Stop; [pscustomobject]@{ MaxBytes = [int64]$l.MaximumSizeInBytes; Mode = "$($l.LogMode)" } } 'event log size'
    $o.ConformanceErrors = @(Get-SafeValue { Get-WinEvent -FilterHashtable @{ LogName = $P.EventLog; Id = 1002; StartTime = (Get-Date).AddMilliseconds(-$P.SinceMs) } -ErrorAction Stop |
        Select-Object -First 5 | ForEach-Object { ($_.Message -split "`r?`n")[0] } } 'event log')
    # Script integrity
    $o.Files = @(foreach ($f in @($P.Files)) {
        $path = Join-Path $P.InstallPath $f
        if (-not (Test-Path -LiteralPath $path)) { [pscustomobject]@{ File = $f; Exists = $false; Sha256 = $null; Signature = $null; Signer = $null }; continue }
        $sig = Get-AuthenticodeSignature -FilePath $path
        [pscustomobject]@{ File = $f; Exists = $true; Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash; Signature = "$($sig.Status)"; Signer = $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }) }
    })
    # Effective "Log on as a batch job" and audit policy (need local admin - only in the interactive scope)
    if ($P.Admin) {
        $o.BatchRight = Get-SafeValue {
            $tmp = Join-Path $env:TEMP ('soa_ur_{0}.inf' -f [guid]::NewGuid().ToString('N'))
            & secedit.exe /export /areas USER_RIGHTS /cfg $tmp /quiet | Out-Null
            $line = Get-Content -Path $tmp -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*SeBatchLogonRight\s*=' } | Select-Object -First 1
            Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
            @(if ($line) { foreach ($e in (($line -split '=', 2)[1] -split ',')) { $e = $e.Trim(); if ($e.StartsWith('*')) { $e.Substring(1) } elseif ($e) { try { ([Security.Principal.NTAccount]$e).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $e } } } })
        } 'batch right'
    }
    if ($P.IsDc) {
        $vi = (Get-Item -Path (Join-Path $env:windir 'System32\ntdsai.dll')).VersionInfo
        $o.Build  = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild
        $o.Ntdsai = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
        $ov = @{}
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides')
        if ($key) { foreach ($n in $key.GetValueNames()) { $ov[$n] = "$($key.GetValue($n))" }; $key.Close() }
        $o.KirOverrides = $ov
        $p = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ErrorAction SilentlyContinue
        $o.DiagLevel = $(if ($p -and ($p.PSObject.Properties.Name -contains '2 Security Events')) { [int]$p.'2 Security Events' } else { $null })
        $ev = @(Get-SafeValue { Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 3095, 3097, 3098; StartTime = (Get-Date).AddDays(-30) } -ErrorAction Stop } 'Directory Service log')
        $ld = $ev | Where-Object { $_.Id -eq 3095 } | Select-Object -First 1
        $o.LastLoadTime  = $(if ($ld) { $ld.TimeCreated } else { $null })
        $o.LastLoadLevel = $(if ($ld) { [int]$ld.Level } else { $null })
        $o.LastLoadMsg   = $(if ($ld) { $m = $ld.Message -replace '\s+', ' '; if ($m.Length -gt 250) { $m.Substring(0, 250) + '...' } else { $m } } else { $null })
        $cut = (Get-Date).AddMilliseconds(-$P.SinceMs)
        $o.Audit3097 = @($ev | Where-Object { $_.Id -eq 3097 -and $_.TimeCreated -ge $cut }).Count
        $blk = @($ev | Where-Object { $_.Id -eq 3098 -and $_.TimeCreated -ge $cut })
        $o.Block3098 = $blk.Count
        $o.BlockSample = @($blk | Select-Object -First 3 | ForEach-Object { $m = $_.Message -replace '\s+', ' '; if ($m.Length -gt 200) { $m.Substring(0, 200) + '...' } else { $m } })
        if ($P.Admin) {
            $o.Audit = Get-SafeValue {
                $tmp = Join-Path $env:TEMP ('soa_ap_{0}.csv' -f [guid]::NewGuid().ToString('N'))
                & auditpol.exe /backup /file:$tmp | Out-Null
                $map = @{}
                foreach ($l in (Get-Content -Path $tmp -ErrorAction SilentlyContinue | Select-Object -Skip 1)) { $f = $l -split ','; if ($f.Count -ge 7 -and $f[3] -match '^\{') { $map[$f[3].ToUpper()] = [int]$f[6] } }
                Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
                $map
            } 'audit policy'
            $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
            $o.ForceSubcategory = $(if ($lsa -and ($lsa.PSObject.Properties.Name -contains 'SCENoApplyLegacyAuditPolicy')) { [int]$lsa.SCENoApplyLegacyAuditPolicy } else { $null })
        }
        # Kerberos failures of cloud users on this DC
        $set = @{}; foreach ($u in @($P.Users)) { $set["$u".ToLower()] = $true }
        $xp = "*[System[(EventID=4768 or EventID=4771) and TimeCreated[timediff(@SystemTime) <= $($P.SinceMs)]] and EventData[Data[@Name='Status']!='0x0']]"
        $o.KerbFailures = @(Get-SafeValue {
            @(Get-WinEvent -LogName Security -FilterXPath $xp -ErrorAction Stop) | ForEach-Object {
                $d = @{}; foreach ($n in ([xml]$_.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
                $user = ("$($d.TargetUserName)" -split '@')[0].ToLower()
                if ($set.ContainsKey($user)) { [pscustomobject]@{ Time = $_.TimeCreated; User = $user; Status = "$($d.Status)".ToLower(); Id = $_.Id } }
            }
        } 'Security log') | Where-Object { $_ }
        if (@($o.Errors | Where-Object { $_ -like 'Security log*' -and $_ -match 'No events were found' }).Count) { $o.Errors = @($o.Errors | Where-Object { $_ -notmatch 'No events were found' }) }
    }
    if ($P.IsAgent) {
        $svc = Get-Service -Name 'AADConnectProvisioningAgent' -ErrorAction SilentlyContinue
        $o.AgentService = $(if ($svc) { "$($svc.Status)" } else { $null })
        $o.AgentVersion = Get-SafeValue {
            $path = (Get-CimInstance -ClassName Win32_Service -Filter "Name='AADConnectProvisioningAgent'").PathName -replace '^"([^"]+)".*$', '$1'
            if ($path -and (Test-Path -LiteralPath $path)) { (Get-Item -LiteralPath $path).VersionInfo.FileVersion } else { $null }
        } 'agent version'
    }
    $o.Errors = @($o.Errors | Where-Object { $_ -notmatch 'No events were found that match' })
    [pscustomobject]$o
}

$files = @('SoaToolkit.psm1', 'SoaToolkit.config.psd1', 'Invoke-CloudUserConformance.ps1', 'Watch-CloudUserConformance.ps1')
$gmsaSid = $null
try { $gm = Get-ADServiceAccount -Identity $cfg.GmsaName -Server $server; $gmsaSid = $gm.SID.Value } catch { }
$kerbAll = New-Object System.Collections.Generic.List[object]

foreach ($h in $hostsToCheck) {
    $short = Get-SoaShortName $h.Host
    $area  = "Host $short"
    $P = @{ TaskFolder = $cfg.TaskFolder; DataPath = $cfg.DataPath; EventLog = $cfg.EventLogName; InstallPath = $cfg.ScriptInstallPath; Files = $files
            SinceMs = [int64]((Get-Date) - $since).TotalMilliseconds; IsDc = $h.IsDc; IsAgent = $h.IsAgent; Admin = ($Scope -eq 'All'); Users = $userSams }
    $res = if ($Scope -eq 'Local') {
        try { [pscustomobject]@{ Ok = $true; Result = (& $hostBlock $P); Error = $null } } catch { [pscustomobject]@{ Ok = $false; Result = $null; Error = $_.Exception.Message } }
    } else { Invoke-SoaOnHost -ComputerName $h.Host -ScriptBlock $hostBlock -ArgumentList $P }
    if (-not $res.Ok) { Add-Result 'HOST-REACH' $area 'Reachable (WinRM)' 'FAIL' $res.Error; continue }
    $d = $res.Result
    foreach ($e in @($d.Errors)) { Add-Result 'HOST-READ' $area 'Data collection' 'INFO' $e }

    # Tasks
    $tasks = @($d.Tasks)
    $expected = @('Monitor') + @(if ($h.IsDc) { 'CloudUserConformance-Event' }) + @(if ($h.IsAgent) { 'CloudUserConformance-Reconcile' })
    foreach ($n in $expected) {
        $t = $tasks | Where-Object { $_.Name -eq $n } | Select-Object -First 1
        if (-not $t) {
            if (-not $tasks.Count -and @($d.Errors | Where-Object { $_ -like 'tasks*' }).Count) { Add-Result 'TASK-READ' $area "Task $n" 'INFO' 'task list not readable with this identity' }
            else { Add-Result 'TASK-MISSING' $area "Task $n" 'FAIL' "not registered in $($cfg.TaskFolder) (Install-SoaToolkit.ps1 -Step DeployTasks)" }
            continue
        }
        $okResult = $t.LastResult -in 0, 267009, 267011     # 0 = success, 0x41301 = running, 0x41303 = not yet run
        if ($n -eq 'CloudUserConformance-Reconcile' -and [int]$cfg.ReconcileMinutes -eq 0) {
            Add-Result 'TASK-STATE' $area "Task $n" 'INFO' "disabled by configuration (ReconcileMinutes = 0) - state $($t.State)"
        } elseif ($t.State -eq 'Disabled') {
            Add-Result 'TASK-STATE' $area "Task $n" 'FAIL' 'task is DISABLED'
        } else {
            Add-Result 'TASK-STATE' $area "Task $n" $(if ($okResult) { 'PASS' } else { 'WARN' }) ("state {0}, last run {1}, last result 0x{2:X}" -f $t.State, $t.LastRun, $t.LastResult)
        }
    }
    if ($h.IsAgent -and [int]$cfg.ReconcileMinutes -gt 0) {
        $st = if ($d.Conformance) { $d.Conformance | ConvertFrom-Json } else { $null }
        if (-not $st) { Add-Result 'RECON-STATUS' $area 'Last conformance run' 'WARN' 'no status file yet' }
        else {
            $age = ((Get-Date) - [datetime]$st.End).TotalMinutes
            $limit = 2.5 * [Math]::Max(5, [int]$cfg.ReconcileMinutes)
            $s = if (-not $st.Success) { 'FAIL' } elseif ($age -gt $limit) { 'WARN' } else { 'PASS' }
            Add-Result 'RECON-STATUS' $area 'Last conformance run' $s ("{0} ({1}) against {2}: success={3}, changed {4}, errors {5}, {6:N0} min ago" -f $st.End, $st.Trigger, $st.Server, $st.Success, $st.Changed, @($st.Errors).Count, $age)
        }
    }
    if (@($d.ConformanceErrors).Count) { Add-Result 'CONF-ERRORS' $area "Conformance errors (${EventHours}h)" 'WARN' (@($d.ConformanceErrors) -join ' | ') }
    Add-Result 'EVENTLOG' $area "Event log '$($cfg.EventLogName)'" $(if ($d.EventLog) { 'PASS' } else { 'FAIL' }) $(if ($d.EventLog) { 'present' } else { 'missing (DeployTasks)' })
    if ($d.EventLog -and $d.EventLogConfig) {
        $wantBytes = [int64]$cfg.EventLogMaxSizeMB * 1MB
        $okSize = ([int64]$d.EventLogConfig.MaxBytes -ge [int64]($wantBytes * 0.99)) -and ("$($d.EventLogConfig.Mode)" -eq 'Circular')
        Add-Result 'EVENTLOG-SIZE' $area "Event log '$($cfg.EventLogName)' size / retention" $(if ($okSize) { 'PASS' } else { 'WARN' }) ("{0:N0} MB, mode {1} (expected >= {2} MB, Circular = overwrite as needed; set by DeployTasks - a full log with retention drops new events)" -f ([int64]$d.EventLogConfig.MaxBytes / 1MB), $d.EventLogConfig.Mode, $cfg.EventLogMaxSizeMB)
    }

    # Integrity
    $expectedHashes = if ($deployment -and $deployment.Files) { $deployment.Files } elseif ($manifest) { (Get-SoaManifestEntry -Manifest $manifest -Kind 'HostDeployment' -Key $h.Host | Select-Object -First 1).Data.Files } else { $null }
    $bad = @(); $unsigned = @()
    foreach ($f in @($d.Files)) {
        if (-not $f.Exists) { $bad += "$($f.File) missing"; continue }
        if ($expectedHashes -and $expectedHashes.PSObject.Properties.Name -contains $f.File -and $expectedHashes.($f.File) -ne $f.Sha256) { $bad += "$($f.File) modified" }
        if ($cfg.SigningCertThumbprint -and $f.Signature -ne 'Valid') { $unsigned += "$($f.File): $($f.Signature)" }
    }
    Add-Result 'INTEGRITY' $area 'Script integrity' $(if ($bad.Count) { 'FAIL' } elseif (-not $expectedHashes) { 'INFO' } else { 'PASS' }) $(if ($bad.Count) { $bad -join '; ' } elseif (-not $expectedHashes) { 'no reference hashes (deployment.json) available' } else { 'all files match the deployment' })
    if ($cfg.SigningCertThumbprint) { Add-Result 'SIGNATURE' $area 'Script signatures' $(if ($unsigned.Count) { 'FAIL' } else { 'PASS' }) $(if ($unsigned.Count) { $unsigned -join '; ' } else { 'valid' }) }

    # Batch logon right
    if ($Scope -eq 'All') {
        if ($null -eq $d.BatchRight) { Add-Result 'BATCH' $area "'Log on as a batch job'" 'INFO' 'not readable' }
        else { Add-Result 'BATCH' $area "'Log on as a batch job'" $(if ($gmsaSid -and @($d.BatchRight) -contains $gmsaSid) { 'PASS' } else { 'FAIL' }) $(if ($gmsaSid -and @($d.BatchRight) -contains $gmsaSid) { "$($cfg.GmsaName) present" } else { "$($cfg.GmsaName) MISSING - tasks cannot start (GPO precedence / replication)" }) }
    } else {
        Add-Result 'BATCH' $area "'Log on as a batch job'" 'PASS' "monitor runs as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) via Task Scheduler (implies the right)"
    }

    if ($h.IsDc) {
        $ok = $minNtdsai.ContainsKey([int]$d.Build) -and ([version]$d.Ntdsai -ge $minNtdsai[[int]$d.Build])
        Add-Result 'DC-NTDSAI' $area 'ntdsai.dll' $(if ($ok) { 'PASS' } else { 'FAIL' }) "$($d.Ntdsai) (build $($d.Build))"
        $kirExp = @(if ($deployment -and $deployment.Kir) { $deployment.Kir } elseif ($manifest) { Get-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' | Where-Object { $_.Key -like 'Kir*' } | ForEach-Object { $_.Data } }) | Where-Object { $_ -and [int]$_.Build -eq [int]$d.Build }
        $ov = $d.KirOverrides
        if ($kirExp) {
            $exp = @($kirExp | Select-Object -First 1)
            $items = @($exp.Items)
            $missing = @(foreach ($it in $items) { if (-not $ov.ContainsKey("$($it.FeatureId)") -or "$($ov["$($it.FeatureId)"])" -ne "$($it.Enabled)") { "$($it.FeatureId)" } })
            if (-not $items.Count) { $missing = @(@($exp.FeatureIds) | Where-Object { -not $ov.ContainsKey("$_") }) }
            Add-Result 'DC-KIR' $area 'KIR feature overrides' $(if ($missing.Count) { 'FAIL' } else { 'PASS' }) $(if ($missing.Count) { "not enabled: $($missing -join ', ') (GPO applied? DC restarted?)" } else { "all feature IDs of '$($exp.Gpo)' enabled" })
        } else {
            Add-Result 'DC-KIR' $area 'KIR feature overrides' 'INFO' ("expected IDs unknown (no KIR entry in deployment/manifest); overrides present: {0}" -f $(if ($ov -and $ov.Count) { ($ov.Keys | Sort-Object) -join ', ' } else { 'none' }))
        }
        Add-Result 'DC-DIAG' $area "'2 Security Events'" $(if ($d.DiagLevel -ge 1) { 'PASS' } else { 'WARN' }) "= $(if ($null -eq $d.DiagLevel) { 'not set (events 3097/3098 invisible)' } else { $d.DiagLevel })"
        $loadStatus = if (-not $d.LastLoadTime) { 'WARN' } elseif ($d.LastLoadLevel -in 1, 2, 3 -or $d.LastLoadMsg -match '(?i)fail|invalid|unable|could not|error') { 'FAIL' } else { 'PASS' }
        Add-Result 'DC-LOAD' $area 'Policy load (3095)' $loadStatus $(if ($d.LastLoadTime) { "$($d.LastLoadTime): $($d.LastLoadMsg)" } else { 'no 3095 in the last 30 days' })
        $pm = Get-SoaPolicyMode -Context $ctx -Server $server
        if ($pm -eq 'Audit') { Add-Result 'DC-3097' $area "Audit events 3097 (${EventHours}h)" $(if ($d.Audit3097) { 'WARN' } else { 'PASS' }) "$($d.Audit3097) change(s) Enforced mode would block" }
        Add-Result 'DC-3098' $area "Blocked writes 3098 (${EventHours}h)" $(if ($d.Block3098) { 'WARN' } else { 'PASS' }) $(if ($d.Block3098) { "$($d.Block3098): $(@($d.BlockSample) -join ' || ')" } else { 'none' })
        if ($Scope -eq 'All') {
            if ($d.Audit) {
                foreach ($a in $auditReq) {
                    $v = if ($d.Audit.ContainsKey($a.Guid)) { [int]$d.Audit[$a.Guid] } else { 0 }
                    Add-Result 'DC-AUDIT' $area $a.Name $(if (($v -band $a.Required) -eq $a.Required) { 'PASS' } else { 'FAIL' }) ("value {0}, needs {1} - {2}" -f $v, $a.Required, $a.Why)
                }
                Add-Result 'DC-AUDIT' $area 'Force audit subcategory settings' $(if ($d.ForceSubcategory -eq 1) { 'PASS' } else { 'WARN' }) "SCENoApplyLegacyAuditPolicy = $($d.ForceSubcategory)"
            } else { Add-Result 'DC-AUDIT' $area 'Audit policy' 'INFO' 'not readable' }
        }
        foreach ($k in @($d.KerbFailures)) { $kerbAll.Add($k) }
    }
    if ($h.IsAgent) {
        Add-Result 'AGENT-SVC' $area 'Provisioning agent' $(if ($d.AgentService -eq 'Running') { 'PASS' } else { 'FAIL' }) $(if ($d.AgentService) { "service $($d.AgentService), version $($d.AgentVersion)" } else { 'service not found' })
    }
}
#endregion

# Kerberos failures seen on a DC that does not run the domain-wide checks (DC-only host in scope Local)
if (-not $domainChecks -and $kerbAll.Count) {
    foreach ($g in ($kerbAll | Group-Object Status)) {
        $sev = if ($g.Name -in '0x17', '0x12') { 'FAIL' } elseif ($g.Name -eq '0x18') { 'WARN' } else { 'INFO' }
        Add-Result "DC-KERB-$($g.Name)" "Host $(Get-SoaShortName $hostsToCheck[0].Host)" ("Kerberos {0} {1}" -f $g.Name, $KerbStatus[$g.Name]) $sev ("{0} failure(s) of cloud users" -f $g.Count) @($g.Group | ForEach-Object { $_.User } | Select-Object -Unique)
    }
}

#region --- Domain-wide checks ----------------------------------------------------------------------
$userRows = @()
if ($domainChecks) {
    # Policy
    $policy = Get-SoaPolicy -Context $ctx -Server $server
    $agentSids = @(if ($deployment -and $deployment.AgentSids) { $deployment.AgentSids } else { Get-SoaAgentGmsa -Config $cfg -Context $ctx -Quiet | ForEach-Object { $_.Sid } })
    if (-not $policy) { Add-Result 'POL-EXISTS' 'Enforcement' 'Policy CN=Cloud' 'FAIL' 'not found - no AD object enforcement' }
    else {
        $mode = (@($policy.keywords) -join ',')
        Add-Result 'POL-MODE' 'Enforcement' 'Mode' $(if ($mode -eq 'Enforced') { 'PASS' } elseif ($mode -eq 'Audit') { 'INFO' } else { 'WARN' }) "keywords = $mode"
        $cur = @($policy.'msDS-Settings' | Where-Object { $_ } | ForEach-Object { "$_" })
        $stale = @($cur | Where-Object { -not (Resolve-SoaSid -Sid $_ -Server $server) })
        Add-Result 'POL-SIDS' 'Enforcement' 'Allow-list SIDs resolvable' $(if ($stale.Count) { 'FAIL' } else { 'PASS' }) $(if ($stale.Count) { "STALE: $($stale -join ', ') - the policy fails to load" } else { "$($cur.Count) SID(s)" })
        foreach ($s in $agentSids) { Add-Result 'POL-AGENT' 'Enforcement' "Agent $s allow-listed" $(if ($cur -contains $s) { 'PASS' } else { 'FAIL' }) $(Resolve-SoaSid -Sid $s -Server $server) }
        Add-Result 'POL-TOOLKIT' 'Enforcement' 'Toolkit gMSA allow-listed' $(if ($gmsaSid -and $cur -contains $gmsaSid) { 'PASS' } else { 'FAIL' }) $(if ($gmsaSid) { $gmsaSid } else { 'gMSA not found' })
        $refKey = "$mode|$((@($cur) | Sort-Object) -join ';')"
        $notRepl = @(foreach ($dc in $ctx.WritableDcs) { $p2 = Get-SoaPolicy -Context $ctx -Server $dc; $k = if ($p2) { "$((@($p2.keywords) -join ','))|$((@($p2.'msDS-Settings' | ForEach-Object { "$_" }) | Sort-Object) -join ';')" } else { '' }; if ($k -ne $refKey) { $dc } })
        Add-Result 'POL-REPL' 'Enforcement' 'Policy replicated' $(if ($notRepl.Count) { 'WARN' } else { 'PASS' }) $(if ($notRepl.Count) { "differs on $($notRepl -join ', ')" } else { 'identical on all writable DCs' })
    }

    # Rolling
    $root = Get-ADObject -Identity $ctx.DomainDN -Server $server -Properties 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts', 'msDS-Behavior-Version'
    $rolling = ($root.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' -eq $true) -and ([int]$root.'msDS-Behavior-Version' -ge 7)
    Add-Result 'ROLL' 'Password policy' 'Automatic rolling (SCRIL)' $(if ($rolling) { 'PASS' } else { 'FAIL' }) ("DFL {0}, msDS-ExpirePasswordsOnSmartCardOnlyAccounts = {1}" -f $root.'msDS-Behavior-Version', $root.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts')

    # PSO
    $pso = $null
    try { $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$($cfg.PsoName)'" -Server $server -Properties Description, AppliesTo } catch { }
    $psoGroup = $null; try { $psoGroup = Get-ADGroup -Identity $cfg.PsoGroupName -Server $server -Properties member, description } catch { }
    if (-not $pso) { Add-Result 'PSO-EXISTS' 'Password policy' "PSO $($cfg.PsoName)" $(if ($Scope -eq 'Local') { 'WARN' } else { 'FAIL' }) 'not found or not readable' }
    else {
        $p = $cfg.Pso
        $want = [ordered]@{ Precedence = [int]$p.Precedence; MaxPasswordAge = (New-TimeSpan -Days $p.MaxPasswordAgeDays); MinPasswordAge = (New-TimeSpan -Days $p.MinPasswordAgeDays)
            MinPasswordLength = [int]$p.MinPasswordLength; ComplexityEnabled = [bool]$p.ComplexityEnabled; PasswordHistoryCount = [int]$p.PasswordHistoryCount
            ReversibleEncryptionEnabled = [bool]$p.ReversibleEncryptionEnabled; LockoutThreshold = [int]$p.LockoutThreshold }
        $diff = @(foreach ($k in $want.Keys) { if ("$($pso.$k)" -ne "$($want[$k])") { "$k=$($pso.$k) (expected $($want[$k]))" } })
        Add-Result 'PSO-VALUES' 'Password policy' "PSO $($cfg.PsoName) values" $(if ($diff.Count) { 'WARN' } else { 'PASS' }) $(if ($diff.Count) { $diff -join '; ' } else { "max age $($pso.MaxPasswordAge.TotalDays) d, min length $($pso.MinPasswordLength), lockout $($pso.LockoutThreshold)" })
        Add-Result 'PSO-MARKER' 'Password policy' "PSO $($cfg.PsoName) marker" $(if (Test-SoaMarker $pso.Description) { 'PASS' } else { 'INFO' }) "$($pso.Description)"
        $applies = @($pso.AppliesTo)
        $okTarget = $psoGroup -and $applies -contains $psoGroup.DistinguishedName
        Add-Result 'PSO-TARGET' 'Password policy' 'PSO applies to PSO group' $(if ($okTarget) { 'PASS' } else { 'FAIL' }) ($applies -join '; ')
        $same = @(Get-ADFineGrainedPasswordPolicy -Filter * -Server $server | Where-Object { $_.Name -ne $cfg.PsoName -and $_.Precedence -le $pso.Precedence })
        if ($same.Count) { Add-Result 'PSO-PREC' 'Password policy' 'PSO precedence' 'WARN' ("PSO(s) with precedence <= {0}: {1} - they win for users they apply to" -f $pso.Precedence, (($same | ForEach-Object { "$($_.Name) ($($_.Precedence))" }) -join ', ')) }
    }

    # Toolkit objects
    $gm = $null; try { $gm = Get-ADServiceAccount -Identity $cfg.GmsaName -Server $server -Properties PrincipalsAllowedToRetrieveManagedPassword, Description } catch { }
    $hg = $null; try { $hg = Get-ADGroup -Identity $cfg.HostGroupName -Server $server -Properties member, description } catch { }
    Add-Result 'OBJ-GMSA' 'Toolkit objects' "gMSA $($cfg.GmsaName)" $(if ($gm -and $hg -and @($gm.PrincipalsAllowedToRetrieveManagedPassword) -contains $hg.DistinguishedName) { 'PASS' } elseif ($gm) { 'WARN' } else { 'FAIL' }) $(if ($gm) { "retrievable by: $(@($gm.PrincipalsAllowedToRetrieveManagedPassword) -join '; ')" } else { 'not found' })
    if ($hg) {
        $mem = @($hg.member | ForEach-Object { "$_".ToLower() })
        $hasDc = @($mem | Where-Object { $_ -like 'cn=domain controllers,*' }).Count -gt 0
        Add-Result 'OBJ-HOSTGROUP' 'Toolkit objects' "Group $($cfg.HostGroupName)" $(if ($hasDc) { 'PASS' } else { 'WARN' }) ("{0} member(s){1}" -f $mem.Count, $(if (-not $hasDc) { ' - Domain Controllers missing' } else { '' }))
    } else { Add-Result 'OBJ-HOSTGROUP' 'Toolkit objects' "Group $($cfg.HostGroupName)" 'FAIL' 'not found' }
    foreach ($gn in @($cfg.ExcludeGroupName, $cfg.PilotGroupName)) {
        $x = $null; try { $x = Get-ADGroup -Identity $gn -Server $server -Properties member } catch { }
        Add-Result 'OBJ-GROUPS' 'Toolkit objects' "Group $gn" $(if ($x) { 'PASS' } else { 'WARN' }) $(if ($x) { "$(@($x.member).Count) member(s)" } else { 'not found' })
    }
    if (Get-Module -ListAvailable -Name GroupPolicy) {
        Import-Module GroupPolicy -Verbose:$false
        $gpoDefs = @(
            @{ Name = $cfg.DiagnosticsGpoName;    Required = $true;  Target = $ctx.DcOu }
            @{ Name = $cfg.BatchLogonGpoNameDc;   Required = $true;  Target = $ctx.DcOu }
            @{ Name = $cfg.AuditGpoName;          Required = $false; Target = $ctx.DcOu }
            @{ Name = "$($cfg.KirGpoNamePrefix) (WS2022)"; Required = $false; Target = $ctx.DcOu }
            @{ Name = "$($cfg.KirGpoNamePrefix) (WS2025)"; Required = $false; Target = $ctx.DcOu }
            @{ Name = $cfg.BatchLogonGpoNameAgent; Required = (@($allRoles | Where-Object { $_.IsAgent -and -not $_.IsDc }).Count -gt 0); Target = $null }
        )
        foreach ($gd in $gpoDefs) {
            $g = $null; try { $g = Get-GPO -Name $gd.Name -Domain $ctx.DnsRoot -Server $server -ErrorAction Stop } catch { }
            if (-not $g) { if ($gd.Required) { Add-Result 'OBJ-GPO' 'Toolkit objects' "GPO $($gd.Name)" 'FAIL' 'not found' }; continue }
            $issues = @()
            if (-not (Test-SoaMarker $g.Description)) { $issues += 'no marker' }
            if ($g.Computer.DSVersion -ne $g.Computer.SysvolVersion) { $issues += "AD version $($g.Computer.DSVersion) <> SYSVOL $($g.Computer.SysvolVersion)" }
            if ($gd.Target) {
                $l = Get-SoaGpoLinkState -Id $g.Id -Target $gd.Target -Context ([pscustomobject]@{ DnsRoot = $ctx.DnsRoot; Pdc = $server })
                if (-not $l.Linked) { $issues += 'not linked to the DC OU' } elseif (-not $l.Enabled) { $issues += 'link disabled' }
            }
            Add-Result 'OBJ-GPO' 'Toolkit objects' "GPO $($gd.Name)" $(if (@($issues | Where-Object { $_ -ne 'no marker' }).Count) { 'WARN' } elseif ($issues.Count) { 'INFO' } else { 'PASS' }) $(if ($issues.Count) { $issues -join '; ' } else { "modified $($g.ModificationTime)" })
        }
    } else { Add-Result 'OBJ-GPO' 'Toolkit objects' 'GPOs' 'INFO' 'GroupPolicy module not available on this host - GPO checks skipped' }

    # Cloud Kerberos Trust
    $neverReveal = @{}
    $aadKerb = $null
    try { $aadKerb = Get-ADComputer -Identity 'AzureADKerberos' -Server $server -Properties 'msDS-NeverRevealGroup' } catch { }
    if (-not $aadKerb) { Add-Result 'CKT-OBJECT' 'Cloud Kerberos Trust' 'AzureADKerberos object' 'FAIL' 'not found - no partial TGTs for AD' }
    else {
        Add-Result 'CKT-OBJECT' 'Cloud Kerberos Trust' 'AzureADKerberos object' 'PASS' $aadKerb.DistinguishedName
        $krb = Get-ADUser -Filter "SamAccountName -like 'krbtgt_AzureAD*'" -Server $server -Properties pwdLastSet | Select-Object -First 1
        $krbSet = if ($krb) { ConvertFrom-SoaFileTime $krb.pwdLastSet } else { $null }
        if ($krbSet) { $age = [int]((Get-Date) - $krbSet).TotalDays; Add-Result 'CKT-KEYAGE' 'Cloud Kerberos Trust' 'krbtgt_AzureAD key age' $(if ($age -gt $cfg.KrbtgtAzureAdWarnDays) { 'WARN' } else { 'PASS' }) "$age day(s) - rotate with Set-AzureADKerberosServer -RotateServerKey" }
        foreach ($g in @($aadKerb.'msDS-NeverRevealGroup')) {
            try {
                $grp = Get-ADGroup -Identity $g -Server $server
                $rid = [int]($grp.SID.Value -split '-')[-1]
                foreach ($u in Get-ADUser -Server $server -LDAPFilter "(|(memberOf:1.2.840.113556.1.4.1941:=$(ConvertTo-SoaLdapValue $g))(primaryGroupID=$rid))" -ResultPageSize 500) { $neverReveal[$u.DistinguishedName.ToLower()] = $grp.Name }
            } catch { }
        }
    }

    # Provisioned but not marked
    $unmarked = @(Get-ADObject -Server $server -LDAPFilter '(&(|(msDS-ExternalDirectoryObjectId=User_*)(msDS-ExternalDirectoryObjectId=Group_*))(!(msDS-ObjectSoa=*)))' -ResultPageSize 500)
    Add-Result 'PRV-UNMARKED' 'Provisioning' 'Provisioned objects not marked' $(if ($unmarked.Count) { 'WARN' } else { 'PASS' }) $(if ($unmarked.Count) { "$($unmarked.Count) object(s) - not protected and not in scope" } else { 'none' }) @($unmarked | Select-Object -First 50 | ForEach-Object { $_.Name })

    # Users
    $psoMembers = Get-SoaGroupMemberSet -Name $cfg.PsoGroupName -Server $server
    $excluded   = Get-SoaGroupMemberSet -Name $cfg.ExcludeGroupName -Server $server -Recursive
    $pilot      = if ($cfg.PilotMode) { Get-SoaGroupMemberSet -Name $cfg.PilotGroupName -Server $server -Recursive } else { @{} }
    $scopeDns   = @(if ($deployment -and $deployment.WriteScope) { $deployment.WriteScope } elseif ($Scope -eq 'All') { Get-SoaWriteScope -Config $cfg -Context $ctx })
    $psoDn      = if ($pso) { $pso.DistinguishedName.ToLower() } else { $null }
    $lastLogon  = @{}
    if ($Scope -eq 'All') {
        foreach ($dc in $ctx.WritableDcs) {
            try { foreach ($u in Get-ADUser -Server $dc -LDAPFilter (Get-SoaCloudUserFilter) -Properties lastLogon -ResultPageSize 500) {
                $t = ConvertFrom-SoaFileTime $u.lastLogon; $k = $u.SamAccountName.ToLower()
                if ($t -and (-not $lastLogon.ContainsKey($k) -or $t -gt $lastLogon[$k])) { $lastLogon[$k] = $t } } } catch { }
        }
    }
    $inScopeSet = @{}
    $agg = @{}
    function Add-Agg([string]$Id, [string]$Status, [string]$Text, [string]$User) {
        if (-not $agg.ContainsKey($Id)) { $agg[$Id] = [pscustomobject]@{ Status = $Status; Text = $Text; Users = (New-Object System.Collections.Generic.List[string]) } }
        if ((Get-SoaStatusRank $Status) -gt (Get-SoaStatusRank $agg[$Id].Status)) { $agg[$Id].Status = $Status }
        $agg[$Id].Users.Add($User)
    }
    $userRows = foreach ($u in $users) {
        $c = Get-SoaUserConformance -User $u -Config $cfg -PsoMembers $psoMembers -ExcludeMembers $excluded -PilotMembers $pilot -WriteScope $(if ($scopeDns.Count) { $scopeDns } else { $null })
        $issues = New-Object System.Collections.Generic.List[string]
        $add = { param($s, $t, $id) $issues.Add("[$s] $t"); if ((Get-SoaStatusRank $s) -gt (Get-SoaStatusRank $script:worstTmp)) { $script:worstTmp = $s }; Add-Agg $id $s $t $u.SamAccountName }
        $script:worstTmp = 'PASS'
        $young = $u.whenCreated -gt (Get-Date).AddMinutes(-[int]$cfg.NewUserGraceMinutes)
        $ucc = [int]$u.'msDS-User-Account-Control-Computed'
        $md = $null; try { $md = Get-SoaSecretMeta -Dn $u.DistinguishedName -Server $server } catch { }
        $expiry = ConvertFrom-SoaFileTime $u.'msDS-UserPasswordExpiryTimeComputed'
        $ll = if ($lastLogon.ContainsKey($u.SamAccountName.ToLower())) { $lastLogon[$u.SamAccountName.ToLower()] } else { ConvertFrom-SoaFileTime $u.lastLogonTimestamp }
        if (-not $c.Marked) { & $add 'WARN' 'provisioned but not marked (msDS-ObjectSoa) - out of scope, not protected' 'USR-UNMARKED' }
        elseif ($c.Excluded) { & $add 'INFO' "excluded ($($c.ExcludeReason))" 'USR-EXCLUDED' }
        elseif ($c.PilotOut) { & $add 'INFO' 'not in pilot group (PilotMode)' 'USR-PILOT' }
        else {
            $inScopeSet[$u.DistinguishedName.ToLower()] = $true
            if (-not $c.Disabled) {
                if (-not $c.Scril) { & $add $(if ($young) { 'WARN' } else { 'FAIL' }) $(if ($young) { 'SCRIL pending (new user)' } else { 'SCRIL missing - the password expires and blocks passwordless sign-in (0x17)' }) 'USR-SCRIL' }
                if ($c.Pne) { & $add 'WARN' "'password never expires' set - disables automatic rolling" 'USR-PNE' }
                if (-not $c.InPsoGroup) { & $add $(if ($young) { 'WARN' } else { 'FAIL' }) "not in $($cfg.PsoGroupName) - domain password policy applies" 'USR-PSOGROUP' }
                if ($psoDn -and $u.'msDS-ResultantPSO' -and "$($u.'msDS-ResultantPSO')".ToLower() -ne $psoDn) { & $add 'WARN' "resultant PSO is $($u.'msDS-ResultantPSO')" 'USR-RPSO' }
                if (-not $c.Writable) { & $add 'FAIL' 'outside the write scope - the toolkit cannot correct this user' 'USR-WRITE' }
                if ($ucc -band $Ucc.Locked) { & $add 'FAIL' 'LOCKED OUT - Kerberos sign-in blocked' 'USR-LOCKED' }
                if (($ucc -band $Ucc.Expired) -and $c.Scril -and -not $c.Pne) {
                    $secretT = if ($md) { $md.SecretTime } else { $null }
                    if ($ll -and $secretT -and $expiry -and $ll -gt ([datetime]$(if ($secretT -gt $expiry) { $secretT } else { $expiry })).AddMinutes(5) -and $lastLogon.Count) {
                        & $add 'FAIL' ("signed in at {0:yyyy-MM-dd HH:mm} while expired, but the secret was not rolled (last change {1:yyyy-MM-dd HH:mm})" -f $ll, $secretT) 'USR-NOROLL'
                    } elseif ($ll -and $secretT -and [Math]::Abs(($ll - $secretT).TotalMinutes) -le 5) {
                        & $add 'INFO' 'secret rolled at the last sign-in but still reported expired -> rolling did not update pwdLastSet (each sign-in rolls again)' 'USR-ROLLPLS'
                    } else {
                        & $add 'INFO' 'secret expired - the DC rolls it at the next passwordless sign-in' 'USR-EXPIRED'
                    }
                } elseif (($ucc -band $Ucc.Expired) -and -not $c.Scril) {
                    & $add 'FAIL' 'PASSWORD EXPIRED without SCRIL - passwordless sign-in fails (0x17)' 'USR-EXPIRED-NOSCRIL'
                }
                if ($neverReveal.ContainsKey($u.DistinguishedName.ToLower())) { & $add 'FAIL' "denied by the AzureADKerberos password replication policy (group '$($neverReveal[$u.DistinguishedName.ToLower()])')" 'USR-NEVERREVEAL' }
            }
        }
        foreach ($g in (@($kerbAll | Where-Object { $_.User -eq $u.SamAccountName.ToLower() }) | Group-Object Status)) {
            $sev = if ($g.Name -in '0x17', '0x12') { 'FAIL' } elseif ($g.Name -eq '0x18') { 'WARN' } else { 'INFO' }
            $txt = 'Kerberos {0} {1} x{2}' -f $g.Name, $KerbStatus[$g.Name], $g.Count
            if ($g.Name -eq '0x18') { $txt += ' (password attempts against a passwordless account - spraying?)' }
            & $add $sev $txt "USR-KERB-$($g.Name)"
        }
        [pscustomobject]@{
            Status = $script:worstTmp; User = $u.SamAccountName
            Origin = $(if ($md) { Get-SoaOriginKind -WhenCreated $u.whenCreated -AnchorTime $md.AnchorTime } else { 'unknown' })
            Enabled = -not $c.Disabled; SCRIL = $c.Scril; PNE = $c.Pne; PsoGroup = $c.InPsoGroup
            Expiry = $(if ($expiry) { $expiry.ToString('yyyy-MM-dd HH:mm') } else { 'never/n.a.' })
            SecretChanged = $(if ($md -and $md.SecretTime) { $md.SecretTime.ToString('yyyy-MM-dd HH:mm') } else { '-' })
            LastLogon = $(if ($ll) { $ll.ToString('yyyy-MM-dd HH:mm') } else { '-' })
            Issues = ($issues -join ' ; ')
        }
    }
    $userRows = @($userRows | Sort-Object @{ e = { Get-SoaStatusRank $_.Status }; Descending = $true }, User)
    foreach ($id in $agg.Keys) { if ($agg[$id].Status -ne 'PASS') { Add-Result $id 'Users' $agg[$id].Text $agg[$id].Status ("{0} user(s)" -f $agg[$id].Users.Count) @($agg[$id].Users | Select-Object -First 50) } }
    $fu = @($userRows | Where-Object { $_.Status -eq 'FAIL' }).Count; $wu = @($userRows | Where-Object { $_.Status -eq 'WARN' }).Count
    Add-Result 'USR-SUMMARY' 'Users' 'Provisioned users' $(if ($fu) { 'FAIL' } elseif ($wu) { 'WARN' } else { 'PASS' }) ("{0} provisioned, {1} in scope, {2} FAIL, {3} WARN" -f $userRows.Count, $inScopeSet.Count, $fu, $wu)

    # SACL for the SOA-conversion trigger (event 5136 on msDS-ObjectSoa); reading a SACL needs
    # "Manage auditing and security log", which the toolkit gMSA deliberately does not have
    if ($Scope -eq 'All') {
        try {
            $attrGuid = Get-SoaAttributeGuid -LdapDisplayName 'msDS-ObjectSoa' -Context $ctx
            $sdrive = Initialize-SoaAdDrive -Server $server
            foreach ($dn in @($scopeDns)) {
                $st = Get-SoaSaclState -Dn $dn -AttributeGuid $attrGuid -Drive $sdrive
                $stat = if ($st.Toolkit) { 'PASS' } else { 'FAIL' }
                $det = if ($st.Toolkit) { 'toolkit entry present (Everyone, Success, Write msDS-ObjectSoa, descendant users)' }
                       else { 'toolkit entry MISSING - SOA-converted users are only onboarded by the reconcile (Install-SoaToolkit.ps1 -Step AuditConfig)' + $(if (@($st.Broad).Count) { ' - other rules exist but are not relied upon' } else { '' }) }
                Add-Result 'AUD-SACL' 'Audit' "SACL $dn" $stat $det
                if (@($st.Broad).Count) { Add-Result 'AUD-SACL-OTHER' 'Audit' "Other audit rules on $dn" 'INFO' 'also audit msDS-ObjectSoa writes (noise / diagnosis leftovers?)' @($st.Broad) }
            }
            if (-not @($scopeDns).Count) { Add-Result 'AUD-SACL' 'Audit' 'SACL' 'WARN' 'write scope unknown - SACL not checked' }
        } catch { Add-Result 'AUD-SACL' 'Audit' 'SACL' 'INFO' "not readable: $($_.Exception.Message)" }
    } else {
        Add-Result 'AUD-SACL' 'Audit' 'SACL (msDS-ObjectSoa)' 'INFO' 'not readable as the toolkit gMSA (needs "Manage auditing and security log") - checked by -Scope All / Install-SoaToolkit.ps1 -Step Verify'
    }

    # PSO group drift (extra members)
    $extra = @($psoMembers.Keys | Where-Object { -not $inScopeSet.ContainsKey($_) })
    Add-Result 'GRP-DRIFT' 'Toolkit objects' "Members of $($cfg.PsoGroupName) not in scope" $(if ($extra.Count) { 'WARN' } else { 'PASS' }) $(if ($extra.Count) { "$($extra.Count) - removed by the next reconcile run" } else { 'none' }) @($extra | Select-Object -First 50)
}
#endregion

#region --- Validation tests (interactive) ----------------------------------------------------------
if ($Scope -eq 'All') {
    $statePath = Join-Path (Join-Path $cfg.ReportPath 'Tests') 'test-state.json'
    if (Test-Path -LiteralPath $statePath) {
        $state = @(Read-SoaJsonArray -Path $statePath)
        $pm = Get-SoaPolicyMode -Context $ctx -Server $server
        foreach ($grp in ($state | Group-Object Test)) {
            $last = $grp.Group | Sort-Object Time -Descending | Select-Object -First 1
            $st = $last.Status
            $detail = "$($last.Time) (mode $($last.PolicyMode)): $($last.Detail)"
            if ($pm -and $last.PolicyMode -and $last.PolicyMode -ne $pm -and $st -ne 'FAIL') { $st = 'WARN'; $detail = "run in mode $($last.PolicyMode), current mode $pm - repeat. " + $detail }
            Add-Result 'TEST' 'Validation tests' $grp.Name $st $detail
        }
    } else { Add-Result 'TEST' 'Validation tests' 'Test-SoaBehavior.ps1' 'INFO' 'no test results yet' }
}
#endregion

#region --- Output ----------------------------------------------------------------------------------
$overall = Get-SoaWorstStatus (@($Results | ForEach-Object { $_.Status }))
$counts = @{ PASS = @($Results | Where-Object { $_.Status -eq 'PASS' }).Count; INFO = @($Results | Where-Object { $_.Status -eq 'INFO' }).Count
             WARN = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count; FAIL = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count }

if ($Scope -eq 'Local') {
    foreach ($r in ($Results | Where-Object { $_.Status -in 'WARN', 'FAIL' })) {
        $id = if ($r.Status -eq 'FAIL') { $EventId.MonitorFailure } else { $EventId.MonitorWarning }
        Write-SoaEvent -Id $id -Level $(if ($r.Status -eq 'FAIL') { 'Error' } else { 'Warning' }) -Message ("[{0}] {1} - {2}: {3}" -f $r.Status, $r.Area, $r.Item, $r.Detail) `
            -Data @{ CheckId = $r.CheckId; Status = $r.Status; Area = $r.Area; Item = $r.Item; Detail = $r.Detail; Objects = $r.Objects } -LogName $cfg.EventLogName
    }
    Write-SoaEvent -Id $EventId.MonitorHeartbeat -Level $(if ($overall -eq 'FAIL') { 'Error' } elseif ($overall -eq 'WARN') { 'Warning' } else { 'Information' }) `
        -Message ("SOA Toolkit monitor heartbeat: overall {0} ({1} FAIL, {2} WARN, {3} PASS, {4} INFO) - roles DC={5}, Agent={6}" -f $overall, $counts.FAIL, $counts.WARN, $counts.PASS, $counts.INFO, $hostsToCheck[0].IsDc, $hostsToCheck[0].IsAgent) `
        -Data @{ Overall = $overall; Counts = $counts; IsDc = $hostsToCheck[0].IsDc; IsAgent = $hostsToCheck[0].IsAgent; DomainChecks = $domainChecks } -LogName $cfg.EventLogName
    try { Save-SoaStatus -DataPath $cfg.DataPath -Name 'monitor' -Status ([pscustomobject]@{ Time = (Get-Date).ToString('s'); Overall = $overall; Counts = $counts; Results = @($Results) }) } catch { }
}

if ($isInteractive) {
    Write-SoaSection ("Result - {0} - scope {1} - overall {2}" -f $ctx.DnsRoot, $Scope, $overall)
    foreach ($area in ($Results | Select-Object -ExpandProperty Area -Unique)) {
        Write-Host ''
        Write-Host $area -ForegroundColor Cyan
        foreach ($r in ($Results | Where-Object { $_.Area -eq $area })) {
            Write-Host ('  [{0}] {1,-40} {2}' -f $r.Status, $r.Item, $r.Detail) -ForegroundColor (Get-SoaStatusColor $r.Status)
            if ($r.Objects -and $r.Status -ne 'PASS') { Write-Host "         $($r.Objects)" -ForegroundColor DarkGray }
        }
    }
    if ($userRows.Count) {
        Write-SoaSection 'Provisioned users'
        foreach ($u in $userRows) {
            Write-Host ('[{0}] {1,-22} {2,-13} SCRIL={3,-5} PNE={4,-5} PSO={5,-5} expiry={6} secret={7} lastLogon={8}' -f $u.Status, $u.User, $u.Origin, $u.SCRIL, $u.PNE, $u.PsoGroup, $u.Expiry, $u.SecretChanged, $u.LastLogon) -ForegroundColor (Get-SoaStatusColor $u.Status)
            if ($u.Issues) { Write-Host "      $($u.Issues)" -ForegroundColor (Get-SoaStatusColor $u.Status) }
        }
    }
}

if ($Scope -eq 'All') {
    if (-not $OutputPath) { $OutputPath = Join-Path $cfg.ReportPath 'Monitor' }
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd_HHmm'
    $Results  | Export-Csv (Join-Path $OutputPath "monitor-checks_$stamp.csv") -NoTypeInformation -Encoding UTF8
    $userRows | Export-Csv (Join-Path $OutputPath "monitor-users_$stamp.csv") -NoTypeInformation -Encoding UTF8
    [pscustomobject]@{ Time = (Get-Date).ToString('s'); Overall = $overall; Counts = $counts; Results = @($Results); Users = @($userRows) } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputPath "monitor_$stamp.json") -Encoding UTF8
    if ($Html) {
        $body = "<h1>SOA Toolkit &ndash; monitoring ($($ctx.DnsRoot))</h1><p>Overall: <b>$overall</b> | FAIL $($counts.FAIL) | WARN $($counts.WARN) | Policy mode: <b>$(Get-SoaPolicyMode -Context $ctx -Server $server)</b> | Event window: ${EventHours} h | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>" +
                '<h2>Checks</h2>' + (ConvertTo-SoaHtmlTable -Rows $Results -Properties @('Status', 'CheckId', 'Area', 'Item', 'Detail', 'Objects')) +
                '<h2>Provisioned users</h2>' + (ConvertTo-SoaHtmlTable -Rows $userRows -Properties @('Status', 'User', 'Origin', 'Enabled', 'SCRIL', 'PNE', 'PsoGroup', 'Expiry', 'SecretChanged', 'LastLogon', 'Issues'))
        $htmlPath = Join-Path $OutputPath "monitor_$stamp.html"
        ConvertTo-Html -Head (Get-SoaHtmlStyle) -Body $body -Title 'SOA Toolkit monitoring' | Set-Content -Path $htmlPath -Encoding UTF8
        Write-Host "Report: $htmlPath" -ForegroundColor Cyan
        Write-Host "        (contains names of your environment - share it only through Export-SoaReport.ps1)" -ForegroundColor DarkGray
    }
}
if ($isInteractive) { Write-Host ''; Write-Host ("Overall: {0}" -f $overall) -ForegroundColor (Get-SoaStatusColor $overall) }
exit (Get-SoaStatusRank $overall)
#endregion
