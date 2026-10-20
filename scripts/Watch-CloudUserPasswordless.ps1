#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Monitoring and validation for users provisioned by Entra Cloud Sync (Entra ID -> AD) - cloud-native users
    and SOA-converted users - so they can keep signing in passwordless (WHfB / FIDO2 via Cloud Kerberos Trust,
    AVD / RemoteApp SSO) to AD while AD object enforcement is active.

.DESCRIPTION
    -Mode Monitor (default, schedule it e.g. daily) - read-only, evaluates and rates:
      Per provisioned user (msDS-ExternalDirectoryObjectId=User_*):
        SCRIL set | marked (msDS-ObjectSoa) | password-expired flag | pwdLastSet=0 | locked out |
        secret age vs. rotation (unicodePwd metadata) | computed password expiry | last logon (max over all DCs) |
        Kerberos failures (0x17 key expired, 0x12 revoked, 0x18 wrong password = spraying) |
        denied by the AzureADKerberos password replication policy (no Cloud Kerberos TGT) |
        origin heuristic (cloud-native vs. SOA-converted)
      Domain / infrastructure:
        SOA policy present + mode + allow-list (stale SIDs, agent, job, break-glass) |
        per DC: ntdsai.dll minimum, '2 Security Events', last policy load (3095), audit/blocked events (3097/3098),
        Kerberos AS failure auditing | AzureADKerberos object + krbtgt_AzureAD key age |
        password / lockout policy, automatic rolling + RotationDays vs. maxPwdAge | SCRIL job tasks (last run / result / errors) |
        Cloud Sync agent service | provisioned objects that are not marked |
        status of the validation tests (rollout step 6)
      Exit code: 0 = OK/INFO, 1 = WARN, 2 = FAIL (usable for scheduling / alerting).

    -Mode Test -Tests <list> - runs the validation tests against the dedicated TestUser. Writes are done
      either as YOU (= an identity NOT in the allow-list, expected to be blocked in Enforced mode) or as the
      allow-listed job gMSA (via a temporary scheduled task on JobHost running Invoke-ScrilJob.ps1 -Mode Test):
        ProbeAllowed       job gMSA writes to the enforced test user                -> must succeed
        UnauthorizedWrite  you write 'info' on the test user against EVERY DC       -> Enforced: blocked on all DCs
        ScrilJob           job removes SCRIL, the scheduled 'Enforce SCRIL' task    -> SCRIL set again
                           must restore it
        Rotation           job rotates the secret                                   -> unicodePwd metadata version
                                                                                       increased, SCRIL kept
        PasswordReset      (optional, only when named) resets via several paths     -> Enforced: each blocked
        Lockout            (optional, only when named) lockout handling            -> lockout registered, job unlocks
      -Tests All runs the core tests (ProbeAllowed, UnauthorizedWrite, ScrilJob, Rotation, MustChange, CktLogon).
        MustChange         job sets pwdLastSet=0 (= "password expired" condition)   -> with SCRIL the
                           -IncludeNegativeControl: same without SCRIL (shows risk)    PE flag must NOT be set
        CktLogon           manual: you sign in as the test user with WHfB/FIDO2 and  -> logon recorded, no
                           open the AVD RemoteApp; script waits and evaluates          Kerberos failures
                           (if combined with MustChange it runs while pwdLastSet=0 - the decisive test)
      Results are stored in ReportPath\test-state.json and shown by every Monitor run.

.NOTES
    Toolkit: cloudsync-ad-enforcement-toolkit 1.0.0 (2026-10-19)
    Run as Domain Admin from a host with RSAT. Requires WinRM to the DCs, JobHost and AgentHosts.
    Configuration: SoaEnforcement.config.psd1 (same folder).
#>
[CmdletBinding()]
param(
    [ValidateSet('Monitor', 'Test')]
    [string] $Mode = 'Monitor',

    [ValidateSet('ProbeAllowed', 'UnauthorizedWrite', 'ScrilJob', 'Rotation', 'PasswordReset', 'Lockout', 'MustChange', 'CktLogon', 'All')]
    [string[]] $Tests = @('All'),

    [switch] $IncludeNegativeControl,

    [int] $EventHours = 24,

    [int] $CktWaitMinutes = 15,

    [string] $ConfigPath = (Join-Path $PSScriptRoot 'SoaEnforcement.config.psd1'),

    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'

#region --- Context --------------------------------------------------------------------------------
$cfg = Import-PowerShellDataFile -Path $ConfigPath
if (-not $OutputPath) { $OutputPath = $cfg.ReportPath }
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
$statePath = Join-Path $OutputPath 'test-state.json'

$domain    = Get-ADDomain
$dnsRoot   = $domain.DNSRoot
$netbios   = $domain.NetBIOSName
$pdc       = $domain.PDCEmulator
$domainDN  = $domain.DistinguishedName
$policyDN  = "CN=Cloud,CN=SOA-Policies,CN=System,$domainDN"
$dcs       = @(Get-ADDomainController -Filter * -Server $pdc | Where-Object { -not $_.IsReadOnly } | Sort-Object HostName | ForEach-Object { $_.HostName })
$TaskPath  = '\SoaEnforcement\'
$MinNtdsai = @{ 20348 = [version]'10.0.20348.5257'; 26100 = [version]'10.0.26100.32995' }
$AllTests  = 'ProbeAllowed', 'UnauthorizedWrite', 'ScrilJob', 'Rotation', 'PasswordReset', 'Lockout', 'MustChange', 'CktLogon'
# 'All' = core tests (documented LDAP writes only); PasswordReset and Lockout run only when named explicitly
$CoreTests = 'ProbeAllowed', 'UnauthorizedWrite', 'ScrilJob', 'Rotation', 'MustChange', 'CktLogon'

$UAC = @{ Disabled = 0x2; DontExpire = 0x10000; Scril = 0x40000 }
$UCC = @{ Locked = 0x10; Expired = 0x800000 }   # msDS-User-Account-Control-Computed

$KerbStatus = @{
    '0x6'  = 'client unknown';                     '0x12' = 'client revoked (disabled / locked / expired account)'
    '0x17' = 'key (password) expired';             '0x18' = 'pre-authentication failed (wrong password)'
    '0x25' = 'clock skew';                         '0x1f' = 'integrity check failed'
    '0x20' = 'ticket expired';                     '0xe'  = 'encryption type not supported'
}

$Severity = @{ PASS = 0; INFO = 0; WARN = 1; FAIL = 2 }
$Colors   = @{ PASS = 'Green'; INFO = 'Gray'; WARN = 'Yellow'; FAIL = 'Red' }
#endregion

#region --- Generic helpers ------------------------------------------------------------------------
$Results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$Area, [string]$Item, [string]$Status, [string]$Detail) {
    $Results.Add([pscustomobject]@{ Area = $Area; Item = $Item; Status = $Status; Detail = $Detail })
}

function Write-Section([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 100) -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 100) -ForegroundColor DarkCyan
}

function Get-Worst([string[]]$Statuses) {
    $w = 'PASS'
    foreach ($s in $Statuses) { if ($Severity[$s] -gt $Severity[$w] -or ($s -eq 'INFO' -and $w -eq 'PASS')) { $w = $s } }
    $w
}

function Resolve-SidName([string]$Sid) {
    try {
        $o = Get-ADObject -Server $pdc -LDAPFilter "(objectSid=$Sid)" -Properties sAMAccountName
        if ($o) { return "$netbios\$($o.sAMAccountName)" }
    } catch { }
    return $null
}

function ConvertTo-LdapValue([string]$Value) {
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
}

function ConvertFrom-FileTime($Value) {
    if ($null -eq $Value -or $Value -le 0 -or $Value -ge [int64]::MaxValue) { return $null }
    try { [datetime]::FromFileTime([int64]$Value) } catch { $null }
}

function Get-PolicyMode {
    try { (@((Get-ADObject -Identity $policyDN -Server $pdc -Properties keywords).keywords) -join ',') } catch { $null }
}

function New-RandomPassword {
    $bytes = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    ([Convert]::ToBase64String($bytes) -replace '[+/=]', 'x') + 'aA1!'
}

function Get-UserSnapshot([string]$Dn, [string]$Server = $pdc) {
    $u = Get-ADUser -Identity $Dn -Server $Server -Properties userAccountControl, 'msDS-User-Account-Control-Computed', pwdLastSet, lockoutTime, badPwdCount, info
    [pscustomobject]@{
        Scril       = [bool]($u.userAccountControl -band $UAC.Scril)
        Expired     = [bool]($u.'msDS-User-Account-Control-Computed' -band $UCC.Expired)
        Locked      = [bool]($u.'msDS-User-Account-Control-Computed' -band $UCC.Locked)
        PwdLastSet  = [int64]$u.pwdLastSet
        SecretVersion = [int](@(Get-ADReplicationAttributeMetadata -Object $Dn -Server $Server) |
                              Where-Object { $_.AttributeName -eq 'unicodePwd' } | Select-Object -First 1).Version
        LockoutTime = [int64]$u.lockoutTime
        BadPwdCount = $u.badPwdCount
        Info        = $u.info
    }
}
#endregion

#region --- Job gMSA execution (temporary scheduled task on JobHost) -------------------------------
function Invoke-AsJob {
    param([string]$Arguments, [string]$ResultFile, [string]$ExistingTask, [int]$TimeoutMinutes = 5)
    $gmsaUser = '{0}\{1}$' -f $netbios, $cfg.JobGmsaName
    $r = Invoke-Command -ComputerName $cfg.JobHost `
        -ArgumentList $cfg.JobScriptPath, $Arguments, $gmsaUser, $cfg.JobDataPath, $ResultFile, $ExistingTask, $TimeoutMinutes, $TaskPath `
        -ScriptBlock {
            param($ScriptPath, $Arguments, $User, $DataPath, $ResultFile, $ExistingTask, $Timeout, $TaskPath)
            $resultPath = Join-Path $DataPath $ResultFile
            Remove-Item -Path $resultPath -Force -ErrorAction SilentlyContinue
            $temporary = -not $ExistingTask
            $name = if ($temporary) { 'Test-' + [guid]::NewGuid().ToString('N').Substring(0, 8) } else { $ExistingTask }
            if ($temporary) {
                $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" {1}' -f $ScriptPath, $Arguments)
                $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Password
                Register-ScheduledTask -TaskName $name -TaskPath $TaskPath -Action $action -Principal $principal | Out-Null
            }
            try {
                Start-ScheduledTask -TaskName $name -TaskPath $TaskPath
                $deadline = (Get-Date).AddMinutes($Timeout)
                do { Start-Sleep -Seconds 3; $done = Test-Path -Path $resultPath } while (-not $done -and (Get-Date) -lt $deadline)
                Start-Sleep -Seconds 1
                $info = Get-ScheduledTaskInfo -TaskName $name -TaskPath $TaskPath
                [pscustomobject]@{
                    Finished       = $done
                    LastTaskResult = $info.LastTaskResult
                    Json           = $(if ($done) { Get-Content -Path $resultPath -Raw } else { $null })
                }
            } finally {
                if ($temporary) { Unregister-ScheduledTask -TaskName $name -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue }
            }
        }
    $parsed = if ($r.Json) { $r.Json | ConvertFrom-Json } else { $null }
    [pscustomobject]@{
        Finished = $r.Finished
        TaskResult = $r.LastTaskResult
        Success  = [bool]($parsed -and $parsed.Success)
        Errors   = $(if ($parsed) { @($parsed.Errors) -join '; ' } else { 'no result file (task did not finish / could not start)' })
        RunAs    = $(if ($parsed) { $parsed.RunAs } else { $null })
    }
}

function Invoke-JobTest([string]$Action, [string]$Sam) {
    Invoke-AsJob -Arguments "-Mode Test -TestAction $Action -Identity $Sam" -ResultFile "test-$Action.json"
}

function Test-Write([scriptblock]$Action) {
    try { & $Action; [pscustomobject]@{ Accepted = $true; Error = $null } }
    catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        [pscustomobject]@{ Accepted = $false; Error = $e.Message }
    }
}
#endregion

#region --- Test state -----------------------------------------------------------------------------
function Get-TestState {
    if (Test-Path -Path $statePath) { @(Get-Content -Path $statePath -Raw | ConvertFrom-Json) } else { @() }
}

function Save-TestResult([string]$Name, [string]$Status, [string]$Detail, [string]$PolicyMode) {
    $all  = @(Get-TestState)
    $all += [pscustomobject]@{ Test = $Name; Time = (Get-Date).ToString('s'); PolicyMode = $PolicyMode; Status = $Status; Detail = $Detail; RunBy = "$env:USERDOMAIN\$env:USERNAME" }
    $all  = @($all | Group-Object Test | ForEach-Object { $_.Group | Sort-Object Time -Descending | Select-Object -First 20 })
    ConvertTo-Json -InputObject $all -Depth 3 | Set-Content -Path $statePath -Encoding UTF8
    Write-Host ('[{0}] {1}: {2}' -f $Status, $Name, $Detail) -ForegroundColor $Colors[$Status]
}
#endregion

#region --- Kerberos events ------------------------------------------------------------------------
# Kerberos failures (4768 / 4769 / 4771 with Status != 0x0) for the given users on every DC
function Get-KerberosFailures([string[]]$Users, [datetime]$Since) {
    if (-not $Users.Count) { return @() }
    $ms = [int64]((Get-Date) - $Since).TotalMilliseconds
    @(Invoke-Command -ComputerName $dcs -ArgumentList (, $Users), $ms -ErrorAction Continue -ScriptBlock {
        param([string[]]$Users, [int64]$Ms)
        $set = @{}; foreach ($u in $Users) { $set[$u.ToLower()] = $true }
        $xp  = "*[System[(EventID=4768 or EventID=4769 or EventID=4771) and TimeCreated[timediff(@SystemTime) <= $Ms]] and EventData[Data[@Name='Status']!='0x0']]"
        try {
            $events = @(Get-WinEvent -LogName Security -FilterXPath $xp -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() }
            else {
                # Fallback if the XPath is not accepted: Audit Failure keyword, filtered in PowerShell
                $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4768, 4769, 4771; Keywords = 4503599627370496; StartTime = (Get-Date).AddMilliseconds(-$Ms) } -ErrorAction SilentlyContinue)
            }
        }
        foreach ($e in $events) {
            $d = @{}
            foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            $user = ("$($d.TargetUserName)" -split '@')[0].ToLower()
            if (-not $set.ContainsKey($user) -or "$($d.Status)" -eq '0x0') { continue }
            [pscustomobject]@{ DC = $env:COMPUTERNAME; Time = $e.TimeCreated; Id = $e.Id; User = $user; Status = "$($d.Status)".ToLower(); Service = $d.ServiceName; Ip = $d.IpAddress }
        }
    })
}

# Highest lastLogon of the given users over all writable DCs (lastLogon is not replicated)
function Get-LastLogonMap([string]$LdapFilter) {
    $map = @{}
    foreach ($dc in $dcs) {
        try {
            foreach ($u in Get-ADUser -Server $dc -LDAPFilter $LdapFilter -Properties lastLogon -ResultPageSize 500) {
                $t = ConvertFrom-FileTime $u.lastLogon
                $k = $u.SamAccountName.ToLower()
                if ($t -and (-not $map.ContainsKey($k) -or $t -gt $map[$k])) { $map[$k] = $t }
            }
        } catch { Write-Warning "lastLogon not readable on ${dc}: $($_.Exception.Message)" }
    }
    $map
}
#endregion

#==================================================================================================
#  TEST MODE
#==================================================================================================
if ($Mode -eq 'Test') {
    if ($Tests -contains 'All') { $Tests = @($CoreTests) + @($Tests | Where-Object { $_ -ne 'All' }) }
    $sam = $cfg.TestUser
    if (-not $sam) { throw 'TestUser is not configured.' }
    $tu = Get-ADUser -Identity $sam -Server $pdc -Properties 'msDS-ExternalDirectoryObjectId', 'msDS-ObjectSoa', userPrincipalName
    if ("$($tu.'msDS-ExternalDirectoryObjectId')" -notlike 'User_*') { throw "TestUser $sam is not provisioned by Cloud Sync." }
    $dn         = $tu.DistinguishedName
    $policyMode = Get-PolicyMode
    $enforced   = ($policyMode -eq 'Enforced')
    $testStart  = Get-Date

    Write-Section ("Validation tests on '{0}' - policy mode: {1} - marked: {2}" -f $sam, $(if ($policyMode) { $policyMode } else { 'NO POLICY' }), (@($tu.'msDS-ObjectSoa') -join ','))
    if (-not $tu.'msDS-ObjectSoa') { Write-Warning 'The test user is NOT marked (msDS-ObjectSoa) - enforcement does not apply to it, results are not meaningful.' }

    foreach ($t in ($AllTests | Where-Object { $Tests -contains $_ })) {
        Write-Host ''
        Write-Host "--- $t ---" -ForegroundColor Cyan
        try {
            switch ($t) {

                'ProbeAllowed' {
                    $r = Invoke-JobTest 'ProbeWrite' $sam
                    if ($r.Success) { Save-TestResult $t 'PASS' "Job identity $($r.RunAs) wrote to the enforced test user - allow-list works." $policyMode }
                    else { Save-TestResult $t 'FAIL' "Job write failed: $($r.Errors) (task result $($r.TaskResult))" $policyMode }
                }

                'UnauthorizedWrite' {
                    $accepted = @(); $blocked = @(); $firstError = $null
                    foreach ($dc in $dcs) {
                        $res = Test-Write { Set-ADUser -Identity $dn -Server $dc -Replace @{ info = "SOA unauthorized probe $(Get-Date -Format s)" } }
                        if ($res.Accepted) {
                            $accepted += $dc
                            try { Set-ADUser -Identity $dn -Server $dc -Clear info } catch { }
                        } else {
                            $blocked += $dc
                            if (-not $firstError) { $firstError = $res.Error }
                        }
                    }
                    if ($enforced) {
                        if ($accepted.Count) { Save-TestResult $t 'FAIL' ("Change ACCEPTED on {0} - enforcement not effective there (or your account is allow-listed)." -f ($accepted -join ', ')) $policyMode }
                        else { Save-TestResult $t 'PASS' ("Blocked on all {0} writable DC(s). Error: {1}" -f $blocked.Count, $firstError) $policyMode }
                    } else {
                        Save-TestResult $t 'INFO' ("Mode {0}: accepted on {1}, blocked on {2}. In Audit mode expect event 3097 on each DC." -f $policyMode, ($accepted -join ', '), ($blocked -join ', ')) $policyMode
                    }
                }

                'ScrilJob' {
                    $off = Invoke-JobTest 'ScrilOff' $sam
                    if (-not $off.Success) { Save-TestResult $t 'FAIL' "Job could not remove SCRIL: $($off.Errors)"  $policyMode; break }
                    $run = Invoke-AsJob -ExistingTask 'Enforce SCRIL' -ResultFile 'status-Enforce.json'
                    $s   = Get-UserSnapshot $dn
                    if ($s.Scril -and $run.Success) { Save-TestResult $t 'PASS' "Scheduled task 'Enforce SCRIL' restored SCRIL under policy mode $policyMode." $policyMode }
                    else {
                        [void](Invoke-JobTest 'ScrilOn' $sam)
                        Save-TestResult $t 'FAIL' ("SCRIL not restored by the scheduled task (task success={0}, errors: {1}). SCRIL re-set directly." -f $run.Success, $run.Errors) $policyMode
                    }
                }

                'Rotation' {
                    $before = Get-UserSnapshot $dn
                    $r      = Invoke-JobTest 'Rotate' $sam
                    $after  = Get-UserSnapshot $dn
                    if ($r.Success -and $after.SecretVersion -gt $before.SecretVersion -and $after.Scril) {
                        Save-TestResult $t 'PASS' ("Secret rotated by the job: unicodePwd metadata version {0} -> {1}, pwdLastSet moved: {2}, SCRIL kept." -f
                            $before.SecretVersion, $after.SecretVersion, ($after.PwdLastSet -gt $before.PwdLastSet)) $policyMode
                    } else {
                        Save-TestResult $t 'FAIL' ("Rotation failed: success={0}, secret changed={1}, SCRIL={2}, errors: {3}" -f $r.Success, ($after.SecretVersion -gt $before.SecretVersion), $after.Scril, $r.Errors) $policyMode
                    }
                }

                'PasswordReset' {
                    $methods = [ordered]@{
                        'LDAP (Set-ADAccountPassword)' = {
                            Set-ADAccountPassword -Identity $dn -Server $pdc -Reset -NewPassword (ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force)
                        }
                        'ADSI SetPassword (LDAP/Kerberos/SAMR)' = {
                            $entry = New-Object DirectoryServices.DirectoryEntry("LDAP://$pdc/$dn")
                            try { [void]$entry.Invoke('SetPassword', (New-RandomPassword)) } finally { $entry.Dispose() }
                        }
                        'SAMR (net user /domain)' = {
                            $out = & net.exe user $sam (New-RandomPassword) /domain 2>&1
                            if ($LASTEXITCODE -ne 0) { throw ($out -join ' ') }
                        }
                    }
                    $lines = @(); $acceptedAny = $false
                    foreach ($m in $methods.Keys) {
                        $res = Test-Write $methods[$m]
                        if ($res.Accepted) { $acceptedAny = $true; $lines += "$m = ACCEPTED" } else { $lines += "$m = blocked ($($res.Error))" }
                    }
                    $rot = Invoke-JobTest 'Rotate' $sam      # never leave a password set by a person
                    $lines += "re-randomized by job: $($rot.Success)"
                    $status = if (-not $enforced) { 'INFO' } elseif ($acceptedAny) { 'WARN' } else { 'PASS' }
                    Save-TestResult $t $status ($lines -join ' | ') $policyMode
                }

                'Lockout' {
                    $pol = $null
                    try { $pol = Get-ADUserResultantPasswordPolicy -Identity $dn -Server $pdc } catch { }
                    if (-not $pol) { $pol = Get-ADDefaultDomainPasswordPolicy -Server $pdc }
                    if (-not $pol.LockoutThreshold) {
                        Save-TestResult $t 'INFO' 'No lockout threshold configured - accounts cannot be locked out (no DoS via lockout, test skipped).' $policyMode
                        break
                    }
                    Add-Type -AssemblyName System.DirectoryServices.Protocols
                    for ($i = 1; $i -le ($pol.LockoutThreshold + 1); $i++) {
                        $id   = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($pdc, 389)
                        $cred = New-Object System.Net.NetworkCredential($sam, (New-RandomPassword), $netbios)
                        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($id, $cred, [System.DirectoryServices.Protocols.AuthType]::Negotiate)
                        try { $conn.Bind() } catch { } finally { $conn.Dispose() }
                    }
                    Start-Sleep -Seconds 3
                    $s = Get-UserSnapshot $dn
                    $lines = @("threshold $($pol.LockoutThreshold), badPwdCount $($s.BadPwdCount), locked: $($s.Locked)")
                    $admin = Test-Write { Unlock-ADAccount -Identity $dn -Server $pdc }
                    $lines += $(if ($admin.Accepted) { 'admin unlock ACCEPTED' } else { "admin unlock blocked ($($admin.Error))" })
                    if (-not $admin.Accepted) { $job = Invoke-JobTest 'Unlock' $sam; $lines += "job unlock success: $($job.Success)" }
                    $after = Get-UserSnapshot $dn
                    $lines += "locked after unlock: $($after.Locked)"
                    $status = if (-not $s.Locked) { 'WARN' } elseif ($after.Locked) { 'FAIL' } else { 'PASS' }
                    if (-not $s.Locked) { $lines += 'lockout NOT registered - DC-internal lockout write blocked?' }
                    if ($enforced -and $admin.Accepted) { $lines += 'note: admin unlock was accepted although Enforced' }
                    Save-TestResult $t $status ($lines -join ' | ') $policyMode
                }

                'MustChange' {
                    [void](Invoke-JobTest 'ScrilOn' $sam)
                    $on = Invoke-JobTest 'MustChangeOn' $sam
                    if (-not $on.Success) { Save-TestResult $t 'FAIL' "Job could not set pwdLastSet=0: $($on.Errors)" $policyMode; break }
                    $s = Get-UserSnapshot $dn
                    $lines = @("SCRIL + pwdLastSet=0 -> password-expired flag: $($s.Expired)")
                    $status = if ($s.Expired) { 'FAIL' } else { 'PASS' }

                    if ($Tests -contains 'CktLogon') {
                        Write-Host 'pwdLastSet=0 is active - now perform the CktLogon test (decisive: logon must still work).' -ForegroundColor Yellow
                        $script:MustChangeActive = $true
                    } else {
                        [void](Invoke-JobTest 'MustChangeOff' $sam)
                    }

                    if ($IncludeNegativeControl) {
                        [void](Invoke-JobTest 'ScrilOff' $sam)
                        [void](Invoke-JobTest 'MustChangeOn' $sam)
                        $n = Get-UserSnapshot $dn
                        $lines += "negative control WITHOUT SCRIL -> password-expired flag: $($n.Expired) (expected True)"
                        [void](Invoke-JobTest 'ScrilOn' $sam)
                        if (-not $script:MustChangeActive) { [void](Invoke-JobTest 'MustChangeOff' $sam) }
                    }
                    Save-TestResult $t $status ($lines -join ' | ') $policyMode
                }

                'CktLogon' {
                    $start = Get-Date
                    Write-Host ''
                    Write-Host "MANUAL STEP - within $CktWaitMinutes minutes:" -ForegroundColor Yellow
                    Write-Host "  1. Sign in as $($tu.userPrincipalName) on an Entra-joined / hybrid-joined Windows device with Windows Hello for Business or a FIDO2 key." -ForegroundColor Yellow
                    Write-Host '  2. Start the AVD RemoteApp / desktop (SSO) and open an AD resource (e.g. a file share).' -ForegroundColor Yellow
                    Write-Host 'Waiting for a logon on any DC ...' -ForegroundColor Yellow
                    $filter   = "(sAMAccountName=$(ConvertTo-LdapValue $sam))"
                    $deadline = $start.AddMinutes($CktWaitMinutes)
                    $logon = $null
                    do {
                        Start-Sleep -Seconds 20
                        $map = Get-LastLogonMap $filter
                        if ($map.ContainsKey($sam.ToLower()) -and $map[$sam.ToLower()] -gt $start) { $logon = $map[$sam.ToLower()] }
                    } while (-not $logon -and (Get-Date) -lt $deadline)
                    $fails = @(Get-KerberosFailures @($sam) $start)
                    $failText = ($fails | Group-Object Status | ForEach-Object { '{0} ({1}) x{2}' -f $_.Name, $KerbStatus[$_.Name], $_.Count }) -join ', '
                    $ctx = if ($script:MustChangeActive) { 'while pwdLastSet=0 (expired condition)' } else { 'normal state' }
                    if ($script:MustChangeActive) { [void](Invoke-JobTest 'MustChangeOff' $sam); $script:MustChangeActive = $false }
                    $critical = @($fails | Where-Object { $_.Status -in '0x17', '0x12' })
                    if ($logon -and -not $critical.Count) { Save-TestResult $t 'PASS' "Logon recorded at $logon ($ctx). Kerberos failures: $(if ($failText) { $failText } else { 'none' })" $policyMode }
                    elseif ($critical.Count) { Save-TestResult $t 'FAIL' "Kerberos failures $failText ($ctx). Logon recorded: $(if ($logon) { $logon } else { 'no' })" $policyMode }
                    else { Save-TestResult $t 'WARN' "No logon recorded within $CktWaitMinutes min ($ctx) - repeat the manual step." $policyMode }
                }
            }
        } catch {
            Save-TestResult $t 'FAIL' "Test aborted: $($_.Exception.Message)" $policyMode
        }
    }

    if ($script:MustChangeActive) { [void](Invoke-JobTest 'MustChangeOff' $sam) }
    $final = Get-UserSnapshot $dn
    if (-not $final.Scril) { [void](Invoke-JobTest 'ScrilOn' $sam) }

    # SOA events written during the test run
    Write-Section 'SOA events on the DCs during this test run (3097 audit / 3098 blocked)'
    $ev = @(Invoke-Command -ComputerName $dcs -ArgumentList $testStart -ErrorAction Continue -ScriptBlock {
        param([datetime]$From)
        Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 3097, 3098; StartTime = $From } -ErrorAction SilentlyContinue |
            ForEach-Object { $m = $_.Message -replace '\s+', ' '; [pscustomobject]@{ DC = $env:COMPUTERNAME; Time = $_.TimeCreated; Id = $_.Id; Message = $(if ($m.Length -gt 220) { $m.Substring(0, 220) + '...' } else { $m }) } }
    })
    if ($ev.Count) { $ev | Sort-Object Time | Format-Table DC, Time, Id, Message -AutoSize -Wrap | Out-Host }
    else { Write-Host 'None (check "2 Security Events" >= 1 if you expected some).' -ForegroundColor Yellow }
    Write-Host "Test state: $statePath" -ForegroundColor Cyan
    return
}

#==================================================================================================
#  MONITOR MODE
#==================================================================================================
$since      = (Get-Date).AddHours(-$EventHours)
$policyMode = Get-PolicyMode

#region --- Policy / allow-list --------------------------------------------------------------------
Write-Section 'Collecting: SOA policy and allow-list'
$policy = $null
try { $policy = Get-ADObject -Identity $policyDN -Server $pdc -Properties keywords, 'msDS-Settings' } catch { }
if (-not $policy) {
    Add-Result 'Policy' 'CN=Cloud' 'FAIL' 'SOA policy not found - no enforcement.'
} else {
    Add-Result 'Policy' 'Mode' $(if ($policyMode -eq 'Enforced') { 'PASS' } elseif ($policyMode -eq 'Audit') { 'INFO' } else { 'WARN' }) "keywords = $policyMode"
    $current = @($policy.'msDS-Settings' | Where-Object { $_ } | ForEach-Object { "$_" })
    $stale   = @($current | Where-Object { -not (Resolve-SidName $_) })
    Add-Result 'Policy' 'Allow-list SIDs valid' $(if ($stale.Count) { 'FAIL' } else { 'PASS' }) $(if ($stale.Count) { "STALE: $($stale -join ', ') - policy fails to load, nobody authorized" } else { "$($current.Count) SID(s), all resolvable" })

    $agentSids = @()
    try {
        $agentSids = @(Invoke-Command -ComputerName $cfg.AgentHosts -ErrorAction Continue -ScriptBlock {
            (Get-CimInstance -ClassName Win32_Service -Filter "Name='AADConnectProvisioningAgent'").StartName } |
            Where-Object { $_ } | ForEach-Object { "$_" } | Select-Object -Unique | ForEach-Object {
                $s = ($_ -split '\\')[-1]; if ($s -notlike '*$') { $s += '$' }
                $a = Get-ADServiceAccount -Filter "SamAccountName -eq '$s'" -Server $pdc
                if ($a) { [pscustomobject]@{ Name = $s; Sid = $a.SID.Value } } })
    } catch { }
    foreach ($a in $agentSids) {
        Add-Result 'Policy' "Agent $($a.Name) allow-listed" $(if ($current -contains $a.Sid) { 'PASS' } else { 'FAIL' }) $a.Sid
    }
    $job = $null; try { $job = Get-ADServiceAccount -Identity $cfg.JobGmsaName -Server $pdc } catch { }
    Add-Result 'Policy' 'Job gMSA allow-listed' $(if ($job -and $current -contains $job.SID.Value) { 'PASS' } else { 'WARN' }) $(if ($job) { $job.SID.Value } else { 'gMSA not found' })
    $bg = Get-ADUser -Filter "SamAccountName -eq '$($cfg.BreakGlassName)'" -Server $pdc
    if ($bg) {
        Add-Result 'Policy' 'Break-glass allow-listed' $(if ($current -contains $bg.SID.Value) { 'PASS' } else { 'WARN' }) "$($bg.SamAccountName) enabled=$($bg.Enabled)"
        if ($bg.Enabled) { Add-Result 'Policy' 'Break-glass state' 'WARN' "$($bg.SamAccountName) is ENABLED - disable it after the emergency." }
    } else { Add-Result 'Policy' 'Break-glass allow-listed' 'WARN' 'break-glass account not found' }
}
#endregion

#region --- Per-DC state ---------------------------------------------------------------------------
Write-Section 'Collecting: domain controllers'
$dcData = @(Invoke-Command -ComputerName $dcs -ArgumentList $since -ErrorAction Continue -ScriptBlock {
    param([datetime]$Since)
    $vi  = (Get-Item -Path (Join-Path $env:windir 'System32\ntdsai.dll')).VersionInfo
    $p   = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ErrorAction SilentlyContinue
    $ev  = @(Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 3095, 3097, 3098; StartTime = (Get-Date).AddDays(-30) } -ErrorAction SilentlyContinue)
    $ld  = $ev | Where-Object { $_.Id -eq 3095 } | Select-Object -First 1
    $blk = @($ev | Where-Object { $_.Id -eq 3098 -and $_.TimeCreated -ge $Since })
    # Kerberos Authentication Service failure auditing (language-independent via auditpol /backup)
    $tmp = Join-Path $env:TEMP ('ap_{0}.csv' -f [guid]::NewGuid().ToString('N'))
    & auditpol.exe /backup /file:$tmp | Out-Null
    $kas = Get-Content -Path $tmp -ErrorAction SilentlyContinue | Where-Object { $_ -match '0CCE9242-69AE-11D9-BED3-505054503030' } | Select-Object -First 1
    Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    $kasVal = if ($kas) { [int](($kas -split ',')[-1]) } else { $null }
    [pscustomobject]@{
        Build         = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild
        Ntdsai        = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
        DiagLevel     = $(if ($p -and ($p.PSObject.Properties.Name -contains '2 Security Events')) { [int]$p.'2 Security Events' } else { $null })
        LastLoadTime  = $(if ($ld) { $ld.TimeCreated } else { $null })
        LastLoadLevel = $(if ($ld) { [int]$ld.Level } else { $null })
        LastLoadMsg   = $(if ($ld) { $m = $ld.Message -replace '\s+', ' '; if ($m.Length -gt 250) { $m.Substring(0, 250) + '...' } else { $m } } else { $null })
        Audit3097     = @($ev | Where-Object { $_.Id -eq 3097 -and $_.TimeCreated -ge $Since }).Count
        Block3098     = $blk.Count
        BlockSample   = @($blk | Select-Object -First 3 | ForEach-Object { $m = $_.Message -replace '\s+', ' '; if ($m.Length -gt 200) { $m.Substring(0, 200) + '...' } else { $m } })
        KasAudit      = $kasVal      # 1 success, 2 failure, 3 both
    }
})

foreach ($dc in $dcs) {
    $d = $dcData | Where-Object { $_.PSComputerName -eq $dc } | Select-Object -First 1
    $short = ($dc -split '\.')[0]
    if (-not $d) { Add-Result "DC $short" 'Reachable (WinRM)' 'FAIL' 'no data'; continue }
    $ok = $MinNtdsai.ContainsKey([int]$d.Build) -and ([version]$d.Ntdsai -ge $MinNtdsai[[int]$d.Build])
    Add-Result "DC $short" 'ntdsai.dll' $(if ($ok) { 'PASS' } else { 'FAIL' }) "$($d.Ntdsai) (build $($d.Build))"
    Add-Result "DC $short" 'SOA event logging' $(if ($d.DiagLevel -ge 1) { 'PASS' } else { 'WARN' }) "'2 Security Events' = $(if ($null -eq $d.DiagLevel) { 'not set' } else { $d.DiagLevel })"
    $loadStatus = if (-not $d.LastLoadTime) { 'WARN' } elseif ($d.LastLoadLevel -in 1, 2, 3 -or $d.LastLoadMsg -match '(?i)fail|invalid|unable|could not|error') { 'FAIL' } else { 'PASS' }
    Add-Result "DC $short" 'Policy load (3095)' $loadStatus $(if ($d.LastLoadTime) { "$($d.LastLoadTime): $($d.LastLoadMsg)" } else { 'no 3095 in the last 30 days' })
    if ($policyMode -eq 'Audit') { Add-Result "DC $short" "Audit events 3097 (${EventHours}h)" $(if ($d.Audit3097) { 'WARN' } else { 'PASS' }) "$($d.Audit3097) change(s) that Enforced mode would block" }
    Add-Result "DC $short" "Blocked writes 3098 (${EventHours}h)" $(if ($d.Block3098) { 'WARN' } else { 'PASS' }) $(if ($d.Block3098) { "$($d.Block3098): $(@($d.BlockSample) -join ' || ')" } else { 'none' })
    Add-Result "DC $short" 'Kerberos AS failure auditing' $(if ($d.KasAudit -in 2, 3) { 'PASS' } else { 'WARN' }) $(if ($d.KasAudit -in 2, 3) { 'enabled' } else { 'failure auditing OFF - 0x17/0x12 failures are invisible' })
}
#endregion

#region --- Cloud Kerberos Trust, password policy --------------------------------------------------
Write-Section 'Collecting: Cloud Kerberos Trust and password policy'
$neverReveal = @{}; $revealGroups = @()
$aadKerb = $null
try { $aadKerb = Get-ADComputer -Identity 'AzureADKerberos' -Server $pdc -Properties 'msDS-NeverRevealGroup', 'msDS-RevealOnDemandGroup' } catch { }
if (-not $aadKerb) {
    Add-Result 'Cloud Kerberos Trust' 'AzureADKerberos object' 'FAIL' 'not found - Entra Kerberos server object missing, no partial TGTs for AD'
} else {
    Add-Result 'Cloud Kerberos Trust' 'AzureADKerberos object' 'PASS' $aadKerb.DistinguishedName
    $krb = Get-ADUser -Filter "SamAccountName -like 'krbtgt_AzureAD*'" -Server $pdc -Properties pwdLastSet | Select-Object -First 1
    $krbSet = if ($krb) { ConvertFrom-FileTime $krb.pwdLastSet } else { $null }
    if ($krbSet) {
        $age = [int]((Get-Date) - $krbSet).TotalDays
        Add-Result 'Cloud Kerberos Trust' 'krbtgt_AzureAD key age' $(if ($age -gt $cfg.KrbtgtAzureAdWarnDays) { 'WARN' } else { 'PASS' }) "$age day(s) - rotate with Set-AzureADKerberosServer -RotateServerKey"
    }
    foreach ($g in @($aadKerb.'msDS-NeverRevealGroup')) {
        try {
            $grp = Get-ADGroup -Identity $g -Server $pdc
            $rid = [int]($grp.SID.Value -split '-')[-1]
            foreach ($u in Get-ADUser -Server $pdc -LDAPFilter "(|(memberOf:1.2.840.113556.1.4.1941:=$(ConvertTo-LdapValue $g))(primaryGroupID=$rid))" -ResultPageSize 500) {
                $neverReveal[$u.DistinguishedName.ToLower()] = $grp.Name
            }
        } catch { }
    }
    $revealGroups = @($aadKerb.'msDS-RevealOnDemandGroup')
}

$ddp = Get-ADDefaultDomainPasswordPolicy -Server $pdc
Add-Result 'Password policy' 'Max password age' 'INFO' $(if ($ddp.MaxPasswordAge.TotalDays -gt 0) { "$([int]$ddp.MaxPasswordAge.TotalDays) day(s) - SCRIL users are not affected" } else { 'never expires (0)' })
Add-Result 'Password policy' 'Lockout threshold' 'INFO' $(if ($ddp.LockoutThreshold) { "$($ddp.LockoutThreshold) - lockout blocks Kerberos for passwordless users too (unlock via job / Entra)" } else { 'none' })
$rootObj = Get-ADObject -Identity $domainDN -Server $pdc -Properties 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts', 'msDS-Behavior-Version'
$roll    = $rootObj.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'
$rollingEffective = ($roll -eq $true) -and ([int]$rootObj.'msDS-Behavior-Version' -ge 7)
Add-Result 'Password policy' 'Automatic SCRIL rolling by DC' 'INFO' $(if ($rollingEffective) { 'ENABLED - SCRIL users without PNE get a new secret at a qualifying sign-on once pwdLastSet + maxPwdAge is reached (MS-SAMS)' } else { 'disabled - rotation only via job' })
$maxDays = [int]$ddp.MaxPasswordAge.TotalDays
if ($rollingEffective -and $maxDays -gt 0) {
    Add-Result 'Password policy' 'RotationDays vs. maxPwdAge' $(if ([int]$cfg.RotationDays -lt $maxDays) { 'PASS' } else { 'WARN' }) ("RotationDays {0}, domain maxPwdAge {1} - rotation must move pwdLastSet (RotationMethod RandomReset/Auto) to keep users out of the rolling window" -f $cfg.RotationDays, $maxDays)
}
#endregion

#region --- SCRIL job and agents -------------------------------------------------------------------
Write-Section 'Collecting: SCRIL job and Cloud Sync agents'
try {
    $jobData = Invoke-Command -ComputerName $cfg.JobHost -ArgumentList $TaskPath, $cfg.JobDataPath -ScriptBlock {
        param($TaskPath, $DataPath)
        foreach ($n in 'Enforce SCRIL', 'Rotate SCRIL secret') {
            $t = Get-ScheduledTask -TaskName $n -TaskPath $TaskPath -ErrorAction SilentlyContinue
            if (-not $t -and $n -eq 'Rotate SCRIL secret') {
                # task name used before toolkit 1.0.0
                $t = Get-ScheduledTask -TaskName 'Rotate SCRIL hash' -TaskPath $TaskPath -ErrorAction SilentlyContinue
                if ($t) { $n = 'Rotate SCRIL hash' }
            }
            $i = if ($t) { Get-ScheduledTaskInfo -TaskName $n -TaskPath $TaskPath } else { $null }
            $f = Join-Path $DataPath $(if ($n -like 'Enforce*') { 'status-Enforce.json' } else { 'status-Rotate.json' })
            [pscustomobject]@{
                Name = $n; Exists = [bool]$t; State = $(if ($t) { "$($t.State)" } else { $null })
                LastRun = $(if ($i) { $i.LastRunTime } else { $null }); LastResult = $(if ($i) { $i.LastTaskResult } else { $null })
                Status = $(if (Test-Path $f) { Get-Content -Path $f -Raw } else { $null })
            }
        }
    }
    foreach ($j in $jobData) {
        $maxAge = if ($j.Name -like 'Enforce*') { [int]$cfg.JobIntervalMinutes * 3 } else { 26 * 60 }
        if (-not $j.Exists) { Add-Result 'SCRIL job' $j.Name 'FAIL' 'task not found on JobHost'; continue }
        if ($j.Name -eq 'Rotate SCRIL hash') { Add-Result 'SCRIL job' 'Task name' 'INFO' "legacy task name '$($j.Name)' - run Initialize-SoaEnforcement.ps1 -Step DeployJob to migrate" }
        $st  = if ($j.Status) { $j.Status | ConvertFrom-Json } else { $null }
        $age = if ($j.LastRun -and $j.LastRun.Year -gt 2000) { [int]((Get-Date) - $j.LastRun).TotalMinutes } else { $null }
        $status = if ($null -eq $age -or $age -gt $maxAge) { 'FAIL' } elseif ($j.LastResult -ne 0 -or ($st -and -not $st.Success)) { 'WARN' } else { 'PASS' }
        $detail = "state $($j.State), last run $($j.LastRun) (result $($j.LastResult))"
        if ($st) { $detail += ", candidates $($st.Candidates), changed $($st.Changed)"; if (@($st.Errors).Count) { $detail += ", errors: $(@($st.Errors) -join '; ')" } }
        Add-Result 'SCRIL job' $j.Name $status $detail
    }
} catch { Add-Result 'SCRIL job' 'JobHost' 'FAIL' "not reachable: $($_.Exception.Message)" }

foreach ($h in $cfg.AgentHosts) {
    try {
        $svc = Invoke-Command -ComputerName $h -ScriptBlock { Get-Service -Name 'AADConnectProvisioningAgent' -ErrorAction SilentlyContinue | Select-Object Status, StartType }
        Add-Result 'Cloud Sync agent' $h $(if ($svc -and "$($svc.Status)" -eq 'Running') { 'PASS' } else { 'FAIL' }) $(if ($svc) { "service $($svc.Status)" } else { 'service not found' })
    } catch { Add-Result 'Cloud Sync agent' $h 'FAIL' "not reachable: $($_.Exception.Message)" }
}

$unmarked = @(Get-ADObject -Server $pdc -LDAPFilter '(&(|(msDS-ExternalDirectoryObjectId=User_*)(msDS-ExternalDirectoryObjectId=Group_*))(!(msDS-ObjectSoa=*)))' -ResultPageSize 500)
Add-Result 'Provisioning' 'Unmarked provisioned objects' $(if ($unmarked.Count) { 'WARN' } else { 'PASS' }) $(if ($unmarked.Count) { ($unmarked.Name | Select-Object -First 10) -join ', ' } else { 'none' })
#endregion

#region --- Per-user evaluation --------------------------------------------------------------------
Write-Section 'Collecting: provisioned users'
$userFilter = '(&(objectCategory=person)(objectClass=user)(msDS-ExternalDirectoryObjectId=User_*))'
$users = @(Get-ADUser -Server $pdc -LDAPFilter $userFilter -ResultPageSize 500 -Properties userAccountControl, 'msDS-User-Account-Control-Computed',
           'msDS-UserPasswordExpiryTimeComputed', pwdLastSet, 'msDS-ObjectSoa', whenCreated, userPrincipalName, 'msDS-ResultantPSO')
$psoAgeCache = @{}
# SecretAgeWarnDays (toolkit 1.0.0); HashAgeWarnDays accepted from older configuration files
$secretWarnDays = if ($cfg.SecretAgeWarnDays) { [int]$cfg.SecretAgeWarnDays } elseif ($cfg.HashAgeWarnDays) { [int]$cfg.HashAgeWarnDays } else { 45 }
$lastLogon = Get-LastLogonMap $userFilter
$kerbFails = @(Get-KerberosFailures @($users | ForEach-Object { $_.SamAccountName }) $since)

$userRows = foreach ($u in $users) {
    $issues = New-Object System.Collections.Generic.List[object]
    function Add-Issue([string]$S, [string]$T) { $issues.Add([pscustomobject]@{ Status = $S; Text = $T }) }

    $uac      = [int]$u.userAccountControl
    $ucc      = [int]$u.'msDS-User-Account-Control-Computed'
    $disabled = [bool]($uac -band $UAC.Disabled)
    $scril    = [bool]($uac -band $UAC.Scril)
    $pls      = [int64]$u.pwdLastSet
    $expiry   = ConvertFrom-FileTime $u.'msDS-UserPasswordExpiryTimeComputed'

    # Replication metadata (values are never read): origin heuristic + age of the secret.
    # The secret age comes from unicodePwd because toggling SCRIL can change the secret without updating pwdLastSet.
    $origin = 'unknown'; $secretAge = $null
    try {
        $mdAll = @(Get-ADReplicationAttributeMetadata -Object $u.DistinguishedName -Server $pdc)
        $md = $mdAll | Where-Object { $_.AttributeName -eq 'msDS-ExternalDirectoryObjectId' } | Select-Object -First 1
        if ($md -and $md.LastOriginatingChangeTime) {
            $origin = if ([Math]::Abs(($md.LastOriginatingChangeTime - $u.whenCreated).TotalMinutes) -le 10) { 'cloud-native' } else { 'SOA-converted' }
        }
        $sm = $mdAll | Where-Object { $_.AttributeName -eq 'unicodePwd' } | Select-Object -First 1
        if ($sm -and $sm.LastOriginatingChangeTime) { $secretAge = [int]((Get-Date) - $sm.LastOriginatingChangeTime).TotalDays }
    } catch { }
    if ($null -eq $secretAge -and $pls -gt 0) { $secretAge = [int]((Get-Date) - (ConvertFrom-FileTime $pls)).TotalDays }

    # Effective max password age (resultant PSO or domain default)
    $maxAge = $ddp.MaxPasswordAge
    if ($u.'msDS-ResultantPSO') {
        $k = "$($u.'msDS-ResultantPSO')"
        if (-not $psoAgeCache.ContainsKey($k)) { $psoAgeCache[$k] = (Get-ADFineGrainedPasswordPolicy -Identity $k -Server $pdc).MaxPasswordAge }
        $maxAge = $psoAgeCache[$k]
    }

    if ($disabled) {
        Add-Issue 'INFO' 'account disabled'
    } else {
        if (-not $scril) {
            if ($u.whenCreated -gt (Get-Date).AddMinutes(-2 * [int]$cfg.JobIntervalMinutes)) { Add-Issue 'WARN' 'SCRIL pending (new user, job not run yet)' }
            elseif (@($cfg.ScrilExclude) -contains $u.SamAccountName) { Add-Issue 'INFO' 'SCRIL excluded by config' }
            else { Add-Issue 'FAIL' 'SCRIL missing - password can expire and block passwordless logon' }
        }
        if (-not $u.'msDS-ObjectSoa') { Add-Issue 'WARN' 'not marked (msDS-ObjectSoa) - not protected by enforcement' }
        if ($ucc -band $UCC.Expired) { Add-Issue 'FAIL' 'PASSWORD EXPIRED flag set - WHfB/FIDO2 (Cloud Kerberos Trust) logon is blocked' }
        if ($pls -eq 0) { Add-Issue $(if ($scril) { 'WARN' } else { 'FAIL' }) "pwdLastSet=0 (must change)$(if ($scril) { ' - neutralized by SCRIL' })" }
        if ($ucc -band $UCC.Locked) { Add-Issue 'FAIL' 'LOCKED OUT - Kerberos logon blocked (unlock via job / wait for lockout duration)' }
        if ($uac -band $UAC.DontExpire) { Add-Issue 'INFO' "'password never expires' set" }
        if ($scril -and $null -ne $secretAge -and $secretAge -gt $secretWarnDays) { Add-Issue 'WARN' "secret $secretAge day(s) old - rotation not working?" }
        if ($scril -and -not ($uac -band $UAC.DontExpire) -and $rollingEffective -and $maxAge.TotalDays -gt 0 -and $pls -gt 0) {
            $window = (ConvertFrom-FileTime $pls) + $maxAge
            if ($window -lt (Get-Date).AddDays(7)) {
                Add-Issue 'WARN' "automatic rolling window (pwdLastSet + maxPwdAge) $(if ($window -lt (Get-Date)) { 'reached' } else { 'near' }): $window - behavior with Cloud Kerberos Trust unverified (Test-ScrilBehavior.ps1 Rolling phases)"
            }
        }
        if (-not $scril -and -not ($uac -band $UAC.DontExpire) -and $expiry -and $expiry -lt (Get-Date).AddDays(14)) { Add-Issue 'FAIL' "password expires $expiry" }
        if ($neverReveal.ContainsKey($u.DistinguishedName.ToLower())) { Add-Issue 'FAIL' "denied by AzureADKerberos password replication policy (group '$($neverReveal[$u.DistinguishedName.ToLower()])') - no Cloud Kerberos TGT" }
    }
    $uf = @($kerbFails | Where-Object { $_.User -eq $u.SamAccountName.ToLower() })
    foreach ($g in ($uf | Group-Object Status)) {
        $sev = if ($g.Name -in '0x17', '0x12') { 'FAIL' } elseif ($g.Name -eq '0x18') { 'WARN' } else { 'INFO' }
        $txt = 'Kerberos {0} {1} x{2} (last {3})' -f $g.Name, $KerbStatus[$g.Name], $g.Count, ($g.Group | Sort-Object Time -Descending | Select-Object -First 1).Time
        if ($g.Name -eq '0x18') { $txt += ' - password attempts against a passwordless account (spraying?)' }
        Add-Issue $sev $txt
    }

    $ll = if ($lastLogon.ContainsKey($u.SamAccountName.ToLower())) { $lastLogon[$u.SamAccountName.ToLower()] } else { $null }
    [pscustomobject]@{
        Status     = Get-Worst @($issues | ForEach-Object { $_.Status })
        User       = $u.SamAccountName
        Origin     = $origin
        Enabled    = -not $disabled
        SCRIL      = $scril
        Marked     = [bool]$u.'msDS-ObjectSoa'
        SecretAgeDays = $secretAge
        LastLogon  = $ll
        Issues     = (($issues | Where-Object { $_.Status -ne 'PASS' } | ForEach-Object { "[$($_.Status)] $($_.Text)" }) -join ' ; ')
    }
}
$userRows = @($userRows | Sort-Object @{ e = { $Severity[$_.Status] }; Descending = $true }, User)

$fu = @($userRows | Where-Object { $_.Status -eq 'FAIL' }).Count
$wu = @($userRows | Where-Object { $_.Status -eq 'WARN' }).Count
Add-Result 'Users' 'Provisioned users' $(if ($fu) { 'FAIL' } elseif ($wu) { 'WARN' } else { 'PASS' }) ("{0} user(s): {1} FAIL, {2} WARN, {3} without SCRIL" -f $userRows.Count, $fu, $wu, @($userRows | Where-Object { $_.Enabled -and -not $_.SCRIL }).Count)
#endregion

#region --- Validation test status (rollout step 6) ------------------------------------------------
$state = @(Get-TestState)
$shown = @($CoreTests) + @($AllTests | Where-Object { $name = $_; $CoreTests -notcontains $name -and @($state | Where-Object { $_.Test -eq $name }).Count })
foreach ($t in $shown) {
    $last = $state | Where-Object { $_.Test -eq $t } | Sort-Object Time -Descending | Select-Object -First 1
    if (-not $last) { Add-Result 'Validation tests' $t 'WARN' 'not run yet - Watch-CloudUserPasswordless.ps1 -Mode Test'; continue }
    $status = $last.Status
    $detail = "$($last.Time) (mode $($last.PolicyMode)): $($last.Detail)"
    if ($policyMode -and $last.PolicyMode -ne $policyMode -and $status -ne 'FAIL') { $status = 'WARN'; $detail = "run in mode $($last.PolicyMode), current mode $policyMode - repeat. " + $detail }
    Add-Result 'Validation tests' $t $status $detail
}
#endregion

#region --- Output ---------------------------------------------------------------------------------
Write-Section ("Result - {0} - policy mode {1}" -f $dnsRoot, $(if ($policyMode) { $policyMode } else { 'NONE' }))
foreach ($area in ($Results | Select-Object -ExpandProperty Area -Unique)) {
    Write-Host ''
    Write-Host $area -ForegroundColor Cyan
    foreach ($r in ($Results | Where-Object { $_.Area -eq $area })) {
        Write-Host ('  [{0}] {1,-34} {2}' -f $r.Status, $r.Item, $r.Detail) -ForegroundColor $Colors[$r.Status]
    }
}

Write-Section 'Provisioned users'
foreach ($u in $userRows) {
    Write-Host ('[{0}] {1,-22} {2,-14} SCRIL={3,-5} marked={4,-5} secret={5,4}d lastLogon={6}' -f $u.Status, $u.User, $u.Origin, $u.SCRIL, $u.Marked,
        $(if ($null -ne $u.SecretAgeDays) { $u.SecretAgeDays } else { '-' }), $(if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { '-' })) -ForegroundColor $Colors[$u.Status]
    if ($u.Issues) { Write-Host "      $($u.Issues)" -ForegroundColor $Colors[$u.Status] }
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmm'
$Results  | Export-Csv (Join-Path $OutputPath "monitor-checks_$stamp.csv") -NoTypeInformation -Encoding UTF8
$userRows | Export-Csv (Join-Path $OutputPath "monitor-users_$stamp.csv")  -NoTypeInformation -Encoding UTF8

$css = '<style>body{font-family:Calibri,Segoe UI,sans-serif;margin:24px;font-size:14px}h1,h2{color:#1f3864}' +
       'table{border-collapse:collapse;margin-bottom:22px}th{background:#1f3864;color:#fff;padding:6px 10px;text-align:left}' +
       'td{border:1px solid #c8c8c8;padding:4px 10px;vertical-align:top}.PASS{background:#d4edda}.WARN{background:#fff3cd}' +
       '.FAIL{background:#f8d7da}.INFO{background:#e7e9ec}</style>'
function ConvertTo-StatusHtml($Rows, [string[]]$Props) {
    $h = '<table><tr>' + (($Props | ForEach-Object { "<th>$_</th>" }) -join '') + '</tr>'
    foreach ($r in $Rows) {
        $h += "<tr class=`"$($r.Status)`">" + (($Props | ForEach-Object { '<td>{0}</td>' -f [Net.WebUtility]::HtmlEncode("$($r.$_)") }) -join '') + '</tr>'
    }
    $h + '</table>'
}
$overall = Get-Worst (@($Results | ForEach-Object { $_.Status }) + @($userRows | ForEach-Object { $_.Status }))
$body = @(
    "<h1>Passwordless sign-in readiness &ndash; $dnsRoot</h1>"
    "<p>Overall: <b>$overall</b> | Policy mode: <b>$policyMode</b> | Event window: ${EventHours} h | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>"
    '<h2>Checks</h2>'
    (ConvertTo-StatusHtml $Results @('Status', 'Area', 'Item', 'Detail'))
    '<h2>Provisioned users</h2>'
    (ConvertTo-StatusHtml $userRows @('Status', 'User', 'Origin', 'Enabled', 'SCRIL', 'Marked', 'SecretAgeDays', 'LastLogon', 'Issues'))
) -join "`n"
$htmlPath = Join-Path $OutputPath "monitor_$stamp.html"
ConvertTo-Html -Head $css -Body $body -Title 'Passwordless readiness' | Set-Content -Path $htmlPath -Encoding UTF8

Write-Host ''
Write-Host ("Overall: {0}   Report: {1}" -f $overall, $htmlPath) -ForegroundColor $Colors[$overall]
exit $Severity[$overall]
#endregion
