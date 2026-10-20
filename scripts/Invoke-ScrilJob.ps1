#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    SCRIL job for users provisioned by Entra Cloud Sync (Entra ID -> AD).
    Runs as the job gMSA, whose SID is in the SOA policy allow-list (msDS-Settings of CN=Cloud),
    so its writes pass AD object enforcement in Enforced mode.

.DESCRIPTION
    -Mode Enforce (scheduled, e.g. every 10 min)
        Sets "Smart card is required for interactive logon" (SCRIL) on every provisioned user
        (msDS-ExternalDirectoryObjectId=User_*) in TargetUserOUs that does not have it yet.
        Optional (config EnforceDenyChangePassword): explicit deny ACEs "User cannot change password".

    -Mode Rotate (scheduled, daily)
        Re-randomizes the secret of SCRIL users whose secret is older than RotationDays.
        The secret age is taken from the replication metadata of unicodePwd (metadata only, the value is
        never read) because pwdLastSet is not reliably updated when SCRIL is toggled.
        RotationMethod (config):
          Toggle       clear + re-set SCRIL
          RandomReset  reset the password to a random 120-character value generated in memory and discarded
          Auto         Toggle; if the unicodePwd metadata version did not change -> RandomReset (default)
        With -Identity only that user is rotated (regardless of age).

    -Mode Test -TestAction <action> -Identity <TestUser>
        Single controlled actions, ONLY allowed on the configured TestUser:
          ScrilOn, ScrilOff, ScrilRewrite (write the unchanged userAccountControl value again), Rotate,
          RandomReset, PneOn, PneOff (password never expires), DenyChangeOn, DenyChangeOff,
          MustChangeOn (pwdLastSet=0), MustChangeOff (pwdLastSet=-1), Unlock, ProbeWrite (write + clear 'info')

    Every run writes a log (JobDataPath\Logs) and a JSON status file:
        status-Enforce.json / status-Rotate.json / test-<TestAction>.json

.NOTES
    Toolkit: cloudsync-ad-enforcement-toolkit 1.0.0 (2026-10-19)
    All reads and writes go to the PDC emulator. Exit code 0 = success, 1 = at least one error.
#>
[CmdletBinding()]
param(
    [ValidateSet('Enforce', 'Rotate', 'Test')]
    [string] $Mode = 'Enforce',

    [ValidateSet('ScrilOn', 'ScrilOff', 'ScrilRewrite', 'Rotate', 'RandomReset', 'PneOn', 'PneOff',
                 'DenyChangeOn', 'DenyChangeOff', 'MustChangeOn', 'MustChangeOff', 'Unlock', 'ProbeWrite')]
    [string] $TestAction,

    [string] $Identity,

    [string] $ConfigPath = (Join-Path $PSScriptRoot 'SoaEnforcement.config.psd1')
)

$ErrorActionPreference = 'Stop'

$cfg     = Import-PowerShellDataFile -Path $ConfigPath
$pdc     = (Get-ADDomain).PDCEmulator
$logDir  = Join-Path $cfg.JobDataPath 'Logs'
New-Item -Path $logDir -ItemType Directory -Force | Out-Null
$logFile = Join-Path $logDir ('{0}_{1:yyyyMMdd}.log' -f $Mode, (Get-Date))
$SCRIL   = 0x40000
$rotationMethod = if ($cfg.RotationMethod) { $cfg.RotationMethod } else { 'Auto' }

# AD: drive bound to the PDC emulator (ACL reads/writes must hit the same DC as all other operations)
if (-not (Get-PSDrive -Name SOAAD -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name SOAAD -PSProvider ActiveDirectory -Root '//RootDSE/' -Server $pdc -Scope Script | Out-Null
}

$status = [ordered]@{
    Mode       = $Mode
    TestAction = $TestAction
    Identity   = $Identity
    RunAs      = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Server     = $pdc
    Start      = (Get-Date).ToString('s')
    End        = $null
    Candidates = 0
    Changed    = 0
    Success    = $false
    Errors     = @()
    Details    = @()
    Before     = $null
    After      = $null
}

#region --- Helpers --------------------------------------------------------------------------------
function Write-Log([string]$Message, [string]$Level = 'INFO') {
    Add-Content -Path $logFile -Value ('{0:s} [{1}] {2}' -f (Get-Date), $Level, $Message) -Encoding UTF8
    if ($Level -eq 'ERROR') { $script:status.Errors += $Message } else { $script:status.Details += $Message }
}

# Replication metadata of the secret (metadata only - the attribute value itself is never readable)
function Get-SecretMeta([string]$Dn) {
    $md = @(Get-ADReplicationAttributeMetadata -Object $Dn -Server $pdc)
    $u  = $md | Where-Object { $_.AttributeName -eq 'unicodePwd' } | Select-Object -First 1
    [pscustomobject]@{
        Version = $(if ($u) { [int]$u.Version } else { 0 })
        Time    = $(if ($u) { $u.LastOriginatingChangeTime } else { $null })
        Origin  = $(if ($u -and $u.LastOriginatingChangeDirectoryServerIdentity -match 'CN=NTDS Settings,CN=([^,]+)') { $Matches[1] } else { $null })
    }
}

function Get-UserState([string]$Dn) {
    $u = Get-ADUser -Identity $Dn -Server $pdc -Properties userAccountControl, pwdLastSet, lockoutTime, badPwdCount, info,
                    'msDS-User-Account-Control-Computed', 'msDS-UserPasswordExpiryTimeComputed'
    $s = Get-SecretMeta $Dn
    [ordered]@{
        UserAccountControl = $u.userAccountControl
        Scril              = [bool]($u.userAccountControl -band $SCRIL)
        PasswordNeverExp   = [bool]($u.userAccountControl -band 0x10000)
        PwdLastSet         = $u.pwdLastSet
        SecretVersion      = $s.Version
        SecretChanged      = $(if ($s.Time) { $s.Time.ToString('s') } else { $null })
        SecretOrigin       = $s.Origin
        LockoutTime        = $u.lockoutTime
        BadPwdCount        = $u.badPwdCount
        UacComputed        = $u.'msDS-User-Account-Control-Computed'
        ExpiryComputed     = $u.'msDS-UserPasswordExpiryTimeComputed'
        Info               = $u.info
    }
}

function Set-ScrilWithRetry([string]$Dn, [bool]$Value) {
    for ($i = 1; $i -le 3; $i++) {
        try { Set-ADUser -Identity $Dn -Server $pdc -SmartcardLogonRequired $Value; return }
        catch { if ($i -eq 3) { throw }; Start-Sleep -Seconds (2 * $i) }
    }
}

# 120 random characters incl. all four character classes; generated in memory and discarded
function New-RandomSecret {
    $sets = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#%+-=?@_~'
    $all  = -join $sets
    $rng  = [Security.Cryptography.RandomNumberGenerator]::Create()
    $buf  = New-Object byte[] 4
    $pick = { param($s) $rng.GetBytes($buf); $s[[BitConverter]::ToUInt32($buf, 0) % $s.Length] }
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($s in $sets) { $chars.Add((& $pick $s)) }
    while ($chars.Count -lt 120) { $chars.Add((& $pick $all)) }
    $sec = New-Object Security.SecureString
    foreach ($c in ($chars | Sort-Object { $rng.GetBytes($buf); [BitConverter]::ToUInt32($buf, 0) })) { $sec.AppendChar($c) }
    $sec.MakeReadOnly()
    $sec
}

function Invoke-RandomReset([string]$Dn) {
    Set-ADAccountPassword -Identity $Dn -Server $pdc -Reset -NewPassword (New-RandomSecret)
}

# Rotation according to RotationMethod; verified via the unicodePwd metadata version
function Invoke-SecretRotation([string]$Dn) {
    $before = Get-SecretMeta $Dn
    $used   = $rotationMethod
    if ($rotationMethod -in 'Toggle', 'Auto') {
        Set-ScrilWithRetry $Dn $false
        try   { Set-ScrilWithRetry $Dn $true }
        catch { Write-Log "CRITICAL: SCRIL could not be re-enabled on $Dn - $($_.Exception.Message)" 'ERROR'; throw }
        $after = Get-SecretMeta $Dn
        if ($after.Version -gt $before.Version) { return "Toggle (secret version $($before.Version) -> $($after.Version))" }
        if ($rotationMethod -eq 'Toggle') { Write-Log "Toggle did not change the secret of $Dn (version $($before.Version))" 'ERROR'; return 'Toggle (no change)' }
        $used = 'RandomReset (fallback - toggle did not change the secret)'
    }
    Invoke-RandomReset $Dn
    if (-not ((Get-ADUser -Identity $Dn -Server $pdc -Properties userAccountControl).userAccountControl -band $SCRIL)) { Set-ScrilWithRetry $Dn $true }
    $after = Get-SecretMeta $Dn
    if ($after.Version -le $before.Version) { Write-Log "Secret of $Dn unchanged after $used" 'ERROR' }
    "$used (secret version $($before.Version) -> $($after.Version))"
}

$ChangePwdRight = [Guid]'ab721a53-1e2f-11d0-9819-00aa0040529b'
$DenySids = 'S-1-1-0', 'S-1-5-10'   # Everyone, SELF

# Explicit deny ACEs for the "Change Password" extended right = "User cannot change password"
function Set-DenyChangePassword([string]$Dn) {
    $path    = "SOAAD:\$Dn"
    $acl     = Get-Acl -Path $path
    $rules   = $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])
    $changed = $false
    foreach ($sidText in $DenySids) {
        $sid = [Security.Principal.SecurityIdentifier]$sidText
        $has = $rules | Where-Object { $_.IdentityReference -eq $sid -and "$($_.AccessControlType)" -eq 'Deny' -and $_.ObjectType -eq $ChangePwdRight }
        if (-not $has) {
            $acl.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Deny', $ChangePwdRight)))
            $changed = $true
        }
    }
    if ($changed) { Set-Acl -Path $path -AclObject $acl }
    $changed
}

function Remove-DenyChangePassword([string]$Dn) {
    $path    = "SOAAD:\$Dn"
    $acl     = Get-Acl -Path $path
    $changed = $false
    foreach ($r in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
        if ("$($r.AccessControlType)" -eq 'Deny' -and $r.ObjectType -eq $ChangePwdRight -and $DenySids -contains $r.IdentityReference.Value) {
            [void]$acl.RemoveAccessRuleSpecific($r); $changed = $true
        }
    }
    if ($changed) { Set-Acl -Path $path -AclObject $acl }
    $changed
}

function Get-ProvisionedUsers([string]$ExtraFilter) {
    foreach ($ou in $cfg.TargetUserOUs) {
        Get-ADUser -Server $pdc -SearchBase $ou -ResultPageSize 500 -Properties pwdLastSet, userAccountControl `
                   -LDAPFilter "(&(objectCategory=person)(objectClass=user)(msDS-ExternalDirectoryObjectId=User_*)$ExtraFilter)"
    }
}
#endregion

try {
    Write-Log "Run started as $($status.RunAs) against $pdc (mode $Mode $TestAction $Identity, rotation method $rotationMethod)"

    switch ($Mode) {

        'Enforce' {
            $users = @(Get-ProvisionedUsers '(!(userAccountControl:1.2.840.113556.1.4.803:=262144))' |
                       Where-Object { @($cfg.ScrilExclude) -notcontains $_.SamAccountName })
            $status.Candidates = $users.Count
            foreach ($u in $users) {
                try {
                    $before = Get-SecretMeta $u.DistinguishedName
                    Set-ScrilWithRetry $u.DistinguishedName $true
                    $status.Changed++
                    $after = Get-SecretMeta $u.DistinguishedName
                    if ($after.Version -gt $before.Version) {
                        Write-Log "SCRIL set: $($u.SamAccountName) (secret re-randomized by the DC)"
                    } else {
                        # SCRIL alone did not randomize the secret -> make sure no known password remains
                        Invoke-RandomReset $u.DistinguishedName
                        Write-Log "SCRIL set: $($u.SamAccountName) (secret unchanged by SCRIL -> random reset applied)"
                    }
                } catch { Write-Log "SCRIL FAILED: $($u.SamAccountName) - $($_.Exception.Message)" 'ERROR' }
            }
            if ($cfg.EnforceDenyChangePassword) {
                foreach ($u in @(Get-ProvisionedUsers '')) {
                    try   { if (Set-DenyChangePassword $u.DistinguishedName) { Write-Log "Deny 'change password' ACEs set: $($u.SamAccountName)" } }
                    catch { Write-Log "Deny ACE FAILED: $($u.SamAccountName) - $($_.Exception.Message)" 'ERROR' }
                }
            }
        }

        'Rotate' {
            if ($Identity) {
                $users = @(Get-ADUser -Identity $Identity -Server $pdc)
            } else {
                $cut   = (Get-Date).AddDays(-[int]$cfg.RotationDays)
                $users = @(Get-ProvisionedUsers '(userAccountControl:1.2.840.113556.1.4.803:=262144)' | Where-Object {
                    $m = Get-SecretMeta $_.DistinguishedName
                    (-not $m.Time) -or ($m.Time -lt $cut)
                })
            }
            $status.Candidates = $users.Count
            foreach ($u in $users) {
                try   { $how = Invoke-SecretRotation $u.DistinguishedName; $status.Changed++; Write-Log "Secret rotated: $($u.SamAccountName) via $how" }
                catch { Write-Log "ROTATION FAILED: $($u.SamAccountName) - $($_.Exception.Message)" 'ERROR' }
            }
        }

        'Test' {
            if (-not $TestAction) { throw '-TestAction is required in Test mode.' }
            if (-not $Identity -or $Identity -ne $cfg.TestUser) { throw "Test actions are only allowed on the configured TestUser '$($cfg.TestUser)'." }
            $u = Get-ADUser -Identity $Identity -Server $pdc -Properties 'msDS-ExternalDirectoryObjectId', userAccountControl
            if ("$($u.'msDS-ExternalDirectoryObjectId')" -notlike 'User_*') { throw "TestUser '$Identity' is not provisioned by Cloud Sync." }
            $dn = $u.DistinguishedName
            $status.Candidates = 1
            $status.Before = Get-UserState $dn
            switch ($TestAction) {
                'ScrilOn'       { Set-ScrilWithRetry $dn $true }
                'ScrilOff'      { Set-ScrilWithRetry $dn $false }
                'ScrilRewrite'  { Set-ADUser -Identity $dn -Server $pdc -Replace @{ userAccountControl = [int]$u.userAccountControl } }
                'Rotate'        { Write-Log ("Rotation via {0}" -f (Invoke-SecretRotation $dn)) }
                'RandomReset'   { Invoke-RandomReset $dn }
                'PneOn'         { Set-ADUser -Identity $dn -Server $pdc -PasswordNeverExpires $true }
                'PneOff'        { Set-ADUser -Identity $dn -Server $pdc -PasswordNeverExpires $false }
                'DenyChangeOn'  { [void](Set-DenyChangePassword $dn) }
                'DenyChangeOff' { [void](Remove-DenyChangePassword $dn) }
                'MustChangeOn'  { Set-ADUser -Identity $dn -Server $pdc -Replace @{ pwdLastSet = 0 } }
                'MustChangeOff' { Set-ADUser -Identity $dn -Server $pdc -Replace @{ pwdLastSet = -1 } }
                'Unlock'        { Unlock-ADAccount -Identity $dn -Server $pdc }
                'ProbeWrite'    {
                    Set-ADUser -Identity $dn -Server $pdc -Replace @{ info = "SOA allow-list probe $(Get-Date -Format s)" }
                    Set-ADUser -Identity $dn -Server $pdc -Clear info
                }
            }
            $status.Changed = 1
            $status.After = Get-UserState $dn
            Write-Log "Test action $TestAction on $Identity completed"
        }
    }
    $status.Success = (@($status.Errors).Count -eq 0)
} catch {
    Write-Log "Run failed: $($_.Exception.Message)" 'ERROR'
    $status.Success = $false
} finally {
    $status.End = (Get-Date).ToString('s')
    $file = if ($Mode -eq 'Test') { "test-$TestAction.json" } else { "status-$Mode.json" }
    [pscustomobject]$status | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $cfg.JobDataPath $file) -Encoding UTF8
    Write-Log ("Run finished: success={0}, candidates={1}, changed={2}, errors={3}" -f $status.Success, $status.Candidates, $status.Changed, @($status.Errors).Count)
}

if (-not $status.Success) { exit 1 }
exit 0
