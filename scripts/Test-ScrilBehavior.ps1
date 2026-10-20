#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Measures how SCRIL ("Smart card is required for interactive logon"), "password never expires",
    "user cannot change password", SCRIL toggling, random resets, automatic secret rolling and maxPwdAge
    actually behave in THIS domain, and collects all results in one repeatable, structured report.

.DESCRIPTION
    All checks use documented LDAP administration (Get-/Set-ADUser, Set-ADAccountPassword -Reset,
    fine-grained password policies, ACLs) and read-only replication metadata. Secret values are never read:
    whether a secret changed is derived from the replication metadata version of unicodePwd.

    -Phase Inventory (default, read-only)
        Domain: functional level, msDS-ExpirePasswordsOnSmartCardOnlyAccounts (automatic rolling),
        default maxPwdAge, fine-grained password policies, RotationDays/RotationMethod of the SCRIL job.
        Every provisioned user: SCRIL, PNE, deny-change ACEs, marked, pwdLastSet vs. last secret change
        (originating DC), computed expiry, PE flag, effective maxPwdAge, rolling eligibility and rolling window.

    -Phase UiObserve [-Identity <user>] (read-only)
        Snapshot of a user on every writable DC, then YOU make a change in ADUC/ADAC (e.g. tick SCRIL + Apply),
        then a second snapshot. Shows exactly what changed on which DC (userAccountControl, pwdLastSet,
        secret metadata version, originating DC) - explains observations like "pwdLastSet did not change".

    -Phase Matrix (writes ONLY to the configured TestUser)
        Runs a defined sequence and measures before/after each step:
          SCRIL off->on | SCRIL rewrite (unchanged value) | SCRIL on->off | off->on | random reset |
          PNE on + toggle | PNE off | deny-change ACE on + toggle | restore
        and derives answers (does SCRIL set randomize? update pwdLastSet? set PNE? does clearing randomize?
        does PNE / deny-change change anything? computed expiry / PE with and without PNE?) plus a
        recommendation for RotationMethod.

    -Phase RollingPrepare / RollingObserve / RollingCleanup (TestUser only)
        Observes automatic rolling: a temporary fine-grained password policy with a short max password age
        (RollingTestMinutes) is applied to the TestUser only; after expiry you sign in passwordless
        (WHfB / FIDO2 via Cloud Kerberos Trust, AVD RemoteApp SSO, access to an AD file share);
        the script records whether the sign-in was recorded, whether a DC rolled the secret (and which DC),
        and asks whether the sign-in succeeded. Cleanup removes the policy and restores a fresh secret.

    -Phase Report
        Rebuilds the consolidated HTML report from all stored findings.

    Write path (-WriteVia): Direct = as the current user; Job = as the allow-listed job gMSA via a temporary
    scheduled task on JobHost running Invoke-ScrilJob.ps1 -Mode Test (needs the current job script version);
    Auto = Job when the SOA policy is Enforced, the TestUser is marked and you are not allow-listed.

    Output: console + ReportPath\ScrilBehavior\scril-findings.json (latest result per phase) + scril-report.html

.NOTES
    Toolkit: cloudsync-ad-enforcement-toolkit 1.0.0 (2026-10-19)
    Run as Domain Admin from a host with RSAT (ActiveDirectory). WinRM to JobHost only for -WriteVia Job.
#>
[CmdletBinding()]
param(
    [ValidateSet('Inventory', 'UiObserve', 'Matrix', 'RollingPrepare', 'RollingObserve', 'RollingCleanup', 'Report')]
    [string] $Phase = 'Inventory',

    [ValidateSet('Auto', 'Direct', 'Job')]
    [string] $WriteVia = 'Auto',

    [string] $Identity,

    [int] $WaitMinutes = 15,

    [switch] $WaitForExpiry,

    [string] $ConfigPath = (Join-Path $PSScriptRoot 'SoaEnforcement.config.psd1'),

    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'

#region --- Context --------------------------------------------------------------------------------
$cfg = Import-PowerShellDataFile -Path $ConfigPath
if (-not $OutputPath) { $OutputPath = Join-Path $cfg.ReportPath 'ScrilBehavior' }
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
$findingsPath = Join-Path $OutputPath 'scril-findings.json'
$baselinePath = Join-Path $OutputPath 'rolling-baseline.json'
$reportPath   = Join-Path $OutputPath 'scril-report.html'

$domain   = Get-ADDomain
$pdc      = $domain.PDCEmulator
$netbios  = $domain.NetBIOSName
$domainDN = $domain.DistinguishedName
$policyDN = "CN=Cloud,CN=SOA-Policies,CN=System,$domainDN"
$dcs      = @(Get-ADDomainController -Filter * -Server $pdc | Where-Object { -not $_.IsReadOnly } | Sort-Object HostName | ForEach-Object { $_.HostName })
$TaskPath = '\SoaEnforcement\'

$UAC = @{ Disabled = 0x2; DontExpire = 0x10000; Scril = 0x40000 }
$UCC = @{ Locked = 0x10; Expired = 0x800000 }
$ChangePwdRight = [Guid]'ab721a53-1e2f-11d0-9819-00aa0040529b'
$DenySids = 'S-1-1-0', 'S-1-5-10'   # Everyone, SELF
$Colors   = @{ PASS = 'Green'; INFO = 'Gray'; WARN = 'Yellow'; FAIL = 'Red' }

if (-not (Get-PSDrive -Name SOAAD -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name SOAAD -PSProvider ActiveDirectory -Root '//RootDSE/' -Server $pdc -Scope Script | Out-Null
}
#endregion

#region --- Helpers: formatting / persistence ------------------------------------------------------
function Write-Section([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 100) -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 100) -ForegroundColor DarkCyan
}

function ConvertFrom-FileTime($Value) {
    if ($null -eq $Value) { return $null }
    $i = [int64]$Value
    if ($i -le 0 -or $i -ge [int64]::MaxValue) { return $null }
    try { [datetime]::FromFileTime($i) } catch { $null }
}

function Format-Time($Value) { if ($Value) { ([datetime]$Value).ToString('yyyy-MM-dd HH:mm:ss') } else { '-' } }

function Format-Expiry($Raw) {
    if ($null -eq $Raw) { return 'n/a' }
    $i = [int64]$Raw
    if ($i -ge [int64]::MaxValue) { return 'never' }
    if ($i -eq 0) { return '0 (expired / must change)' }
    Format-Time (ConvertFrom-FileTime $i)
}

function Get-YesNo($Value) { if ($null -eq $Value) { 'n/a' } elseif ($Value) { 'YES' } else { 'no' } }

function Get-ServerName([string]$NtdsDn) { if ($NtdsDn -match 'CN=NTDS Settings,CN=([^,]+)') { $Matches[1] } else { $NtdsDn } }

function Save-Finding([string]$Key, $Object) {
    $all = [ordered]@{}
    if (Test-Path -Path $findingsPath) {
        $j = Get-Content -Path $findingsPath -Raw | ConvertFrom-Json
        foreach ($p in $j.PSObject.Properties) { $all[$p.Name] = $p.Value }
    }
    $all[$Key] = $Object
    [pscustomobject]$all | ConvertTo-Json -Depth 8 | Set-Content -Path $findingsPath -Encoding UTF8
}

function New-Finding([string]$Title, [string[]]$Summary, $Tables) {
    [pscustomobject]@{ Time = (Get-Date).ToString('s'); Title = $Title; Summary = @($Summary); Tables = $Tables }
}

function Write-Report {
    if (-not (Test-Path -Path $findingsPath)) { return }
    $j   = Get-Content -Path $findingsPath -Raw | ConvertFrom-Json
    $css = '<style>body{font-family:Calibri,Segoe UI,sans-serif;margin:24px;font-size:14px;color:#1b1b1b}h1,h2,h3{color:#1f3864}' +
           'table{border-collapse:collapse;margin-bottom:20px}th{background:#1f3864;color:#fff;padding:6px 9px;text-align:left}' +
           'td{border:1px solid #c8c8c8;padding:4px 9px;vertical-align:top}.box{border-left:4px solid #1f3864;background:#eef2f8;padding:8px 14px;margin:8px 0 16px}</style>'
    $order = 'Inventory', 'Matrix', 'Rolling'
    $keys  = @($order | Where-Object { $j.PSObject.Properties.Name -contains $_ }) +
             @($j.PSObject.Properties.Name | Where-Object { $order -notcontains $_ } | Sort-Object -Descending)
    $body = New-Object System.Text.StringBuilder
    [void]$body.Append("<h1>SCRIL behavior &ndash; $($domain.DNSRoot)</h1><p>Report generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>")
    foreach ($k in $keys) {
        $f = $j.$k
        [void]$body.Append("<h2>$([Net.WebUtility]::HtmlEncode($f.Title))</h2><p>Recorded: $($f.Time)</p><div class='box'>")
        foreach ($s in @($f.Summary)) { [void]$body.Append("<div>$([Net.WebUtility]::HtmlEncode($s))</div>") }
        [void]$body.Append('</div>')
        if ($f.Tables) {
            foreach ($t in $f.Tables.PSObject.Properties) {
                $rows = @($t.Value)
                if (-not $rows.Count) { continue }
                [void]$body.Append("<h3>$([Net.WebUtility]::HtmlEncode($t.Name))</h3>")
                [void]$body.Append((($rows | ConvertTo-Html -Fragment) -join "`n"))
            }
        }
    }
    ConvertTo-Html -Head $css -Body $body.ToString() -Title 'SCRIL behavior' | Set-Content -Path $reportPath -Encoding UTF8
    Write-Host "Report: $reportPath" -ForegroundColor Cyan
}
#endregion

#region --- Helpers: directory state ---------------------------------------------------------------
# Replication metadata of the password-related attributes (metadata only, values are never read)
function Get-SecretMeta([string]$Dn, [string]$Server = $pdc) {
    $md  = @(Get-ADReplicationAttributeMetadata -Object $Dn -Server $Server)
    $u   = $md | Where-Object { $_.AttributeName -eq 'unicodePwd' } | Select-Object -First 1
    $p   = $md | Where-Object { $_.AttributeName -eq 'pwdLastSet' } | Select-Object -First 1
    $a   = $md | Where-Object { $_.AttributeName -eq 'userAccountControl' } | Select-Object -First 1
    [pscustomobject]@{
        SecretVersion     = $(if ($u) { [int]$u.Version } else { 0 })
        SecretTime        = $(if ($u) { $u.LastOriginatingChangeTime } else { $null })
        SecretOrigin      = $(if ($u) { Get-ServerName $u.LastOriginatingChangeDirectoryServerIdentity } else { $null })
        PwdLastSetVersion = $(if ($p) { [int]$p.Version } else { 0 })
        UacVersion        = $(if ($a) { [int]$a.Version } else { 0 })
        UacOrigin         = $(if ($a) { Get-ServerName $a.LastOriginatingChangeDirectoryServerIdentity } else { $null })
    }
}

function Get-DenyChangeState([string]$Dn) {
    $acl   = Get-Acl -Path "SOAAD:\$Dn"
    $rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object {
        "$($_.AccessControlType)" -eq 'Deny' -and $_.ObjectType -eq $ChangePwdRight -and $DenySids -contains $_.IdentityReference.Value })
    ($rules.Count -ge 2)
}

function Get-Snapshot([string]$Dn, [string]$Server = $pdc, [switch]$IncludeAcl) {
    $u = Get-ADUser -Identity $Dn -Server $Server -Properties userAccountControl, 'msDS-User-Account-Control-Computed',
         'msDS-UserPasswordExpiryTimeComputed', pwdLastSet, 'msDS-ResultantPSO', 'msDS-ObjectSoa', whenChanged, whenCreated, Enabled
    $m = Get-SecretMeta $Dn $Server
    [pscustomobject]@{
        Server        = $Server
        Sam           = $u.SamAccountName
        Uac           = [int]$u.userAccountControl
        Scril         = [bool]($u.userAccountControl -band $UAC.Scril)
        Pne           = [bool]($u.userAccountControl -band $UAC.DontExpire)
        Enabled       = -not [bool]($u.userAccountControl -band $UAC.Disabled)
        PeFlag        = [bool]($u.'msDS-User-Account-Control-Computed' -band $UCC.Expired)
        Locked        = [bool]($u.'msDS-User-Account-Control-Computed' -band $UCC.Locked)
        PwdLastSetRaw = [int64]$u.pwdLastSet
        PwdLastSet    = ConvertFrom-FileTime $u.pwdLastSet
        ExpiryRaw     = $u.'msDS-UserPasswordExpiryTimeComputed'
        ResultantPso  = $u.'msDS-ResultantPSO'
        Marked        = [bool]$u.'msDS-ObjectSoa'
        SecretVersion = $m.SecretVersion
        SecretTime    = $m.SecretTime
        SecretOrigin  = $m.SecretOrigin
        UacVersion    = $m.UacVersion
        UacOrigin     = $m.UacOrigin
        DenyChange    = $(if ($IncludeAcl) { Get-DenyChangeState $Dn } else { $null })
        WhenChanged   = $u.whenChanged
        WhenCreated   = $u.whenCreated
    }
}

function Get-DomainScrilConfig {
    $root = Get-ADObject -Identity $domainDN -Server $pdc -Properties 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts', 'msDS-Behavior-Version'
    $dfl  = [int]$root.'msDS-Behavior-Version'
    $roll = $root.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'
    $ddp  = Get-ADDefaultDomainPasswordPolicy -Server $pdc
    $psos = @(Get-ADFineGrainedPasswordPolicy -Filter * -Server $pdc -Properties AppliesTo | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name; Precedence = $_.Precedence; MaxPasswordAge = $_.MaxPasswordAge; MinPasswordAge = $_.MinPasswordAge
            LockoutThreshold = $_.LockoutThreshold
            AppliesTo = (@($_.AppliesTo | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join ', ')
        }
    })
    [pscustomobject]@{
        DomainMode       = "$($domain.DomainMode)"
        Dfl              = $dfl
        RollingAttribute = $(if ($null -eq $roll) { 'not set' } else { "$([bool]$roll)" })
        RollingEffective = (($roll -eq $true) -and ($dfl -ge 7))
        DefaultMaxPwdAge = $ddp.MaxPasswordAge
        DefaultMinPwdAge = $ddp.MinPasswordAge
        Psos             = $psos
    }
}

$psoCache = @{}
function Get-EffectiveMaxAge($Snapshot, $DomainCfg) {
    if (-not $Snapshot.ResultantPso) { return $DomainCfg.DefaultMaxPwdAge }
    $k = "$($Snapshot.ResultantPso)"
    if (-not $psoCache.ContainsKey($k)) { $psoCache[$k] = (Get-ADFineGrainedPasswordPolicy -Identity $k -Server $pdc).MaxPasswordAge }
    $psoCache[$k]
}

function Get-LastLogonMax([string]$Dn) {
    $max = $null
    foreach ($dc in $dcs) {
        try {
            $t = ConvertFrom-FileTime (Get-ADUser -Identity $Dn -Server $dc -Properties lastLogon).lastLogon
            if ($t -and (-not $max -or $t -gt $max)) { $max = $t }
        } catch { }
    }
    $max
}

function Get-SecretAllDcs([string]$Dn) {
    foreach ($dc in $dcs) {
        try {
            $m = Get-SecretMeta $Dn $dc
            [pscustomobject]@{ DC = ($dc -split '\.')[0]; Version = $m.SecretVersion; Time = Format-Time $m.SecretTime; Origin = $m.SecretOrigin }
        } catch { [pscustomobject]@{ DC = ($dc -split '\.')[0]; Version = $null; Time = $null; Origin = "error: $($_.Exception.Message)" } }
    }
}

function Get-TestUser {
    $sam = if ($Identity) { $Identity } else { $cfg.TestUser }
    if ($sam -ne $cfg.TestUser) { throw "Phase $Phase writes to the user and is only allowed on the configured TestUser '$($cfg.TestUser)'." }
    $u = Get-ADUser -Identity $sam -Server $pdc -Properties 'msDS-ExternalDirectoryObjectId'
    if ("$($u.'msDS-ExternalDirectoryObjectId')" -notlike 'User_*') { throw "TestUser '$sam' is not provisioned by Cloud Sync." }
    $u
}
#endregion

#region --- Helpers: write path --------------------------------------------------------------------
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

function Set-DenyChange([string]$Dn, [bool]$Present) {
    $path = "SOAAD:\$Dn"
    $acl  = Get-Acl -Path $path
    $changed = $false
    if ($Present) {
        $rules = $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])
        foreach ($s in $DenySids) {
            $sid = [Security.Principal.SecurityIdentifier]$s
            if (-not ($rules | Where-Object { $_.IdentityReference -eq $sid -and "$($_.AccessControlType)" -eq 'Deny' -and $_.ObjectType -eq $ChangePwdRight })) {
                $acl.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Deny', $ChangePwdRight))); $changed = $true
            }
        }
    } else {
        foreach ($r in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
            if ("$($r.AccessControlType)" -eq 'Deny' -and $r.ObjectType -eq $ChangePwdRight -and $DenySids -contains $r.IdentityReference.Value) {
                [void]$acl.RemoveAccessRuleSpecific($r); $changed = $true
            }
        }
    }
    if ($changed) { Set-Acl -Path $path -AclObject $acl }
}

function Resolve-WriteVia($Snapshot) {
    if ($WriteVia -ne 'Auto') { return $WriteVia }
    $p = $null
    try { $p = Get-ADObject -Identity $policyDN -Server $pdc -Properties keywords, 'msDS-Settings' } catch { }
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($p -and (@($p.keywords) -join ',') -eq 'Enforced' -and $Snapshot.Marked -and (@($p.'msDS-Settings' | ForEach-Object { "$_" }) -notcontains $me)) { 'Job' } else { 'Direct' }
}

function Invoke-AsJob([string]$Arguments, [string]$ResultFile, [int]$TimeoutMinutes = 5) {
    $gmsaUser = '{0}\{1}$' -f $netbios, $cfg.JobGmsaName
    $r = Invoke-Command -ComputerName $cfg.JobHost `
        -ArgumentList $cfg.JobScriptPath, $Arguments, $gmsaUser, $cfg.JobDataPath, $ResultFile, $TimeoutMinutes, $TaskPath `
        -ScriptBlock {
            param($ScriptPath, $Arguments, $User, $DataPath, $ResultFile, $Timeout, $TaskPath)
            $resultPath = Join-Path $DataPath $ResultFile
            Remove-Item -Path $resultPath -Force -ErrorAction SilentlyContinue
            $name      = 'ScrilTest-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" {1}' -f $ScriptPath, $Arguments)
            $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Password
            Register-ScheduledTask -TaskName $name -TaskPath $TaskPath -Action $action -Principal $principal | Out-Null
            try {
                Start-ScheduledTask -TaskName $name -TaskPath $TaskPath
                $deadline = (Get-Date).AddMinutes($Timeout)
                do { Start-Sleep -Seconds 3; $done = Test-Path -Path $resultPath } while (-not $done -and (Get-Date) -lt $deadline)
                Start-Sleep -Seconds 1
                [pscustomobject]@{ Finished = $done; Json = $(if ($done) { Get-Content -Path $resultPath -Raw } else { $null }) }
            } finally {
                Unregister-ScheduledTask -TaskName $name -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    $parsed = if ($r.Json) { $r.Json | ConvertFrom-Json } else { $null }
    [pscustomobject]@{
        Success = [bool]($parsed -and $parsed.Success)
        Errors  = $(if ($parsed) { @($parsed.Errors) -join '; ' } else { 'no result file (task did not finish / job script outdated?)' })
    }
}

function Invoke-TestAction([string]$Action, [string]$Dn, [string]$Sam, [string]$Via) {
    try {
        if ($Via -eq 'Job') {
            $r = Invoke-AsJob -Arguments "-Mode Test -TestAction $Action -Identity $Sam" -ResultFile "test-$Action.json"
            return [pscustomobject]@{ Accepted = $r.Success; Error = $(if (-not $r.Success) { $r.Errors } else { $null }) }
        }
        switch ($Action) {
            'ScrilOn'       { Set-ADUser -Identity $Dn -Server $pdc -SmartcardLogonRequired $true }
            'ScrilOff'      { Set-ADUser -Identity $Dn -Server $pdc -SmartcardLogonRequired $false }
            'ScrilRewrite'  {
                $v = (Get-ADUser -Identity $Dn -Server $pdc -Properties userAccountControl).userAccountControl
                Set-ADUser -Identity $Dn -Server $pdc -Replace @{ userAccountControl = [int]$v }
            }
            'RandomReset'   { Set-ADAccountPassword -Identity $Dn -Server $pdc -Reset -NewPassword (New-RandomSecret) }
            'PneOn'         { Set-ADUser -Identity $Dn -Server $pdc -PasswordNeverExpires $true }
            'PneOff'        { Set-ADUser -Identity $Dn -Server $pdc -PasswordNeverExpires $false }
            'DenyChangeOn'  { Set-DenyChange $Dn $true }
            'DenyChangeOff' { Set-DenyChange $Dn $false }
            default         { throw "Unknown action $Action" }
        }
        [pscustomobject]@{ Accepted = $true; Error = $null }
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        [pscustomobject]@{ Accepted = $false; Error = $e.Message }
    }
}
#endregion

#==================================================================================================
switch ($Phase) {

    #----------------------------------------------------------------------------------------------
    'Inventory' {
        Write-Section 'Inventory: domain configuration'
        $dc = Get-DomainScrilConfig
        $maxDays = [int]$dc.DefaultMaxPwdAge.TotalDays
        $summary = @(
            "Domain functional level: $($dc.DomainMode) (msDS-Behavior-Version $($dc.Dfl); automatic rolling needs >= 7 = Windows Server 2016)"
            "msDS-ExpirePasswordsOnSmartCardOnlyAccounts: $($dc.RollingAttribute) -> automatic rolling $(if ($dc.RollingEffective) { 'ENABLED' } else { 'DISABLED' })"
            "Default domain maxPwdAge: $(if ($maxDays -gt 0) { "$maxDays day(s)" } else { 'never expires (0)' }); minPwdAge: $([int]$dc.DefaultMinPwdAge.TotalDays) day(s)"
            "Fine-grained password policies: $(if ($dc.Psos.Count) { ($dc.Psos | ForEach-Object { "$($_.Name) (prec $($_.Precedence), max $($_.MaxPasswordAge), applies to: $($_.AppliesTo))" }) -join ' | ' } else { 'none' })"
            "SCRIL job: RotationDays $($cfg.RotationDays), RotationMethod $(if ($cfg.RotationMethod) { $cfg.RotationMethod } else { 'Auto' })"
        )
        if ($dc.RollingEffective -and $maxDays -gt 0) {
            if ([int]$cfg.RotationDays -ge $maxDays) {
                $summary += "WARN: RotationDays ($($cfg.RotationDays)) >= maxPwdAge ($maxDays) - automatic rolling becomes due before the job rotates."
            } else {
                $summary += "OK: RotationDays < maxPwdAge - but only if the rotation also moves pwdLastSet (see Matrix: toggle vs. random reset)."
            }
        }

        Write-Section 'Inventory: provisioned users'
        $users = @(Get-ADUser -Server $pdc -ResultPageSize 500 -LDAPFilter '(&(objectCategory=person)(objectClass=user)(msDS-ExternalDirectoryObjectId=User_*))')
        $rows = foreach ($u in $users) {
            $s      = Get-Snapshot $u.DistinguishedName -IncludeAcl
            $max    = Get-EffectiveMaxAge $s $dc
            $notes  = @()
            $status = 'PASS'

            $gap = if ($s.SecretTime -and $s.PwdLastSet) { ($s.SecretTime - $s.PwdLastSet).TotalMinutes } else { $null }
            $gapText = if ($null -eq $gap) { 'n/a' } elseif ([Math]::Abs($gap) -le 2) { 'aligned' } elseif ($gap -gt 0) { 'secret newer by {0:N1} d' -f ($gap / 1440) } else { 'pwdLastSet newer by {0:N1} d' -f (-$gap / 1440) }
            if ($null -ne $gap -and $gap -gt 2) { $notes += 'secret changed later than pwdLastSet -> a secret change did not update pwdLastSet' }

            $eligible = $dc.RollingEffective -and $s.Scril -and -not $s.Pne -and $max.TotalDays -gt 0
            $window   = if ($eligible -and $s.PwdLastSet) { $s.PwdLastSet + $max } else { $null }

            if ($s.Enabled -and -not $s.Scril) { $status = 'FAIL'; $notes += 'SCRIL missing' }
            if ($s.PeFlag) { $status = 'FAIL'; $notes += 'PASSWORD EXPIRED flag set' }
            if ($s.Pne -and $s.Scril) { $notes += 'PNE set: automatic rolling is excluded for this user (MS-SAMS)' }
            if ($window) {
                if ($window -lt (Get-Date)) {
                    if ($status -ne 'FAIL') { $status = 'WARN' }
                    $notes += "rolling window reached ($(Format-Time $window)) - DC rolls at next qualifying sign-on; behavior with Cloud Kerberos Trust: see Rolling phases"
                } elseif ($window -lt (Get-Date).AddDays(7)) {
                    if ($status -ne 'FAIL') { $status = 'WARN' }
                    $notes += "rolling window in < 7 days ($(Format-Time $window))"
                }
            }
            if ($status -eq 'PASS' -and $notes.Count) { $status = 'INFO' }

            [pscustomobject]@{
                Status        = $status
                User          = $s.Sam
                Enabled       = $s.Enabled
                SCRIL         = $s.Scril
                PNE           = $s.Pne
                DenyChange    = $s.DenyChange
                Marked        = $s.Marked
                PwdLastSet    = Format-Time $s.PwdLastSet
                SecretChanged = Format-Time $s.SecretTime
                SecretOrigin  = $s.SecretOrigin
                SecretVsPwdLastSet = $gapText
                MaxPwdAgeDays = [int]$max.TotalDays
                ExpiryComputed = Format-Expiry $s.ExpiryRaw
                PEFlag        = $s.PeFlag
                RollingWindow = $(if ($window) { Format-Time $window } elseif ($eligible) { 'n/a' } else { 'not eligible' })
                Notes         = ($notes -join '; ')
            }
        }
        $rows = @($rows | Sort-Object @{ e = { switch ($_.Status) { 'FAIL' { 0 } 'WARN' { 1 } 'INFO' { 2 } default { 3 } } } }, User)

        foreach ($l in $summary) { Write-Host $l -ForegroundColor $(if ($l -like 'WARN*') { 'Yellow' } else { 'Gray' }) }
        Write-Host ''
        foreach ($r in $rows) {
            Write-Host ('[{0}] {1,-20} SCRIL={2,-5} PNE={3,-5} deny={4,-5} pwdLastSet={5}  secret={6} ({7})  expiry={8}  window={9}' -f
                $r.Status, $r.User, $r.SCRIL, $r.PNE, $r.DenyChange, $r.PwdLastSet, $r.SecretChanged, $r.SecretOrigin, $r.ExpiryComputed, $r.RollingWindow) -ForegroundColor $Colors[$r.Status]
            if ($r.Notes) { Write-Host "      $($r.Notes)" -ForegroundColor $Colors[$r.Status] }
        }
        Save-Finding 'Inventory' (New-Finding 'Inventory (read-only)' $summary ([ordered]@{ 'Provisioned users' = $rows; 'Fine-grained password policies' = $dc.Psos }))
        Write-Report
    }

    #----------------------------------------------------------------------------------------------
    'UiObserve' {
        $sam = if ($Identity) { $Identity } else { $cfg.TestUser }
        $u   = Get-ADUser -Identity $sam -Server $pdc
        Write-Section "UiObserve: $sam - snapshot on every writable DC"
        $before = @(foreach ($dc in $dcs) { Get-Snapshot $u.DistinguishedName $dc })
        $before | Format-Table Server, Scril, Pne, @{ n = 'pwdLastSet'; e = { Format-Time $_.PwdLastSet } }, SecretVersion, @{ n = 'SecretChanged'; e = { Format-Time $_.SecretTime } }, SecretOrigin, UacVersion -AutoSize | Out-Host
        Write-Host 'Now make the change in ADUC / ADAC (e.g. tick "Smart card is required for interactive logon" and click Apply).' -ForegroundColor Yellow
        Write-Host 'Note which DC the console is connected to (ADUC: right-click domain > Change Domain Controller).' -ForegroundColor Yellow
        $what = Read-Host 'Describe the change you made (free text, stored in the report)'
        Read-Host 'Press Enter when the change has been applied' | Out-Null
        Start-Sleep -Seconds 5
        $after = @(foreach ($dc in $dcs) { Get-Snapshot $u.DistinguishedName $dc })
        Write-Host 'Waiting 60 s for replication, then a third snapshot ...'
        Start-Sleep -Seconds 60
        $later = @(foreach ($dc in $dcs) { Get-Snapshot $u.DistinguishedName $dc })

        $rows = for ($i = 0; $i -lt $dcs.Count; $i++) {
            $b = $before[$i]; $a = $after[$i]; $l = $later[$i]
            [pscustomobject]@{
                DC                 = ($dcs[$i] -split '\.')[0]
                UacBefore          = '0x{0:X}' -f $b.Uac
                UacAfter           = '0x{0:X}' -f $a.Uac
                UacAfter60s        = '0x{0:X}' -f $l.Uac
                ScrilAfter         = $a.Scril
                PneAfter           = $a.Pne
                PwdLastSetChanged  = ($l.PwdLastSetRaw -ne $b.PwdLastSetRaw)
                SecretChanged      = ($l.SecretVersion -gt $b.SecretVersion)
                SecretVersion      = "$($b.SecretVersion) -> $($a.SecretVersion) -> $($l.SecretVersion)"
                SecretOriginAfter  = $l.SecretOrigin
                UacOriginAfter     = $l.UacOrigin
            }
        }
        $rows | Format-Table -AutoSize | Out-Host

        $p = $rows | Where-Object { $_.DC -eq ($pdc -split '\.')[0] } | Select-Object -First 1
        if (-not $p) { $p = $rows[0] }
        $uacChanged = @($rows | Where-Object { $_.UacBefore -ne $_.UacAfter60s }).Count -gt 0
        $summary = @("Change described: $what")
        if (-not $uacChanged) {
            $summary += 'userAccountControl unchanged on all DCs -> no effective write (flag was already set, change not applied, or write rejected).'
        } elseif (@($rows | Where-Object { $_.SecretChanged }).Count -and -not @($rows | Where-Object { $_.PwdLastSetChanged }).Count) {
            $summary += 'userAccountControl changed and the secret was re-randomized, but pwdLastSet was NOT updated -> pwdLastSet is not a reliable rotation indicator.'
        } elseif (@($rows | Where-Object { $_.SecretChanged }).Count) {
            $summary += 'userAccountControl changed, secret re-randomized and pwdLastSet updated.'
        } else {
            $summary += 'userAccountControl changed, but the secret was NOT changed (no unicodePwd metadata change).'
        }
        if (@($rows | Where-Object { $_.UacAfter -ne $_.UacAfter60s }).Count) { $summary += 'Some DCs only showed the change after replication - a check directly after the change can show old values.' }
        $summary += "Originating DC of the userAccountControl change: $($p.UacOriginAfter); of the last secret change: $($p.SecretOriginAfter)"
        foreach ($l in $summary) { Write-Host $l }
        Save-Finding ("UiObserve-{0:yyyyMMddHHmmss}" -f (Get-Date)) (New-Finding "UI observation: $sam" $summary ([ordered]@{ 'Per DC' = $rows }))
        Write-Report
    }

    #----------------------------------------------------------------------------------------------
    'Matrix' {
        $tu  = Get-TestUser
        $dn  = $tu.DistinguishedName
        $sam = $tu.SamAccountName
        $s0  = Get-Snapshot $dn -IncludeAcl
        $via = Resolve-WriteVia $s0
        Write-Section "Matrix on '$sam' - write path: $via"
        Write-Host 'Note: the scheduled "Enforce SCRIL" task may re-set SCRIL during the steps where it is off; such external changes are flagged.' -ForegroundColor Yellow

        $restoreDeny = if ($cfg.EnforceDenyChangePassword) { 'DenyChangeOn' } else { 'DenyChangeOff' }
        $steps = @(
            @{ Id = 'N1'; Name = 'Normalize: PNE off';                 Action = 'PneOff' }
            @{ Id = 'N2'; Name = 'Normalize: deny-change ACEs off';    Action = 'DenyChangeOff' }
            @{ Id = 'N3'; Name = 'Normalize: SCRIL off';               Action = 'ScrilOff' }
            @{ Id = 'A1'; Name = 'SCRIL off -> on';                    Action = 'ScrilOn' }
            @{ Id = 'A2'; Name = 'SCRIL on -> on (same value again)';  Action = 'ScrilRewrite' }
            @{ Id = 'A3'; Name = 'SCRIL on -> off';                    Action = 'ScrilOff' }
            @{ Id = 'A4'; Name = 'SCRIL off -> on (2nd)';              Action = 'ScrilOn' }
            @{ Id = 'R1'; Name = 'Random reset while SCRIL is set';    Action = 'RandomReset' }
            @{ Id = 'B1'; Name = 'PNE on (SCRIL set)';                 Action = 'PneOn' }
            @{ Id = 'B2'; Name = 'SCRIL on -> off (PNE set)';          Action = 'ScrilOff' }
            @{ Id = 'B3'; Name = 'SCRIL off -> on (PNE set)';          Action = 'ScrilOn' }
            @{ Id = 'B4'; Name = 'PNE off';                            Action = 'PneOff' }
            @{ Id = 'C1'; Name = 'Deny-change ACEs on';                Action = 'DenyChangeOn' }
            @{ Id = 'C2'; Name = 'SCRIL on -> off (deny ACEs)';        Action = 'ScrilOff' }
            @{ Id = 'C3'; Name = 'SCRIL off -> on (deny ACEs)';        Action = 'ScrilOn' }
            @{ Id = 'C4'; Name = 'Restore deny-change per config';     Action = $restoreDeny }
            @{ Id = 'F1'; Name = 'Final: make sure SCRIL is set';      Action = 'EnsureScril' }
        )

        $rows = @(); $prev = $s0
        foreach ($st in $steps) {
            $b = Get-Snapshot $dn -IncludeAcl
            $external = ($b.Uac -ne $prev.Uac) -or ($b.SecretVersion -ne $prev.SecretVersion) -or ($b.DenyChange -ne $prev.DenyChange)
            $action = $st.Action
            if ($action -eq 'EnsureScril') { $action = if ($b.Scril) { '-' } else { 'ScrilOn' } }
            $res = if ($action -eq '-') { [pscustomobject]@{ Accepted = $true; Error = $null } } else { Invoke-TestAction $action $dn $sam $via }
            Start-Sleep -Seconds 2
            $a = Get-Snapshot $dn -IncludeAcl
            $row = [pscustomobject]@{
                Step              = $st.Id
                Name              = $st.Name
                Action            = $action
                Accepted          = $res.Accepted
                Error             = $res.Error
                Uac               = '0x{0:X} -> 0x{1:X}' -f $b.Uac, $a.Uac
                SCRIL             = "$($b.Scril) -> $($a.Scril)"
                PNE               = "$($b.Pne) -> $($a.Pne)"
                DenyChange        = "$($b.DenyChange) -> $($a.DenyChange)"
                SecretChanged     = ($a.SecretVersion -gt $b.SecretVersion)
                SecretVersion     = "$($b.SecretVersion) -> $($a.SecretVersion)"
                SecretOrigin      = $a.SecretOrigin
                PwdLastSetChanged = ($a.PwdLastSetRaw -ne $b.PwdLastSetRaw)
                PwdLastSet        = Format-Time $a.PwdLastSet
                PEFlag            = $a.PeFlag
                ExpiryComputed    = Format-Expiry $a.ExpiryRaw
                ExternalChange    = $external
            }
            $rows += $row
            $color = if (-not $res.Accepted) { 'Red' } elseif ($external) { 'Yellow' } else { 'Gray' }
            Write-Host ('{0,-3} {1,-36} accepted={2,-5} secretChanged={3,-5} pwdLastSetChanged={4,-5} SCRIL {5,-14} PNE {6,-14} expiry={7}{8}' -f
                $row.Step, $row.Name, $row.Accepted, $row.SecretChanged, $row.PwdLastSetChanged, $row.SCRIL, $row.PNE, $row.ExpiryComputed,
                $(if ($res.Error) { "  ERROR: $($res.Error)" } elseif ($external) { '  (external change before this step)' } else { '' })) -ForegroundColor $color
            $prev = $a
        }

        function Get-Row([string]$Id) { $rows | Where-Object { $_.Step -eq $Id } | Select-Object -First 1 }
        function Get-Answer([string]$Question, [string[]]$Ids, [scriptblock]$Eval, [string]$Evidence) {
            $r = @($Ids | ForEach-Object { Get-Row $_ })
            $notTested = @($r | Where-Object { -not $_ -or -not $_.Accepted })
            $ext = @($r | Where-Object { $_ -and $_.ExternalChange })
            $result = if ($notTested.Count) { "not tested (write rejected in $(($notTested | ForEach-Object { $_.Step }) -join ', '))" } else { & $Eval $r }
            [pscustomobject]@{ Question = $Question; Result = $result; Evidence = $Evidence; Caveat = $(if ($ext.Count) { "external change before $(($ext | ForEach-Object { $_.Step }) -join ', ')" } else { '' }) }
        }

        $a1 = Get-Row 'A1'; $a2 = Get-Row 'A2'; $a3 = Get-Row 'A3'; $a4 = Get-Row 'A4'; $r1 = Get-Row 'R1'
        $b1 = Get-Row 'B1'; $b3 = Get-Row 'B3'; $c3 = Get-Row 'C3'
        $answers = @(
            Get-Answer 'Setting SCRIL (off -> on) re-randomizes the secret' 'A1' { Get-YesNo $args[0][0].SecretChanged } "A1 secret $($a1.SecretVersion)"
            Get-Answer 'Setting SCRIL updates pwdLastSet' 'A1' { Get-YesNo $args[0][0].PwdLastSetChanged } "A1 pwdLastSet now $($a1.PwdLastSet)"
            Get-Answer 'Setting SCRIL also sets "password never expires" (0x10000)' 'A1' { Get-YesNo ($args[0][0].PNE -like '* -> True') } "A1 PNE $($a1.PNE)"
            Get-Answer 'Writing the unchanged SCRIL value again (UI "Apply") re-randomizes' 'A2' { Get-YesNo $args[0][0].SecretChanged } "A2 secret $($a2.SecretVersion)"
            Get-Answer 'Clearing SCRIL (on -> off) re-randomizes' 'A3' { Get-YesNo $args[0][0].SecretChanged } "A3 secret $($a3.SecretVersion)"
            Get-Answer 'Toggle rotation (off + on) changes the secret' 'A3', 'A4' { Get-YesNo ($args[0][0].SecretChanged -or $args[0][1].SecretChanged) } "A3 $($a3.SecretVersion), A4 $($a4.SecretVersion)"
            Get-Answer 'Toggle rotation moves pwdLastSet' 'A3', 'A4' { Get-YesNo ($args[0][0].PwdLastSetChanged -or $args[0][1].PwdLastSetChanged) } "A4 pwdLastSet $($a4.PwdLastSet)"
            Get-Answer 'Random reset changes the secret while SCRIL is set' 'R1' { Get-YesNo $args[0][0].SecretChanged } "R1 secret $($r1.SecretVersion)"
            Get-Answer 'Random reset moves pwdLastSet' 'R1' { Get-YesNo $args[0][0].PwdLastSetChanged } "R1 pwdLastSet $($r1.PwdLastSet)"
            Get-Answer 'PE (password expired) flag set at any point while SCRIL was set' 'A1' { Get-YesNo (@($rows | Where-Object { $_.SCRIL -like '* -> True' -and $_.PEFlag }).Count -gt 0) } 'all rows with SCRIL set'
            Get-Answer 'Computed expiry with SCRIL, without PNE' 'A4' { $args[0][0].ExpiryComputed } 'msDS-UserPasswordExpiryTimeComputed after A4'
            Get-Answer 'Computed expiry with SCRIL and PNE' 'B1' { $args[0][0].ExpiryComputed } 'msDS-UserPasswordExpiryTimeComputed after B1'
            Get-Answer 'PNE changes the randomization on SCRIL set' 'A4', 'B3' { Get-YesNo ($args[0][0].SecretChanged -ne $args[0][1].SecretChanged) } "A4 $($a4.SecretChanged) vs. B3 $($b3.SecretChanged)"
            Get-Answer '"User cannot change password" changes the randomization on SCRIL set' 'A4', 'C3' { Get-YesNo ($args[0][0].SecretChanged -ne $args[0][1].SecretChanged) } "A4 $($a4.SecretChanged) vs. C3 $($c3.SecretChanged)"
        )

        $toggleSecret = $a3.SecretChanged -or $a4.SecretChanged
        $togglePls    = $a3.PwdLastSetChanged -or $a4.PwdLastSetChanged
        $recommend = if (-not $a3.Accepted -or -not $a4.Accepted) { 'Toggle could not be tested - see errors.' }
                     elseif ($toggleSecret -and $togglePls) { 'Toggle rotates the secret AND moves pwdLastSet -> RotationMethod Toggle or Auto is sufficient.' }
                     elseif ($toggleSecret) { 'Toggle rotates the secret but does NOT move pwdLastSet. Expiry / automatic rolling are computed from pwdLastSet -> use RotationMethod RandomReset if automatic rolling is enabled.' }
                     else { 'Toggle does NOT rotate the secret -> RotationMethod RandomReset is required (Auto falls back to it).' }

        Write-Section 'Answers'
        $answers | Format-Table Question, Result, Evidence, Caveat -AutoSize -Wrap | Out-Host
        Write-Host "Recommendation: $recommend" -ForegroundColor Cyan

        $summary = @("Write path: $via", "Recommendation: $recommend") + @($answers | ForEach-Object { "$($_.Question): $($_.Result)" })
        Save-Finding 'Matrix' (New-Finding "Matrix on $sam" $summary ([ordered]@{ 'Answers' = $answers; 'Steps' = $rows }))
        Write-Report
    }

    #----------------------------------------------------------------------------------------------
    'RollingPrepare' {
        $tu  = Get-TestUser
        $dn  = $tu.DistinguishedName
        $sam = $tu.SamAccountName
        $dc  = Get-DomainScrilConfig
        Write-Section "RollingPrepare on '$sam'"
        if (-not $dc.RollingEffective) {
            Write-Warning "Automatic rolling is DISABLED (attribute $($dc.RollingAttribute), DFL $($dc.Dfl)). The observation will show expiry behavior without rolling."
        }
        $min  = [int]$cfg.RollingTestMinutes
        $name = $cfg.ScrilTestPsoName
        $pso  = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -Server $pdc
        if (-not $pso) {
            New-ADFineGrainedPasswordPolicy -Name $name -Server $pdc -Precedence 1 -MaxPasswordAge (New-TimeSpan -Minutes $min) `
                -MinPasswordAge ([TimeSpan]::Zero) -MinPasswordLength 14 -ComplexityEnabled $true -PasswordHistoryCount 0 `
                -LockoutThreshold 0 -ReversibleEncryptionEnabled $false -ProtectedFromAccidentalDeletion $false `
                -Description 'TEMPORARY: SCRIL rolling observation (Test-ScrilBehavior.ps1). Remove with -Phase RollingCleanup.'
            $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -Server $pdc
            Write-Host "  + PSO $name created (max password age $min min, applies to nobody yet)" -ForegroundColor Green
        } else {
            Set-ADFineGrainedPasswordPolicy -Identity $pso -Server $pdc -MaxPasswordAge (New-TimeSpan -Minutes $min) -MinPasswordAge ([TimeSpan]::Zero)
        }
        $subjects = @((Get-ADFineGrainedPasswordPolicy -Identity $pso -Server $pdc -Properties AppliesTo).AppliesTo)
        if ($subjects -notcontains $dn) { Add-ADFineGrainedPasswordPolicySubject -Identity $pso -Subjects $dn -Server $pdc }
        $others = @($subjects | Where-Object { $_ -ne $dn })
        if ($others.Count) { Write-Warning "PSO $name also applies to: $($others -join '; ') - remove these subjects." }
        Start-Sleep -Seconds 2
        $res = Get-ADUserResultantPasswordPolicy -Identity $dn -Server $pdc
        if (-not $res -or $res.Name -ne $name) { Write-Warning "Resultant policy of $sam is '$($res.Name)', not $name (another PSO with precedence 1 or lower?)." }

        $s   = Get-Snapshot $dn
        $via = Resolve-WriteVia $s
        foreach ($act in @('PneOff') + $(if (-not $s.Scril) { @('ScrilOn') } else { @() }) + @('RandomReset')) {
            $r = Invoke-TestAction $act $dn $sam $via
            if (-not $r.Accepted) { throw "Preparation step $act failed ($via): $($r.Error)" }
        }
        Start-Sleep -Seconds 2
        $s = Get-Snapshot $dn
        $baseline = [pscustomobject]@{
            Time             = (Get-Date).ToString('s')
            Dn               = $dn
            Sam              = $sam
            Via              = $via
            PsoName          = $name
            MaxAgeMinutes    = $min
            PwdLastSet       = $s.PwdLastSet.ToString('s')
            ExpectedExpiry   = $s.PwdLastSet.AddMinutes($min).ToString('s')
            ExpiryComputed   = Format-Expiry $s.ExpiryRaw
            SecretVersionMax = (@(Get-SecretAllDcs $dn) | Measure-Object -Property Version -Maximum).Maximum
            LastLogon        = $(if (($ll = Get-LastLogonMax $dn)) { $ll.ToString('s') } else { $null })
            RollingEffective = $dc.RollingEffective
        }
        $baseline | ConvertTo-Json | Set-Content -Path $baselinePath -Encoding UTF8
        $baseline | Format-List | Out-Host
        Write-Host ("Run -Phase RollingObserve after {0} (use -WaitForExpiry to wait automatically)." -f $baseline.ExpectedExpiry) -ForegroundColor Cyan
    }

    #----------------------------------------------------------------------------------------------
    'RollingObserve' {
        if (-not (Test-Path -Path $baselinePath)) { throw 'No baseline - run -Phase RollingPrepare first.' }
        $bl  = Get-Content -Path $baselinePath -Raw | ConvertFrom-Json
        $dn  = $bl.Dn
        $exp = [datetime]$bl.ExpectedExpiry
        Write-Section "RollingObserve on '$($bl.Sam)' - expected expiry $(Format-Time $exp)"

        if ((Get-Date) -lt $exp) {
            if (-not $WaitForExpiry) { Write-Host ("Not expired yet ({0:N0} min left). Re-run later or use -WaitForExpiry." -f ($exp - (Get-Date)).TotalMinutes) -ForegroundColor Yellow; return }
            while ((Get-Date) -lt $exp.AddMinutes(1)) {
                Write-Host ("  waiting for expiry: {0:N0} min left" -f [Math]::Max(0, ($exp.AddMinutes(1) - (Get-Date)).TotalMinutes))
                Start-Sleep -Seconds 60
            }
        }

        $atExpiry = Get-Snapshot $dn
        Write-Host ("At expiry: PE flag={0}, computed expiry={1}, SCRIL={2}, PNE={3}, secret version {4}" -f $atExpiry.PeFlag, (Format-Expiry $atExpiry.ExpiryRaw), $atExpiry.Scril, $atExpiry.Pne, $atExpiry.SecretVersion)
        $rolledBefore = $atExpiry.SecretVersion -gt [int]$bl.SecretVersionMax
        if ($rolledBefore) { Write-Host 'The secret already changed before the sign-in test (rolled by an earlier sign-on or another change).' -ForegroundColor Yellow }

        Write-Host ''
        Write-Host "MANUAL STEP - within $WaitMinutes minutes, as $($bl.Sam):" -ForegroundColor Yellow
        Write-Host '  1. Sign in (or lock + unlock) on an Entra-joined / hybrid-joined device with Windows Hello for Business or a FIDO2 key.' -ForegroundColor Yellow
        Write-Host '  2. Open the AVD RemoteApp / desktop (SSO) and access an AD resource (e.g. \\server\share).' -ForegroundColor Yellow
        Read-Host 'Press Enter right before you start the sign-in' | Out-Null
        $obsStart = Get-Date
        $deadline = $obsStart.AddMinutes($WaitMinutes)
        $logon = $null; $rolled = $null
        do {
            Start-Sleep -Seconds 20
            $ll = Get-LastLogonMax $dn
            if ($ll -and $ll -gt $obsStart) { $logon = $ll }
            $sec = @(Get-SecretAllDcs $dn)
            $hit = $sec | Where-Object { $_.Version -gt [int]$atExpiry.SecretVersion } | Sort-Object Version -Descending | Select-Object -First 1
            if ($hit) { $rolled = $hit }
            Write-Host ("  {0:HH:mm:ss}  logon recorded: {1}  secret changed: {2}" -f (Get-Date), $(if ($logon) { Format-Time $logon } else { 'no' }), $(if ($rolled) { "yes (origin $($rolled.Origin))" } else { 'no' }))
            if ($logon -and $rolled) { break }
        } while ((Get-Date) -lt $deadline)

        $answer = Read-Host 'Did the sign-in AND the access to the AD resource succeed? (y/n)'
        $ok     = $answer -match '^(y|j)'
        $after  = Get-Snapshot $dn
        $verdict = if (-not $ok) { 'FAIL: passwordless sign-in / AD access failed after expiry -> keep pwdLastSet fresh (RandomReset rotation, RotationDays < maxPwdAge) or exclude these users from expiry (PNE / maxPwdAge 0 via PSO).' }
                   elseif ($rolled) { "PASS: sign-in worked and a DC rolled the secret ($($rolled.Origin), $($rolled.Time)) - automatic rolling is triggered by this sign-in path." }
                   elseif ($logon) { 'INFO: sign-in worked after expiry, but this sign-in path did NOT trigger rolling -> rotation must come from the job.' }
                   else { 'WARN: sign-in reported as successful but no logon was recorded (lastLogon) - repeat with a fresh sign-in and an AD resource access.' }
        Write-Host $verdict -ForegroundColor $(if ($verdict -like 'FAIL*') { 'Red' } elseif ($verdict -like 'PASS*') { 'Green' } elseif ($verdict -like 'WARN*') { 'Yellow' } else { 'Gray' })

        $summary = @(
            $verdict
            "Automatic rolling enabled in domain: $($bl.RollingEffective); PSO max age: $($bl.MaxAgeMinutes) min; write path used for preparation: $($bl.Via)"
            "At expiry: PE flag $($atExpiry.PeFlag), computed expiry $(Format-Expiry $atExpiry.ExpiryRaw)"
            "Logon recorded: $(if ($logon) { Format-Time $logon } else { 'no' }); secret rolled: $(if ($rolled) { "yes, origin $($rolled.Origin) at $($rolled.Time)" } else { 'no' }); rolled before test: $rolledBefore"
            "pwdLastSet: baseline $($bl.PwdLastSet) -> now $(Format-Time $after.PwdLastSet)"
        )
        Save-Finding 'Rolling' (New-Finding "Automatic rolling observation on $($bl.Sam)" $summary ([ordered]@{ 'Secret per DC' = @(Get-SecretAllDcs $dn) }))
        Write-Report
        Write-Host 'Run -Phase RollingCleanup when done.' -ForegroundColor Cyan
    }

    #----------------------------------------------------------------------------------------------
    'RollingCleanup' {
        $tu  = Get-TestUser
        $dn  = $tu.DistinguishedName
        $name = $cfg.ScrilTestPsoName
        Write-Section "RollingCleanup on '$($tu.SamAccountName)'"
        $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -Server $pdc
        if ($pso) {
            Remove-ADFineGrainedPasswordPolicy -Identity $pso -Server $pdc -Confirm:$false
            Write-Host "  - PSO $name removed" -ForegroundColor Green
        }
        $s   = Get-Snapshot $dn
        $via = Resolve-WriteVia $s
        foreach ($act in $(if (-not $s.Scril) { @('ScrilOn') } else { @() }) + @('RandomReset')) {
            $r = Invoke-TestAction $act $dn $tu.SamAccountName $via
            Write-Host ("  {0}: {1}" -f $act, $(if ($r.Accepted) { 'done' } else { "FAILED - $($r.Error)" })) -ForegroundColor $(if ($r.Accepted) { 'Green' } else { 'Red' })
        }
        Remove-Item -Path $baselinePath -Force -ErrorAction SilentlyContinue
        $s = Get-Snapshot $dn
        Write-Host ("Resultant policy restored; SCRIL={0}, pwdLastSet={1}, computed expiry={2}" -f $s.Scril, (Format-Time $s.PwdLastSet), (Format-Expiry $s.ExpiryRaw))
    }

    #----------------------------------------------------------------------------------------------
    'Report' { Write-Report }
}
