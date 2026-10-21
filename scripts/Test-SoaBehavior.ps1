#Requires -Version 5.1
#Requires -Modules ActiveDirectory
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Repeatable acceptance tests: how SCRIL, "password never expires", "user cannot change password", random resets,
    automatic rolling, the toolkit tasks and AD object enforcement actually behave in THIS domain.

.DESCRIPTION
    Writes ONLY to the configured TestUser (a user created in Entra ID and provisioned by Cloud Sync). Secret values are
    never read - whether a secret changed is derived from the replication metadata version of unicodePwd.

    Suites (several per call are run in this order):
      Inventory       read-only: domain functional level, automatic rolling, password policies / PSOs, every provisioned
                      user (SCRIL, PNE, deny-change ACEs, pwdLastSet vs. last secret change, expiry, resultant PSO)
      UiObserve       read-only snapshot per DC, YOU change the user in ADUC/ADAC, second snapshot - shows what changed where
      Scril           matrix: SCRIL off->on / rewrite / on->off / toggle, random reset, PNE, deny-change - derives the answers
      RollingPrepare  temporary PSO (RollingTestMinutes) on the TestUser, fresh secret
      RollingObserve  after expiry: YOU sign in passwordless (WHfB / FIDO2 via Cloud Kerberos Trust, AVD SSO, file share);
                      records whether a DC rolled the secret and whether pwdLastSet moved with it
      RollingCleanup  removes the temporary PSO
      Onboarding      the toolkit identity removes SCRIL / sets PNE / removes the PSO group membership of the TestUser,
                      then the reconcile task must restore the target state
      Enforcement     ProbeAllowed (toolkit identity writes the marked TestUser -> must succeed) and UnauthorizedWrite
                      (YOU write against every DC -> in Enforced mode blocked everywhere)
      Logon           manual: sign in as the TestUser; checks the recorded logon and Kerberos failures (0x17 / 0x12)
      Report          rebuilds the HTML report

    Write path (-WriteVia): Direct = as you; Job = as the allow-listed toolkit gMSA through a temporary scheduled task on
    an agent host (Invoke-CloudUserConformance.ps1 -Mode Test); Auto = Job when the policy is Enforced, the TestUser
    is marked and you are not allow-listed.

    Output: console + <ReportPath>\Tests\test-state.json (latest results, shown by Watch-CloudUserConformance.ps1),
            behavior-findings.json and behavior-report.html

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.0.5 (2026-10-21)
    Run as Domain Admin from the admin workstation (RSAT). WinRM to the DCs and agent hosts.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Inventory', 'UiObserve', 'Scril', 'RollingPrepare', 'RollingObserve', 'RollingCleanup', 'Onboarding', 'Enforcement', 'Logon', 'Report')]
    [string[]] $Suite,

    [ValidateSet('Auto', 'Direct', 'Job')]
    [string] $WriteVia = 'Auto',

    [string] $Identity,

    [int] $WaitMinutes = 15,

    [switch] $WaitForExpiry,

    [string] $ConfigPath,

    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
Import-Module (Join-Path $ScriptRoot 'SoaToolkit.psm1') -Force -DisableNameChecking
$ConfigPath = Resolve-SoaConfigPath -ConfigPath $ConfigPath -ScriptRoot $ScriptRoot

#region --- Context --------------------------------------------------------------------------------
$cfg = Import-SoaConfig -Path $ConfigPath
Assert-SoaAdminPaths -Config $cfg -ScriptRoot $ScriptRoot
Initialize-SoaReportPath -Config $cfg
$ctx = Get-SoaContext
$pdc = $ctx.Pdc
if (-not $OutputPath) { $OutputPath = Join-Path $cfg.ReportPath 'Tests' }
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
$findingsPath = Join-Path $OutputPath 'behavior-findings.json'
$statePath    = Join-Path $OutputPath 'test-state.json'
$baselinePath = Join-Path $OutputPath 'rolling-baseline.json'
$reportPath   = Join-Path $OutputPath 'behavior-report.html'
$Uac  = Get-SoaConstant 'Uac'
$Ucc  = Get-SoaConstant 'Ucc'
$KnownGuid = Get-SoaConstant 'Guid'
$drive = Initialize-SoaAdDrive -Server $pdc
$dcs  = $ctx.WritableDcs
$roles = @(Get-SoaHostRoles -Config $cfg -Context $ctx)
$KerbStatus = @{ '0x12' = 'client revoked (disabled / locked / expired)'; '0x17' = 'key (password) expired'; '0x18' = 'pre-authentication failed' }
#endregion

#region --- Helpers: formatting / persistence ------------------------------------------------------
function Format-Time($Value) { if ($Value) { ([datetime]$Value).ToString('yyyy-MM-dd HH:mm:ss') } else { '-' } }
function Format-Expiry($Raw) {
    if ($null -eq $Raw) { return 'n/a' }
    $i = [int64]$Raw
    if ($i -ge [int64]::MaxValue) { return 'never' }
    if ($i -eq 0) { return '0 (expired / must change)' }
    Format-Time (ConvertFrom-SoaFileTime $i)
}
function Get-YesNo($Value) { if ($null -eq $Value) { 'n/a' } elseif ($Value) { 'YES' } else { 'no' } }

function Save-Finding([string]$Key, $Object) {
    $all = [ordered]@{}
    if (Test-Path -Path $findingsPath) { $j = Get-Content -Path $findingsPath -Raw | ConvertFrom-Json; foreach ($p in $j.PSObject.Properties) { $all[$p.Name] = $p.Value } }
    $all[$Key] = $Object
    [pscustomobject]$all | ConvertTo-Json -Depth 8 | Set-Content -Path $findingsPath -Encoding UTF8
}
function New-Finding([string]$Title, [string[]]$Summary, $Tables) { [pscustomobject]@{ Time = (Get-Date).ToString('s'); Title = $Title; Summary = @($Summary); Tables = $Tables } }

function Save-TestResult([string]$Name, [string]$Status, [string]$Detail) {
    $all = @(Read-SoaJsonArray -Path $statePath)
    $all += [pscustomobject]@{ Test = $Name; Time = (Get-Date).ToString('s'); PolicyMode = (Get-SoaPolicyMode -Context $ctx); Status = $Status; Detail = $Detail; RunBy = "$env:USERDOMAIN\$env:USERNAME" }
    $all = @($all | Group-Object Test | ForEach-Object { $_.Group | Sort-Object Time -Descending | Select-Object -First 20 })
    ConvertTo-Json -InputObject $all -Depth 3 | Set-Content -Path $statePath -Encoding UTF8
    Write-Host ('[{0}] {1}: {2}' -f $Status, $Name, $Detail) -ForegroundColor (Get-SoaStatusColor $Status)
}

function Write-Report {
    if (-not (Test-Path -Path $findingsPath)) { return }
    $j = Get-Content -Path $findingsPath -Raw | ConvertFrom-Json
    $order = 'Inventory', 'Scril', 'Rolling', 'Onboarding', 'Enforcement', 'Logon'
    $keys = @($order | Where-Object { $j.PSObject.Properties.Name -contains $_ }) + @($j.PSObject.Properties.Name | Where-Object { $order -notcontains $_ } | Sort-Object -Descending)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<h1>SOA Toolkit &ndash; behavior tests ($($ctx.DnsRoot))</h1><p>Report generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>")
    foreach ($k in $keys) {
        $f = $j.$k
        [void]$sb.Append("<h2>$([Net.WebUtility]::HtmlEncode($f.Title))</h2><p>Recorded: $($f.Time)</p><div class='box'>")
        foreach ($s in @($f.Summary)) { [void]$sb.Append("<div>$([Net.WebUtility]::HtmlEncode($s))</div>") }
        [void]$sb.Append('</div>')
        if ($f.Tables) { foreach ($t in $f.Tables.PSObject.Properties) { $rows = @($t.Value); if ($rows.Count) { [void]$sb.Append("<h3>$([Net.WebUtility]::HtmlEncode($t.Name))</h3>" + (($rows | ConvertTo-Html -Fragment) -join "`n")) } } }
    }
    ConvertTo-Html -Head (Get-SoaHtmlStyle) -Body $sb.ToString() -Title 'SOA Toolkit behavior tests' | Set-Content -Path $reportPath -Encoding UTF8
    Write-Host "Report: $reportPath" -ForegroundColor Cyan
    Write-Host "        (contains names of your environment - share it only through Export-SoaReport.ps1)" -ForegroundColor DarkGray
}
#endregion

#region --- Helpers: directory state ---------------------------------------------------------------
function Get-DenyChangeState([string]$Dn) {
    $acl = Get-Acl -Path "$drive\$Dn"
    (@($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { "$($_.AccessControlType)" -eq 'Deny' -and $_.ObjectType -eq $KnownGuid.ChangePwd -and $_.IdentityReference.Value -in 'S-1-1-0', 'S-1-5-10' }).Count -ge 2)
}

function Get-Snapshot([string]$Dn, [string]$Server = $pdc, [switch]$IncludeAcl) {
    $u = Get-ADUser -Identity $Dn -Server $Server -Properties userAccountControl, 'msDS-User-Account-Control-Computed', 'msDS-UserPasswordExpiryTimeComputed', pwdLastSet, 'msDS-ResultantPSO', 'msDS-ObjectSoa', memberOf
    $m = Get-SoaSecretMeta -Dn $Dn -Server $Server
    [pscustomobject]@{
        Server = $Server; Sam = $u.SamAccountName; Uac = [int]$u.userAccountControl
        Scril = [bool]($u.userAccountControl -band $Uac.Scril); Pne = [bool]($u.userAccountControl -band $Uac.DontExpire); Enabled = -not [bool]($u.userAccountControl -band $Uac.Disabled)
        PeFlag = [bool]($u.'msDS-User-Account-Control-Computed' -band $Ucc.Expired); Locked = [bool]($u.'msDS-User-Account-Control-Computed' -band $Ucc.Locked)
        PwdLastSetRaw = [int64]$u.pwdLastSet; PwdLastSet = ConvertFrom-SoaFileTime $u.pwdLastSet; ExpiryRaw = $u.'msDS-UserPasswordExpiryTimeComputed'
        ResultantPso = "$($u.'msDS-ResultantPSO')"; Marked = [bool]$u.'msDS-ObjectSoa'
        InPsoGroup = [bool](@($u.memberOf) | Where-Object { $_ -like "CN=$($cfg.PsoGroupName),*" })
        SecretVersion = $m.SecretVersion; SecretTime = $m.SecretTime; SecretOrigin = $m.SecretOrigin; UacVersion = $m.UacVersion; UacOrigin = $m.UacOrigin
        PwdLastSetVersion = $m.PwdLastSetVersion
        DenyChange = $(if ($IncludeAcl) { Get-DenyChangeState $Dn } else { $null })
    }
}

function Get-LastLogonMax([string]$Dn) {
    $max = $null
    foreach ($dc in $dcs) { try { $t = ConvertFrom-SoaFileTime (Get-ADUser -Identity $Dn -Server $dc -Properties lastLogon).lastLogon; if ($t -and (-not $max -or $t -gt $max)) { $max = $t } } catch { } }
    $max
}

function Get-SecretAllDcs([string]$Dn) {
    foreach ($dc in $dcs) {
        try { $m = Get-SoaSecretMeta -Dn $Dn -Server $dc; [pscustomobject]@{ DC = (Get-SoaShortName $dc); Version = $m.SecretVersion; Time = Format-Time $m.SecretTime; Origin = $m.SecretOrigin } }
        catch { [pscustomobject]@{ DC = (Get-SoaShortName $dc); Version = $null; Time = $null; Origin = "error: $($_.Exception.Message)" } }
    }
}

function Get-TestUser {
    $sam = if ($Identity) { $Identity } else { $cfg.TestUser }
    if (-not $cfg.TestUser -or $sam -ne $cfg.TestUser) { throw "This suite writes to the user and is only allowed on the configured TestUser '$($cfg.TestUser)'." }
    $u = Get-ADUser -Identity $sam -Server $pdc -Properties 'msDS-ExternalDirectoryObjectId', 'msDS-ObjectSoa', userPrincipalName
    if ("$($u.'msDS-ExternalDirectoryObjectId')" -notlike 'User_*') { throw "TestUser '$sam' is not provisioned by Cloud Sync." }
    $u
}
#endregion

#region --- Helpers: write path --------------------------------------------------------------------
function Resolve-WriteVia($Snapshot) {
    if ($WriteVia -ne 'Auto') { return $WriteVia }
    $p = Get-SoaPolicy -Context $ctx
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($p -and (@($p.keywords) -join ',') -eq 'Enforced' -and $Snapshot.Marked -and (@($p.'msDS-Settings' | ForEach-Object { "$_" }) -notcontains $me)) { 'Job' } else { 'Direct' }
}

# Runs Invoke-CloudUserConformance.ps1 as the toolkit gMSA through a temporary task on the first reachable agent host
function Invoke-AsToolkit([string]$Arguments, [string]$StatusName, [int]$TimeoutMinutes = 5) {
    $user = '{0}\{1}$' -f $ctx.NetBios, $cfg.GmsaName
    foreach ($h in @($roles | Where-Object { $_.IsAgent } | ForEach-Object { $_.Host })) {
        $res = Invoke-SoaOnHost -ComputerName $h -ArgumentList $cfg.ScriptInstallPath, $Arguments, $user, $cfg.DataPath, $StatusName, $TimeoutMinutes, $cfg.TaskFolder -ScriptBlock {
            param($InstallPath, $Arguments, $User, $DataPath, $StatusName, $Timeout, $TaskFolder)
            $script = Join-Path $InstallPath 'Invoke-CloudUserConformance.ps1'
            if (-not (Test-Path $script)) { throw "$script not found (Install-SoaToolkit.ps1 -Step DeployTasks)." }
            $statusFile = Join-Path $DataPath "Status\$StatusName.json"
            Remove-Item -Path $statusFile -Force -ErrorAction SilentlyContinue
            $name = 'Test-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $action = New-ScheduledTaskAction -Execute $psExe -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" {1}' -f $script, $Arguments) -WorkingDirectory $InstallPath
            Register-ScheduledTask -TaskName $name -TaskPath $TaskFolder -Action $action -Principal (New-ScheduledTaskPrincipal -UserId $User -LogonType Password) -Description 'SOA Toolkit - temporary test task (Test-SoaBehavior.ps1)' | Out-Null
            try {
                Start-ScheduledTask -TaskName $name -TaskPath $TaskFolder
                $deadline = (Get-Date).AddMinutes($Timeout)
                do { Start-Sleep -Seconds 3 } while (-not (Test-Path $statusFile) -and (Get-Date) -lt $deadline)
                Start-Sleep -Seconds 1
                [pscustomobject]@{ Finished = (Test-Path $statusFile); TaskResult = (Get-ScheduledTaskInfo -TaskName $name -TaskPath $TaskFolder).LastTaskResult; Json = $(if (Test-Path $statusFile) { Get-Content $statusFile -Raw }) }
            } finally { Unregister-ScheduledTask -TaskName $name -TaskPath $TaskFolder -Confirm:$false -ErrorAction SilentlyContinue }
        }
        if (-not $res.Ok) { Write-Warning "${h}: $($res.Error)"; continue }
        $parsed = if ($res.Result.Json) { $res.Result.Json | ConvertFrom-Json } else { $null }
        return [pscustomobject]@{ Success = [bool]($parsed -and $parsed.Success); Errors = $(if ($parsed) { @($parsed.Errors) -join '; ' } else { "no status file (task result $($res.Result.TaskResult))" }); RunAs = $(if ($parsed) { $parsed.RunAs }); Host = $h }
    }
    [pscustomobject]@{ Success = $false; Errors = 'no agent host could run the temporary task'; RunAs = $null; Host = $null }
}

function Invoke-TestAction([string]$Action, [string]$Dn, [string]$Sam, [string]$Via) {
    try {
        if ($Via -eq 'Job') {
            $r = Invoke-AsToolkit -Arguments "-Mode Test -TestAction $Action -Identity $Sam" -StatusName "test-$Action"
            return [pscustomobject]@{ Accepted = $r.Success; Error = $(if (-not $r.Success) { $r.Errors }) }
        }
        switch ($Action) {
            'ScrilOn'       { [void](Set-SoaUacFlags -Dn $Dn -Server $pdc -SetBits $Uac.Scril) }
            'ScrilOff'      { [void](Set-SoaUacFlags -Dn $Dn -Server $pdc -ClearBits $Uac.Scril) }
            'ScrilRewrite'  { Set-ADUser -Identity $Dn -Server $pdc -Replace @{ userAccountControl = [int](Get-ADUser -Identity $Dn -Server $pdc -Properties userAccountControl).userAccountControl } }
            'RandomReset'   { Set-ADAccountPassword -Identity $Dn -Server $pdc -Reset -NewPassword (New-SoaRandomSecret) }
            'PneOn'         { [void](Set-SoaUacFlags -Dn $Dn -Server $pdc -SetBits $Uac.DontExpire) }
            'PneOff'        { [void](Set-SoaUacFlags -Dn $Dn -Server $pdc -ClearBits $Uac.DontExpire) }
            'DenyChangeOn'  {
                $acl = Get-Acl -Path "$drive\$Dn"
                foreach ($s in 'S-1-1-0', 'S-1-5-10') { $acl.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule([Security.Principal.SecurityIdentifier]$s, 'ExtendedRight', 'Deny', $KnownGuid.ChangePwd))) }
                Set-Acl -Path "$drive\$Dn" -AclObject $acl
            }
            'DenyChangeOff' {
                $acl = Get-Acl -Path "$drive\$Dn"
                foreach ($r in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) { if ("$($r.AccessControlType)" -eq 'Deny' -and $r.ObjectType -eq $KnownGuid.ChangePwd -and $r.IdentityReference.Value -in 'S-1-1-0', 'S-1-5-10') { [void]$acl.RemoveAccessRuleSpecific($r) } }
                Set-Acl -Path "$drive\$Dn" -AclObject $acl
            }
            'GroupRemove'   { Remove-ADGroupMember -Identity $cfg.PsoGroupName -Members $Dn -Server $pdc -Confirm:$false }
            'GroupAdd'      { Add-ADGroupMember -Identity $cfg.PsoGroupName -Members $Dn -Server $pdc }
            default         { throw "Unknown action $Action" }
        }
        [pscustomobject]@{ Accepted = $true; Error = $null }
    } catch {
        $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }
        [pscustomobject]@{ Accepted = $false; Error = $e.Message }
    }
}
#endregion

$suiteOrder = 'Inventory', 'UiObserve', 'Scril', 'RollingPrepare', 'RollingObserve', 'RollingCleanup', 'Onboarding', 'Enforcement', 'Logon', 'Report'
foreach ($current in ($suiteOrder | Where-Object { $Suite -contains $_ })) {
    switch ($current) {

        #----------------------------------------------------------------------------------------------
        'Inventory' {
            Write-SoaSection 'Inventory (read-only)'
            $root = Get-ADObject -Identity $ctx.DomainDN -Server $pdc -Properties 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts', 'msDS-Behavior-Version'
            $dfl  = [int]$root.'msDS-Behavior-Version'
            $roll = $root.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'
            $rollingEffective = ($roll -eq $true) -and ($dfl -ge 7)
            $ddp  = Get-ADDefaultDomainPasswordPolicy -Server $pdc
            $psos = @(Get-ADFineGrainedPasswordPolicy -Filter * -Server $pdc -Properties AppliesTo | ForEach-Object {
                [pscustomobject]@{ Name = $_.Name; Precedence = $_.Precedence; MaxPasswordAge = $_.MaxPasswordAge; MinPasswordLength = $_.MinPasswordLength; LockoutThreshold = $_.LockoutThreshold
                                   AppliesTo = (@($_.AppliesTo | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join ', ') } })
            $summary = @(
                "Domain functional level: $($ctx.Domain.DomainMode) (msDS-Behavior-Version $dfl; automatic rolling needs >= 7)"
                "msDS-ExpirePasswordsOnSmartCardOnlyAccounts: $(if ($null -eq $roll) { 'not set' } else { $roll }) -> automatic rolling $(if ($rollingEffective) { 'ENABLED' } else { 'DISABLED' })"
                "Default domain maxPwdAge: $([int]$ddp.MaxPasswordAge.TotalDays) day(s); minPwdAge: $([int]$ddp.MinPasswordAge.TotalDays) day(s)"
                "Fine-grained password policies: $(if ($psos.Count) { ($psos | ForEach-Object { "$($_.Name) (prec $($_.Precedence), max $($_.MaxPasswordAge), min length $($_.MinPasswordLength), applies to: $($_.AppliesTo))" }) -join ' | ' } else { 'none' })"
            )
            $users = @(Get-SoaCloudUser -Server $pdc)
            $psoCache = @{}
            $rows = foreach ($u in $users) {
                $s = Get-Snapshot $u.DistinguishedName -IncludeAcl
                $max = $ddp.MaxPasswordAge
                if ($s.ResultantPso) { if (-not $psoCache.ContainsKey($s.ResultantPso)) { $psoCache[$s.ResultantPso] = (Get-ADFineGrainedPasswordPolicy -Identity $s.ResultantPso -Server $pdc).MaxPasswordAge }; $max = $psoCache[$s.ResultantPso] }
                $notes = @(); $status = 'PASS'
                $gap = if ($s.SecretTime -and $s.PwdLastSet) { ($s.SecretTime - $s.PwdLastSet).TotalMinutes } else { $null }
                if ($null -ne $gap -and $gap -gt 2) { $notes += 'secret changed later than pwdLastSet (SCRIL set or rolled without pwdLastSet update)' }
                if ($s.Enabled -and $s.Marked -and -not $s.Scril) { $status = 'FAIL'; $notes += 'SCRIL missing' }
                if ($s.Pne) { if ($status -ne 'FAIL') { $status = 'WARN' }; $notes += 'PNE set: automatic rolling is disabled for this user' }
                if ($s.PeFlag -and $s.Scril -and -not $s.Pne -and $rollingEffective) { $notes += 'expired - rolls at the next passwordless sign-in' }
                elseif ($s.PeFlag) { $status = 'FAIL'; $notes += 'PASSWORD EXPIRED' }
                if ($status -eq 'PASS' -and $notes.Count) { $status = 'INFO' }
                [pscustomobject]@{
                    Status = $status; User = $s.Sam; Enabled = $s.Enabled; Marked = $s.Marked; SCRIL = $s.Scril; PNE = $s.Pne; DenyChange = $s.DenyChange; PsoGroup = $s.InPsoGroup
                    ResultantPso = $(if ($s.ResultantPso) { ($s.ResultantPso -split ',')[0] -replace '^CN=' } else { '(domain)' }); MaxPwdAgeDays = [int]$max.TotalDays
                    PwdLastSet = Format-Time $s.PwdLastSet; SecretChanged = Format-Time $s.SecretTime; SecretOrigin = $s.SecretOrigin; ExpiryComputed = Format-Expiry $s.ExpiryRaw; PEFlag = $s.PeFlag; Notes = ($notes -join '; ')
                }
            }
            $rows = @($rows | Sort-Object @{ e = { Get-SoaStatusRank $_.Status }; Descending = $true }, User)
            foreach ($l in $summary) { Write-Host $l }
            Write-Host ''
            foreach ($r in $rows) {
                Write-Host ('[{0}] {1,-20} SCRIL={2,-5} PNE={3,-5} deny={4,-5} PSO={5,-22} pwdLastSet={6} secret={7} ({8}) expiry={9}' -f $r.Status, $r.User, $r.SCRIL, $r.PNE, $r.DenyChange, $r.ResultantPso, $r.PwdLastSet, $r.SecretChanged, $r.SecretOrigin, $r.ExpiryComputed) -ForegroundColor (Get-SoaStatusColor $r.Status)
                if ($r.Notes) { Write-Host "      $($r.Notes)" -ForegroundColor (Get-SoaStatusColor $r.Status) }
            }
            Save-Finding 'Inventory' (New-Finding 'Inventory (read-only)' $summary ([ordered]@{ 'Provisioned users' = $rows; 'Fine-grained password policies' = $psos }))
            Write-Report
        }

        #----------------------------------------------------------------------------------------------
        'UiObserve' {
            $sam = if ($Identity) { $Identity } else { $cfg.TestUser }
            $u = Get-ADUser -Identity $sam -Server $pdc
            Write-SoaSection "UiObserve: $sam - snapshot on every writable DC"
            $before = @(foreach ($dc in $dcs) { Get-Snapshot $u.DistinguishedName $dc })
            $before | Format-Table Server, Scril, Pne, @{ n = 'pwdLastSet'; e = { Format-Time $_.PwdLastSet } }, SecretVersion, @{ n = 'SecretChanged'; e = { Format-Time $_.SecretTime } }, SecretOrigin, UacVersion -AutoSize | Out-Host
            Write-Host 'Now make the change in ADUC / ADAC and note the DC the console is connected to.' -ForegroundColor Yellow
            $what = Read-Host 'Describe the change you made (stored in the report)'
            Read-Host 'Press Enter when the change has been applied' | Out-Null
            Start-Sleep -Seconds 5
            $after = @(foreach ($dc in $dcs) { Get-Snapshot $u.DistinguishedName $dc })
            Write-Host 'Waiting 60 s for replication, then a third snapshot ...'
            Start-Sleep -Seconds 60
            $later = @(foreach ($dc in $dcs) { Get-Snapshot $u.DistinguishedName $dc })
            $rows = for ($i = 0; $i -lt $dcs.Count; $i++) {
                $b = $before[$i]; $a = $after[$i]; $l = $later[$i]
                [pscustomobject]@{ DC = (Get-SoaShortName $dcs[$i]); UacBefore = '0x{0:X}' -f $b.Uac; UacAfter60s = '0x{0:X}' -f $l.Uac; PwdLastSetChanged = ($l.PwdLastSetRaw -ne $b.PwdLastSetRaw)
                                   SecretChanged = ($l.SecretVersion -gt $b.SecretVersion); SecretVersion = "$($b.SecretVersion) -> $($a.SecretVersion) -> $($l.SecretVersion)"; SecretOrigin = $l.SecretOrigin; UacOrigin = $l.UacOrigin }
            }
            $rows | Format-Table -AutoSize | Out-Host
            Save-Finding ("UiObserve-{0:yyyyMMddHHmmss}" -f (Get-Date)) (New-Finding "UI observation: $sam" @("Change described: $what") ([ordered]@{ 'Per DC' = $rows }))
            Write-Report
        }

        #----------------------------------------------------------------------------------------------
        'Scril' {
            $tu = Get-TestUser; $dn = $tu.DistinguishedName; $sam = $tu.SamAccountName
            $s0 = Get-Snapshot $dn -IncludeAcl
            $via = Resolve-WriteVia $s0
            Write-SoaSection "Scril matrix on '$sam' - write path: $via"
            Write-Host 'Note: the toolkit tasks may restore SCRIL / PNE during the steps where they are changed; such external changes are flagged.' -ForegroundColor Yellow
            $steps = @(
                @{ Id = 'N1'; Name = 'Normalize: PNE off';                Action = 'PneOff' }
                @{ Id = 'N2'; Name = 'Normalize: deny-change ACEs off';   Action = 'DenyChangeOff' }
                @{ Id = 'N3'; Name = 'Normalize: SCRIL off';              Action = 'ScrilOff' }
                @{ Id = 'A1'; Name = 'SCRIL off -> on';                   Action = 'ScrilOn' }
                @{ Id = 'A2'; Name = 'SCRIL on -> on (same value again)'; Action = 'ScrilRewrite' }
                @{ Id = 'A3'; Name = 'SCRIL on -> off';                   Action = 'ScrilOff' }
                @{ Id = 'A4'; Name = 'SCRIL off -> on (2nd)';             Action = 'ScrilOn' }
                @{ Id = 'R1'; Name = 'Random reset while SCRIL is set';   Action = 'RandomReset' }
                @{ Id = 'B1'; Name = 'PNE on (SCRIL set)';                Action = 'PneOn' }
                @{ Id = 'B2'; Name = 'SCRIL on -> off (PNE set)';         Action = 'ScrilOff' }
                @{ Id = 'B3'; Name = 'SCRIL off -> on (PNE set)';         Action = 'ScrilOn' }
                @{ Id = 'B4'; Name = 'PNE off';                           Action = 'PneOff' }
                @{ Id = 'C1'; Name = 'Deny-change ACEs on';               Action = 'DenyChangeOn' }
                @{ Id = 'C2'; Name = 'SCRIL on -> off (deny ACEs)';       Action = 'ScrilOff' }
                @{ Id = 'C3'; Name = 'SCRIL off -> on (deny ACEs)';       Action = 'ScrilOn' }
                @{ Id = 'C4'; Name = 'Deny-change ACEs off (restore)';    Action = 'DenyChangeOff' }
                @{ Id = 'F1'; Name = 'Final: make sure SCRIL is set';     Action = 'EnsureScril' }
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
                    Step = $st.Id; Name = $st.Name; Action = $action; Accepted = $res.Accepted; Error = $res.Error
                    SCRIL = "$($b.Scril) -> $($a.Scril)"; PNE = "$($b.Pne) -> $($a.Pne)"; DenyChange = "$($b.DenyChange) -> $($a.DenyChange)"
                    SecretChanged = ($a.SecretVersion -gt $b.SecretVersion); SecretVersion = "$($b.SecretVersion) -> $($a.SecretVersion)"
                    PwdLastSetChanged = ($a.PwdLastSetRaw -ne $b.PwdLastSetRaw); PwdLastSet = Format-Time $a.PwdLastSet; PEFlag = $a.PeFlag; ExpiryComputed = Format-Expiry $a.ExpiryRaw; ExternalChange = $external
                }
                $rows += $row
                Write-Host ('{0,-3} {1,-36} accepted={2,-5} secretChanged={3,-5} pwdLastSetChanged={4,-5} SCRIL {5,-14} PNE {6,-14} expiry={7}{8}' -f $row.Step, $row.Name, $row.Accepted, $row.SecretChanged, $row.PwdLastSetChanged, $row.SCRIL, $row.PNE, $row.ExpiryComputed,
                    $(if ($res.Error) { "  ERROR: $($res.Error)" } elseif ($external) { '  (external change before this step)' } else { '' })) -ForegroundColor $(if (-not $res.Accepted) { 'Red' } elseif ($external) { 'Yellow' } else { 'Gray' })
                $prev = $a
            }
            function Get-Row([string]$Id) { $rows | Where-Object { $_.Step -eq $Id } | Select-Object -First 1 }
            function Get-Answer([string]$Question, [string[]]$Ids, [scriptblock]$Eval, [string]$Evidence) {
                $r = @($Ids | ForEach-Object { Get-Row $_ })
                $notTested = @($r | Where-Object { -not $_ -or -not $_.Accepted }); $ext = @($r | Where-Object { $_ -and $_.ExternalChange })
                $result = if ($notTested.Count) { "not tested (write rejected in $(($notTested | ForEach-Object { $_.Step }) -join ', '))" } else { & $Eval $r }
                [pscustomobject]@{ Question = $Question; Result = $result; Evidence = $Evidence; Caveat = $(if ($ext.Count) { "external change before $(($ext | ForEach-Object { $_.Step }) -join ', ')" } else { '' }) }
            }
            $a1 = Get-Row 'A1'; $a2 = Get-Row 'A2'; $a3 = Get-Row 'A3'; $a4 = Get-Row 'A4'; $r1 = Get-Row 'R1'; $b1 = Get-Row 'B1'; $b3 = Get-Row 'B3'; $c3 = Get-Row 'C3'
            $answers = @(
                Get-Answer 'Setting SCRIL (off -> on) re-randomizes the secret' 'A1' { Get-YesNo $args[0][0].SecretChanged } "A1 secret $($a1.SecretVersion)"
                Get-Answer 'Setting SCRIL updates pwdLastSet' 'A1' { Get-YesNo $args[0][0].PwdLastSetChanged } "A1 pwdLastSet now $($a1.PwdLastSet)"
                Get-Answer 'Setting SCRIL also sets "password never expires"' 'A1' { Get-YesNo ($args[0][0].PNE -like '* -> True') } "A1 PNE $($a1.PNE)"
                Get-Answer 'Writing the unchanged value again (UI "Apply") re-randomizes' 'A2' { Get-YesNo $args[0][0].SecretChanged } "A2 secret $($a2.SecretVersion)"
                Get-Answer 'Clearing SCRIL re-randomizes' 'A3' { Get-YesNo $args[0][0].SecretChanged } "A3 secret $($a3.SecretVersion)"
                Get-Answer 'Random reset changes the secret while SCRIL is set' 'R1' { Get-YesNo $args[0][0].SecretChanged } "R1 secret $($r1.SecretVersion)"
                Get-Answer 'Random reset moves pwdLastSet' 'R1' { Get-YesNo $args[0][0].PwdLastSetChanged } "R1 pwdLastSet $($r1.PwdLastSet)"
                Get-Answer 'Computed expiry with SCRIL, without PNE' 'A4' { $args[0][0].ExpiryComputed } 'msDS-UserPasswordExpiryTimeComputed after A4'
                Get-Answer 'Computed expiry with SCRIL and PNE' 'B1' { $args[0][0].ExpiryComputed } 'msDS-UserPasswordExpiryTimeComputed after B1'
                Get-Answer 'PNE changes the randomization on SCRIL set' 'A4', 'B3' { Get-YesNo ($args[0][0].SecretChanged -ne $args[0][1].SecretChanged) } "A4 $($a4.SecretChanged) vs. B3 $($b3.SecretChanged)"
                Get-Answer '"User cannot change password" changes the randomization' 'A4', 'C3' { Get-YesNo ($args[0][0].SecretChanged -ne $args[0][1].SecretChanged) } "A4 $($a4.SecretChanged) vs. C3 $($c3.SecretChanged)"
            )
            $conclusion = @()
            if ($b1 -and $b1.Accepted -and $b1.ExpiryComputed -eq 'never') { $conclusion += 'PNE makes the password never expire -> automatic rolling never triggers: do NOT set PNE on cloud users.' }
            if ($a4 -and $a4.Accepted -and $a4.ExpiryComputed -notin 'never', 'n/a') { $conclusion += 'With rolling enabled, SCRIL secrets expire on schedule (expiry = pwdLastSet + max age) and are rolled by the DC at the next qualifying sign-in.' }
            if ($a1 -and $a1.Accepted -and $a1.SecretChanged -and -not $a1.PwdLastSetChanged) { $conclusion += 'Setting SCRIL re-randomizes the secret but keeps pwdLastSet: an old pwdLastSet means "expired" right away (rolled at the next sign-in).' }
            Write-SoaSection 'Answers'
            $answers | Format-Table Question, Result, Evidence, Caveat -AutoSize -Wrap | Out-Host
            foreach ($c in $conclusion) { Write-Host "Conclusion: $c" -ForegroundColor Cyan }
            Save-Finding 'Scril' (New-Finding "SCRIL matrix on $sam" (@("Write path: $via") + $conclusion + @($answers | ForEach-Object { "$($_.Question): $($_.Result)" })) ([ordered]@{ 'Answers' = $answers; 'Steps' = $rows }))
            Save-TestResult 'Scril' $(if (@($rows | Where-Object { -not $_.Accepted }).Count) { 'WARN' } else { 'PASS' }) ($conclusion -join ' ')
            Write-Report
        }

        #----------------------------------------------------------------------------------------------
        'RollingPrepare' {
            $tu = Get-TestUser; $dn = $tu.DistinguishedName; $sam = $tu.SamAccountName
            Write-SoaSection "RollingPrepare on '$sam'"
            $min = [int]$cfg.RollingTestMinutes; $name = $cfg.RollingTestPsoName
            $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -Server $pdc
            if (-not $pso) {
                New-ADFineGrainedPasswordPolicy -Name $name -Server $pdc -Precedence 1 -MaxPasswordAge (New-TimeSpan -Minutes $min) -MinPasswordAge ([TimeSpan]::Zero) -MinPasswordLength 14 `
                    -ComplexityEnabled $true -PasswordHistoryCount 0 -LockoutThreshold 0 -ReversibleEncryptionEnabled $false -ProtectedFromAccidentalDeletion $false `
                    -Description (Get-SoaMarker -Config $cfg -Short -Purpose 'TEMPORARY rolling observation (Test-SoaBehavior.ps1). Remove with -Suite RollingCleanup')
                $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -Server $pdc
                Write-SoaLine ADD "PSO $name created (max password age $min min)"
            } else { Set-ADFineGrainedPasswordPolicy -Identity $pso -Server $pdc -MaxPasswordAge (New-TimeSpan -Minutes $min) -MinPasswordAge ([TimeSpan]::Zero) }
            $subjects = @((Get-ADFineGrainedPasswordPolicy -Identity $pso -Server $pdc -Properties AppliesTo).AppliesTo)
            if ($subjects -notcontains $dn) { Add-ADFineGrainedPasswordPolicySubject -Identity $pso -Subjects $dn -Server $pdc }
            Start-Sleep -Seconds 2
            $s = Get-Snapshot $dn
            $via = Resolve-WriteVia $s
            foreach ($act in @('PneOff') + @(if (-not $s.Scril) { 'ScrilOn' }) + @('RandomReset')) {
                $r = Invoke-TestAction $act $dn $sam $via
                if (-not $r.Accepted) { throw "Preparation step $act failed ($via): $($r.Error)" }
            }
            Start-Sleep -Seconds 2
            $s = Get-Snapshot $dn
            if ($s.ResultantPso -notlike "CN=$name,*") { Write-Warning "Resultant policy of $sam is '$($s.ResultantPso)', not $name." }
            $baseline = [pscustomobject]@{
                Time = (Get-Date).ToString('s'); Dn = $dn; Sam = $sam; Via = $via; PsoName = $name; MaxAgeMinutes = $min
                PwdLastSet = $s.PwdLastSet.ToString('s'); ExpectedExpiry = $s.PwdLastSet.AddMinutes($min).ToString('s'); ExpiryComputed = Format-Expiry $s.ExpiryRaw
                SecretVersionMax = (@(Get-SecretAllDcs $dn) | Measure-Object -Property Version -Maximum).Maximum
                LastLogon = $(if (($ll = Get-LastLogonMax $dn)) { $ll.ToString('s') } else { $null })
            }
            $baseline | ConvertTo-Json | Set-Content -Path $baselinePath -Encoding UTF8
            $baseline | Format-List | Out-Host
            Write-Host ("Run -Suite RollingObserve after {0} (use -WaitForExpiry to wait automatically)." -f $baseline.ExpectedExpiry) -ForegroundColor Cyan
        }

        #----------------------------------------------------------------------------------------------
        'RollingObserve' {
            if (-not (Test-Path -Path $baselinePath)) { throw 'No baseline - run -Suite RollingPrepare first.' }
            $bl = Get-Content -Path $baselinePath -Raw | ConvertFrom-Json
            $dn = $bl.Dn; $exp = [datetime]$bl.ExpectedExpiry
            Write-SoaSection "RollingObserve on '$($bl.Sam)' - expected expiry $(Format-Time $exp)"
            if ((Get-Date) -lt $exp) {
                if (-not $WaitForExpiry) { Write-Host ("Not expired yet ({0:N0} min left). Re-run later or use -WaitForExpiry." -f ($exp - (Get-Date)).TotalMinutes) -ForegroundColor Yellow; break }
                while ((Get-Date) -lt $exp.AddMinutes(1)) { Write-Host ("  waiting for expiry: {0:N0} min left" -f [Math]::Max(0, ($exp.AddMinutes(1) - (Get-Date)).TotalMinutes)); Start-Sleep -Seconds 60 }
            }
            $atExpiry = Get-Snapshot $dn
            Write-Host ("At expiry: PE flag={0}, computed expiry={1}, SCRIL={2}, PNE={3}, secret version {4}, pwdLastSet {5}" -f $atExpiry.PeFlag, (Format-Expiry $atExpiry.ExpiryRaw), $atExpiry.Scril, $atExpiry.Pne, $atExpiry.SecretVersion, (Format-Time $atExpiry.PwdLastSet))
            Write-Host ''
            Write-Host "MANUAL STEP - within $WaitMinutes minutes, as $($bl.Sam):" -ForegroundColor Yellow
            Write-Host '  1. Sign in (or lock + unlock) on an Entra-joined / hybrid-joined device with Windows Hello for Business or a FIDO2 key.' -ForegroundColor Yellow
            Write-Host '  2. Open the AVD RemoteApp / desktop (SSO) and access an AD resource (e.g. \\server\share).' -ForegroundColor Yellow
            Read-Host 'Press Enter right before you start the sign-in' | Out-Null
            $obsStart = Get-Date; $deadline = $obsStart.AddMinutes($WaitMinutes); $logon = $null; $rolled = $null
            do {
                Start-Sleep -Seconds 20
                $ll = Get-LastLogonMax $dn; if ($ll -and $ll -gt $obsStart) { $logon = $ll }
                $hit = @(Get-SecretAllDcs $dn) | Where-Object { $_.Version -gt [int]$atExpiry.SecretVersion } | Sort-Object Version -Descending | Select-Object -First 1
                if ($hit) { $rolled = $hit }
                Write-Host ("  {0:HH:mm:ss}  logon recorded: {1}  secret changed: {2}" -f (Get-Date), $(if ($logon) { Format-Time $logon } else { 'no' }), $(if ($rolled) { "yes (origin $($rolled.Origin))" } else { 'no' }))
                if ($logon -and $rolled) { break }
            } while ((Get-Date) -lt $deadline)
            $ok = (Read-Host 'Did the sign-in AND the access to the AD resource succeed? (y/n)') -match '^(y|j)'
            Start-Sleep -Seconds 20
            $after = Get-Snapshot $dn
            $plsMoved = $after.PwdLastSetRaw -ne $atExpiry.PwdLastSetRaw
            $verdict = if (-not $ok) { 'FAIL: passwordless sign-in / AD access failed after expiry.' }
                       elseif ($rolled) { "PASS: sign-in worked and a DC rolled the secret ($($rolled.Origin), $($rolled.Time)) - automatic rolling is triggered by this sign-in path." }
                       elseif ($logon) { 'WARN: sign-in worked after expiry, but this sign-in path did NOT roll the secret.' }
                       else { 'WARN: sign-in reported as successful but no logon was recorded - repeat.' }
            $v1 = if (-not $rolled) { 'n/a (no roll observed)' }
                  elseif ($plsMoved) { "YES - rolling updated pwdLastSet ($(Format-Time $atExpiry.PwdLastSet) -> $(Format-Time $after.PwdLastSet)); PE flag now $($after.PeFlag), new expiry $(Format-Expiry $after.ExpiryRaw)" }
                  else { "NO - pwdLastSet unchanged ($(Format-Time $after.PwdLastSet)); PE flag $($after.PeFlag) - every sign-in rolls again" }
            Write-Host $verdict -ForegroundColor $(if ($verdict -like 'FAIL*') { 'Red' } elseif ($verdict -like 'PASS*') { 'Green' } else { 'Yellow' })
            Write-Host "Rolling updates pwdLastSet: $v1" -ForegroundColor Cyan
            $summary = @($verdict, "Rolling updates pwdLastSet: $v1", "At expiry: PE flag $($atExpiry.PeFlag), computed expiry $(Format-Expiry $atExpiry.ExpiryRaw)",
                         "Logon recorded: $(if ($logon) { Format-Time $logon } else { 'no' }); secret rolled: $(if ($rolled) { "yes, origin $($rolled.Origin) at $($rolled.Time)" } else { 'no' })")
            Save-Finding 'Rolling' (New-Finding "Automatic rolling observation on $($bl.Sam)" $summary ([ordered]@{ 'Secret per DC' = @(Get-SecretAllDcs $dn) }))
            Save-TestResult 'Rolling' $(if ($verdict -like 'PASS*') { 'PASS' } elseif ($verdict -like 'FAIL*') { 'FAIL' } else { 'WARN' }) ("$verdict | pwdLastSet updated: $v1")
            Write-Report
            Write-Host 'Run -Suite RollingCleanup when done.' -ForegroundColor Cyan
        }

        #----------------------------------------------------------------------------------------------
        'RollingCleanup' {
            $tu = Get-TestUser; $name = $cfg.RollingTestPsoName
            Write-SoaSection "RollingCleanup on '$($tu.SamAccountName)'"
            $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -Server $pdc
            if ($pso) { Remove-ADFineGrainedPasswordPolicy -Identity $pso -Server $pdc -Confirm:$false; Write-SoaLine DEL "PSO $name removed" }
            Remove-Item -Path $baselinePath -Force -ErrorAction SilentlyContinue
            $s = Get-Snapshot $tu.DistinguishedName
            Write-Host ("Resultant policy now {0}; SCRIL={1}, pwdLastSet={2}, computed expiry={3}" -f $(if ($s.ResultantPso) { $s.ResultantPso } else { '(domain)' }), $s.Scril, (Format-Time $s.PwdLastSet), (Format-Expiry $s.ExpiryRaw))
        }

        #----------------------------------------------------------------------------------------------
        'Onboarding' {
            $tu = Get-TestUser; $dn = $tu.DistinguishedName; $sam = $tu.SamAccountName
            Write-SoaSection "Onboarding / reconcile on '$sam'"
            foreach ($act in 'ScrilOff', 'PneOn', 'GroupRemove') {
                $r = Invoke-TestAction $act $dn $sam 'Job'
                Write-SoaLine $(if ($r.Accepted) { 'INFO' } else { 'FAIL' }) "toolkit identity: $act $(if (-not $r.Accepted) { "- $($r.Error)" })"
            }
            $b = Get-Snapshot $dn
            Write-Host ("Deviation created: SCRIL={0}, PNE={1}, PSO group={2}" -f $b.Scril, $b.Pne, $b.InPsoGroup)
            $run = Invoke-AsToolkit -Arguments '-Mode Apply -Trigger Manual' -StatusName 'conformance' -TimeoutMinutes 10
            Start-Sleep -Seconds 3
            $a = Get-Snapshot $dn
            $ok = $a.Scril -and -not $a.Pne -and $a.InPsoGroup
            $detail = "reconcile on $($run.Host): success=$($run.Success); after: SCRIL=$($a.Scril), PNE=$($a.Pne), PSO group=$($a.InPsoGroup), secret re-randomized=$($a.SecretVersion -gt $b.SecretVersion)$(if (-not $run.Success) { "; errors: $($run.Errors)" })"
            if (-not $ok) { foreach ($act in @(if (-not $a.Scril) { 'ScrilOn' }) + @(if ($a.Pne) { 'PneOff' }) + @(if (-not $a.InPsoGroup) { 'GroupAdd' })) { [void](Invoke-TestAction $act $dn $sam 'Job') } }
            Save-TestResult 'Onboarding' $(if ($ok) { 'PASS' } else { 'FAIL' }) $detail
            Save-Finding 'Onboarding' (New-Finding "Onboarding / reconcile on $sam" @($detail) $null)
            Write-Report
        }

        #----------------------------------------------------------------------------------------------
        'Enforcement' {
            $tu = Get-TestUser; $dn = $tu.DistinguishedName; $sam = $tu.SamAccountName
            $mode = Get-SoaPolicyMode -Context $ctx
            Write-SoaSection ("Enforcement on '{0}' - policy mode {1} - marked {2}" -f $sam, $(if ($mode) { $mode } else { 'NO POLICY' }), (@($tu.'msDS-ObjectSoa') -join ','))
            $r = Invoke-TestAction 'ProbeWrite' $dn $sam 'Job'
            Save-TestResult 'ProbeAllowed' $(if ($r.Accepted) { 'PASS' } else { 'FAIL' }) $(if ($r.Accepted) { 'toolkit identity wrote to the marked TestUser - allow-list works' } else { "toolkit write failed: $($r.Error)" })
            $accepted = @(); $blocked = @(); $firstError = $null
            foreach ($dc in $dcs) {
                try { Set-ADUser -Identity $dn -Server $dc -Replace @{ info = "SOA Toolkit unauthorized probe $(Get-Date -Format s)" }; $accepted += $dc; try { Set-ADUser -Identity $dn -Server $dc -Clear info } catch { } }
                catch { $blocked += $dc; if (-not $firstError) { $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }; $firstError = $e.Message } }
            }
            if ($mode -eq 'Enforced') {
                Save-TestResult 'UnauthorizedWrite' $(if ($accepted.Count) { 'FAIL' } else { 'PASS' }) $(if ($accepted.Count) { "change ACCEPTED on $($accepted -join ', ') - enforcement not effective there (or your account is allow-listed)" } else { "blocked on all $($blocked.Count) writable DC(s): $firstError" })
            } else {
                Save-TestResult 'UnauthorizedWrite' 'INFO' ("mode {0}: accepted on {1}, blocked on {2} - in Audit mode expect event 3097 on each DC" -f $mode, ($accepted -join ', '), ($blocked -join ', '))
            }
            Save-Finding 'Enforcement' (New-Finding "Enforcement tests on $sam (mode $mode)" @("Toolkit write: $($r.Accepted)", "Your write accepted on: $($accepted -join ', ')", "Blocked on: $($blocked -join ', ')") $null)
            Write-Report
        }

        #----------------------------------------------------------------------------------------------
        'Logon' {
            $tu = Get-TestUser; $sam = $tu.SamAccountName
            $start = Get-Date
            Write-SoaSection "Logon test as $($tu.userPrincipalName)"
            Write-Host "MANUAL STEP - within $WaitMinutes minutes: sign in with WHfB / FIDO2 and open the AVD RemoteApp / an AD file share." -ForegroundColor Yellow
            $logon = $null; $deadline = $start.AddMinutes($WaitMinutes)
            do { Start-Sleep -Seconds 20; $ll = Get-LastLogonMax $tu.DistinguishedName; if ($ll -and $ll -gt $start) { $logon = $ll } } while (-not $logon -and (Get-Date) -lt $deadline)
            $fails = @(foreach ($dc in $dcs) {
                $res = Invoke-SoaOnHost -ComputerName $dc -ArgumentList $sam, ([int64]((Get-Date) - $start).TotalMilliseconds + 60000) -ScriptBlock {
                    param($Sam, $Ms)
                    $xp = "*[System[(EventID=4768 or EventID=4771) and TimeCreated[timediff(@SystemTime) <= $Ms]] and EventData[Data[@Name='Status']!='0x0']]"
                    @(Get-WinEvent -LogName Security -FilterXPath $xp -ErrorAction SilentlyContinue) | ForEach-Object {
                        $d = @{}; foreach ($n in ([xml]$_.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
                        if ((("$($d.TargetUserName)" -split '@')[0]) -ieq $Sam) { "$($d.Status)".ToLower() }
                    }
                }
                if ($res.Ok) { @($res.Result) }
            })
            $critical = @($fails | Where-Object { $_ -in '0x17', '0x12' })
            $failText = (($fails | Group-Object | ForEach-Object { '{0} ({1}) x{2}' -f $_.Name, $KerbStatus[$_.Name], $_.Count }) -join ', ')
            if ($logon -and -not $critical.Count) { Save-TestResult 'Logon' 'PASS' "logon recorded at $logon; Kerberos failures: $(if ($failText) { $failText } else { 'none' })" }
            elseif ($critical.Count) { Save-TestResult 'Logon' 'FAIL' "Kerberos failures $failText; logon recorded: $(if ($logon) { $logon } else { 'no' })" }
            else { Save-TestResult 'Logon' 'WARN' "no logon recorded within $WaitMinutes min - repeat" }
        }

        'Report' { Write-Report }
    }
}
