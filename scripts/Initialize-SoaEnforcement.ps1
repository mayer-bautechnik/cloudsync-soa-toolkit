#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Rollout step 5 for Entra Cloud Sync AD object enforcement: identities that may still write to enforced
    objects (job gMSA, break-glass), their least-privilege delegation, the SOA policy allow-list, the SCRIL job,
    verification of the policy load on every DC, and the mode switch Audit <-> Enforced.

.DESCRIPTION
    Each step is idempotent; run them in this order (several steps per call are executed in this order):

      CreateJobGmsa     gMSA for the SCRIL job; allowed for JobHost, installed and tested on JobHost
      DelegateJob       minimal ACLs for the job gMSA on TargetUserOUs:
                          Write userAccountControl (SCRIL) + Reset Password (RotationMethod RandomReset)
                          (+ Modify permissions if EnforceDenyChangePassword)
                        + full control on the TestUser object only (for the validation tests)
                        >> run BEFORE switching to Enforced (the test user is an enforced object)
      CreateBreakGlass  DISABLED emergency account (password prompted, Protected Users, not delegable)
                        with full control on TargetUserOUs + TargetGroupOUs
      AllowList         adds the Cloud Sync agent gMSA(s), job gMSA and break-glass SID to msDS-Settings of
                        CN=Cloud. Validates every SID first; stale SIDs make the whole policy fail to load.
      DeployJob         copies Invoke-ScrilJob.ps1 + config to JobHost, grants the gMSA "Log on as a batch job"
                        and write access to JobDataPath, registers the tasks
                          \SoaEnforcement\Enforce SCRIL      (every JobIntervalMinutes)
                          \SoaEnforcement\Rotate SCRIL secret (daily at RotationTime)
                        (a task 'Rotate SCRIL hash' registered by earlier versions is removed)
      Verify            replication of CN=Cloud to every writable DC + policy-load events (3095) per DC
      SetMode           -Mode Audit|Enforced: writes 'keywords' on CN=Cloud (pre-checks unless -Force),
                        waits for replication and shows the policy-load events

    Prerequisite: CN=Cloud created by Microsoft's Set-CloudSyncSOAPolicy.ps1 (run it once with -EnforcementMode Audit).
    Note: Set-CloudSyncSOAPolicy.ps1 does NOT change an existing policy (it returns "already exists. No changes
    were made.") although the Microsoft documentation says to re-run it to switch the mode (README, upstream
    finding F1). The mode is therefore switched here by writing the 'keywords' attribute of CN=Cloud directly.

.EXAMPLE
    .\Initialize-SoaEnforcement.ps1 -Step CreateJobGmsa, DelegateJob, CreateBreakGlass, AllowList, DeployJob, Verify
    .\Initialize-SoaEnforcement.ps1 -Step SetMode -Mode Enforced
    .\Initialize-SoaEnforcement.ps1 -Step SetMode -Mode Audit          # rollback
    .\Initialize-SoaEnforcement.ps1 -Step Verify -Since (Get-Date).AddMinutes(-30)

.NOTES
    Toolkit: cloudsync-ad-enforcement-toolkit 1.0.0 (2026-10-19)
    Run as Domain Admin from a host with RSAT. Supports -WhatIf / -Confirm.
    WinRM to DCs, AgentHosts and JobHost required.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('CreateJobGmsa', 'DelegateJob', 'CreateBreakGlass', 'AllowList', 'DeployJob', 'Verify', 'SetMode')]
    [string[]] $Step,

    [ValidateSet('Audit', 'Enforced')]
    [string] $Mode,

    [switch] $RemoveStaleSids,

    [switch] $Force,

    [datetime] $Since = (Get-Date).AddHours(-2),

    [string] $ConfigPath = (Join-Path $PSScriptRoot 'SoaEnforcement.config.psd1')
)

$ErrorActionPreference = 'Stop'

#region --- Context --------------------------------------------------------------------------------
$cfg      = Import-PowerShellDataFile -Path $ConfigPath
$Cmdlet   = $PSCmdlet
$domain   = Get-ADDomain
$dnsRoot  = $domain.DNSRoot
$netbios  = $domain.NetBIOSName
$pdc      = $domain.PDCEmulator
$domainDN = $domain.DistinguishedName
$policyDN = "CN=Cloud,CN=SOA-Policies,CN=System,$domainDN"
$dcs      = @(Get-ADDomainController -Filter * -Server $pdc | Where-Object { -not $_.IsReadOnly } | Sort-Object HostName | ForEach-Object { $_.HostName })
$TaskPath = '\SoaEnforcement\'
$MinNtdsai = @{ 20348 = [version]'10.0.20348.5257'; 26100 = [version]'10.0.26100.32995' }

$Guid = @{
    UserClass  = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
    GroupClass = [guid]'bf967a9c-0de6-11d0-a285-00aa003049e2'
    UacAttr    = [guid]'bf967a68-0de6-11d0-a285-00aa003049e2'
    ResetPwd   = [guid]'00299570-246d-11d0-a768-00aa006e0529'
}

# AD: drive bound to the PDC emulator for all ACL operations
if (-not (Get-PSDrive -Name SOAAD -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name SOAAD -PSProvider ActiveDirectory -Root '//RootDSE/' -Server $pdc -Scope Script | Out-Null
}
#endregion

#region --- Helpers --------------------------------------------------------------------------------
function Write-Step([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 96) -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 96) -ForegroundColor DarkCyan
}

function Resolve-SidName([string]$Sid) {
    try {
        $o = Get-ADObject -Server $pdc -LDAPFilter "(objectSid=$Sid)" -Properties sAMAccountName
        if ($o) { return "$netbios\$($o.sAMAccountName)" }
    } catch { }
    return $null
}

function Get-Policy {
    try { Get-ADObject -Identity $policyDN -Server $pdc -Properties keywords, 'msDS-Settings', whenChanged }
    catch { $null }
}

function Get-JobGmsa {
    try { Get-ADServiceAccount -Identity $cfg.JobGmsaName -Server $pdc } catch { $null }
}

function Get-BreakGlass {
    Get-ADUser -Filter "SamAccountName -eq '$($cfg.BreakGlassName)'" -Server $pdc
}

function Get-AgentGmsas {
    $names = @(Invoke-Command -ComputerName $cfg.AgentHosts -ErrorAction Continue -ScriptBlock {
        (Get-CimInstance -ClassName Win32_Service -Filter "Name='AADConnectProvisioningAgent'").StartName
    })
    foreach ($n in @($names | Where-Object { $_ } | ForEach-Object { "$_" } | Select-Object -Unique)) {
        $sam = ($n -split '\\')[-1]
        if ($sam -notlike '*$') { $sam += '$' }
        $acc = Get-ADServiceAccount -Filter "SamAccountName -eq '$sam'" -Server $pdc
        if ($acc) { [pscustomobject]@{ Name = $sam; Sid = $acc.SID.Value } }
        else { Write-Warning "Provisioning agent runs as '$n', which is not a gMSA of this domain." }
    }
}

function Add-AdAce {
    param(
        [string] $TargetDn,
        [Security.Principal.SecurityIdentifier] $Sid,
        [DirectoryServices.ActiveDirectoryRights] $Rights,
        [guid] $ObjectType = [guid]::Empty,
        [DirectoryServices.ActiveDirectorySecurityInheritance] $Inheritance = 'None',
        [guid] $InheritedObjectType = [guid]::Empty,
        [string] $Label
    )
    $path  = "SOAAD:\$TargetDn"
    $acl   = Get-Acl -Path $path
    $exist = $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.IdentityReference -eq $Sid -and "$($_.AccessControlType)" -eq 'Allow' -and
        (($_.ActiveDirectoryRights -band $Rights) -eq $Rights) -and $_.ObjectType -eq $ObjectType -and
        $_.InheritanceType -eq $Inheritance -and $_.InheritedObjectType -eq $InheritedObjectType
    }
    if ($exist) { Write-Host "  = present : $Label  [$TargetDn]" -ForegroundColor DarkGray; return }
    if ($Cmdlet.ShouldProcess($TargetDn, "Grant $Label")) {
        $acl.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($Sid, $Rights, 'Allow', $ObjectType, $Inheritance, $InheritedObjectType)))
        Set-Acl -Path $path -AclObject $acl
        Write-Host "  + granted : $Label  [$TargetDn]" -ForegroundColor Green
    }
}

function ConvertTo-PlainText([securestring]$Secure) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

# Replication state of CN=Cloud + SOA events per writable DC
function Get-PolicyState([datetime]$From) {
    $ref = Get-Policy
    $refMode = if ($ref) { (@($ref.keywords) -join ',') } else { $null }
    $refSids = if ($ref) { (@($ref.'msDS-Settings' | ForEach-Object { "$_" }) | Sort-Object) -join ';' } else { $null }

    $remote = @(Invoke-Command -ComputerName $dcs -ArgumentList $From -ErrorAction Continue -ScriptBlock {
        param([datetime]$From)
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 3095, 3097, 3098; StartTime = $From } -ErrorAction SilentlyContinue)
        $p  = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ErrorAction SilentlyContinue
        $vi = (Get-Item -Path (Join-Path $env:windir 'System32\ntdsai.dll')).VersionInfo
        $loads = @($ev | Where-Object { $_.Id -eq 3095 } | Select-Object -First 3 | ForEach-Object {
            $m = $_.Message -replace '\s+', ' '
            [pscustomobject]@{ Time = $_.TimeCreated; Level = [int]$_.Level; Message = $(if ($m.Length -gt 300) { $m.Substring(0, 300) + '...' } else { $m }) }
        })
        [pscustomobject]@{
            Build     = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild
            Ntdsai    = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
            DiagLevel = $(if ($p -and ($p.PSObject.Properties.Name -contains '2 Security Events')) { [int]$p.'2 Security Events' } else { $null })
            Loads     = $loads
            Audit     = @($ev | Where-Object { $_.Id -eq 3097 }).Count
            Blocked   = @($ev | Where-Object { $_.Id -eq 3098 }).Count
        }
    })

    foreach ($dc in $dcs) {
        $r = $remote | Where-Object { $_.PSComputerName -eq $dc } | Select-Object -First 1
        $local = $null
        try { $local = Get-ADObject -Identity $policyDN -Server $dc -Properties keywords, 'msDS-Settings' } catch { }
        $mode = if ($local) { (@($local.keywords) -join ',') } else { $null }
        $sids = if ($local) { (@($local.'msDS-Settings' | ForEach-Object { "$_" }) | Sort-Object) -join ';' } else { $null }
        $last = if ($r) { $r.Loads | Select-Object -First 1 } else { $null }
        $loadStatus = if (-not $r) { 'NO DATA' }
                      elseif (-not $last) { 'NONE' }
                      elseif ($last.Level -in 1, 2, 3 -or $last.Message -match '(?i)fail|invalid|unable|could not|error') { 'ERROR' }
                      else { 'OK' }
        $ntdsOk = $null
        if ($r -and $MinNtdsai.ContainsKey([int]$r.Build)) { $ntdsOk = ([version]$r.Ntdsai -ge $MinNtdsai[[int]$r.Build]) }
        [pscustomobject]@{
            DC          = $dc
            Replicated  = ($local -and $mode -eq $refMode -and $sids -eq $refSids)
            Mode        = $mode
            SidCount    = $(if ($local) { @($local.'msDS-Settings').Count } else { 0 })
            NtdsaiOk    = $ntdsOk
            DiagLevel   = $(if ($r) { $r.DiagLevel } else { $null })
            LastLoad    = $(if ($last) { $last.Time } else { $null })
            LoadStatus  = $loadStatus
            LoadMessage = $(if ($last) { $last.Message } else { $null })
            Audit3097   = $(if ($r) { $r.Audit } else { $null })
            Block3098   = $(if ($r) { $r.Blocked } else { $null })
        }
    }
}

function Show-PolicyState($State) {
    $State | Format-Table DC, Replicated, Mode, SidCount, NtdsaiOk, DiagLevel, LastLoad, LoadStatus, Audit3097, Block3098 -AutoSize | Out-Host
    foreach ($s in $State) {
        if ($s.LoadMessage) {
            $c = if ($s.LoadStatus -eq 'OK') { 'Gray' } else { 'Red' }
            Write-Host ("  {0} last 3095: {1}" -f $s.DC, $s.LoadMessage) -ForegroundColor $c
        }
    }
}
#endregion

$order = 'CreateJobGmsa', 'DelegateJob', 'CreateBreakGlass', 'AllowList', 'DeployJob', 'Verify', 'SetMode'
foreach ($current in ($order | Where-Object { $Step -contains $_ })) {
    switch ($current) {

        #----------------------------------------------------------------------------------------------
        'CreateJobGmsa' {
            Write-Step "CreateJobGmsa: $($cfg.JobGmsaName) for $($cfg.JobHost)"
            try { if (-not (Get-KdsRootKey)) { throw 'No KDS root key in the forest - create one first (Add-KdsRootKey).' } }
            catch [System.Management.Automation.CommandNotFoundException] { Write-Warning 'Get-KdsRootKey not available here - KDS root key not checked.' }

            $hostComputer = Get-ADComputer -Identity (($cfg.JobHost -split '\.')[0]) -Server $pdc
            $gmsa = Get-JobGmsa
            if (-not $gmsa) {
                if ($Cmdlet.ShouldProcess($cfg.JobGmsaName, 'Create gMSA')) {
                    New-ADServiceAccount -Name $cfg.JobGmsaName -DNSHostName "$($cfg.JobGmsaName).$dnsRoot" -Server $pdc `
                        -PrincipalsAllowedToRetrieveManagedPassword $hostComputer -KerberosEncryptionType AES128, AES256 `
                        -Description 'SOA enforcement: SCRIL job identity (allow-listed in CN=Cloud msDS-Settings)'
                    Write-Host "  + gMSA $($cfg.JobGmsaName) created" -ForegroundColor Green
                }
            } else {
                $allowedHosts = @((Get-ADServiceAccount -Identity $cfg.JobGmsaName -Server $pdc -Properties PrincipalsAllowedToRetrieveManagedPassword).PrincipalsAllowedToRetrieveManagedPassword)
                if ($allowedHosts -notcontains $hostComputer.DistinguishedName -and $Cmdlet.ShouldProcess($cfg.JobGmsaName, "Allow $($hostComputer.Name) to retrieve the password")) {
                    Set-ADServiceAccount -Identity $cfg.JobGmsaName -Server $pdc -PrincipalsAllowedToRetrieveManagedPassword (@($allowedHosts) + $hostComputer.DistinguishedName)
                }
                Write-Host "  = gMSA $($cfg.JobGmsaName) exists" -ForegroundColor DarkGray
            }

            if (-not $WhatIfPreference) {
                $ok = $false
                for ($i = 1; $i -le 10 -and -not $ok; $i++) {
                    try {
                        $ok = Invoke-Command -ComputerName $cfg.JobHost -ArgumentList $cfg.JobGmsaName -ScriptBlock {
                            param($Name)
                            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { throw 'RSAT AD PowerShell missing on the job host (Install-WindowsFeature RSAT-AD-PowerShell).' }
                            & klist.exe -li 0x3e7 purge | Out-Null          # refresh the computer's group memberships / tickets
                            Install-ADServiceAccount -Identity $Name
                            Test-ADServiceAccount -Identity $Name
                        }
                    } catch {
                        if ($_.Exception.Message -match 'RSAT') { throw }
                        Write-Host "  waiting for AD replication to the job host's DC ($i/10) ..." -ForegroundColor Yellow
                        Start-Sleep -Seconds 30
                    }
                }
                if ($ok) { Write-Host "  + gMSA installed and tested on $($cfg.JobHost)" -ForegroundColor Green }
                else { Write-Warning "Test-ADServiceAccount on $($cfg.JobHost) did not succeed - check replication / host group membership." }
            }
        }

        #----------------------------------------------------------------------------------------------
        'DelegateJob' {
            Write-Step "DelegateJob: least-privilege ACLs for $($cfg.JobGmsaName)"
            $gmsa = Get-JobGmsa
            if (-not $gmsa) { throw "gMSA $($cfg.JobGmsaName) not found - run -Step CreateJobGmsa first." }
            $pol = Get-Policy
            if ($pol -and (@($pol.keywords) -contains 'Enforced')) {
                Write-Warning 'Policy is Enforced: ACL changes on enforced objects (TestUser) will be blocked for your account. OU ACLs still work.'
            }
            foreach ($ou in $cfg.TargetUserOUs) {
                Add-AdAce $ou $gmsa.SID 'WriteProperty' $Guid.UacAttr  'Descendents' $Guid.UserClass 'Write userAccountControl (descendant users)'
                Add-AdAce $ou $gmsa.SID 'ExtendedRight' $Guid.ResetPwd 'Descendents' $Guid.UserClass 'Reset Password (descendant users)'
                if ($cfg.EnforceDenyChangePassword) {
                    Add-AdAce $ou $gmsa.SID 'WriteDacl' ([guid]::Empty) 'Descendents' $Guid.UserClass 'Modify permissions (descendant users)'
                }
            }
            if ($cfg.TestUser) {
                $tu = Get-ADUser -Identity $cfg.TestUser -Server $pdc
                Add-AdAce $tu.DistinguishedName $gmsa.SID 'GenericAll' ([guid]::Empty) 'None' ([guid]::Empty) 'Full control (TestUser only - validation tests)'
            }
        }

        #----------------------------------------------------------------------------------------------
        'CreateBreakGlass' {
            Write-Step "CreateBreakGlass: $($cfg.BreakGlassName)"
            $bg = Get-BreakGlass
            if (-not $bg) {
                if ($Cmdlet.ShouldProcess($cfg.BreakGlassName, 'Create DISABLED break-glass account')) {
                    $p1 = Read-Host -AsSecureString "Password for $($cfg.BreakGlassName) (store it in your vault; account stays disabled)"
                    $p2 = Read-Host -AsSecureString 'Confirm password'
                    if ((ConvertTo-PlainText $p1) -cne (ConvertTo-PlainText $p2)) { throw 'Passwords do not match.' }
                    New-ADUser -Name $cfg.BreakGlassName -SamAccountName $cfg.BreakGlassName -UserPrincipalName "$($cfg.BreakGlassName)@$dnsRoot" `
                        -Path $cfg.BreakGlassOU -AccountPassword $p1 -Enabled $false -AccountNotDelegated $true -Server $pdc `
                        -Description 'Break-glass: allow-listed in SOA policy (CN=Cloud). Keep DISABLED; enable only if cloud provisioning is unavailable.'
                    Add-ADGroupMember -Identity "$($domain.DomainSID.Value)-525" -Members $cfg.BreakGlassName -Server $pdc   # Protected Users
                    $bg = Get-BreakGlass
                    Write-Host "  + $($cfg.BreakGlassName) created (disabled, Protected Users, not delegable)" -ForegroundColor Green
                }
            } else {
                Write-Host ("  = {0} exists (enabled: {1})" -f $bg.SamAccountName, $bg.Enabled) -ForegroundColor DarkGray
            }
            if ($bg) {
                foreach ($ou in @($cfg.TargetUserOUs) + @($cfg.TargetGroupOUs)) {
                    Add-AdAce $ou $bg.SID 'GenericAll' ([guid]::Empty) 'Descendents' ([guid]::Empty) 'Full control (descendant objects)'
                }
            }
        }

        #----------------------------------------------------------------------------------------------
        'AllowList' {
            Write-Step 'AllowList: msDS-Settings of CN=Cloud'
            $pol = Get-Policy
            if (-not $pol) { throw "CN=Cloud not found. Run Microsoft's Set-CloudSyncSOAPolicy.ps1 -EnforcementMode Audit on an agent host first." }

            $wanted = [ordered]@{}
            foreach ($a in @(Get-AgentGmsas)) { $wanted[$a.Sid] = "Cloud Sync agent ($($a.Name))" }
            $j = Get-JobGmsa
            if ($j) { $wanted[$j.SID.Value] = "SCRIL job ($($j.SamAccountName))" } else { Write-Warning 'Job gMSA not found - not added.' }
            $bg = Get-BreakGlass
            if ($bg) { $wanted[$bg.SID.Value] = "Break-glass ($($bg.SamAccountName))" } else { Write-Warning 'Break-glass account not found - not added.' }
            if (-not @($wanted.Keys | Where-Object { $_ -like 'S-1-5-21-*' }).Count) { throw 'No agent SID could be determined - aborting.' }

            $current = @($pol.'msDS-Settings' | Where-Object { $_ } | ForEach-Object { "$_" })
            $rows = foreach ($s in $current) {
                $n = Resolve-SidName $s
                [pscustomobject]@{ Sid = $s; Name = $n; State = $(if ($n) { 'OK' } else { 'STALE' }); Role = $(if ($wanted.Contains($s)) { $wanted[$s] } else { 'other' }) }
            }
            Write-Host 'Current allow-list:'
            $rows | Format-Table Sid, Name, Role, State -AutoSize | Out-Host

            $stale = @($rows | Where-Object { $_.State -eq 'STALE' })
            if ($stale.Count) {
                if ($RemoveStaleSids) {
                    if ($Cmdlet.ShouldProcess($policyDN, "Remove stale SIDs $($stale.Sid -join ', ')")) {
                        Set-ADObject -Identity $policyDN -Server $pdc -Remove @{ 'msDS-Settings' = [string[]]$stale.Sid }
                        Write-Host "  - removed stale SID(s): $($stale.Sid -join ', ')" -ForegroundColor Green
                    }
                } else {
                    Write-Warning ("Stale SID(s) {0}: the policy fails to load while they are present (nobody authorized). Re-run with -RemoveStaleSids." -f ($stale.Sid -join ', '))
                }
            }

            $missing = @($wanted.Keys | Where-Object { $current -notcontains $_ })
            foreach ($m in $missing) {
                if (-not (Resolve-SidName $m)) { throw "SID $m ($($wanted[$m])) does not resolve - not adding it." }
            }
            if (($current.Count - $stale.Count + $missing.Count) -gt 64) { throw 'The allow-list would exceed the documented maximum of 64 SIDs.' }
            if ($missing.Count) {
                if ($Cmdlet.ShouldProcess($policyDN, "Add $($missing.Count) SID(s) to msDS-Settings")) {
                    Set-ADObject -Identity $policyDN -Server $pdc -Add @{ 'msDS-Settings' = [string[]]$missing }
                    foreach ($m in $missing) { Write-Host "  + added $m  ($($wanted[$m]))" -ForegroundColor Green }
                    Write-Host '  Next: -Step Verify (replication + policy-load event 3095 on every DC).' -ForegroundColor Cyan
                }
            } else {
                Write-Host '  = all required SIDs already present' -ForegroundColor DarkGray
            }
        }

        #----------------------------------------------------------------------------------------------
        'DeployJob' {
            Write-Step "DeployJob: SCRIL job on $($cfg.JobHost)"
            $gmsa = Get-JobGmsa
            if (-not $gmsa) { throw "gMSA $($cfg.JobGmsaName) not found." }
            $jobScript = Join-Path $PSScriptRoot 'Invoke-ScrilJob.ps1'
            if (-not (Test-Path $jobScript)) { throw "Invoke-ScrilJob.ps1 not found next to this script." }
            if (-not $Cmdlet.ShouldProcess($cfg.JobHost, 'Deploy job script, grant batch logon, register scheduled tasks')) { break }

            $session = New-PSSession -ComputerName $cfg.JobHost
            try {
                $scriptDir = Split-Path -Path $cfg.JobScriptPath -Parent
                Invoke-Command -Session $session -ArgumentList $scriptDir, $cfg.JobDataPath -ScriptBlock {
                    param($ScriptDir, $DataPath)
                    New-Item -Path $ScriptDir, $DataPath -ItemType Directory -Force | Out-Null
                }
                Copy-Item -Path $jobScript  -Destination $cfg.JobScriptPath -ToSession $session -Force
                Copy-Item -Path $ConfigPath -Destination (Join-Path $scriptDir 'SoaEnforcement.config.psd1') -ToSession $session -Force

                $out = Invoke-Command -Session $session -ScriptBlock {
                    param($GmsaUser, $GmsaSid, $ScriptPath, $DataPath, $IntervalMin, $RotationTime, $TaskPath)
                    $msg = @()

                    # Data folder: gMSA may write logs / status files
                    & icacls.exe $DataPath /grant ('*{0}:(OI)(CI)M' -f $GmsaSid) | Out-Null
                    $msg += "Modify on $DataPath granted"

                    # Script folder: only Administrators/SYSTEM may change the job script
                    $scriptDir = Split-Path -Path $ScriptPath -Parent
                    & icacls.exe $scriptDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' ('*{0}:(OI)(CI)RX' -f $GmsaSid) | Out-Null
                    $msg += "Script folder locked down (Administrators/SYSTEM full, gMSA read+execute)"

                    # "Log on as a batch job" for the gMSA
                    $tmp = Join-Path $env:TEMP ('secpol_{0}' -f [guid]::NewGuid().ToString('N'))
                    & secedit.exe /export /cfg "$tmp.inf" /areas USER_RIGHTS | Out-Null
                    $lines = [System.Collections.Generic.List[string]](Get-Content -Path "$tmp.inf")
                    $entry = "*$GmsaSid"
                    $idx   = $lines.FindIndex([Predicate[string]] { param($l) $l -like 'SeBatchLogonRight*' })
                    $changed = $false
                    if ($idx -ge 0) {
                        if ($lines[$idx] -notmatch [regex]::Escape($entry)) { $lines[$idx] = "$($lines[$idx]),$entry"; $changed = $true }
                    } else {
                        $pi = $lines.IndexOf('[Privilege Rights]')
                        if ($pi -lt 0) { $lines.Add('[Privilege Rights]'); $pi = $lines.Count - 1 }
                        $lines.Insert($pi + 1, "SeBatchLogonRight = $entry"); $changed = $true
                    }
                    if ($changed) {
                        Set-Content -Path "$tmp.inf" -Value $lines -Encoding Unicode
                        & secedit.exe /configure /db "$tmp.sdb" /cfg "$tmp.inf" /areas USER_RIGHTS /quiet | Out-Null
                        $msg += 'Log on as a batch job granted (local policy - a GPO defining this right would override it)'
                    } else { $msg += 'Log on as a batch job already granted' }
                    Remove-Item -Path "$tmp.*" -Force -ErrorAction SilentlyContinue

                    # Scheduled tasks
                    $principal = New-ScheduledTaskPrincipal -UserId $GmsaUser -LogonType Password
                    $settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
                    $argBase   = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $ScriptPath

                    $aE = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "$argBase -Mode Enforce"
                    $tE = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMin)
                    Register-ScheduledTask -TaskName 'Enforce SCRIL' -TaskPath $TaskPath -Action $aE -Trigger $tE -Principal $principal -Settings $settings -Force | Out-Null

                    $aR = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "$argBase -Mode Rotate"
                    $tR = New-ScheduledTaskTrigger -Daily -At $RotationTime
                    Register-ScheduledTask -TaskName 'Rotate SCRIL secret' -TaskPath $TaskPath -Action $aR -Trigger $tR -Principal $principal -Settings $settings -Force | Out-Null
                    if (Get-ScheduledTask -TaskName 'Rotate SCRIL hash' -TaskPath $TaskPath -ErrorAction SilentlyContinue) {
                        Unregister-ScheduledTask -TaskName 'Rotate SCRIL hash' -TaskPath $TaskPath -Confirm:$false
                        $msg += 'Legacy task "Rotate SCRIL hash" removed'
                    }
                    $msg += "Tasks registered: ${TaskPath}Enforce SCRIL (every $IntervalMin min), ${TaskPath}Rotate SCRIL secret (daily $RotationTime)"
                    $msg
                } -ArgumentList ('{0}\{1}$' -f $netbios, $cfg.JobGmsaName), $gmsa.SID.Value, $cfg.JobScriptPath, $cfg.JobDataPath,
                                 [int]$cfg.JobIntervalMinutes, $cfg.RotationTime, $TaskPath
                $out | ForEach-Object { Write-Host "  + $_" -ForegroundColor Green }
            } finally {
                Remove-PSSession -Session $session
            }
        }

        #----------------------------------------------------------------------------------------------
        'Verify' {
            Write-Step ("Verify: CN=Cloud replication and policy-load events since {0:yyyy-MM-dd HH:mm}" -f $Since)
            $state = @(Get-PolicyState $Since)
            Show-PolicyState $state
            if (@($state | Where-Object { -not $_.Replicated }).Count) { Write-Host 'Not yet replicated everywhere - re-run in a few minutes.' -ForegroundColor Yellow }
            if (@($state | Where-Object { $_.LoadStatus -eq 'ERROR' }).Count) { Write-Host 'POLICY LOAD ERROR on at least one DC - do NOT switch to Enforced.' -ForegroundColor Red }
            if (@($state | Where-Object { $_.LoadStatus -eq 'NONE' }).Count) { Write-Host 'No 3095 since -Since on some DCs (policy unchanged in that window or diagnostics level 0). Use an earlier -Since.' -ForegroundColor Yellow }
        }

        #----------------------------------------------------------------------------------------------
        'SetMode' {
            if (-not $Mode) { throw '-Mode Audit|Enforced is required for -Step SetMode.' }
            Write-Step "SetMode: $Mode"
            $pol = Get-Policy
            if (-not $pol) { throw 'CN=Cloud not found.' }

            if ($Mode -eq 'Enforced' -and -not $Force) {
                $problems = @()
                $current  = @($pol.'msDS-Settings' | Where-Object { $_ } | ForEach-Object { "$_" })
                foreach ($s in $current) { if (-not (Resolve-SidName $s)) { $problems += "stale SID in allow-list: $s" } }
                foreach ($a in @(Get-AgentGmsas)) { if ($current -notcontains $a.Sid) { $problems += "agent gMSA $($a.Name) not in allow-list" } }
                $j = Get-JobGmsa
                if (-not $j -or $current -notcontains $j.SID.Value) { $problems += 'job gMSA not in allow-list' }
                $state = @(Get-PolicyState ((Get-Date).AddDays(-7)))
                foreach ($s in $state) {
                    if (-not $s.Replicated)       { $problems += "$($s.DC): CN=Cloud not replicated" }
                    if ($s.NtdsaiOk -ne $true)    { $problems += "$($s.DC): ntdsai.dll below minimum / unsupported OS" }
                    if ($s.LoadStatus -ne 'OK')   { $problems += "$($s.DC): last policy load (3095, 7 days) = $($s.LoadStatus)" }
                }
                if ($problems.Count) {
                    $problems | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Red }
                    throw 'Pre-checks failed - fix the items above or use -Force.'
                }
                Write-Host '  Pre-checks passed (allow-list valid, agent + job present, replicated, policy loaded on all DCs).' -ForegroundColor Green
            }

            if ((@($pol.keywords) -join ',') -eq $Mode) { Write-Host "  = mode already $Mode" -ForegroundColor DarkGray }
            elseif ($Cmdlet.ShouldProcess($policyDN, "Set enforcement mode (keywords) to $Mode")) {
                $switchTime = Get-Date
                Set-ADObject -Identity $policyDN -Server $pdc -Replace @{ keywords = $Mode }
                Write-Host "  + keywords = $Mode written on $pdc" -ForegroundColor Green
                $deadline = (Get-Date).AddMinutes(5)
                do {
                    Start-Sleep -Seconds 15
                    $pending = @($dcs | Where-Object {
                        try { (@((Get-ADObject -Identity $policyDN -Server $_ -Properties keywords).keywords) -join ',') -ne $Mode } catch { $true }
                    })
                    if ($pending.Count) { Write-Host "  waiting for replication: $($pending -join ', ')" -ForegroundColor Yellow }
                } while ($pending.Count -and (Get-Date) -lt $deadline)
                Start-Sleep -Seconds 15
                Show-PolicyState @(Get-PolicyState $switchTime.AddMinutes(-1))
                Write-Host "Next: Watch-CloudUserPasswordless.ps1 -Mode Test -Tests All" -ForegroundColor Cyan
            }
        }
    }
}
