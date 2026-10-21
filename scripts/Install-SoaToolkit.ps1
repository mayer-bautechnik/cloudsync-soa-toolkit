#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Sets up the SOA Toolkit step by step: identities, Group Policies, AD object enforcement policy, password policy,
    delegation, scheduled tasks on every toolkit host, initial conformance and the enforcement mode.

.DESCRIPTION
    Every step is idempotent, supports -WhatIf and records what it created or changed (incl. previous values) in the
    install manifest (<ReportPath>\State\manifest.json) so that Uninstall-SoaToolkit.ps1 can restore the original state.
    Every object created carries the marker "[SoaToolkit] Managed by SOA Toolkit - do not modify manually".

    Steps (several per call are executed in this order):
      HostGroup       global group SOA-Toolkit-Hosts = Domain Controllers + agent hosts (may retrieve the gMSA password)
      Gmsa            toolkit identity (gMSA), tested on every toolkit host
      BatchLogonGpo   "Log on as a batch job" for the gMSA via GPO (DC OU; agent-host OUs if agents run on member
                      servers). User rights from GPOs are not merged: the GPO contains the CURRENT effective list + gMSA.
      KirGpo          feature enablement for AD object enforcement from Microsoft's Group Policy package(s):
                      -KirMsi2022 / -KirMsi2025. Extracts the MSI, copies ADMX/ADML to the central store, creates one
                      GPO per OS with a WMI filter on the build number. A DC restart is required afterwards.
      DiagnosticsGpo  NTDS diagnostics '2 Security Events' = 1 (events 3095/3097/3098) via Set-SoaDiagnosticsGpo.ps1
      AuditConfig     checks the effective audit policy on every DC; creates a GPO only for missing subcategories;
                      always sets the toolkit's own narrow SACL entry for writes to msDS-ObjectSoa on every write-scope
                      container (event 5136 = trigger for SOA-converted users); broader rules of others are reported,
                      never relied upon
      EnableRolling   msDS-ExpirePasswordsOnSmartCardOnlyAccounts = TRUE (only if not set; needs DFL >= 2016)
      Policy          CN=Cloud (AD object enforcement policy) in mode Audit - the same object Microsoft's
                      Set-CloudSyncSOAPolicy.ps1 creates, but the container CN=SOA-Policies is NOT created (it must
                      come from the enforcement engine on the PDC emulator). An existing policy is kept.
      Groups          SOA-CloudUsers-PSO (PSO target), SOA-CloudUsers-Exclude, SOA-CloudUsers-Pilot
      Pso             fine-grained password policy for cloud users (values from the config), applied to the PSO group
      BreakGlass      OPTIONAL disabled emergency account (only if BreakGlassName is set; not part of 'All')
      Delegate        least privilege for the gMSA: write userAccountControl on users in the write scope, write
                      member of the PSO group, read password settings, full control on TestUser only, Event Log Readers
      AllowList       msDS-Settings of CN=Cloud: all agent gMSAs + toolkit gMSA (+ break-glass); stale SIDs reported
      DeployTasks     copies the runtime scripts to every toolkit host (optional code signing), locks the folders,
                      creates the event log 'SoaToolkit' and registers the tasks:
                        writable DC : \SoaToolkit\CloudUserConformance-Event    (events 4720 / 5136 by the agent)
                        agent host  : \SoaToolkit\CloudUserConformance-Reconcile (every ReconcileMinutes, staggered)
                        every host  : \SoaToolkit\Monitor                        (every MonitorMinutes)
      Conform         initial analysis (read-only, as you) and - after confirmation - one reconcile run as the gMSA
      SetMode         -Mode Audit|Enforced (pre-checks unless -Force)
      RemoveLegacy    removes toolkit 1.x artefacts (job host tasks, legacy gMSA, legacy ACEs, renames the diagnostics GPO)
      Verify          policy replication + policy load per DC, then Watch-CloudUserConformance.ps1 -Scope All

    'All' = HostGroup, Gmsa, BatchLogonGpo, KirGpo (only if an MSI is given), DiagnosticsGpo, AuditConfig,
            EnableRolling, Policy, Groups, Pso, Delegate, AllowList, DeployTasks, Verify

.EXAMPLE
    .\Install-SoaToolkit.ps1 -Step All -KirMsi2025 C:\Install\ADEnforcement2025.msi -WhatIf
    .\Install-SoaToolkit.ps1 -Step All -KirMsi2025 C:\Install\ADEnforcement2025.msi
    # restart the DCs one at a time, then:
    .\Install-SoaToolkit.ps1 -Step Policy, AllowList, Verify
    .\Install-SoaToolkit.ps1 -Step Conform -WhatIf      # analysis only
    .\Install-SoaToolkit.ps1 -Step Conform
    .\Install-SoaToolkit.ps1 -Step SetMode -Mode Enforced

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.0.2 (2026-10-21)
    Run as Domain Admin from an admin workstation (PAW) with RSAT (ActiveDirectory, GroupPolicy).
    All AD and GPO writes go to the PDC emulator. WinRM (5985) to every writable DC and agent host is required.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('HostGroup', 'Gmsa', 'BatchLogonGpo', 'KirGpo', 'DiagnosticsGpo', 'AuditConfig', 'EnableRolling', 'Policy',
                 'Groups', 'Pso', 'BreakGlass', 'Delegate', 'AllowList', 'DeployTasks', 'Conform', 'SetMode', 'RemoveLegacy', 'Verify', 'All')]
    [string[]] $Step,

    [ValidateSet('Audit', 'Enforced')]
    [string] $Mode,

    [string] $KirMsi2022,
    [string] $KirMsi2025,
    [string] $KirPolicyName,

    [switch] $RemoveStaleSids,
    [switch] $Refresh,
    [switch] $Force,

    [datetime] $Since = (Get-Date).AddHours(-2),

    [string] $ConfigPath = (Join-Path $PSScriptRoot 'SoaToolkit.config.psd1')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SoaToolkit.psm1') -Force -DisableNameChecking

#region --- Context --------------------------------------------------------------------------------
$cfg      = Import-SoaConfig -Path $ConfigPath
$ctx      = Get-SoaContext
$Cmdlet   = $PSCmdlet
$pdc      = $ctx.Pdc
$G        = Get-SoaConstant 'Guid'
$S        = Get-SoaConstant 'Sid'
$drive    = Initialize-SoaAdDrive -Server $pdc
$manifest = Get-SoaManifest -Config $cfg
$roles    = @(Get-SoaHostRoles -Config $cfg -Context $ctx)
$ver      = Get-SoaVersion
$installLog = Join-Path (Join-Path $cfg.ReportPath 'State') ('install_{0:yyyyMMdd}.log' -f (Get-Date))
New-Item -Path (Split-Path $installLog -Parent) -ItemType Directory -Force | Out-Null

function Write-InstallLog([string]$Text) {
    Add-Content -Path $installLog -Value ('{0:s} {1} {2}' -f (Get-Date), [Security.Principal.WindowsIdentity]::GetCurrent().Name, $Text) -Encoding UTF8
}
function Save-Manifest { if (-not $WhatIfPreference) { Save-SoaManifest -Config $cfg -Manifest $manifest -Context $ctx } }
function Get-ToolkitGroup([string]$Name) { Get-ADGroup -Filter "Name -eq '$Name'" -Server $pdc -Properties description, info, member }

$order = 'HostGroup', 'Gmsa', 'BatchLogonGpo', 'KirGpo', 'DiagnosticsGpo', 'AuditConfig', 'EnableRolling', 'Policy', 'Groups',
         'Pso', 'BreakGlass', 'Delegate', 'AllowList', 'DeployTasks', 'Conform', 'SetMode', 'RemoveLegacy', 'Verify'
if ($Step -contains 'All') {
    $Step = @('HostGroup', 'Gmsa', 'BatchLogonGpo', 'DiagnosticsGpo', 'AuditConfig', 'EnableRolling', 'Policy', 'Groups', 'Pso',
              'Delegate', 'AllowList', 'DeployTasks', 'Verify') + @($Step | Where-Object { $_ -ne 'All' })
    if ($KirMsi2022 -or $KirMsi2025) { $Step += 'KirGpo' }
}

# Run log (evaluated by Export-SoaReport.ps1: idempotency, planned vs. applied changes)
$runId = [guid]::NewGuid().ToString('N').Substring(0, 8)
Write-InstallLog ("RUN {0} START tool=Install version={1} steps={2} whatif={3}" -f $runId, $ver.Version, ((@($Step) | Select-Object -Unique) -join ','), [bool]$WhatIfPreference)
Set-SoaLineLog -Path $installLog -Prefix "RUN $runId"

Write-SoaSection ("SOA Toolkit {0} - Install - domain {1} - PDC emulator {2}" -f $ver.Version, $ctx.DnsRoot, $pdc)
Write-Host ("Writable DCs : {0}" -f ($ctx.WritableDcs -join ', '))
Write-Host ("Agent hosts  : {0}" -f (@($cfg.AgentHosts) -join ', '))
foreach ($r in $roles) { Write-Host ("  {0,-34} DC={1,-5} Agent={2}" -f $r.Host, $r.IsDc, $r.IsAgent) -ForegroundColor DarkGray }
#endregion

#region --- Policy state helpers (Verify / SetMode) -----------------------------------------------
function Get-PolicyState([datetime]$From) {
    $ref = Get-SoaPolicy -Context $ctx
    $refMode = if ($ref) { (@($ref.keywords) -join ',') } else { $null }
    $refSids = if ($ref) { (@($ref.'msDS-Settings' | ForEach-Object { "$_" }) | Sort-Object) -join ';' } else { $null }
    $minNtdsai = Get-SoaConstant 'MinNtdsai'
    $remote = @(foreach ($dc in $ctx.WritableDcs) {
        $r = Invoke-SoaOnHost -ComputerName $dc -ArgumentList $From -ScriptBlock {
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
        }
        $r | Add-Member -NotePropertyName Dc -NotePropertyValue $dc -PassThru
    })
    foreach ($dc in $ctx.WritableDcs) {
        $rr = $remote | Where-Object { $_.Dc -eq $dc } | Select-Object -First 1
        $r  = if ($rr -and $rr.Ok) { $rr.Result } else { $null }
        $local = Get-SoaPolicy -Context $ctx -Server $dc
        $mode = if ($local) { (@($local.keywords) -join ',') } else { $null }
        $sids = if ($local) { (@($local.'msDS-Settings' | ForEach-Object { "$_" }) | Sort-Object) -join ';' } else { $null }
        $last = if ($r) { @($r.Loads) | Select-Object -First 1 } else { $null }
        $loadStatus = if (-not $r) { 'NO DATA' }
                      elseif (-not $last) { 'NONE' }
                      elseif ($last.Level -in 1, 2, 3 -or $last.Message -match '(?i)fail|invalid|unable|could not|error') { 'ERROR' }
                      else { 'OK' }
        $ntdsOk = $null
        if ($r -and $minNtdsai.ContainsKey([int]$r.Build)) { $ntdsOk = ([version]$r.Ntdsai -ge $minNtdsai[[int]$r.Build]) }
        [pscustomobject]@{
            DC = $dc; Replicated = [bool]($local -and $mode -eq $refMode -and $sids -eq $refSids); Mode = $mode
            SidCount = $(if ($local) { @($local.'msDS-Settings').Count } else { 0 }); NtdsaiOk = $ntdsOk
            DiagLevel = $(if ($r) { $r.DiagLevel } else { $null }); LastLoad = $(if ($last) { $last.Time } else { $null })
            LoadStatus = $loadStatus; LoadMessage = $(if ($last) { $last.Message } else { $null })
            Audit3097 = $(if ($r) { $r.Audit } else { $null }); Block3098 = $(if ($r) { $r.Blocked } else { $null })
        }
    }
}

function Show-PolicyState($State) {
    $State | Format-Table DC, Replicated, Mode, SidCount, NtdsaiOk, DiagLevel, LastLoad, LoadStatus, Audit3097, Block3098 -AutoSize | Out-Host
    foreach ($s in $State) {
        if ($s.LoadMessage) { Write-Host ("  {0} last 3095: {1}" -f $s.DC, $s.LoadMessage) -ForegroundColor $(if ($s.LoadStatus -eq 'OK') { 'Gray' } else { 'Red' }) }
    }
}
#endregion

#region --- Task registration (runs on the toolkit host) -------------------------------------------
$registerTasksBlock = {
    param($P)
    $out = @()
    $principal = New-ScheduledTaskPrincipal -UserId $P.UserId -LogonType Password -RunLevel Limited
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    function New-Settings([bool]$Enabled) {
        $s = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                                          -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
        if (-not $Enabled) { $s.Enabled = $false }
        $s
    }
    $existingFolder = @(Get-ScheduledTask -TaskPath $P.TaskFolder -ErrorAction SilentlyContinue)
    $wanted = @()

    if ($P.IsDc) {
        $cls = Get-CimClass -Namespace 'ROOT\Microsoft\Windows\TaskScheduler' -ClassName 'MSFT_TaskEventTrigger'
        $triggers = foreach ($sub in @($P.SubscriptionUserCreated, $P.SubscriptionSoaWritten)) {
            $t = New-CimInstance -CimClass $cls -ClientOnly
            $t.Enabled = $true
            $t.Subscription = $sub
            $t.Delay = 'PT{0}S' -f $P.DelaySeconds
            $t
        }
        $arg = '-NoProfile -NonInteractive -ExecutionPolicy {0} -File "{1}" -Mode Apply -Trigger Event' -f $P.ExecutionPolicy, (Join-Path $P.InstallPath 'Invoke-CloudUserConformance.ps1')
        $action = New-ScheduledTaskAction -Execute $psExe -Argument $arg -WorkingDirectory $P.InstallPath
        Register-ScheduledTask -TaskName 'CloudUserConformance-Event' -TaskPath $P.TaskFolder -Action $action -Trigger $triggers -Principal $principal `
            -Settings (New-Settings $true) -Description ($P.Marker + ' Onboarding: runs when the Cloud Sync agent creates a user (4720) or writes msDS-ObjectSoa (5136) on this DC.') -Force | Out-Null
        $out += 'task CloudUserConformance-Event (event triggers 4720 / 5136)'
        $wanted += 'CloudUserConformance-Event'
    }
    if ($P.IsAgent) {
        $interval = [Math]::Max(5, [int]$P.ReconcileMinutes)
        $start = (Get-Date).Date.AddMinutes([int]$P.ReconcileOffset)
        $tt = New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Minutes $interval)
        $tb = New-ScheduledTaskTrigger -AtStartup
        $tb.Delay = 'PT5M'
        $arg = '-NoProfile -NonInteractive -ExecutionPolicy {0} -File "{1}" -Mode Apply -Trigger Schedule' -f $P.ExecutionPolicy, (Join-Path $P.InstallPath 'Invoke-CloudUserConformance.ps1')
        $action = New-ScheduledTaskAction -Execute $psExe -Argument $arg -WorkingDirectory $P.InstallPath
        Register-ScheduledTask -TaskName 'CloudUserConformance-Reconcile' -TaskPath $P.TaskFolder -Action $action -Trigger @($tt, $tb) -Principal $principal `
            -Settings (New-Settings ([int]$P.ReconcileMinutes -gt 0)) -Description ($P.Marker + " Reconcile: brings every in-scope cloud user to the target state (every $interval min, staggered between agent hosts).") -Force | Out-Null
        $out += ('task CloudUserConformance-Reconcile (every {0} min from {1:HH:mm}, enabled={2})' -f $interval, $start, ([int]$P.ReconcileMinutes -gt 0))
        $wanted += 'CloudUserConformance-Reconcile'
    }
    $mi = [Math]::Max(10, [int]$P.MonitorMinutes)
    $mt = New-ScheduledTaskTrigger -Once -At ((Get-Date).Date.AddMinutes([int]$P.MonitorOffset)) -RepetitionInterval (New-TimeSpan -Minutes $mi)
    $arg = '-NoProfile -NonInteractive -ExecutionPolicy {0} -File "{1}" -Scope Local -Quiet' -f $P.ExecutionPolicy, (Join-Path $P.InstallPath 'Watch-CloudUserConformance.ps1')
    $action = New-ScheduledTaskAction -Execute $psExe -Argument $arg -WorkingDirectory $P.InstallPath
    Register-ScheduledTask -TaskName 'Monitor' -TaskPath $P.TaskFolder -Action $action -Trigger $mt -Principal $principal -Settings (New-Settings $true) `
        -Description ($P.Marker + " Monitoring (read-only): results in the event log '$($P.EventLog)' (2000 heartbeat, 2001 warning, 2002 failure).") -Force | Out-Null
    $out += "task Monitor (every $mi min)"
    $wanted += 'Monitor'

    # Tasks of this toolkit that no longer belong to this host's roles
    foreach ($t in $existingFolder) {
        if ($wanted -notcontains $t.TaskName) {
            Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $P.TaskFolder -Confirm:$false
            $out += "removed task $($t.TaskName) (role changed)"
        }
    }
    $out
}
#endregion

foreach ($current in ($order | Where-Object { $Step -contains $_ })) {
    Write-InstallLog "Step $current started (WhatIf=$WhatIfPreference)"
    switch ($current) {

        #----------------------------------------------------------------------------------------------
        'HostGroup' {
            Write-SoaSection "HostGroup: $($cfg.HostGroupName)"
            if (-not $cfg.ToolkitGroupOU) { throw 'ToolkitGroupOU is not configured.' }
            $g = Get-ToolkitGroup $cfg.HostGroupName
            if (-not $g) {
                if ($Cmdlet.ShouldProcess($cfg.HostGroupName, 'Create global security group')) {
                    New-ADGroup -Name $cfg.HostGroupName -SamAccountName $cfg.HostGroupName -GroupScope Global -GroupCategory Security -Path $cfg.ToolkitGroupOU -Server $pdc `
                        -Description (Get-SoaMarker -Config $cfg -Short -Purpose 'Hosts that may retrieve the toolkit gMSA password') `
                        -OtherAttributes @{ info = (Get-SoaMarker -Config $cfg -Purpose 'Members: Domain Controllers + Cloud Sync agent hosts. Used as PrincipalsAllowedToRetrieveManagedPassword of the toolkit gMSA and as security filter of the agent-host batch logon GPO') }
                    Write-SoaLine ADD "group $($cfg.HostGroupName) created"
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Group' -Key 'HostGroup' -Action Created -Data @{ Name = $cfg.HostGroupName }
                    $g = Get-ToolkitGroup $cfg.HostGroupName
                }
            } else {
                Write-SoaLine SAME "group $($cfg.HostGroupName) exists"
                if (-not (Get-SoaManifestEntry -Manifest $manifest -Kind 'Group' -Key 'HostGroup')) {
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Group' -Key 'HostGroup' -Action $(if (Test-SoaMarker $g.description) { 'Created' } else { 'PreExisting' }) -Data @{ Name = $cfg.HostGroupName }
                }
            }
            if ($g) {
                $members = @($g.member | ForEach-Object { "$_".ToLower() })
                $wantedMembers = @((Get-ADGroup -Identity "$($ctx.DomainSid)-516" -Server $pdc).DistinguishedName)
                foreach ($r in ($roles | Where-Object { $_.IsAgent -and -not $_.IsDc })) {
                    $c = Get-ADComputer -Identity (Get-SoaShortName $r.Host) -Server $pdc
                    $wantedMembers += $c.DistinguishedName
                }
                foreach ($m in $wantedMembers) {
                    if ($members -contains $m.ToLower()) { Write-SoaLine SAME "member $m"; continue }
                    if ($Cmdlet.ShouldProcess($cfg.HostGroupName, "Add member $m")) {
                        Add-ADGroupMember -Identity $g -Members $m -Server $pdc
                        Write-SoaLine ADD "member $m"
                    }
                }
                Write-Host '  Note: hosts pick up the new membership with their next computer TGT (Gmsa step purges the tickets).' -ForegroundColor DarkGray
            }
            Save-Manifest
        }

        #----------------------------------------------------------------------------------------------
        'Gmsa' {
            Write-SoaSection "Gmsa: $($cfg.GmsaName)"
            try { if (-not (Get-KdsRootKey)) { throw 'No KDS root key in the forest - create one first (Add-KdsRootKey) and wait for replication (up to 10 h).' } }
            catch [System.Management.Automation.CommandNotFoundException] { Write-Warning 'Get-KdsRootKey not available here - KDS root key not checked.' }
            $hg = Get-ToolkitGroup $cfg.HostGroupName
            if (-not $hg) { throw "Group $($cfg.HostGroupName) not found - run -Step HostGroup first." }
            $gmsa = Get-SoaJobGmsa -Config $cfg -Context $ctx
            if (-not $gmsa) {
                if ($Cmdlet.ShouldProcess($cfg.GmsaName, 'Create gMSA')) {
                    New-ADServiceAccount -Name $cfg.GmsaName -DNSHostName "$($cfg.GmsaName).$($ctx.DnsRoot)" -Server $pdc `
                        -PrincipalsAllowedToRetrieveManagedPassword $hg.DistinguishedName -KerberosEncryptionType AES128, AES256 `
                        -Description (Get-SoaMarker -Config $cfg -Short -Purpose 'Toolkit identity (allow-listed in the AD object enforcement policy)') `
                        -OtherAttributes @{ info = (Get-SoaMarker -Config $cfg -Purpose 'Runs the conformance and monitoring tasks on all toolkit hosts') }
                    Write-SoaLine ADD "gMSA $($cfg.GmsaName) created"
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Gmsa' -Key 'Toolkit' -Action Created -Data @{ Name = $cfg.GmsaName }
                }
            } else {
                Write-SoaLine SAME "gMSA $($cfg.GmsaName) exists"
                $allowed = @($gmsa.PrincipalsAllowedToRetrieveManagedPassword | ForEach-Object { "$_".ToLower() })
                if ($allowed -notcontains $hg.DistinguishedName.ToLower() -and $Cmdlet.ShouldProcess($cfg.GmsaName, "Allow $($cfg.HostGroupName) to retrieve the password")) {
                    Set-ADServiceAccount -Identity $cfg.GmsaName -Server $pdc -PrincipalsAllowedToRetrieveManagedPassword (@($gmsa.PrincipalsAllowedToRetrieveManagedPassword) + $hg.DistinguishedName)
                    Write-SoaLine ADD "PrincipalsAllowedToRetrieveManagedPassword += $($cfg.HostGroupName)"
                }
                if (-not (Get-SoaManifestEntry -Manifest $manifest -Kind 'Gmsa' -Key 'Toolkit')) {
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Gmsa' -Key 'Toolkit' -Action $(if (Test-SoaMarker $gmsa.Description) { 'Created' } else { 'PreExisting' }) -Data @{ Name = $cfg.GmsaName }
                }
            }
            Save-Manifest
            if (-not $WhatIfPreference) {
                foreach ($r in $roles) {
                    $ok = $false; $err = $null
                    for ($i = 1; $i -le 6 -and -not $ok; $i++) {
                        $res = Invoke-SoaOnHost -ComputerName $r.Host -ArgumentList $cfg.GmsaName -ScriptBlock {
                            param($Name)
                            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { throw 'RSAT AD PowerShell missing on this host (Install-WindowsFeature RSAT-AD-PowerShell).' }
                            & klist.exe -li 0x3e7 purge | Out-Null
                            Import-Module ActiveDirectory
                            Test-ADServiceAccount -Identity $Name
                        }
                        if ($res.Ok -and $res.Result -eq $true) { $ok = $true }
                        else {
                            $err = if ($res.Error) { $res.Error } else { 'Test-ADServiceAccount returned False' }
                            if ($err -match 'RSAT') { break }
                            Write-Host "  $($r.Host): waiting for replication / group membership ($i/6) ..." -ForegroundColor Yellow
                            Start-Sleep -Seconds 30
                        }
                    }
                    if ($ok) { Write-SoaLine PASS "$($r.Host): gMSA usable (Test-ADServiceAccount)" }
                    else { Write-SoaLine FAIL "$($r.Host): gMSA not usable - $err" }
                }
            }
        }

        #----------------------------------------------------------------------------------------------
        'BatchLogonGpo' {
            Write-SoaSection 'BatchLogonGpo: "Log on as a batch job" for the toolkit gMSA'
            $gmsa = Get-SoaJobGmsa -Config $cfg -Context $ctx
            if (-not $gmsa) { throw "gMSA $($cfg.GmsaName) not found - run -Step Gmsa first." }
            $block = Get-SoaBatchRightBlock

            $targets = @(
                [pscustomobject]@{ Key = 'BatchLogonDc'; Name = $cfg.BatchLogonGpoNameDc; Hosts = @($ctx.WritableDcs); Ous = @($ctx.DcOu); Filter = $false }
            )
            $memberAgents = @($roles | Where-Object { $_.IsAgent -and -not $_.IsDc })
            if ($memberAgents.Count) {
                $ous = @($memberAgents | ForEach-Object { ((Get-ADComputer -Identity (Get-SoaShortName $_.Host) -Server $pdc).DistinguishedName -split ',', 2)[1] } | Select-Object -Unique)
                $targets += [pscustomobject]@{ Key = 'BatchLogonAgent'; Name = $cfg.BatchLogonGpoNameAgent; Hosts = @($memberAgents.Host); Ous = $ous; Filter = $true }
            }

            foreach ($t in $targets) {
                Write-Host ''
                Write-Host "$($t.Name) -> $($t.Ous -join '; ')" -ForegroundColor Cyan
                $effective = @{}
                foreach ($h in $t.Hosts) {
                    $res = Invoke-SoaOnHost -ComputerName $h -ScriptBlock $block
                    if (-not $res.Ok) { throw "Effective user rights not readable on ${h}: $($res.Error)" }
                    $effective[$h] = @($res.Result)
                    Write-Host ("  {0}: {1}" -f $h, ((@($res.Result) | ForEach-Object { if ($_ -like 'S-1-*') { $n = Resolve-SoaSid -Sid $_ -Server $pdc -NetBios $ctx.NetBios; if ($n) { $n } else { $_ } } else { $_ } }) -join ', ')) -ForegroundColor DarkGray
                }
                $lists = @($effective.Values | ForEach-Object { ((@($_) | Sort-Object) -join ',') } | Select-Object -Unique)
                if ($lists.Count -gt 1) { Write-Warning "Effective 'Log on as a batch job' differs between the hosts of this GPO - the union is used." }
                $unresolved = @($effective.Values | ForEach-Object { $_ } | Where-Object { $_ -like 'UNRESOLVED:*' } | Select-Object -Unique)
                if ($unresolved.Count) { Write-Warning ("Unresolvable entries are dropped: {0}" -f ($unresolved -join ', ')) }
                $desired = @(@($effective.Values | ForEach-Object { $_ }) + $gmsa.SID.Value | Where-Object { $_ -like 'S-1-*' } | Select-Object -Unique | Sort-Object)

                $prevEntry = Get-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key $t.Key | Select-Object -First 1
                $res = New-SoaGpo -Name $t.Name -Config $cfg -Context $ctx -Purpose "Grants 'Log on as a batch job' to the toolkit gMSA. Contains the complete list of this right (user rights from GPOs are not merged)"
                if (-not $res) { continue }
                $gpo = $res.Gpo
                $currentLine = @(Get-SoaGpoSecurityTemplate -Id $gpo.Id -Context $ctx | Where-Object { $_ -match '^\s*SeBatchLogonRight\s*=' }) | Select-Object -First 1
                $current = if ($currentLine) { @((($currentLine -split '=', 2)[1] -split ',') | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ } | Sort-Object) } else { @() }
                if (($current -join ',') -ne ($desired -join ',')) {
                    if ($Cmdlet.ShouldProcess($t.Name, "Set SeBatchLogonRight = $($desired -join ', ')")) {
                        Set-SoaGpoSecurityTemplate -Id $gpo.Id -Context $ctx -Sections ([ordered]@{ 'Privilege Rights' = @('SeBatchLogonRight = ' + (($desired | ForEach-Object { "*$_" }) -join ',')) })
                        [void](Update-SoaGpoMachineVersion -Id $gpo.Id -Context $ctx -AddCse @((Get-SoaConstant 'Cse').Security))
                        Write-SoaLine ADD ("SeBatchLogonRight = {0} entries (incl. {1})" -f $desired.Count, $cfg.GmsaName)
                    }
                } else { Write-SoaLine SAME 'SeBatchLogonRight already contains the desired list' }
                if ($t.Filter) {
                    if ($Cmdlet.ShouldProcess($t.Name, "Security filtering: apply only to $($cfg.HostGroupName)")) {
                        Set-GPPermission -Guid $gpo.Id -DomainName $ctx.DnsRoot -Server $pdc -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel GpoRead -Replace | Out-Null
                        Set-GPPermission -Guid $gpo.Id -DomainName $ctx.DnsRoot -Server $pdc -TargetName $cfg.HostGroupName -TargetType Group -PermissionLevel GpoApply | Out-Null
                        Write-SoaLine ADD "security filter: $($cfg.HostGroupName) (Authenticated Users: read only)"
                    }
                }
                foreach ($ou in $t.Ous) { Set-SoaGpoLink -Id $gpo.Id -Target $ou -Context $ctx -Order 1 -WhatIf:$WhatIfPreference }
                Set-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key $t.Key -Action $(if ($res.Created -or ($prevEntry -and $prevEntry.Action -eq 'Created')) { 'Created' } else { 'PreExisting' }) `
                    -Data @{ Id = "$($gpo.Id)"; Name = $t.Name; Links = $t.Ous; Rights = $desired } -Previous @{ EffectiveBefore = $effective }
                Save-Manifest
            }
            if ($Refresh -and -not $WhatIfPreference) {
                Write-Host 'Waiting 30 s for AD/SYSVOL replication, then gpupdate on all toolkit hosts ...'
                Start-Sleep -Seconds 30
                foreach ($r in $roles) {
                    [void](Invoke-SoaOnHost -ComputerName $r.Host -ScriptBlock { gpupdate.exe /target:computer /force | Out-Null })
                    $res = Invoke-SoaOnHost -ComputerName $r.Host -ScriptBlock $block
                    if ($res.Ok -and @($res.Result) -contains $gmsa.SID.Value) { Write-SoaLine PASS "$($r.Host): gMSA has 'Log on as a batch job'" }
                    else { Write-SoaLine WARN "$($r.Host): gMSA not (yet) in the effective list - check GPO precedence (enforced links?) / SYSVOL replication" }
                }
            } else { Write-Host '  Run with -Refresh (or wait for the next policy refresh) and check with -Step Verify.' -ForegroundColor DarkGray }
        }

        #----------------------------------------------------------------------------------------------
        'KirGpo' {
            Write-SoaSection 'KirGpo: feature enablement for AD object enforcement (Known Issue Rollback model)'
            $packages = @()
            if ($KirMsi2022) { $packages += [pscustomobject]@{ Label = 'WS2022'; Build = 20348; Msi = $KirMsi2022 } }
            if ($KirMsi2025) { $packages += [pscustomobject]@{ Label = 'WS2025'; Build = 26100; Msi = $KirMsi2025 } }
            if (-not $packages.Count) { throw 'Pass -KirMsi2022 and/or -KirMsi2025 (Microsoft Group Policy package for AD object enforcement: aka.ms/ADEnforcementGPMSI2022 / aka.ms/ADEnforcementGPMSI2025).' }

            # OS builds of the writable DCs
            $builds = @{}
            foreach ($dc in $ctx.WritableDcs) {
                $res = Invoke-SoaOnHost -ComputerName $dc -ScriptBlock { [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild }
                if ($res.Ok) { $builds[$dc] = [int]$res.Result } else { Write-Warning "OS build of $dc not readable: $($res.Error)" }
            }
            foreach ($b in @($builds.Values | Select-Object -Unique)) {
                if (-not @($packages | Where-Object { $_.Build -eq $b }).Count) { Write-SoaLine WARN ("Writable DC(s) with build {0} ({1}) but no matching package given." -f $b, (($builds.Keys | Where-Object { $builds[$_] -eq $b }) -join ', ')) }
            }

            $central = "\\$($ctx.DnsRoot)\SYSVOL\$($ctx.DnsRoot)\Policies\PolicyDefinitions"
            $store = if (Test-Path -LiteralPath $central) { $central } else { $null }
            if (-not $store) {
                $store = Join-Path $env:windir 'PolicyDefinitions'
                Write-SoaLine WARN "No central store found. ADMX/ADML are copied to the LOCAL store of this host ($store) only. A central store is NOT created by the toolkit (it would hide all other templates that are not in it)."
            }

            # GPOs effective on the DC OU (to detect a pre-existing KIR GPO)
            $inh = Get-GPInheritance -Target $ctx.DcOu -Domain $ctx.DnsRoot -Server $pdc
            $dcOuGpos = @(@($inh.GpoLinks) + @($inh.InheritedGpoLinks) | Where-Object { $_ } | Sort-Object GpoId -Unique)

            foreach ($pkg in $packages) {
                Write-Host ''
                Write-Host "Package $($pkg.Label): $($pkg.Msi)" -ForegroundColor Cyan
                if (-not (Test-Path -LiteralPath $pkg.Msi)) { throw "MSI not found: $($pkg.Msi)" }
                $tmp = Join-Path $env:TEMP ('soa_kir_{0}_{1}' -f $pkg.Label, [guid]::NewGuid().ToString('N').Substring(0, 8))
                New-Item -Path $tmp -ItemType Directory -Force | Out-Null
                $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/a', "`"$((Resolve-Path -LiteralPath $pkg.Msi).Path)`"", '/qn', "TARGETDIR=`"$tmp`"") -Wait -PassThru
                if ($p.ExitCode -ne 0) { throw "msiexec /a failed with exit code $($p.ExitCode) for $($pkg.Msi)." }
                $admxFiles = @(Get-ChildItem -LiteralPath $tmp -Recurse -Filter '*.admx' -File)
                if (-not $admxFiles.Count) { throw "No ADMX found in $($pkg.Msi) (extracted to $tmp)." }

                $defs = @(foreach ($a in $admxFiles) { Get-SoaKirDefinition -AdmxPath $a.FullName })
                if ($KirPolicyName) { $defs = @($defs | Where-Object { $_.PolicyName -eq $KirPolicyName -or $_.DisplayName -eq $KirPolicyName }) }
                if (-not $defs.Count) { throw "No policy writing FeatureManagement overrides found in $($pkg.Msi)." }
                if ($defs.Count -gt 1) { throw ("Several KIR policies found - pass -KirPolicyName: {0}" -f (($defs | ForEach-Object { "$($_.PolicyName) ('$($_.DisplayName)')" }) -join '; ')) }
                $def = $defs[0]
                Write-Host ("  policy '{0}' ({1}) - feature IDs: {2}" -f $def.DisplayName, $def.AdmxFile, (($def.Items | ForEach-Object { "$($_.FeatureId)=$($_.Enabled)" }) -join ', '))

                # 1. ADMX/ADML to the policy store
                $copied = @()
                $srcDir = Split-Path -Path ($admxFiles | Where-Object { $_.Name -eq $def.AdmxFile } | Select-Object -First 1).FullName -Parent
                $files = @(Get-ChildItem -LiteralPath $srcDir -Filter ([IO.Path]::ChangeExtension($def.AdmxFile, '.admx')) -File) +
                         @(Get-ChildItem -LiteralPath $srcDir -Recurse -Filter ([IO.Path]::ChangeExtension($def.AdmxFile, '.adml')) -File)
                foreach ($f in $files) {
                    $rel  = $f.FullName.Substring($srcDir.Length).TrimStart('\')
                    $dest = Join-Path $store $rel
                    $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
                    if (Test-Path -LiteralPath $dest) {
                        if ((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -eq $hash) { Write-SoaLine SAME "$rel (identical)"; continue }
                        if (-not $Force) { Write-SoaLine WARN "$rel exists with different content - not overwritten (use -Force)"; continue }
                    }
                    if ($Cmdlet.ShouldProcess($dest, 'Copy policy definition')) {
                        New-Item -Path (Split-Path $dest -Parent) -ItemType Directory -Force | Out-Null
                        Copy-Item -LiteralPath $f.FullName -Destination $dest -Force
                        Write-SoaLine ADD "$rel -> $store"
                        $copied += [pscustomobject]@{ Path = $dest; Sha256 = $hash }
                    }
                }
                if ($copied.Count) { Set-SoaManifestEntry -Manifest $manifest -Kind 'AdmxFiles' -Key $pkg.Label -Action Created -Data @{ Files = $copied } }

                # 2. Pre-existing KIR GPO with these feature IDs?
                $ids = @($def.Items | ForEach-Object { $_.FeatureId })
                $gpoName = '{0} ({1})' -f $cfg.KirGpoNamePrefix, $pkg.Label
                $preExisting = $null
                foreach ($l in $dcOuGpos) {
                    $gg = Get-GPO -Guid $l.GpoId -Domain $ctx.DnsRoot -Server $pdc
                    if ($gg.DisplayName -eq $gpoName) { continue }
                    $vals = @()
                    foreach ($k in @($def.Items | ForEach-Object { $_.Key } | Select-Object -Unique)) {
                        try { $vals += @(Get-GPRegistryValue -Guid $l.GpoId -Domain $ctx.DnsRoot -Server $pdc -Key "HKLM\$k" -ErrorAction Stop) } catch { }
                    }
                    if (@($vals | Where-Object { $ids -contains $_.ValueName }).Count) { $preExisting = $gg; break }
                }
                if ($preExisting -and -not $Force) {
                    Write-SoaLine SAME "pre-existing GPO '$($preExisting.DisplayName)' already sets these feature IDs - not creating a second one (use -Force to create the toolkit GPO anyway)"
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key "Kir$($pkg.Label)" -Action PreExisting -Data @{ Id = "$($preExisting.Id)"; Name = $preExisting.DisplayName; FeatureIds = $ids; Build = $pkg.Build }
                    Save-Manifest
                    continue
                }

                # 3. GPO with the registry values of the policy (applied without the ADMX; the ADMX only serves editing/reporting)
                $res = New-SoaGpo -Name $gpoName -Config $cfg -Context $ctx -Purpose "Enables AD object enforcement on $($pkg.Label) domain controllers (Microsoft Group Policy package, KIR model). Removing it disables the feature after a DC restart"
                if (-not $res) { continue }
                $gpo = $res.Gpo
                foreach ($it in $def.Items) {
                    if ($Cmdlet.ShouldProcess($gpoName, "HKLM\$($it.Key)\$($it.FeatureId) = $($it.Enabled)")) {
                        Set-GPRegistryValue -Guid $gpo.Id -Domain $ctx.DnsRoot -Server $pdc -Key "HKLM\$($it.Key)" -ValueName $it.FeatureId -Type DWord -Value ([int]$it.Enabled) | Out-Null
                        Write-SoaLine ADD "HKLM\$($it.Key)\$($it.FeatureId) = $($it.Enabled)"
                    }
                }
                $wf = New-SoaWmiFilter -Name ("SOA Toolkit - OS build {0} ({1})" -f $pkg.Build, $pkg.Label) -Query ('SELECT * FROM Win32_OperatingSystem WHERE BuildNumber = "{0}"' -f $pkg.Build) -Config $cfg -Context $ctx `
                                       -Description (Get-SoaMarker -Config $cfg -Short -Purpose "Matches $($pkg.Label) (build $($pkg.Build))") -WhatIf:$WhatIfPreference
                if ($wf -and -not $WhatIfPreference) {
                    Set-SoaGpoWmiFilter -GpoId $gpo.Id -FilterId $wf.Id -Context $ctx
                    Write-SoaLine ADD "WMI filter $($wf.Id) assigned"
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'WmiFilter' -Key $pkg.Label -Action $(if ($wf.Created) { 'Created' } else { 'PreExisting' }) -Data @{ Id = $wf.Id; Dn = $wf.Dn }
                }
                $order2 = @((Get-GPInheritance -Target $ctx.DcOu -Domain $ctx.DnsRoot -Server $pdc).GpoLinks).Count + 1
                $state = Get-SoaGpoLinkState -Id $gpo.Id -Target $ctx.DcOu -Context $ctx
                if (-not $state.Linked) { Set-SoaGpoLink -Id $gpo.Id -Target $ctx.DcOu -Context $ctx -Order $order2 -WhatIf:$WhatIfPreference } else { Write-SoaLine SAME "linked to $($ctx.DcOu)" }
                Set-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key "Kir$($pkg.Label)" -Action $(if ($res.Created -or (Test-SoaMarker $gpo.Description)) { 'Created' } else { 'PreExisting' }) `
                    -Data @{ Id = "$($gpo.Id)"; Name = $gpoName; FeatureIds = $ids; Build = $pkg.Build; Policy = $def.DisplayName; Items = @($def.Items) }
                Save-Manifest
                Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Host ''
            Write-Host 'NEXT: wait for SYSVOL replication, run gpupdate /target:computer /force on every writable DC and restart the DCs' -ForegroundColor Cyan
            Write-Host '      ONE AT A TIME (PDC emulator included). Then: Test-SoaPrerequisites.ps1 and -Step Policy, AllowList, Verify.' -ForegroundColor Cyan
        }

        #----------------------------------------------------------------------------------------------
        'DiagnosticsGpo' {
            Write-SoaSection "DiagnosticsGpo: $($cfg.DiagnosticsGpoName)"
            $existed = [bool](Get-SoaGpo -Name $cfg.DiagnosticsGpoName -Context $ctx)
            $legacy  = if ($cfg.LegacyDiagnosticsGpoName) { Get-SoaGpo -Name $cfg.LegacyDiagnosticsGpoName -Context $ctx } else { $null }
            if (-not $existed -and $legacy) {
                if ($Cmdlet.ShouldProcess($cfg.LegacyDiagnosticsGpoName, "Rename to '$($cfg.DiagnosticsGpoName)' (toolkit 1.x GPO)")) {
                    Rename-GPO -Guid $legacy.Id -TargetName $cfg.DiagnosticsGpoName -Domain $ctx.DnsRoot -Server $pdc | Out-Null
                    $g2 = Get-GPO -Guid $legacy.Id -Domain $ctx.DnsRoot -Server $pdc
                    $g2.Description = Get-SoaMarker -Config $cfg -Purpose "Sets NTDS\Diagnostics '2 Security Events'=1 (AD object enforcement events 3095/3097/3098). Toggle with Set-SoaDiagnosticsGpo.ps1"
                    Write-SoaLine ADD "renamed '$($cfg.LegacyDiagnosticsGpoName)' -> '$($cfg.DiagnosticsGpoName)' and marked"
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key 'Diagnostics' -Action Adopted -Data @{ Id = "$($legacy.Id)"; Name = $cfg.DiagnosticsGpoName } -Previous @{ Name = $cfg.LegacyDiagnosticsGpoName }
                    Save-Manifest
                    $existed = $true
                }
            }
            $diagScript = Join-Path $PSScriptRoot 'Set-SoaDiagnosticsGpo.ps1'
            if (-not $existed) {
                & $diagScript -Action Install -ConfigPath $ConfigPath -WhatIf:$WhatIfPreference
                $g3 = Get-SoaGpo -Name $cfg.DiagnosticsGpoName -Context $ctx
                if ($g3) { Set-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key 'Diagnostics' -Action Created -Data @{ Id = "$($g3.Id)"; Name = $cfg.DiagnosticsGpoName }; Save-Manifest }
            } elseif (-not (Get-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key 'Diagnostics')) {
                $g3 = Get-SoaGpo -Name $cfg.DiagnosticsGpoName -Context $ctx
                Set-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key 'Diagnostics' -Action $(if (Test-SoaMarker $g3.Description) { 'Created' } else { 'PreExisting' }) -Data @{ Id = "$($g3.Id)"; Name = $cfg.DiagnosticsGpoName }
                Save-Manifest
            }
            if (-not $WhatIfPreference) { & $diagScript -Action Enable -ConfigPath $ConfigPath -Refresh:$Refresh }
        }

        #----------------------------------------------------------------------------------------------
        'AuditConfig' {
            Write-SoaSection 'AuditConfig: audit policy on the DCs + SACL for msDS-ObjectSoa'
            $subs  = Get-SoaConstant 'Audit'
            $block = Get-SoaAuditPolicyBlock
            $union = @{}; $missing = @{}; $forceNeeded = $false; $perDc = @{}
            foreach ($s in $subs) { $union[$s.Guid] = 0 }
            foreach ($dc in $ctx.WritableDcs) {
                $res = Invoke-SoaOnHost -ComputerName $dc -ScriptBlock $block
                if (-not $res.Ok) { throw "Audit policy not readable on ${dc}: $($res.Error)" }
                $perDc[$dc] = $res.Result
                foreach ($s in $subs) {
                    $v = if ($res.Result.Subcategories.ContainsKey($s.Guid)) { [int]$res.Result.Subcategories[$s.Guid] } else { 0 }
                    $union[$s.Guid] = $union[$s.Guid] -bor $v
                    $ok = (($v -band $s.Required) -eq $s.Required)
                    Write-SoaLine $(if ($ok) { 'PASS' } else { 'WARN' }) ("{0}: {1} = {2} (needs {3}: {4})" -f (Get-SoaShortName $dc), $s.Name, $v, $s.Required, $s.Why)
                    if (-not $ok) { $missing[$s.Guid] = $s }
                }
                if ($res.Result.ForceSubcategory -ne 1) {
                    $forceNeeded = $true
                    Write-SoaLine WARN ("{0}: 'Audit: Force audit policy subcategory settings' (SCENoApplyLegacyAuditPolicy) = {1}" -f (Get-SoaShortName $dc), $res.Result.ForceSubcategory)
                }
            }
            if ($missing.Count -or $forceNeeded) {
                $settings = @(foreach ($s in $missing.Values) { [pscustomobject]@{ Name = $s.Name; Guid = $s.Guid; Value = ($union[$s.Guid] -bor $s.Required) } })
                $res = New-SoaGpo -Name $cfg.AuditGpoName -Config $cfg -Context $ctx -Purpose 'Adds ONLY the audit subcategories the toolkit needs and that were missing (current effective value OR required value, so no auditing is reduced)'
                if ($res) {
                    $gpo = $res.Gpo
                    # keep what this GPO already provides (otherwise those subcategories would be missing on the next run)
                    foreach ($old in @(Get-SoaGpoAuditCsv -Id $gpo.Id -Context $ctx)) {
                        $hit = @($settings | Where-Object { $_.Guid -eq $old.Guid }) | Select-Object -First 1
                        if ($hit) { $hit.Value = $hit.Value -bor $old.Value } else { $settings += $old }
                    }
                    if ($Cmdlet.ShouldProcess($cfg.AuditGpoName, ("audit.csv: {0}" -f (($settings | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', ')))) {
                        $cse = @()
                        if ($settings.Count) { Set-SoaGpoAuditCsv -Id $gpo.Id -Context $ctx -Settings $settings; $cse += (Get-SoaConstant 'Cse').Audit }
                        if ($forceNeeded) {
                            Set-SoaGpoSecurityTemplate -Id $gpo.Id -Context $ctx -Sections ([ordered]@{ 'Registry Values' = @('MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1') })
                            $cse += (Get-SoaConstant 'Cse').Security
                        }
                        [void](Update-SoaGpoMachineVersion -Id $gpo.Id -Context $ctx -AddCse $cse)
                        foreach ($s in $settings) { Write-SoaLine ADD "$($s.Name) = $($s.Value)" }
                        if ($forceNeeded) { Write-SoaLine ADD 'SCENoApplyLegacyAuditPolicy = 1' }
                    }
                    Set-SoaGpoLink -Id $gpo.Id -Target $ctx.DcOu -Context $ctx -Order 1 -WhatIf:$WhatIfPreference
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' -Key 'Audit' -Action Created -Data @{ Id = "$($gpo.Id)"; Name = $cfg.AuditGpoName; Settings = $settings } -Previous @{ PerDc = $perDc }
                }
            } else {
                Write-SoaLine PASS 'All required audit subcategories are effective on every writable DC - no audit GPO needed.'
            }

            # SACL: writes to msDS-ObjectSoa (Success) on user objects below the write scope -> event 5136.
            # The toolkit ALWAYS sets its own narrow entry (identified by its fingerprint, see Test-SoaSaclFingerprint)
            # and never relies on broader rules of others (e.g. a diagnostic "Write all properties" SACL).
            $agents = @(Get-SoaAgentGmsa -Config $cfg -Context $ctx -Quiet)
            $scope  = @(Get-SoaWriteScope -Config $cfg -Context $ctx -AgentGmsa $agents)
            $attr   = Get-SoaAttributeGuid -LdapDisplayName 'msDS-ObjectSoa' -Context $ctx
            $added  = @()
            foreach ($dn in $scope) {
                $st = Get-SoaSaclState -Dn $dn -AttributeGuid $attr -Drive $drive
                foreach ($b in @($st.Broad)) { Write-SoaLine INFO "SACL on ${dn}: other rule also audits msDS-ObjectSoa writes (not relied upon; remove it if it was only for diagnosis): $b" }
                if ($st.Toolkit) { Write-SoaLine SAME "SACL on ${dn}: toolkit entry present (Everyone, Success, Write msDS-ObjectSoa, descendant users)"; continue }
                if ($Cmdlet.ShouldProcess($dn, 'Add SACL: Everyone, Success, Write msDS-ObjectSoa, descendant users')) {
                    $acl = $st.Acl
                    $acl.AddAuditRule((New-SoaSaclRule -AttributeGuid $attr))
                    Set-Acl -Path "$drive\$dn" -AclObject $acl
                    Write-SoaLine ADD "SACL on ${dn}: Success, Write msDS-ObjectSoa (descendant users)"
                    $added += $dn
                }
            }
            if ($added.Count) {
                $old = Get-SoaManifestEntry -Manifest $manifest -Kind 'Sacl' -Key 'msDS-ObjectSoa' | Select-Object -First 1
                $all = @($added) + @(if ($old) { @($old.Data.Dns) } else { @() }) | Select-Object -Unique
                Set-SoaManifestEntry -Manifest $manifest -Kind 'Sacl' -Key 'msDS-ObjectSoa' -Action Created -Data @{ Dns = $all; AttributeGuid = "$attr" }
            }
            Save-Manifest
        }

        #----------------------------------------------------------------------------------------------
        'EnableRolling' {
            Write-SoaSection 'EnableRolling: automatic rolling of expiring NTLM secrets for smart-card-only accounts'
            $root = Get-ADObject -Identity $ctx.DomainDN -Server $pdc -Properties 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts', 'msDS-Behavior-Version'
            $dfl  = [int]$root.'msDS-Behavior-Version'
            $val  = $root.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'
            if ($dfl -lt 7) { throw "Domain functional level $dfl < 7 (Windows Server 2016): automatic rolling is not available. Toolkit 2.x relies on it." }
            if ($val -eq $true) {
                Write-SoaLine SAME 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts = TRUE (already enabled)'
                if (-not (Get-SoaManifestEntry -Manifest $manifest -Kind 'Domain' -Key 'Rolling')) { Set-SoaManifestEntry -Manifest $manifest -Kind 'Domain' -Key 'Rolling' -Action PreExisting -Data @{ Value = $true } -Previous @{ Value = $true } }
            } elseif ($Cmdlet.ShouldProcess($ctx.DomainDN, 'Set msDS-ExpirePasswordsOnSmartCardOnlyAccounts = TRUE')) {
                Set-ADObject -Identity $ctx.DomainDN -Server $pdc -Replace @{ 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' = $true }
                Write-SoaLine ADD "msDS-ExpirePasswordsOnSmartCardOnlyAccounts = TRUE (was: $(if ($null -eq $val) { 'not set' } else { $val }))"
                Set-SoaManifestEntry -Manifest $manifest -Kind 'Domain' -Key 'Rolling' -Action Changed -Data @{ Value = $true } -Previous @{ Value = $val }
            }
            Save-Manifest
        }

        #----------------------------------------------------------------------------------------------
        'Policy' {
            Write-SoaSection 'Policy: CN=Cloud (AD object enforcement policy)'
            $container = $null
            try { $container = Get-ADObject -Identity $ctx.ContainerDN -Server $pdc -Properties whenCreated } catch { }
            if (-not $container) {
                Write-SoaLine WARN "$($ctx.ContainerDN) does not exist on the PDC emulator: the enforcement engine is not active there yet (KIR GPO applied + DC restarted?). The toolkit does NOT create the container (unlike Set-CloudSyncSOAPolicy.ps1) because its existence proves the engine is running. Re-run -Step Policy, AllowList after the restart."
                break
            }
            $md = Get-ADReplicationAttributeMetadata -Object $ctx.ContainerDN -Server $pdc -Properties objectClass | Select-Object -First 1
            $origin = if ($md) { Get-SoaServerFromNtdsDn $md.LastOriginatingChangeDirectoryServerIdentity } else { $null }
            if ($origin -and $origin -ne (Get-SoaShortName $pdc)) { Write-SoaLine WARN "Container was originally written on '$origin', not on the PDC emulator - possibly created by a script; the engine on the PDCe is not proven by it." }
            else { Write-SoaLine PASS "Container present (written on the PDC emulator at $($md.LastOriginatingChangeTime))" }

            $pol = Get-SoaPolicy -Context $ctx
            if ($pol) {
                Write-SoaLine SAME ("CN=Cloud exists (mode {0}, {1} SID(s)) - kept; mode via -Step SetMode, allow-list via -Step AllowList" -f (@($pol.keywords) -join ','), @($pol.'msDS-Settings').Count)
                if (-not (Get-SoaManifestEntry -Manifest $manifest -Kind 'Policy' -Key 'Cloud')) {
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Policy' -Key 'Cloud' -Action $(if (Test-SoaMarker $pol.description) { 'Created' } else { 'PreExisting' }) `
                        -Data @{ Dn = $ctx.PolicyDN } -Previous @{ Mode = (@($pol.keywords) -join ','); Sids = @($pol.'msDS-Settings' | ForEach-Object { "$_" }) }
                }
            } else {
                $sids = @(Get-SoaAgentGmsa -Config $cfg -Context $ctx | ForEach-Object { $_.Sid })
                if (-not $sids.Count) { throw 'No Cloud Sync agent gMSA found - the policy needs at least the agent SID.' }
                $j = Get-SoaJobGmsa -Config $cfg -Context $ctx
                if ($j) { $sids += $j.SID.Value } else { Write-Warning 'Toolkit gMSA not found - add it later with -Step AllowList.' }
                $sids = @($sids | Select-Object -Unique)
                foreach ($s in $sids) { if (-not (Resolve-SoaSid -Sid $s -Server $pdc)) { throw "SID $s does not resolve - not creating the policy (a stale SID makes the policy fail to load)." } }
                if ($Cmdlet.ShouldProcess($ctx.PolicyDN, "Create policy (keywords=Audit, msDS-Settings=$($sids -join ', '))")) {
                    New-ADObject -Name 'Cloud' -Type 'serviceConnectionPoint' -Path $ctx.ContainerDN -Server $pdc -OtherAttributes @{
                        serviceBindingInformation = 'CloudSync'
                        keywords                  = 'Audit'
                        'msDS-Settings'           = [string[]]$sids
                        description               = (Get-SoaMarker -Config $cfg -Short -Purpose 'AD object enforcement policy (same object as created by Set-CloudSyncSOAPolicy.ps1)')
                    }
                    Write-SoaLine ADD 'CN=Cloud created in mode Audit'
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Policy' -Key 'Cloud' -Action Created -Data @{ Dn = $ctx.PolicyDN; Sids = $sids } -Previous @{ Mode = $null; Sids = @() }
                }
            }
            Save-Manifest
        }

        #----------------------------------------------------------------------------------------------
        'Groups' {
            Write-SoaSection 'Groups: PSO target, exclusion, pilot'
            if (-not $cfg.ToolkitGroupOU) { throw 'ToolkitGroupOU is not configured.' }
            $defs = @(
                @{ Key = 'PsoGroup';     Name = $cfg.PsoGroupName;     Purpose = "Target of $($cfg.PsoName). Members are maintained ONLY by the toolkit (in-scope cloud users)" }
                @{ Key = 'ExcludeGroup'; Name = $cfg.ExcludeGroupName; Purpose = 'Cloud users the toolkit must leave untouched (no SCRIL / PNE change, removed from the PSO group). Maintained by admins' }
                @{ Key = 'PilotGroup';   Name = $cfg.PilotGroupName;   Purpose = 'With PilotMode = $true the toolkit applies the target state only to members of this group. Maintained by admins' }
            )
            foreach ($d in $defs) {
                $g = Get-ToolkitGroup $d.Name
                if ($g) {
                    Write-SoaLine SAME "group $($d.Name) exists"
                    if (-not (Get-SoaManifestEntry -Manifest $manifest -Kind 'Group' -Key $d.Key)) {
                        Set-SoaManifestEntry -Manifest $manifest -Kind 'Group' -Key $d.Key -Action $(if (Test-SoaMarker $g.description) { 'Created' } else { 'PreExisting' }) -Data @{ Name = $d.Name }
                    }
                    continue
                }
                if ($Cmdlet.ShouldProcess($d.Name, 'Create global security group')) {
                    New-ADGroup -Name $d.Name -SamAccountName $d.Name -GroupScope Global -GroupCategory Security -Path $cfg.ToolkitGroupOU -Server $pdc `
                        -Description (Get-SoaMarker -Config $cfg -Short -Purpose $d.Purpose) -OtherAttributes @{ info = (Get-SoaMarker -Config $cfg -Purpose $d.Purpose) }
                    Write-SoaLine ADD "group $($d.Name) created"
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Group' -Key $d.Key -Action Created -Data @{ Name = $d.Name }
                }
            }
            Save-Manifest
        }

        #----------------------------------------------------------------------------------------------
        'Pso' {
            Write-SoaSection "Pso: $($cfg.PsoName)"
            $p = $cfg.Pso
            $want = [ordered]@{
                Precedence                  = [int]$p.Precedence
                MaxPasswordAge              = New-TimeSpan -Days ([int]$p.MaxPasswordAgeDays)
                MinPasswordAge              = New-TimeSpan -Days ([int]$p.MinPasswordAgeDays)
                MinPasswordLength           = [int]$p.MinPasswordLength
                ComplexityEnabled           = [bool]$p.ComplexityEnabled
                PasswordHistoryCount        = [int]$p.PasswordHistoryCount
                ReversibleEncryptionEnabled = [bool]$p.ReversibleEncryptionEnabled
                LockoutThreshold            = [int]$p.LockoutThreshold
                LockoutDuration             = New-TimeSpan -Minutes ([int]$p.LockoutDurationMinutes)
                LockoutObservationWindow    = New-TimeSpan -Minutes ([int]$p.LockoutObservationWindowMinutes)
            }
            if ($want.LockoutObservationWindow -gt $want.LockoutDuration) { throw 'Pso.LockoutObservationWindowMinutes must not exceed Pso.LockoutDurationMinutes.' }
            $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$($cfg.PsoName)'" -Server $pdc -Properties Description, AppliesTo
            if (-not $pso) {
                if ($Cmdlet.ShouldProcess($cfg.PsoName, 'Create fine-grained password policy')) {
                    New-ADFineGrainedPasswordPolicy -Name $cfg.PsoName -Server $pdc @want -ProtectedFromAccidentalDeletion $true `
                        -Description (Get-SoaMarker -Config $cfg -Short -Purpose "Cloud users (SCRIL): expiry = rolling interval of the DC-generated secret; applies to $($cfg.PsoGroupName)")
                    Write-SoaLine ADD ("PSO created: {0}" -f (($want.Keys | ForEach-Object { "$_=$($want[$_])" }) -join ', '))
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Pso' -Key 'CloudUsers' -Action Created -Data @{ Name = $cfg.PsoName }
                    $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$($cfg.PsoName)'" -Server $pdc -Properties Description, AppliesTo
                }
            } else {
                $diff = [ordered]@{}; $prev = [ordered]@{}
                foreach ($k in $want.Keys) { if ("$($pso.$k)" -ne "$($want[$k])") { $diff[$k] = $want[$k]; $prev[$k] = "$($pso.$k)" } }
                if ($diff.Count) {
                    if ($Cmdlet.ShouldProcess($cfg.PsoName, ("Update {0}" -f (($diff.Keys | ForEach-Object { "$_ $($prev[$_]) -> $($diff[$_])" }) -join ', ')))) {
                        Set-ADFineGrainedPasswordPolicy -Identity $pso -Server $pdc @diff
                        foreach ($k in $diff.Keys) { Write-SoaLine ADD "$k $($prev[$k]) -> $($diff[$k])" }
                    }
                } else { Write-SoaLine SAME 'PSO values match the configuration' }
                if (-not (Get-SoaManifestEntry -Manifest $manifest -Kind 'Pso' -Key 'CloudUsers')) {
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Pso' -Key 'CloudUsers' -Action $(if (Test-SoaMarker $pso.Description) { 'Created' } else { 'PreExisting' }) -Data @{ Name = $cfg.PsoName } -Previous $prev
                }
            }
            if ($pso) {
                $grp = Get-ToolkitGroup $cfg.PsoGroupName
                if (-not $grp) { Write-SoaLine WARN "group $($cfg.PsoGroupName) not found - run -Step Groups" }
                elseif (@($pso.AppliesTo) -notcontains $grp.DistinguishedName) {
                    if ($Cmdlet.ShouldProcess($cfg.PsoName, "Apply to $($cfg.PsoGroupName)")) {
                        Add-ADFineGrainedPasswordPolicySubject -Identity $pso -Subjects $grp -Server $pdc
                        Write-SoaLine ADD "applies to $($cfg.PsoGroupName)"
                    }
                } else { Write-SoaLine SAME "applies to $($cfg.PsoGroupName)" }
                $others = @($pso.AppliesTo | Where-Object { $grp -and $_ -ne $grp.DistinguishedName })
                if ($others.Count) { Write-SoaLine WARN ("PSO also applies to: {0}" -f ($others -join '; ')) }
                $same = @(Get-ADFineGrainedPasswordPolicy -Filter * -Server $pdc | Where-Object { $_.Name -ne $cfg.PsoName -and $_.Precedence -eq [int]$p.Precedence })
                if ($same.Count) { Write-SoaLine WARN ("Other PSO(s) with the same precedence {0}: {1} (tie -> lowest GUID wins)" -f $p.Precedence, ($same.Name -join ', ')) }
            }
            Save-Manifest
        }

        #----------------------------------------------------------------------------------------------
        'BreakGlass' {
            Write-SoaSection 'BreakGlass (optional)'
            if (-not $cfg.BreakGlassName -or -not $cfg.BreakGlassOU) { Write-SoaLine SKIP 'BreakGlassName / BreakGlassOU not configured - recovery path is "-Step SetMode -Mode Audit" (Domain Admins can always change the policy object).'; break }
            $bg = Get-ADUser -Filter "SamAccountName -eq '$($cfg.BreakGlassName)'" -Server $pdc -Properties description
            if (-not $bg) {
                if ($Cmdlet.ShouldProcess($cfg.BreakGlassName, 'Create DISABLED break-glass account')) {
                    $p1 = Read-Host -AsSecureString "Password for $($cfg.BreakGlassName) (store it in your vault; the account stays disabled)"
                    $p2 = Read-Host -AsSecureString 'Confirm password'
                    $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1); $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
                    try { $same = ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1) -ceq [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)) }
                    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1); [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2) }
                    if (-not $same) { throw 'Passwords do not match.' }
                    New-ADUser -Name $cfg.BreakGlassName -SamAccountName $cfg.BreakGlassName -UserPrincipalName "$($cfg.BreakGlassName)@$($ctx.DnsRoot)" -Path $cfg.BreakGlassOU `
                        -AccountPassword $p1 -Enabled $false -AccountNotDelegated $true -Server $pdc `
                        -Description (Get-SoaMarker -Config $cfg -Short -Purpose 'Break-glass: allow-listed in CN=Cloud. Keep DISABLED')
                    Add-ADGroupMember -Identity "$($ctx.DomainSid)-525" -Members $cfg.BreakGlassName -Server $pdc   # Protected Users
                    $bg = Get-ADUser -Filter "SamAccountName -eq '$($cfg.BreakGlassName)'" -Server $pdc
                    Write-SoaLine ADD "$($cfg.BreakGlassName) created (disabled, Protected Users, not delegable)"
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'User' -Key 'BreakGlass' -Action Created -Data @{ Sam = $cfg.BreakGlassName }
                }
            } else { Write-SoaLine SAME "$($cfg.BreakGlassName) exists" }
            if ($bg) {
                foreach ($dn in @(Get-SoaWriteScope -Config $cfg -Context $ctx)) {
                    $a1 = Add-SoaAce -TargetDn $dn -Sid $bg.SID -Rights GenericAll -Inheritance Descendents -InheritedObjectType $G.UserClass -Label 'Full control (descendant users)' -WhatIf:$WhatIfPreference
                    $a2 = Add-SoaAce -TargetDn $dn -Sid $bg.SID -Rights GenericAll -Inheritance Descendents -InheritedObjectType $G.GroupClass -Label 'Full control (descendant groups)' -WhatIf:$WhatIfPreference
                    foreach ($a in @($a1, $a2) | Where-Object { $_ }) { Set-SoaManifestEntry -Manifest $manifest -Kind 'Ace' -Key "$($a.TargetDn)|$($a.Sid)|$($a.Label)" -Action Created -Data $a }
                }
                $ex = Get-ToolkitGroup $cfg.ExcludeGroupName
                if ($ex -and @($ex.member) -notcontains $bg.DistinguishedName -and $Cmdlet.ShouldProcess($cfg.ExcludeGroupName, "Add $($cfg.BreakGlassName)")) { Add-ADGroupMember -Identity $ex -Members $bg -Server $pdc }
            }
            Save-Manifest
        }

        #----------------------------------------------------------------------------------------------
        'Delegate' {
            Write-SoaSection "Delegate: least privilege for $($cfg.GmsaName)"
            $gmsa = Get-SoaJobGmsa -Config $cfg -Context $ctx
            if (-not $gmsa) { throw "gMSA $($cfg.GmsaName) not found - run -Step Gmsa first." }
            $mode = Get-SoaPolicyMode -Context $ctx
            if ($mode -eq 'Enforced') { Write-Warning 'Policy is Enforced: ACL changes on marked objects (TestUser) are blocked for your account. Container ACLs still work.' }
            $aces = @()
            $scope = @(Get-SoaWriteScope -Config $cfg -Context $ctx)
            Write-Host ("Write scope ({0}): {1}" -f $cfg.WriteScope, ($scope -join '; '))
            foreach ($dn in $scope) {
                $aces += Add-SoaAce -TargetDn $dn -Sid $gmsa.SID -Rights WriteProperty -ObjectType $G.UacAttr -Inheritance Descendents -InheritedObjectType $G.UserClass -Label 'Write userAccountControl (descendant users)' -WhatIf:$WhatIfPreference
            }
            $pg = Get-ToolkitGroup $cfg.PsoGroupName
            if ($pg) { $aces += Add-SoaAce -TargetDn $pg.DistinguishedName -Sid $gmsa.SID -Rights WriteProperty -ObjectType $G.MemberAttr -Label "Write member ($($cfg.PsoGroupName))" -WhatIf:$WhatIfPreference }
            else { Write-SoaLine WARN "group $($cfg.PsoGroupName) not found - run -Step Groups and repeat -Step Delegate" }
            $aces += Add-SoaAce -TargetDn $ctx.PscDN -Sid $gmsa.SID -Rights GenericRead -Inheritance All -Label 'Read password settings (monitoring of the PSO)' -WhatIf:$WhatIfPreference
            if ($cfg.TestUser) {
                $tu = Get-ADUser -Filter "SamAccountName -eq '$($cfg.TestUser)'" -Server $pdc
                if ($tu) { $aces += Add-SoaAce -TargetDn $tu.DistinguishedName -Sid $gmsa.SID -Rights GenericAll -Label 'Full control (TestUser only - Test-SoaBehavior.ps1)' -WhatIf:$WhatIfPreference }
                else { Write-SoaLine WARN "TestUser $($cfg.TestUser) not found (create it in Entra ID and provision it first)" }
            }
            foreach ($a in @($aces | Where-Object { $_ })) { Set-SoaManifestEntry -Manifest $manifest -Kind 'Ace' -Key "$($a.TargetDn)|$($a.Sid)|$($a.Label)" -Action Created -Data $a }
            $elr = Get-ADGroup -Identity $S.EventLogReaders -Server $pdc -Properties member
            if (@($elr.member) -notcontains $gmsa.DistinguishedName) {
                if ($Cmdlet.ShouldProcess('BUILTIN\Event Log Readers', "Add $($cfg.GmsaName) (monitor reads the Security / Directory Service logs on the DCs)")) {
                    Add-ADGroupMember -Identity $elr -Members $gmsa -Server $pdc
                    Write-SoaLine ADD "BUILTIN\Event Log Readers += $($cfg.GmsaName)"
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'Membership' -Key 'EventLogReaders' -Action Created -Data @{ Group = $S.EventLogReaders; Member = $gmsa.DistinguishedName }
                }
            } else { Write-SoaLine SAME "BUILTIN\Event Log Readers contains $($cfg.GmsaName)" }
            Save-Manifest
        }

        #----------------------------------------------------------------------------------------------
        'AllowList' {
            Write-SoaSection 'AllowList: msDS-Settings of CN=Cloud'
            $pol = Get-SoaPolicy -Context $ctx
            if (-not $pol) { Write-SoaLine WARN 'CN=Cloud not found - run -Step Policy first (after the enforcement engine is active).'; break }
            $wanted = [ordered]@{}
            foreach ($a in @(Get-SoaAgentGmsa -Config $cfg -Context $ctx)) { $wanted[$a.Sid] = "Cloud Sync agent ($($a.Name))" }
            $j = Get-SoaJobGmsa -Config $cfg -Context $ctx
            if ($j) { $wanted[$j.SID.Value] = "SOA Toolkit ($($j.SamAccountName))" } else { Write-Warning 'Toolkit gMSA not found - not added.' }
            if ($cfg.BreakGlassName) {
                $bg = Get-ADUser -Filter "SamAccountName -eq '$($cfg.BreakGlassName)'" -Server $pdc
                if ($bg) { $wanted[$bg.SID.Value] = "Break-glass ($($bg.SamAccountName))" }
            }
            if (-not @($wanted.Keys | Where-Object { $_ -like 'S-1-5-21-*' }).Count) { throw 'No SID could be determined - aborting.' }
            $current = @($pol.'msDS-Settings' | Where-Object { $_ } | ForEach-Object { "$_" })
            $rows = foreach ($s in $current) {
                $n = Resolve-SoaSid -Sid $s -Server $pdc -NetBios $ctx.NetBios
                [pscustomobject]@{ Sid = $s; Name = $n; State = $(if ($n) { 'OK' } else { 'STALE' }); Role = $(if ($wanted.Contains($s)) { $wanted[$s] } else { 'other' }) }
            }
            Write-Host 'Current allow-list:'
            $rows | Format-Table Sid, Name, Role, State -AutoSize | Out-Host
            $stale = @($rows | Where-Object { $_.State -eq 'STALE' })
            if ($stale.Count) {
                if ($RemoveStaleSids) {
                    if ($Cmdlet.ShouldProcess($ctx.PolicyDN, "Remove stale SIDs $($stale.Sid -join ', ')")) {
                        Set-ADObject -Identity $ctx.PolicyDN -Server $pdc -Remove @{ 'msDS-Settings' = [string[]]$stale.Sid }
                        Write-SoaLine DEL "removed stale SID(s): $($stale.Sid -join ', ')"
                    }
                } else { Write-SoaLine FAIL ("Stale SID(s) {0}: the policy fails to load while they are present. Re-run with -RemoveStaleSids." -f ($stale.Sid -join ', ')) }
            }
            $missing = @($wanted.Keys | Where-Object { $current -notcontains $_ })
            foreach ($m in $missing) { if (-not (Resolve-SoaSid -Sid $m -Server $pdc)) { throw "SID $m ($($wanted[$m])) does not resolve - not adding it." } }
            if (($current.Count - $stale.Count + $missing.Count) -gt 64) { throw 'The allow-list would exceed the documented maximum of 64 SIDs.' }
            if ($missing.Count) {
                if ($Cmdlet.ShouldProcess($ctx.PolicyDN, "Add $($missing.Count) SID(s) to msDS-Settings")) {
                    Set-ADObject -Identity $ctx.PolicyDN -Server $pdc -Add @{ 'msDS-Settings' = [string[]]$missing }
                    foreach ($m in $missing) { Write-SoaLine ADD "$m  ($($wanted[$m]))" }
                    $old = Get-SoaManifestEntry -Manifest $manifest -Kind 'AllowList' -Key 'Sids' | Select-Object -First 1
                    $added = @($missing) + @(if ($old) { @($old.Data.Added) } else { @() }) | Select-Object -Unique
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'AllowList' -Key 'Sids' -Action Changed -Data @{ Added = $added } -Previous @{ Sids = $current }
                    Write-Host '  Next: -Step Verify (replication + policy-load event 3095 on every DC).' -ForegroundColor Cyan
                }
            } else { Write-SoaLine SAME 'all required SIDs present' }
            Save-Manifest
        }

        #----------------------------------------------------------------------------------------------
        'DeployTasks' {
            Write-SoaSection 'DeployTasks: runtime scripts and scheduled tasks on every toolkit host'
            $gmsa = Get-SoaJobGmsa -Config $cfg -Context $ctx
            if (-not $gmsa) { throw "gMSA $($cfg.GmsaName) not found." }
            $agents = @(Get-SoaAgentGmsa -Config $cfg -Context $ctx)
            if (-not $agents.Count) { throw 'No agent gMSA found - the event triggers need the agent SID(s).' }
            $subs = Get-SoaEventSubscription -AgentSids @($agents | ForEach-Object { $_.Sid })

            # Staging (+ optional code signing)
            $files = 'SoaToolkit.psm1', 'SoaToolkit.config.psd1', 'Invoke-CloudUserConformance.ps1', 'Watch-CloudUserConformance.ps1'
            $stage = Join-Path $env:TEMP ('soa_stage_{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -Path $stage -ItemType Directory -Force | Out-Null
            foreach ($f in $files) {
                $src = if ($f -eq 'SoaToolkit.config.psd1') { $cfg.ConfigPath } else { Join-Path $PSScriptRoot $f }
                if (-not (Test-Path -LiteralPath $src)) { throw "File not found: $src" }
                Copy-Item -LiteralPath $src -Destination (Join-Path $stage $f) -Force
            }
            $execPolicy = 'Bypass'
            if ($cfg.SigningCertThumbprint) {
                $cert = @(Get-ChildItem -Path Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $cfg.SigningCertThumbprint }) | Select-Object -First 1
                if (-not $cert) { throw "Code-signing certificate $($cfg.SigningCertThumbprint) not found (CurrentUser\My / LocalMachine\My, EKU Code Signing)." }
                foreach ($f in $files) {
                    $sp = @{ FilePath = (Join-Path $stage $f); Certificate = $cert; HashAlgorithm = 'SHA256' }
                    if ($cfg.PSObject.Properties.Name -contains 'SigningTimestampUrl' -and $cfg.SigningTimestampUrl) { $sp.TimestampServer = $cfg.SigningTimestampUrl }
                    $sig = Set-AuthenticodeSignature @sp
                    if ($sig.Status -ne 'Valid') { throw "Signing $f failed: $($sig.Status) $($sig.StatusMessage)" }
                }
                $execPolicy = 'AllSigned'
                Write-SoaLine ADD "scripts signed with $($cert.Subject) - tasks run with -ExecutionPolicy AllSigned (the certificate must be trusted on every host: Trusted Publishers + root CA)"
            }
            $hashes = @{}
            foreach ($f in $files) { $hashes[$f] = (Get-FileHash -LiteralPath (Join-Path $stage $f) -Algorithm SHA256).Hash }
            # Values the gMSA cannot determine itself at runtime (no WinRM to other hosts): write scope, agent SIDs, KIR feature IDs
            $writeScope = @(Get-SoaWriteScope -Config $cfg -Context $ctx -AgentGmsa $agents)
            $kir = @(Get-SoaManifestEntry -Manifest $manifest -Kind 'Gpo' | Where-Object { $_.Key -like 'Kir*' } | ForEach-Object {
                [pscustomobject]@{ Build = $_.Data.Build; FeatureIds = @($_.Data.FeatureIds); Gpo = $_.Data.Name; Items = @($_.Data.Items) } })
            $deployInfo = [pscustomobject]@{
                Product = $ver.Product; Version = $ver.Version; Deployed = (Get-Date).ToString('s'); By = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                Signed = [bool]$cfg.SigningCertThumbprint; Files = $hashes; WriteScope = $writeScope
                AgentSids = @($agents | ForEach-Object { $_.Sid }); AgentGmsas = @($agents | ForEach-Object { $_.Name }); Kir = $kir
                Hosts = @($roles | ForEach-Object { [pscustomobject]@{ Host = $_.Host; IsDc = $_.IsDc; IsAgent = $_.IsAgent } })
            }
            Write-Host ("Write scope: {0}" -f ($writeScope -join '; '))
            $deployInfo | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $stage 'deployment.json') -Encoding UTF8
            $manifestCopy = Get-SoaManifestPath -Config $cfg

            $agentCount = [Math]::Max(1, @($roles | Where-Object { $_.IsAgent }).Count)
            $hostIdx = 0
            foreach ($r in $roles) {
                Write-Host ''
                Write-Host ("{0}  (DC={1}, Agent={2})" -f $r.Host, $r.IsDc, $r.IsAgent) -ForegroundColor Cyan
                if (-not $Cmdlet.ShouldProcess($r.Host, 'Deploy scripts, lock folders, create event log, register tasks')) { $hostIdx++; continue }
                $isLocal = ($r.Host -eq (Get-SoaLocalFqdn)) -or ((Get-SoaShortName $r.Host) -ieq $env:COMPUTERNAME)
                $session = if ($isLocal) { $null } else { New-PSSession -ComputerName $r.Host }
                try {
                    $prep = {
                        param($InstallPath, $DataPath, $GmsaSid, $LogName)
                        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { throw 'RSAT AD PowerShell missing (Install-WindowsFeature RSAT-AD-PowerShell).' }
                        foreach ($p in @($InstallPath, $DataPath, (Join-Path $DataPath 'State'))) { New-Item -Path $p -ItemType Directory -Force | Out-Null }
                        & icacls.exe $InstallPath /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' ('*{0}:(OI)(CI)RX' -f $GmsaSid) | Out-Null
                        & icacls.exe $DataPath /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' ('*{0}:(OI)(CI)M' -f $GmsaSid) | Out-Null
                        if (-not [Diagnostics.EventLog]::SourceExists($LogName)) { [Diagnostics.EventLog]::CreateEventSource($LogName, $LogName) }
                        # Channel access: SYSTEM full, Administrators read/write/clear, gMSA + batch logons read/write, Event Log Readers read
                        $sddl = 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;{0})(A;;0x3;;;S-1-5-3)(A;;0x1;;;S-1-5-32-573)' -f $GmsaSid
                        & wevtutil.exe sl $LogName "/ca:$sddl" | Out-Null
                        'folders locked (Administrators/SYSTEM full, gMSA read+execute on scripts, modify on data); event log ready (gMSA may write)'
                    }
                    $prepArgs = @($cfg.ScriptInstallPath, $cfg.DataPath, $gmsa.SID.Value, $cfg.EventLogName)
                    $msg = if ($session) { Invoke-Command -Session $session -ScriptBlock $prep -ArgumentList $prepArgs } else { & $prep @prepArgs }
                    Write-SoaLine ADD $msg
                    foreach ($f in @($files) + 'deployment.json') {
                        if ($session) { Copy-Item -LiteralPath (Join-Path $stage $f) -Destination (Join-Path $cfg.ScriptInstallPath $f) -ToSession $session -Force }
                        else { Copy-Item -LiteralPath (Join-Path $stage $f) -Destination (Join-Path $cfg.ScriptInstallPath $f) -Force }
                    }
                    if (Test-Path -LiteralPath $manifestCopy) {
                        $mDest = Join-Path (Join-Path $cfg.DataPath 'State') 'manifest.json'
                        if ($session) { Copy-Item -LiteralPath $manifestCopy -Destination $mDest -ToSession $session -Force } else { Copy-Item -LiteralPath $manifestCopy -Destination $mDest -Force }
                    }
                    Write-SoaLine ADD ("{0} file(s) copied to {1}" -f ($files.Count + 1), $cfg.ScriptInstallPath)

                    $agentIdx = if ($r.IsAgent) { $r.AgentIndex } else { 0 }
                    $P = @{
                        UserId = ('{0}\{1}$' -f $ctx.NetBios, $cfg.GmsaName); TaskFolder = $cfg.TaskFolder; InstallPath = $cfg.ScriptInstallPath
                        IsDc = $r.IsDc; IsAgent = $r.IsAgent; ExecutionPolicy = $execPolicy; EventLog = $cfg.EventLogName
                        SubscriptionUserCreated = $subs.UserCreated; SubscriptionSoaWritten = $subs.SoaWritten; DelaySeconds = [int]$cfg.EventTriggerDelaySeconds
                        ReconcileMinutes = [int]$cfg.ReconcileMinutes; ReconcileOffset = [int]([Math]::Floor([Math]::Max(5, [int]$cfg.ReconcileMinutes) * $agentIdx / $agentCount))
                        MonitorMinutes = [int]$cfg.MonitorMinutes; MonitorOffset = (($hostIdx * 7) % [Math]::Max(10, [int]$cfg.MonitorMinutes))
                        Marker = (Get-SoaMarker -Config $cfg -Short)
                    }
                    $out = if ($session) { Invoke-Command -Session $session -ScriptBlock $registerTasksBlock -ArgumentList $P } else { & $registerTasksBlock $P }
                    foreach ($o in @($out)) { Write-SoaLine ADD $o }
                    Set-SoaManifestEntry -Manifest $manifest -Kind 'HostDeployment' -Key $r.Host -Action Created -Data @{
                        Host = $r.Host; IsDc = $r.IsDc; IsAgent = $r.IsAgent; InstallPath = $cfg.ScriptInstallPath; DataPath = $cfg.DataPath
                        TaskFolder = $cfg.TaskFolder; EventLog = $cfg.EventLogName; Files = $hashes; Signed = [bool]$cfg.SigningCertThumbprint
                    }
                } catch {
                    Write-SoaLine FAIL "$($r.Host): $($_.Exception.Message)"
                } finally {
                    if ($session) { Remove-PSSession -Session $session }
                }
                $hostIdx++
            }
            Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
            Save-Manifest
            Write-Host ''
            Write-Host ("Event subscription (4720): {0}" -f $subs.XPathUserCreated) -ForegroundColor DarkGray
            Write-Host ("Event subscription (5136): {0}" -f $subs.XPathSoaWritten) -ForegroundColor DarkGray
        }

        #----------------------------------------------------------------------------------------------
        'Conform' {
            Write-SoaSection 'Conform: initial analysis and target state for all marked cloud users'
            $runner = Join-Path $PSScriptRoot 'Invoke-CloudUserConformance.ps1'
            & $runner -Mode Analyze -ConfigPath $ConfigPath -OutputPath (Join-Path $cfg.ReportPath 'Conformance')
            if ($WhatIfPreference) { Write-Host 'WhatIf: analysis only - no changes.' -ForegroundColor Cyan; break }
            if (-not $Cmdlet.ShouldProcess('all in-scope cloud users', 'Apply the target state (one reconcile run as the toolkit gMSA)')) { break }
            $agentHosts = @($roles | Where-Object { $_.IsAgent } | ForEach-Object { $_.Host })
            $done = $false
            foreach ($h in $agentHosts) {
                $res = Invoke-SoaOnHost -ComputerName $h -ArgumentList $cfg.TaskFolder, $cfg.DataPath -ScriptBlock {
                    param($TaskFolder, $DataPath)
                    $t = Get-ScheduledTask -TaskName 'CloudUserConformance-Reconcile' -TaskPath $TaskFolder -ErrorAction Stop
                    $wasDisabled = ("$($t.State)" -eq 'Disabled')
                    if ($wasDisabled) { Enable-ScheduledTask -TaskName $t.TaskName -TaskPath $TaskFolder | Out-Null }
                    $statusFile = Join-Path $DataPath 'Status\conformance.json'
                    $before = if (Test-Path $statusFile) { (Get-Item $statusFile).LastWriteTimeUtc } else { [datetime]::MinValue }
                    Start-ScheduledTask -TaskName $t.TaskName -TaskPath $TaskFolder
                    $deadline = (Get-Date).AddMinutes(15)
                    do { Start-Sleep -Seconds 5; $now = if (Test-Path $statusFile) { (Get-Item $statusFile).LastWriteTimeUtc } else { [datetime]::MinValue } } while ($now -le $before -and (Get-Date) -lt $deadline)
                    if ($wasDisabled) { Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $TaskFolder | Out-Null }
                    if ($now -le $before) { throw 'The reconcile run did not finish within 15 minutes.' }
                    Get-Content -Path $statusFile -Raw
                }
                if (-not $res.Ok) { Write-SoaLine WARN "${h}: $($res.Error)"; continue }
                $st = $res.Result | ConvertFrom-Json
                Write-SoaLine $(if ($st.Success) { 'PASS' } else { 'FAIL' }) ("Reconcile on {0} against {1}: candidates {2}, changed {3}, errors {4}" -f $h, $st.Server, $st.Candidates, $st.Changed, @($st.Errors).Count)
                foreach ($d in @($st.Changes)) { Write-Host "    $d" -ForegroundColor Gray }
                foreach ($e in @($st.Errors)) { Write-Host "    ERROR: $e" -ForegroundColor Red }
                $done = $true
                break
            }
            if (-not $done) { throw 'No agent host could run the reconcile task (run -Step DeployTasks first).' }
        }

        #----------------------------------------------------------------------------------------------
        'SetMode' {
            if (-not $Mode) { throw '-Mode Audit|Enforced is required for -Step SetMode.' }
            Write-SoaSection "SetMode: $Mode"
            $pol = Get-SoaPolicy -Context $ctx
            if (-not $pol) { throw 'CN=Cloud not found.' }
            if ($Mode -eq 'Enforced' -and -not $Force) {
                $problems = @()
                $current  = @($pol.'msDS-Settings' | Where-Object { $_ } | ForEach-Object { "$_" })
                foreach ($s in $current) { if (-not (Resolve-SoaSid -Sid $s -Server $pdc)) { $problems += "stale SID in allow-list: $s" } }
                foreach ($a in @(Get-SoaAgentGmsa -Config $cfg -Context $ctx)) { if ($current -notcontains $a.Sid) { $problems += "agent gMSA $($a.Name) not in allow-list" } }
                $j = Get-SoaJobGmsa -Config $cfg -Context $ctx
                if (-not $j -or $current -notcontains $j.SID.Value) { $problems += 'toolkit gMSA not in allow-list' }
                foreach ($s in @(Get-PolicyState ((Get-Date).AddDays(-7)))) {
                    if (-not $s.Replicated)     { $problems += "$($s.DC): CN=Cloud not replicated" }
                    if ($s.NtdsaiOk -ne $true)  { $problems += "$($s.DC): ntdsai.dll below minimum / unsupported OS" }
                    if ($s.LoadStatus -ne 'OK') { $problems += "$($s.DC): last policy load (3095, 7 days) = $($s.LoadStatus)" }
                }
                if ($problems.Count) { $problems | ForEach-Object { Write-SoaLine FAIL $_ }; throw 'Pre-checks failed - fix the items above or use -Force.' }
                Write-SoaLine PASS 'Pre-checks passed (allow-list valid, agents + toolkit gMSA present, replicated, policy loaded on all DCs).'
            }
            $now = (@($pol.keywords) -join ',')
            if ($now -eq $Mode) { Write-SoaLine SAME "mode already $Mode" }
            elseif ($Cmdlet.ShouldProcess($ctx.PolicyDN, "Set enforcement mode (keywords) to $Mode")) {
                $switchTime = Get-Date
                Set-ADObject -Identity $ctx.PolicyDN -Server $pdc -Replace @{ keywords = $Mode }
                Write-SoaLine ADD "keywords = $Mode written on $pdc (was $now)"
                Set-SoaManifestEntry -Manifest $manifest -Kind 'PolicyMode' -Key 'Cloud' -Action Changed -Data @{ Mode = $Mode } -Previous @{ Mode = $now }
                Save-Manifest
                $deadline = (Get-Date).AddMinutes(5)
                do {
                    Start-Sleep -Seconds 15
                    $pending = @($ctx.WritableDcs | Where-Object { (Get-SoaPolicyMode -Context $ctx -Server $_) -ne $Mode })
                    if ($pending.Count) { Write-Host "  waiting for replication: $($pending -join ', ')" -ForegroundColor Yellow }
                } while ($pending.Count -and (Get-Date) -lt $deadline)
                Start-Sleep -Seconds 15
                Show-PolicyState @(Get-PolicyState $switchTime.AddMinutes(-1))
                Write-Host 'Next: Test-SoaBehavior.ps1 -Suite Enforcement, Onboarding' -ForegroundColor Cyan
            }
        }

        #----------------------------------------------------------------------------------------------
        'RemoveLegacy' {
            Write-SoaSection 'RemoveLegacy: artefacts of toolkit 1.x'
            $legacyTasks = 'Enforce SCRIL', 'Rotate SCRIL secret', 'Rotate SCRIL hash'
            $hosts = @(@($roles | ForEach-Object { $_.Host }) + @(if ($cfg.LegacyJobHost) { $cfg.LegacyJobHost }) | Select-Object -Unique)
            foreach ($h in $hosts) {
                if (-not $Cmdlet.ShouldProcess($h, 'Remove \SoaEnforcement\ tasks of toolkit 1.x')) { continue }
                $res = Invoke-SoaOnHost -ComputerName $h -ArgumentList (, $legacyTasks) -ScriptBlock {
                    param($Names)
                    $out = @()
                    foreach ($n in $Names) {
                        if (Get-ScheduledTask -TaskName $n -TaskPath '\SoaEnforcement\' -ErrorAction SilentlyContinue) {
                            Unregister-ScheduledTask -TaskName $n -TaskPath '\SoaEnforcement\' -Confirm:$false; $out += "task \SoaEnforcement\$n removed"
                        }
                    }
                    $out
                }
                if ($res.Ok) { foreach ($o in @($res.Result)) { Write-SoaLine DEL "${h}: $o" } } else { Write-SoaLine WARN "${h}: $($res.Error)" }
            }
            if ($cfg.LegacyJobHost -and $cfg.LegacyGmsaName -and $Cmdlet.ShouldProcess($cfg.LegacyJobHost, "Remove legacy script folder and local 'Log on as a batch job' entry")) {
                $lg = $null; try { $lg = Get-ADServiceAccount -Identity $cfg.LegacyGmsaName -Server $pdc } catch { }
                $res = Invoke-SoaOnHost -ComputerName $cfg.LegacyJobHost -ArgumentList $cfg.LegacyScriptFolder, $(if ($lg) { $lg.SID.Value } else { '' }) -ScriptBlock {
                    param($Folder, $Sid)
                    $out = @()
                    foreach ($f in 'Invoke-ScrilJob.ps1', 'SoaEnforcement.config.psd1') {
                        $p = Join-Path $Folder $f
                        if (Test-Path $p) { Remove-Item -Path $p -Force; $out += "removed $p" }
                    }
                    if ((Test-Path $Folder) -and -not @(Get-ChildItem -Path $Folder -Force).Count) { Remove-Item -Path $Folder -Force; $out += "removed empty folder $Folder" }
                    if ($Sid) {
                        $tmp = Join-Path $env:TEMP ('soa_legacy_{0}' -f [guid]::NewGuid().ToString('N'))
                        & secedit.exe /export /cfg "$tmp.inf" /areas USER_RIGHTS | Out-Null
                        $lines = Get-Content -Path "$tmp.inf"
                        $new = foreach ($l in $lines) {
                            if ($l -match '^\s*SeBatchLogonRight\s*=') {
                                $entries = @((($l -split '=', 2)[1] -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne "*$Sid" })
                                'SeBatchLogonRight = ' + ($entries -join ',')
                            } else { $l }
                        }
                        Set-Content -Path "$tmp.inf" -Value $new -Encoding Unicode
                        & secedit.exe /configure /db "$tmp.sdb" /cfg "$tmp.inf" /areas USER_RIGHTS /quiet | Out-Null
                        Remove-Item -Path "$tmp.*" -Force -ErrorAction SilentlyContinue
                        $out += 'legacy gMSA removed from the local "Log on as a batch job" right'
                    }
                    $out
                }
                if ($res.Ok) { foreach ($o in @($res.Result)) { Write-SoaLine DEL "$($cfg.LegacyJobHost): $o" } } else { Write-SoaLine WARN "$($cfg.LegacyJobHost): $($res.Error)" }
            }
            if ($cfg.LegacyGmsaName) {
                $lg = $null; try { $lg = Get-ADServiceAccount -Identity $cfg.LegacyGmsaName -Server $pdc } catch { }
                if ($lg) {
                    foreach ($ou in @($cfg.LegacyTargetUserOUs)) {
                        $n = Remove-SoaTrusteeAces -TargetDn $ou -Sid $lg.SID.Value -WhatIf:$WhatIfPreference
                        if ($n) { Write-SoaLine DEL "$n ACE(s) of $($cfg.LegacyGmsaName) removed on $ou" }
                    }
                    if ($cfg.LegacyGmsaName -ne $cfg.GmsaName) {
                        $pol = Get-SoaPolicy -Context $ctx
                        if ($pol -and @($pol.'msDS-Settings' | ForEach-Object { "$_" }) -contains $lg.SID.Value) {
                            if ($Cmdlet.ShouldProcess($ctx.PolicyDN, "Remove legacy gMSA SID $($lg.SID.Value) from msDS-Settings (BEFORE deleting the gMSA - a stale SID breaks the policy)")) {
                                Set-ADObject -Identity $ctx.PolicyDN -Server $pdc -Remove @{ 'msDS-Settings' = $lg.SID.Value }
                                Write-SoaLine DEL "legacy gMSA removed from the allow-list"
                            }
                        }
                        if ($Cmdlet.ShouldProcess($cfg.LegacyGmsaName, 'Delete legacy gMSA')) {
                            Remove-ADServiceAccount -Identity $lg -Server $pdc -Confirm:$false
                            Write-SoaLine DEL "legacy gMSA $($cfg.LegacyGmsaName) deleted"
                        }
                    } else {
                        Write-SoaLine INFO 'Legacy gMSA name equals GmsaName: all its legacy ACEs were removed - run -Step Delegate again.'
                    }
                } else { Write-SoaLine SKIP "legacy gMSA $($cfg.LegacyGmsaName) not found" }
            }
            if ($cfg.LegacyDiagnosticsGpoName -and (Get-SoaGpo -Name $cfg.LegacyDiagnosticsGpoName -Context $ctx)) {
                Write-SoaLine INFO "Legacy GPO '$($cfg.LegacyDiagnosticsGpoName)' still exists - -Step DiagnosticsGpo renames and adopts it."
            }
            Save-Manifest
        }

        #----------------------------------------------------------------------------------------------
        'Verify' {
            Write-SoaSection ("Verify: CN=Cloud replication and policy-load events since {0:yyyy-MM-dd HH:mm}" -f $Since)
            if (Get-SoaPolicy -Context $ctx) {
                $state = @(Get-PolicyState $Since)
                Show-PolicyState $state
                if (@($state | Where-Object { -not $_.Replicated }).Count) { Write-SoaLine WARN 'Not yet replicated everywhere - re-run in a few minutes.' }
                if (@($state | Where-Object { $_.LoadStatus -eq 'ERROR' }).Count) { Write-SoaLine FAIL 'POLICY LOAD ERROR on at least one DC - do NOT switch to Enforced.' }
                if (@($state | Where-Object { $_.LoadStatus -eq 'NONE' }).Count) { Write-SoaLine INFO 'No 3095 since -Since on some DCs (policy unchanged in that window or diagnostics level 0). Use an earlier -Since.' }
            } else { Write-SoaLine WARN 'CN=Cloud not present yet.' }
            & (Join-Path $PSScriptRoot 'Watch-CloudUserConformance.ps1') -Scope All -ConfigPath $ConfigPath -Html
        }
    }
    Write-InstallLog "Step $current finished"
}
Set-SoaLineLog
Write-InstallLog "RUN $runId END"
Write-Host ''
Write-Host ("Manifest: {0}" -f (Get-SoaManifestPath -Config $cfg)) -ForegroundColor Cyan
