#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Collects the results of the lab validation (L1-L20) or the data for a bug report into one reviewable,
    anonymized report folder - and packages it only after you have reviewed it.

.DESCRIPTION
    Read-only towards AD, GPOs and the toolkit hosts. Nothing is sent anywhere: the result is a folder on this
    workstation. The process has three explicit phases:

      1. COLLECT   .\Export-SoaReport.ps1 [-Purpose Validation|BugReport]
                   Reads the toolkit's own reports and logs (ReportPath), the journals / status files / event counts of
                   every toolkit host (WinRM) and a few domain facts, evaluates L1-L20, replaces identifiers by
                   pseudonyms and writes the folder  <OutputPath>\SoaReport_<purpose>_<timestamp>\
                     README-FIRST.md   what is inside, what was replaced, leak-check result, review checklist
                     report.md         human-readable summary (environment, L1-L20, problems)
                     report.json       the same, machine-readable
                     artifacts\        anonymized copies of the source files
                   The pseudonym map (original -> pseudonym) is written OUTSIDE the folder to
                   <OutputPath>\private\<folder name>.map.csv - it never belongs into the package.
      2. REVIEW    Open README-FIRST.md and report.md. Search for names the tool cannot know (company, sites, project
                   names). If something must be hidden, run phase 1 again with -AdditionalTerms / -TermsFile.
      3. PACKAGE   .\Export-SoaReport.ps1 -Package <folder>
                   Runs the leak check again, lists every file and asks for confirmation; then writes <folder>.zip and
                   <folder>.zip.sha256. Share the zip yourself (GitHub issue, private vulnerability report, e-mail).

    Manual results (items the toolkit cannot observe, e.g. L16 "Cloud Sync still writes under Enforced"):
        .\Export-SoaReport.ps1 -Record L16 -Result PASS -Note 'department change arrived in AD after 2 min'
    Recorded results are stored in <ReportPath>\Validation\manual-results.json and override the automatic status.

    List the validation items with instructions:   .\Export-SoaReport.ps1 -ListChecks

    What is never collected: passwords, password hashes or any secret attribute; the full user list (only users
    that appear in the toolkit's own journals / reports, as pseudonyms); GPO contents; event messages of other
    logs than 'SoaToolkit' (from 'Directory Service' and 'Security' only counts and, for 5136, the writer account).

.PARAMETER Purpose
    Validation (default) or BugReport. Both collect the same data; BugReport puts -Description and recent errors first.

.PARAMETER Description
    Bug report: what you did, what you expected, what happened (anonymized like everything else).

.PARAMETER Days
    Time window for journals, logs and event counts (default 60).

.PARAMETER AdditionalTerms
    Further names to replace (company, site, project names ...). Replaced as TERM-n.

.PARAMETER TermsFile
    Additional text file with one term per line (lines starting with # are ignored). SoaToolkit.terms.txt next to the
    configuration file is always loaded (template: SoaToolkit.terms.example.txt).

.PARAMETER ResetPseudonyms
    Start a new pseudonym map. By default the map of earlier reports (<OutputPath>\private\pseudonyms.csv) is reused,
    so that the same DC, user or OU has the same pseudonym in every report from this workstation.

.PARAMETER NoAnonymize
    Writes the original values (for internal use only). The folder is marked NOT ANONYMIZED and -Package refuses it
    unless -Force is given.

.PARAMETER NoRemote
    Do not contact the toolkit hosts (only local reports and domain facts).

.PARAMETER ExcludeUserDetails
    Leave out the per-user rows of the monitoring report (only counts remain).

.PARAMETER Record
    Records a manual result: L1..L20 or NOTE (free text for the report).

.PARAMETER Package
    Path of a report folder created in phase 1.

.EXAMPLE
    .\Export-SoaReport.ps1 -ListChecks
    .\Export-SoaReport.ps1                                    # SoaToolkit.terms.txt next to the configuration is loaded automatically
    .\Export-SoaReport.ps1 -AdditionalTerms 'Contoso', 'Springfield'
    .\Export-SoaReport.ps1 -Purpose BugReport -Description 'Event task does not start on dc02 after 4720' -Days 7
    .\Export-SoaReport.ps1 -Package 'C:\SoaToolkitAdmin\Reports\Export\SoaReport_Validation_20261121_093015'

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.1.0 (2026-10-22)
    Run as Domain Admin from the admin workstation (RSAT, WinRM to the toolkit hosts). See docs/REPORTING.md.
#>
[CmdletBinding(DefaultParameterSetName = 'Collect', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(ParameterSetName = 'Collect')][ValidateSet('Validation', 'BugReport')][string] $Purpose = 'Validation',
    [Parameter(ParameterSetName = 'Collect')][string] $Description,
    [Parameter(ParameterSetName = 'Collect')][ValidateRange(1, 3650)][int] $Days = 60,
    [Parameter(ParameterSetName = 'Collect')][string[]] $AdditionalTerms = @(),
    [Parameter(ParameterSetName = 'Collect')][string] $TermsFile,
    [Parameter(ParameterSetName = 'Collect')][switch] $NoAnonymize,
    [Parameter(ParameterSetName = 'Collect')][switch] $NoRemote,
    [Parameter(ParameterSetName = 'Collect')][switch] $ExcludeUserDetails,
    [Parameter(ParameterSetName = 'Collect')][switch] $ResetPseudonyms,

    [Parameter(ParameterSetName = 'Record', Mandatory = $true)][ValidatePattern('^(L([1-9]|1[0-9]|20)|NOTE)$')][string] $Record,
    [Parameter(ParameterSetName = 'Record', Mandatory = $true)][ValidateSet('PASS', 'FAIL', 'WARN', 'SKIP', 'N/A', 'INFO')][string] $Result,
    [Parameter(ParameterSetName = 'Record')][string] $Note = '',

    [Parameter(ParameterSetName = 'Package', Mandatory = $true)][string] $Package,
    [Parameter(ParameterSetName = 'Package')][switch] $Force,

    [Parameter(ParameterSetName = 'List', Mandatory = $true)][switch] $ListChecks,

    [string] $OutputPath,
    [string] $ConfigPath
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
Import-Module (Join-Path $ScriptRoot 'SoaToolkit.psm1') -Force -DisableNameChecking -Verbose:$false

#region --- Validation catalogue (keep in sync with docs/VALIDATION.md) -------------------------------
$Catalogue = @(
    [pscustomobject]@{ Id = 'L1';  Title = 'Prerequisites';                       How = '.\Test-SoaPrerequisites.ps1';                                                     Expected = 'all PASS or explained' }
    [pscustomobject]@{ Id = 'L2';  Title = 'Installation dry run';                How = '.\Install-SoaToolkit.ps1 -Step All -KirMsi2025 <msi> -WhatIf';                     Expected = 'no unexpected planned change (review, then -Record L2)' }
    [pscustomobject]@{ Id = 'L3';  Title = 'Installation and idempotency';        How = 'Install -Step All, restart DCs one by one, run Install -Step All again';          Expected = 'second run: no ADD / DEL, no FAIL' }
    [pscustomobject]@{ Id = 'L4';  Title = 'Batch logon GPO keeps existing rights'; How = 'compare SeBatchLogonRight before/after (secedit /export /areas USER_RIGHTS)';  Expected = 'after = before + toolkit gMSA (then -Record L4)' }
    [pscustomobject]@{ Id = 'L5';  Title = 'KIR GPO, WMI filter, engine per DC';  How = '.\Watch-CloudUserConformance.ps1 -Html (DC-NTDSAI, DC-KIR, DC-LOAD)';              Expected = 'engine active on every writable DC' }
    [pscustomobject]@{ Id = 'L6';  Title = 'Audit policy and SACL';               How = 'Install -Step AuditConfig; remove diagnostic SACLs; Install -Step Verify';         Expected = 'DC-AUDIT and AUD-SACL PASS, no AUD-SACL-OTHER' }
    [pscustomobject]@{ Id = 'L7';  Title = 'Tasks and event log as gMSA';         How = 'after DeployTasks wait one MonitorMinutes interval';                               Expected = 'heartbeat event 2000 on every toolkit host' }
    [pscustomobject]@{ Id = 'L8';  Title = 'New cloud-only user (4720 path)';     How = 'create a user in Entra ID, wait for provisioning';                                 Expected = 'event task on the processing DC, target state within minutes' }
    [pscustomobject]@{ Id = 'L9';  Title = 'SOA conversion (5136 path)';          How = 'convert the SOA of an existing AD user to the cloud';                               Expected = '5136 on msDS-ObjectSoa by the agent gMSA, event task, target state' }
    [pscustomobject]@{ Id = 'L10'; Title = 'Reconcile repairs drift';             How = '.\Test-SoaBehavior.ps1 -Suite Onboarding';                                         Expected = 'target state restored' }
    [pscustomobject]@{ Id = 'L11'; Title = 'userAccountControl update method';    How = 'journal of L8 / L10';                                                              Expected = 'method recorded (answers the compare-and-swap question)' }
    [pscustomobject]@{ Id = 'L12'; Title = 'SCRIL matrix with 2.x code';          How = '.\Test-SoaBehavior.ps1 -Suite Scril';                                              Expected = 'results as K11' }
    [pscustomobject]@{ Id = 'L13'; Title = 'Rolling updates pwdLastSet (V1)';     How = '-Suite RollingPrepare, sign in passwordless after expiry, -Suite RollingObserve, -Suite RollingCleanup'; Expected = 'answers V1' }
    [pscustomobject]@{ Id = 'L14'; Title = 'Audit phase impact';                  How = '.\Get-SoaEnforcementImpact.ps1';                                                   Expected = 'only known writers' }
    [pscustomobject]@{ Id = 'L15'; Title = 'Enforced mode';                       How = 'Install -Step SetMode -Mode Enforced; .\Test-SoaBehavior.ps1 -Suite Enforcement';  Expected = 'toolkit write allowed, own write blocked on every DC' }
    [pscustomobject]@{ Id = 'L16'; Title = 'Cloud Sync writes under Enforced';    How = 'change an attribute in Entra ID (e.g. department)';                                Expected = 'arrives in AD (then -Record L16)' }
    [pscustomobject]@{ Id = 'L17'; Title = 'Emergency switch back to Audit';      How = '.\Uninstall-SoaToolkit.ps1 -Step SetModeAudit, then Install -Step SetMode -Mode Enforced'; Expected = 'mode switch effective (counterpart of F1)' }
    [pscustomobject]@{ Id = 'L18'; Title = 'Monitoring';                          How = '.\Watch-CloudUserConformance.ps1 -Html; scheduled monitor as gMSA';                Expected = 'all PASS or explained' }
    [pscustomobject]@{ Id = 'L19'; Title = 'Rollback and reinstall';              How = '.\Uninstall-SoaToolkit.ps1 -Preset Decommission (-WhatIf first), then reinstall';  Expected = 'previous values restored, nothing pre-existing deleted (then -Record L19)' }
    [pscustomobject]@{ Id = 'L20'; Title = 'Long-term rolling';                   How = 'after one PSO max age (+5 days): .\Watch-CloudUserConformance.ps1 -Html';            Expected = 'active users rolled, no Kerberos 0x17' }
)
if ($PSCmdlet.ParameterSetName -eq 'List') {
    foreach ($c in $Catalogue) { Write-Host ("{0,-4} {1}" -f $c.Id, $c.Title) -ForegroundColor Cyan; Write-Host "     how     : $($c.How)"; Write-Host "     expected: $($c.Expected)" -ForegroundColor DarkGray }
    return
}
#endregion

$ConfigPath = Resolve-SoaConfigPath -ConfigPath $ConfigPath -ScriptRoot $ScriptRoot
$cfg = Import-SoaConfig -Path $ConfigPath
Assert-SoaAdminPaths -Config $cfg -ScriptRoot $ScriptRoot
Initialize-SoaReportPath -Config $cfg
if (-not $OutputPath) { $OutputPath = Join-Path $cfg.ReportPath 'Export' }
$manualPath = Join-Path (Join-Path $cfg.ReportPath 'Validation') 'manual-results.json'

#region --- Phase: record a manual result ------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Record') {
    New-Item -Path (Split-Path $manualPath -Parent) -ItemType Directory -Force | Out-Null
    $all = @(Read-SoaJsonArray -Path $manualPath)
    $all += [pscustomobject]@{ Id = $Record; Result = $Result; Note = $Note; Time = (Get-Date).ToString('s'); By = "$env:USERDOMAIN\$env:USERNAME" }
    ConvertTo-Json -InputObject @($all) -Depth 3 | Set-Content -LiteralPath $manualPath -Encoding UTF8
    Write-SoaLine PASS ("recorded {0} = {1} in {2}" -f $Record, $Result, $manualPath)
    return
}
#endregion

#region --- Phase: package a reviewed folder ---------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Package') {
    $folder = (Resolve-Path -LiteralPath $Package).Path.TrimEnd('\')
    if (-not (Test-Path -LiteralPath (Join-Path $folder 'report.md'))) { throw "$folder is not a report folder (report.md missing)." }
    $name = Split-Path $folder -Leaf
    $notAnon = Test-Path -LiteralPath (Join-Path $folder 'NOT-ANONYMIZED.txt')
    if ($notAnon -and -not $Force) { throw 'This folder was created with -NoAnonymize. Packaging refused (use -Force only for internal hand-over).' }
    $mapFile = Join-Path (Join-Path (Split-Path $folder -Parent) 'private') "$name.map.csv"
    $map = @(if (Test-Path -LiteralPath $mapFile) { Import-Csv -LiteralPath $mapFile } else { Write-SoaLine WARN "pseudonym map not found ($mapFile) - only pattern checks possible" })
    $anon = New-SoaAnonymizer
    $files = @(Get-ChildItem -LiteralPath $folder -Recurse -File)
    $hits = @()
    foreach ($f in $files) { foreach ($h in (Find-SoaResidualIdentifier -Anonymizer $anon -Text (Get-Content -LiteralPath $f.FullName -Raw) -MapEntries $map)) { $hits += [pscustomobject]@{ File = $f.FullName.Substring($folder.Length + 1); Type = $h.Type; Value = $h.Value } } }
    Write-SoaSection "Package $name"
    foreach ($f in $files) { Write-Host ("  {0,-60} {1,10:N0} bytes" -f $f.FullName.Substring($folder.Length + 1), $f.Length) }
    if ($hits.Count -and -not $notAnon) {
        foreach ($h in $hits) { Write-SoaLine FAIL ("{0}: {1} '{2}'" -f $h.File, $h.Type, $h.Value) }
        if (-not $Force) { throw "Leak check found $($hits.Count) possible identifier(s). Re-run the collection with -AdditionalTerms, or edit the files and package again (-Force packages anyway)." }
    } elseif (-not $notAnon) { Write-SoaLine PASS 'leak check: no original value of the pseudonym map and no identifier pattern found' }
    $zip = "$folder.zip"
    if ($PSCmdlet.ShouldProcess($zip, "Create package from $($files.Count) reviewed file(s)")) {
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        Compress-Archive -Path (Join-Path $folder '*') -DestinationPath $zip
        $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
        "$hash  $(Split-Path $zip -Leaf)" | Set-Content -LiteralPath "$zip.sha256" -Encoding ASCII
        Write-SoaLine ADD "package: $zip"
        Write-SoaLine INFO "SHA-256: $hash"
        Write-Host 'The pseudonym map stays in the private folder. Do not attach it.' -ForegroundColor Yellow
    }
    return
}
#endregion

#region --- Phase: collect ---------------------------------------------------------------------------
$since = (Get-Date).AddDays(-$Days)
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$bundleName = "SoaReport_{0}_{1}" -f $Purpose, $stamp
$bundle = Join-Path $OutputPath $bundleName
$artDir = Join-Path $bundle 'artifacts'
New-Item -Path $artDir -ItemType Directory -Force | Out-Null
$warnings = New-Object System.Collections.Generic.List[string]
function Add-CollectWarning([string]$Text) { $warnings.Add($Text); Write-SoaLine WARN $Text }
function Format-Ts($Value) { if ($null -eq $Value -or "$Value" -eq '') { return '' }; try { ([datetime]$Value).ToString('yyyy-MM-dd HH:mm') } catch { "$Value" } }
function Read-JsonFile([string]$Path) { if ($Path -and (Test-Path -LiteralPath $Path)) { try { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { Add-CollectWarning "unreadable JSON: $Path"; $null } } }
function Get-LatestFile([string]$Dir, [string]$Filter, [switch]$Recurse) {
    if (-not (Test-Path -LiteralPath $Dir)) { return $null }
    Get-ChildItem -LiteralPath $Dir -Filter $Filter -File -Recurse:$Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

Write-SoaSection ("SOA Toolkit {0} - Export-SoaReport - purpose {1} - window {2} days" -f (Get-SoaVersion).Version, $Purpose, $Days)

# --- Domain facts --------------------------------------------------------------------------------------
$ctx = Get-SoaContext
$server = $ctx.Server
$roles = @(Get-SoaHostRoles -Config $cfg -Context $ctx)
$allDcs = @(Get-ADDomainController -Filter * -Server $server)
$forest = Get-ADForest -Server $server
$rolling = (Get-ADObject -Identity $ctx.DomainDN -Server $server -Properties 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts').'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'
$policy = Get-SoaPolicy -Context $ctx
$mode = Get-SoaPolicyMode -Context $ctx -Server $server
$agents = @(try { Get-SoaAgentGmsa -Config $cfg -Context $ctx -Quiet } catch { Add-CollectWarning "agent gMSA lookup failed: $($_.Exception.Message)" })
$pso = try { Get-ADFineGrainedPasswordPolicy -Identity $cfg.PsoName -Server $server } catch { $null }
$provisioned = @(Get-ADUser -LDAPFilter (Get-SoaCloudUserFilter) -Server $server -Properties 'msDS-ObjectSoa', userAccountControl -ResultPageSize 500)
$marked = @($provisioned | Where-Object { "$($_.'msDS-ObjectSoa')" -eq 'Cloud' })
$adModule = Get-Module ActiveDirectory
$gpModule = Get-Module -ListAvailable GroupPolicy | Select-Object -First 1

# Integrity of the scripts used on this workstation (against SHA256SUMS.txt of the release, if present)
$sumsFile = @((Join-Path $ScriptRoot 'SHA256SUMS.txt'), (Join-Path (Split-Path $ScriptRoot -Parent) 'SHA256SUMS.txt')) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$sums = @{}
if ($sumsFile) { foreach ($l in Get-Content -LiteralPath $sumsFile) { if ($l -match '^([0-9a-f]{64})\s+\*?(.+)$') { $sums[(Split-Path $Matches[2] -Leaf).ToLower()] = $Matches[1] } } }
$localFiles = @(Get-ChildItem -LiteralPath $ScriptRoot -File | Where-Object { $_.Extension -in '.ps1', '.psm1' } | ForEach-Object {
    $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
    [pscustomobject]@{ File = $_.Name; Sha256 = $h; Release = $(if (-not $sums.Count) { 'no SHA256SUMS.txt' } elseif (-not $sums.ContainsKey($_.Name.ToLower())) { 'not in release' } elseif ($sums[$_.Name.ToLower()] -eq $h) { 'match' } else { 'MODIFIED' }) }
})

$environment = [ordered]@{
    Collected        = (Get-Date).ToString('s')
    ToolkitVersion   = (Get-SoaVersion).Version
    Domain           = $ctx.DnsRoot
    NetBios          = $ctx.NetBios
    DomainMode       = "$($ctx.Domain.DomainMode)"
    ForestMode       = "$($forest.ForestMode)"
    AutomaticRolling = [bool]$rolling
    WritableDcs      = @($ctx.WritableDcs).Count
    ReadOnlyDcs      = @($allDcs | Where-Object { $_.IsReadOnly }).Count
    AgentHosts       = @($cfg.AgentHosts).Count
    AgentHostsOnDcs  = @($roles | Where-Object { $_.IsAgent -and $_.IsDc }).Count
    AgentGmsas       = @($agents | ForEach-Object { $_.Name })
    PolicyPresent    = [bool]$policy
    PolicyMode       = $mode
    AllowListSids    = $(if ($policy) { @($policy.'msDS-Settings').Count } else { 0 })
    Pso              = $(if ($pso) { [ordered]@{ Name = $pso.Name; Precedence = $pso.Precedence; MaxAgeDays = [int]$pso.MaxPasswordAge.TotalDays; MinAgeDays = [int]$pso.MinPasswordAge.TotalDays; MinLength = $pso.MinPasswordLength; Complexity = $pso.ComplexityEnabled; History = $pso.PasswordHistoryCount; LockoutThreshold = $pso.LockoutThreshold } } else { $null })
    ProvisionedUsers = $provisioned.Count
    MarkedUsers      = $marked.Count
    WriteScope       = "$($cfg.WriteScope)"
    PilotMode        = [bool]$cfg.PilotMode
    DomainControllers = @($allDcs | Sort-Object HostName | ForEach-Object { [ordered]@{ Host = $_.HostName; ReadOnly = $_.IsReadOnly; OS = $_.OperatingSystem; OSVersion = $_.OperatingSystemVersion; Site = $_.Site; IsAgentHost = $false } })
    AdminWorkstation = [ordered]@{ PowerShell = $PSVersionTable.PSVersion.ToString(); OSBuild = [Environment]::OSVersion.Version.ToString(); ActiveDirectoryModule = "$($adModule.Version)"; GroupPolicyModule = "$($gpModule.Version)" }
    ScriptIntegrity  = $localFiles
}
foreach ($d in $environment.DomainControllers) { $d.IsAgentHost = [bool](@($cfg.AgentHosts) | Where-Object { $_ -ieq $d.Host }) }

# --- Hosts (WinRM) --------------------------------------------------------------------------------------
$hostBlock = {
    param($DataPath, $InstallPath, $LogName, $TaskFolder, [datetime]$Since, [bool]$IsDc, $AgentService)
    $o = [ordered]@{}
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $o.OS = [pscustomobject]@{ Caption = $cv.ProductName; DisplayVersion = $cv.DisplayVersion; Build = $cv.CurrentBuild; Ubr = $cv.UBR; InstallationType = $cv.InstallationType }
    $o.LastBoot = try { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('s') } catch { $null }
    $o.Hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 3 | ForEach-Object { [pscustomobject]@{ Id = $_.HotFixID; InstalledOn = $_.InstalledOn.ToString('yyyy-MM-dd'); Description = $_.Description } })
    $o.PowerShell = $PSVersionTable.PSVersion.ToString()
    $svc = Get-CimInstance Win32_Service -Filter "Name='$AgentService'" -ErrorAction SilentlyContinue
    $o.Agent = $null
    if ($svc) {
        $exe = if ($svc.PathName -match '^"([^"]+)"') { $Matches[1] } else { ($svc.PathName -split ' ')[0] }
        $ver = try { (Get-Item -LiteralPath $exe).VersionInfo.FileVersion } catch { $null }
        $o.Agent = [pscustomobject]@{ State = $svc.State; StartName = $svc.StartName; Version = $ver }
    }
    $o.ToolkitFiles = @(if (Test-Path -LiteralPath $InstallPath) { Get-ChildItem -LiteralPath $InstallPath -File | Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1', '.json' } | ForEach-Object { [pscustomobject]@{ File = $_.Name; Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower() } } })
    $o.Tasks = @(Get-ScheduledTask -TaskPath $TaskFolder -ErrorAction SilentlyContinue | ForEach-Object {
        $i = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        [pscustomobject]@{ Name = $_.TaskName; State = "$($_.State)"; Principal = $_.Principal.UserId; LastRun = $(if ($i -and $i.LastRunTime) { $i.LastRunTime.ToString('s') }); LastResult = $(if ($i) { '0x{0:X}' -f $i.LastTaskResult }) } })
    $o.EventLog = [pscustomobject]@{ Present = $false; Counts = @(); LastHeartbeat = $null; Recent = @() }
    if ([System.Diagnostics.EventLog]::Exists($LogName)) {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $Since } -MaxEvents 5000 -ErrorAction SilentlyContinue)
        $hb = $ev | Where-Object { $_.Id -eq 2000 } | Select-Object -First 1
        $o.EventLog = [pscustomobject]@{
            Present = $true
            Counts = @($ev | Group-Object Id | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Id = [int]$_.Name; Count = $_.Count } })
            LastHeartbeat = $(if ($hb) { $hb.TimeCreated.ToString('s') })
            Recent = @($ev | Where-Object { $_.Id -ne 2000 -or $_.LevelDisplayName -ne 'Information' } | Select-Object -First 40 | ForEach-Object { $m = "$($_.Message)"; [pscustomobject]@{ Time = $_.TimeCreated.ToString('s'); Id = $_.Id; Level = $_.LevelDisplayName; Message = $m.Substring(0, [Math]::Min(800, $m.Length)) } })
        }
    }
    if ($IsDc) {
        $ds = @(Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 3095, 3097, 3098; StartTime = $Since } -MaxEvents 5000 -ErrorAction SilentlyContinue)
        $l95 = $ds | Where-Object { $_.Id -eq 3095 } | Select-Object -First 1
        $o.DirectoryService = [pscustomobject]@{ Counts = @($ds | Group-Object Id | ForEach-Object { [pscustomobject]@{ Id = [int]$_.Name; Count = $_.Count } }); Last3095 = $(if ($l95) { $l95.TimeCreated.ToString('s') }) }
        $sec = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720, 5136; StartTime = $Since } -MaxEvents 20000 -ErrorAction SilentlyContinue)
        $soaWrites = @(foreach ($e in ($sec | Where-Object { $_.Id -eq 5136 })) {
            $x = [xml]$e.ToXml(); $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            if ($d['AttributeLDAPDisplayName'] -eq 'msDS-ObjectSoa') { [pscustomobject]@{ Time = $e.TimeCreated.ToString('s'); Writer = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])"; Value = $d['AttributeValue']; Operation = $d['OperationType'] } }
        })
        $created = @(foreach ($e in ($sec | Where-Object { $_.Id -eq 4720 })) { $x = [xml]$e.ToXml(); $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }; "$($d['SubjectDomainName'])\$($d['SubjectUserName'])" })
        $o.Security = [pscustomobject]@{
            Created4720ByWriter = @($created | Group-Object | ForEach-Object { [pscustomobject]@{ Writer = $_.Name; Count = $_.Count } })
            ObjectSoa5136 = @($soaWrites | Group-Object Writer | ForEach-Object { [pscustomobject]@{ Writer = $_.Name; Count = $_.Count; Last = ($_.Group | Select-Object -First 1).Time } })
            Other5136 = @($sec | Where-Object { $_.Id -eq 5136 }).Count - $soaWrites.Count
        }
    }
    $st = Join-Path $DataPath 'Status'
    $o.Status = [pscustomobject]@{
        Conformance = $(if (Test-Path (Join-Path $st 'conformance.json')) { Get-Content (Join-Path $st 'conformance.json') -Raw })
        Monitor     = $(if (Test-Path (Join-Path $st 'monitor.json')) { Get-Content (Join-Path $st 'monitor.json') -Raw })
    }
    $o.Journal = @(if (Test-Path (Join-Path $DataPath 'Journal')) {
        foreach ($f in (Get-ChildItem (Join-Path $DataPath 'Journal') -Filter 'journal-*.jsonl' -File | Where-Object { $_.LastWriteTime -ge $Since })) {
            foreach ($line in (Get-Content -LiteralPath $f.FullName)) { if ($line.Trim()) { $line } }
        }
    })
    $o.Logs = @(if (Test-Path (Join-Path $DataPath 'Logs')) {
        foreach ($f in (Get-ChildItem (Join-Path $DataPath 'Logs') -Filter '*.log' -File | Where-Object { $_.LastWriteTime -ge $Since } | Sort-Object LastWriteTime -Descending | Select-Object -First 6)) {
            [pscustomobject]@{ File = $f.Name; Tail = @(Get-Content -LiteralPath $f.FullName -Tail 200) }
        }
    })
    [pscustomobject]$o
}

$hosts = @()
if (-not $NoRemote) {
    foreach ($r in $roles) {
        Write-Host ("  collecting from {0} ..." -f $r.Host) -ForegroundColor DarkGray
        $res = Invoke-SoaOnHost -ComputerName $r.Host -ScriptBlock $hostBlock -ArgumentList $cfg.DataPath, $cfg.ScriptInstallPath, $cfg.EventLogName, $cfg.TaskFolder, $since, $r.IsDc, (Get-SoaConstant 'AgentService')
        if (-not $res.Ok) { Add-CollectWarning "host $($r.Host) not reachable: $($res.Error)" }
        $hosts += [pscustomobject]@{ Host = $r.Host; IsDc = $r.IsDc; IsAgent = $r.IsAgent; Ok = $res.Ok; Error = $res.Error; Data = $res.Result }
    }
}

# --- Local reports (ReportPath) ---------------------------------------------------------------------------
$rp = $cfg.ReportPath
$prereqFile  = Get-LatestFile (Join-Path $rp 'Prerequisites') 'checks.csv' -Recurse
$monitorFile = Get-LatestFile (Join-Path $rp 'Monitor') 'monitor_*.json'
$impactFile  = Get-LatestFile (Join-Path $rp 'Impact') 'writer-summary.csv' -Recurse
$testFile    = Join-Path (Join-Path $rp 'Tests') 'test-state.json'
$findFile    = Join-Path (Join-Path $rp 'Tests') 'behavior-findings.json'
$manifestFile = Get-SoaManifestPath -Config $cfg
$runLogs = @(if (Test-Path (Join-Path $rp 'State')) { Get-ChildItem (Join-Path $rp 'State') -File | Where-Object { $_.Name -match '^(install|uninstall)_\d{8}\.log$' -and $_.LastWriteTime -ge $since } | Sort-Object Name })

$prereq  = @(if ($prereqFile) { Import-Csv -LiteralPath $prereqFile.FullName })
$monitor = if ($monitorFile) { Read-JsonFile $monitorFile.FullName } else { $null }
$impact  = @(if ($impactFile) { Import-Csv -LiteralPath $impactFile.FullName })
$tests   = @(Read-SoaJsonArray -Path $testFile)
$findings = Read-JsonFile $findFile
$manifest = Read-JsonFile $manifestFile
$manual  = @(Read-SoaJsonArray -Path $manualPath)

# Run logs -> runs with counted output lines
$runs = @{}
foreach ($f in $runLogs) {
    foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
        if ($line -match '^(?<t>\S+) .*? RUN (?<id>[0-9a-f]{8}) START tool=(?<tool>\w+) version=(?<v>\S+) steps=(?<s>\S*)(?: preset=(?<p>\S*))? whatif=(?<w>\w+)') {
            $runs[$Matches.id] = [pscustomobject]@{ Id = $Matches.id; Tool = $Matches.tool; Start = [datetime]$Matches.t; Version = $Matches.v; Steps = @($Matches.s -split ',' | Where-Object { $_ }); Preset = $Matches.p; WhatIf = ($Matches.w -eq 'True'); Ended = $false
                                                Counts = @{ ADD = 0; DEL = 0; SAME = 0; FAIL = 0; WARN = 0; SKIP = 0; PASS = 0; INFO = 0 }; Samples = New-Object System.Collections.Generic.List[string]; File = $f.Name }
        } elseif ($line -match '^\S+ RUN (?<id>[0-9a-f]{8}) \[(?<st>[A-Z]+)\] (?<x>.*)$' -and $runs.ContainsKey($Matches.id)) {
            $r = $runs[$Matches.id]; $r.Counts[$Matches.st]++
            if ($Matches.st -in 'ADD', 'DEL', 'FAIL', 'WARN' -and $r.Samples.Count -lt 15) { $r.Samples.Add("[$($Matches.st)] $($Matches.x)") }
        } elseif ($line -match ' RUN (?<id>[0-9a-f]{8}) END$' -and $runs.ContainsKey($Matches.id)) { $runs[$Matches.id].Ended = $true }
    }
}
$runList = @($runs.Values | Sort-Object Start)
$legacyLogs = @($runLogs | Where-Object { -not (Select-String -LiteralPath $_.FullName -Pattern ' RUN [0-9a-f]{8} START' -Quiet) })

# Journals of all hosts (deduplicated)
$journal = @()
$seen = @{}
foreach ($h in $hosts) {
    if (-not $h.Ok) { continue }
    foreach ($line in @($h.Data.Journal)) {
        try { $e = $line | ConvertFrom-Json } catch { continue }
        $k = "$($e.Time)|$($e.Host)|$($e.User)"
        if ($seen.ContainsKey($k)) { continue }; $seen[$k] = $true
        $journal += $e
    }
}
# Without remote collection: use the local journal if this workstation is a toolkit host (single-host labs)
if (-not $journal.Count -and (Test-Path -LiteralPath (Join-Path $cfg.DataPath 'Journal'))) {
    foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $cfg.DataPath 'Journal') -Filter 'journal-*.jsonl' -File | Where-Object { $_.LastWriteTime -ge $since })) {
        foreach ($line in (Get-Content -LiteralPath $f.FullName)) { if ($line.Trim()) { try { $journal += ($line | ConvertFrom-Json) } catch { Write-Verbose 'skipped unreadable journal line' } } }
    }
}
$journal = @($journal | Sort-Object Time)
#endregion

#region --- Evaluate L1-L20 ---------------------------------------------------------------------------
$auto = [ordered]@{}
function Set-L([string]$Id, [string]$Status, [string]$Detail, [string[]]$Evidence = @()) { $auto[$Id] = [pscustomobject]@{ Status = $Status; Detail = $Detail; Evidence = @($Evidence) } }
function Get-MonitorChecks([string[]]$Ids) { @(if ($monitor) { @($monitor.Results) | Where-Object { $_.CheckId -in $Ids } }) }
function Get-Worst($Rows) { Get-SoaWorstStatus (@($Rows | ForEach-Object { $_.Status })) }
function Get-LatestTest([string]$Name) { @($tests | Where-Object { $_.Test -eq $Name } | Sort-Object Time -Descending) | Select-Object -First 1 }
$monAge = if ($monitorFile) { "monitor report $($monitorFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))" } else { $null }

# L1
if ($prereq.Count) {
    $f = @($prereq | Where-Object { $_.Status -eq 'FAIL' }); $w = @($prereq | Where-Object { $_.Status -eq 'WARN' })
    Set-L 'L1' $(if ($f.Count) { 'FAIL' } elseif ($w.Count) { 'WARN' } else { 'PASS' }) ("{0} checks, {1} FAIL, {2} WARN" -f $prereq.Count, $f.Count, $w.Count) (@("prerequisites report $($prereqFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))") + @($f + $w | Select-Object -First 10 | ForEach-Object { "[$($_.Status)] $($_.DC) $($_.Check): $($_.Detail)" }))
} else { Set-L 'L1' 'OPEN' 'no prerequisites report found' }

# L2 / L3
$installs = @($runList | Where-Object { $_.Tool -eq 'Install' })
$dry = @($installs | Where-Object { $_.WhatIf -and ($_.Steps -contains 'HostGroup') -and $_.Steps.Count -ge 8 }) | Select-Object -Last 1
if ($dry) { Set-L 'L2' 'REVIEW' ("dry run {0}: {1} planned ADD, {2} DEL, {3} FAIL - confirm with -Record L2" -f $dry.Start.ToString('yyyy-MM-dd HH:mm'), $dry.Counts.ADD, $dry.Counts.DEL, $dry.Counts.FAIL) @($dry.Samples) }
elseif ($legacyLogs.Count) { Set-L 'L2' 'OPEN' 'only install logs without run markers (toolkit < 2.0.2) - repeat with 2.0.2' }
else { Set-L 'L2' 'OPEN' 'no -WhatIf run of Install -Step All found' }

$real = @($installs | Where-Object { -not $_.WhatIf })
$first = $real | Where-Object { $_.Steps.Count -ge 8 -and $_.Counts.ADD -gt 0 } | Select-Object -First 1
if ($first) {
    $second = @($real | Where-Object { $_.Start -gt $first.Start -and $_.Steps.Count -ge 8 }) | Select-Object -Last 1
    if (-not $second) { Set-L 'L3' 'OPEN' ("first full run {0} ({1} ADD) - run Install -Step All again" -f $first.Start.ToString('yyyy-MM-dd HH:mm'), $first.Counts.ADD) }
    elseif ($second.Counts.ADD -eq 0 -and $second.Counts.DEL -eq 0 -and $second.Counts.FAIL -eq 0) { Set-L 'L3' 'PASS' ("repeat run {0}: only SAME ({1}); first run {2} added {3}" -f $second.Start.ToString('yyyy-MM-dd HH:mm'), $second.Counts.SAME, $first.Start.ToString('yyyy-MM-dd HH:mm'), $first.Counts.ADD) @("first run $($first.Id) ($($first.File)): " + (($first.Counts.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '), "repeat run $($second.Id) ($($second.File)): " + (($second.Counts.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')) }
    else { Set-L 'L3' $(if ($second.Counts.FAIL) { 'FAIL' } else { 'WARN' }) ("repeat run {0}: {1} ADD, {2} DEL, {3} FAIL" -f $second.Start.ToString('yyyy-MM-dd HH:mm'), $second.Counts.ADD, $second.Counts.DEL, $second.Counts.FAIL) @($second.Samples) }
} else { Set-L 'L3' 'OPEN' 'no applied full installation run with run markers found' }

# L4
$batch = Get-MonitorChecks 'BATCH'
if ($batch.Count) { $s = Get-Worst $batch; Set-L 'L4' $(if ($s -eq 'PASS') { 'REVIEW' } else { $s }) ("BATCH: {0} host(s), worst {1} - compare the before/after lists, then -Record L4" -f $batch.Count, $s) @($batch | ForEach-Object { "[$($_.Status)] $($_.Item): $($_.Detail)" }) }
else { Set-L 'L4' 'OPEN' "no BATCH result (run Watch-CloudUserConformance.ps1 -Scope All)" }

# L5
$eng = Get-MonitorChecks 'DC-NTDSAI', 'DC-KIR', 'DC-LOAD'
if ($eng.Count) { Set-L 'L5' (Get-Worst $eng) ("{0} engine checks, worst {1}" -f $eng.Count, (Get-Worst $eng)) (@($monAge) + @($eng | Where-Object { $_.Status -ne 'PASS' } | ForEach-Object { "[$($_.Status)] $($_.CheckId) $($_.Item): $($_.Detail)" })) }
else { Set-L 'L5' 'OPEN' 'no monitor report with engine checks' }

# L6
$aud = Get-MonitorChecks 'DC-AUDIT', 'AUD-SACL'; $other = Get-MonitorChecks 'AUD-SACL-OTHER'
if ($aud.Count) {
    $s = Get-Worst $aud; if ($s -eq 'PASS' -and $other.Count) { $s = 'WARN' }
    Set-L 'L6' $s ("{0} audit/SACL checks, {1} container(s) with other audit rules" -f $aud.Count, $other.Count) (@($aud + $other | Where-Object { $_.Status -ne 'PASS' } | ForEach-Object { "[$($_.Status)] $($_.CheckId) $($_.Item): $($_.Detail)" }))
} else { Set-L 'L6' 'OPEN' 'no monitor report with DC-AUDIT / AUD-SACL (toolkit >= 2.0.1, -Scope All)' }

# L7
if ($hosts.Count) {
    $limit = (Get-Date).AddMinutes(-(2 * [int]$cfg.MonitorMinutes + 30))
    $hb = @($hosts | ForEach-Object {
        $last = if ($_.Ok -and $_.Data.EventLog.LastHeartbeat) { [datetime]$_.Data.EventLog.LastHeartbeat } else { $null }
        [pscustomobject]@{ Host = $_.Host; Status = $(if (-not $_.Ok) { 'WARN' } elseif ($last -and $last -ge $limit) { 'PASS' } else { 'FAIL' }); Last = $last } })
    Set-L 'L7' (Get-Worst $hb) ("{0} of {1} host(s) with a current heartbeat (2000)" -f @($hb | Where-Object { $_.Status -eq 'PASS' }).Count, $hb.Count) @($hb | ForEach-Object { "[$($_.Status)] $($_.Host): last heartbeat $(if ($_.Last) { $_.Last.ToString('yyyy-MM-dd HH:mm') } else { 'none' })" })
} else { Set-L 'L7' 'OPEN' 'hosts not collected (-NoRemote)' }

# L8 / L9 - event-triggered runs, origin and latency
$eventRuns = @($journal | Where-Object { $_.Trigger -eq 'Event' -and $_.ObjectGuid })
$evRows = @(foreach ($e in $eventRuns) {
    try {
        $u = Get-ADUser -Identity $e.ObjectGuid -Server $server -Properties whenCreated
        $md = Get-SoaSecretMeta -Dn $u.DistinguishedName -Server $server
        $origin = Get-SoaOriginKind -WhenCreated $u.whenCreated -AnchorTime $md.AnchorTime
        $ref = if ($origin -eq 'cloud-native') { $u.whenCreated } elseif ($md.AnchorTime) { [datetime]$md.AnchorTime } else { $null }
        [pscustomobject]@{ User = $e.User; Host = $e.Host; Time = [datetime]$e.Time; Origin = $origin; LatencyMin = $(if ($ref) { [Math]::Round(([datetime]$e.Time - $ref).TotalMinutes, 1) } else { $null }) }
    } catch { [pscustomobject]@{ User = $e.User; Host = $e.Host; Time = [datetime]$e.Time; Origin = 'unknown (object not found)'; LatencyMin = $null } }
})
$soa5136 = @($hosts | Where-Object { $_.Ok -and $_.Data.Security } | ForEach-Object { $h = $_.Host; @($_.Data.Security.ObjectSoa5136) | ForEach-Object { "5136 msDS-ObjectSoa on ${h}: $($_.Count)x by $($_.Writer) (last $(Format-Ts $_.Last))" } })
foreach ($pair in @(@('L8', 'cloud-native'), @('L9', 'SOA-converted'))) {
    $rows = @($evRows | Where-Object { $_.Origin -eq $pair[1] })
    $ev = @($rows | ForEach-Object { "{0} on {1} at {2:yyyy-MM-dd HH:mm}, {3} min after {4}" -f $_.User, $_.Host, $_.Time, $_.LatencyMin, $(if ($pair[1] -eq 'cloud-native') { 'creation' } else { 'conversion' }) } | Select-Object -First 10)
    if ($pair[0] -eq 'L9') { $ev += $soa5136 }
    if (-not $rows.Count) { Set-L $pair[0] 'OPEN' ("no event-triggered run for a {0} user in the last {1} days" -f $pair[1], $Days) $ev; continue }
    $fast = @($rows | Where-Object { $null -ne $_.LatencyMin -and $_.LatencyMin -le 10 })
    Set-L $pair[0] $(if ($fast.Count) { 'PASS' } else { 'WARN' }) ("{0} event-triggered run(s), fastest {1} min" -f $rows.Count, (@($rows | Where-Object { $null -ne $_.LatencyMin } | Measure-Object LatencyMin -Minimum).Minimum)) $ev
}

# L10, L12, L13, L15 - Test-SoaBehavior results
function Set-FromTest([string]$Id, [string[]]$Names, [string]$NeedMode) {
    $t = @($Names | ForEach-Object { Get-LatestTest $_ } | Where-Object { $_ })
    if ($t.Count -lt $Names.Count) { Set-L $Id 'OPEN' ("no result yet for: {0}" -f (($Names | Where-Object { -not (Get-LatestTest $_) }) -join ', ')) @($t | ForEach-Object { "[$($_.Status)] $($_.Test) $(Format-Ts $_.Time): $($_.Detail)" }); return }
    $s = Get-Worst $t
    if ($NeedMode -and @($t | Where-Object { $_.PolicyMode -ne $NeedMode }).Count -and $s -ne 'FAIL') { $s = 'OPEN'; $note = " - repeat in mode $NeedMode" } else { $note = '' }
    Set-L $Id $s ("{0}{1}" -f (($t | ForEach-Object { "$($_.Test)=$($_.Status)" }) -join ', '), $note) @($t | ForEach-Object { "[$($_.Status)] $($_.Test) $(Format-Ts $_.Time) (mode $($_.PolicyMode)): $($_.Detail)" })
}
Set-FromTest 'L10' @('Onboarding') $null
Set-FromTest 'L12' @('Scril') $null
Set-FromTest 'L13' @('Rolling') $null
Set-FromTest 'L15' @('ProbeAllowed', 'UnauthorizedWrite') 'Enforced'

# L11 - update method from the journal
$methods = @($journal | ForEach-Object { @($_.Actions) } | Where-Object { $_ -match '^userAccountControl .*\((\w+)\)$' } | ForEach-Object { if ($_ -match '\((\w+)\)$') { $Matches[1] } })
if ($methods.Count) { Set-L 'L11' 'PASS' ("methods used: {0}" -f (($methods | Group-Object | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')) }
else { Set-L 'L11' 'OPEN' 'no userAccountControl change in the journals of the window' }

# L14
if ($impact.Count) {
    $would = @($impact | Where-Object { $_.Verdict -like '*WOULD*' })
    Set-L 'L14' $(if ($would.Count) { 'WARN' } else { 'PASS' }) ("{0} writer group(s), {1} would be blocked" -f $impact.Count, $would.Count) (@("impact report $($impactFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))") + @($would | ForEach-Object { "$($_.Verdict): $($_.Subject) ($($_.Count) events)" }))
} else { Set-L 'L14' 'OPEN' 'no impact report found' }

# L16 - manual only
Set-L 'L16' 'OPEN' 'manual: change an attribute in Entra ID under Enforced, then -Record L16'

# L17
$back = @($runList | Where-Object { $_.Tool -eq 'Uninstall' -and -not $_.WhatIf -and $_.Steps -contains 'SetModeAudit' }) | Select-Object -Last 1
if ($back) {
    $again = @($installs | Where-Object { -not $_.WhatIf -and $_.Steps -contains 'SetMode' -and $_.Start -gt $back.Start }) | Select-Object -Last 1
    if ($again) { Set-L 'L17' $(if ($back.Counts.FAIL -or $again.Counts.FAIL) { 'FAIL' } else { 'PASS' }) ("SetModeAudit {0}, SetMode again {1}" -f $back.Start.ToString('yyyy-MM-dd HH:mm'), $again.Start.ToString('yyyy-MM-dd HH:mm')) @($back.Samples + $again.Samples) }
    else { Set-L 'L17' 'OPEN' ("SetModeAudit {0} found - switch back with Install -Step SetMode -Mode Enforced" -f $back.Start.ToString('yyyy-MM-dd HH:mm')) }
} else { Set-L 'L17' 'OPEN' 'no applied Uninstall -Step SetModeAudit found' }

# L18
if ($monitor) {
    $hostMon = @($hosts | Where-Object { $_.Ok -and $_.Data.Status.Monitor } | ForEach-Object { $m = $_.Data.Status.Monitor | ConvertFrom-Json; [pscustomobject]@{ Host = $_.Host; Status = $m.Overall; Time = $m.Time } })
    $s = Get-SoaWorstStatus (@($monitor.Overall) + @($hostMon | ForEach-Object { $_.Status }))
    $monResult = if ($monitor.PSObject.Properties.Name -contains 'Assessment' -and $monitor.Assessment.Result) { "result $($monitor.Assessment.Result); " } else { '' }   # Result since 2.1.0
    Set-L 'L18' $s ("interactive: {0} ({1}FAIL {2}, WARN {3}); scheduled monitor on {4} host(s)" -f $monitor.Overall, $monResult, $monitor.Counts.FAIL, $monitor.Counts.WARN, $hostMon.Count) (@($monAge) + @($hostMon | ForEach-Object { "scheduled monitor $($_.Host): $($_.Status) ($(Format-Ts $_.Time))" }) + @(@($monitor.Results) | Where-Object { $_.Status -in 'FAIL', 'WARN' } | Select-Object -First 15 | ForEach-Object { "[$($_.Status)] $($_.CheckId) $($_.Item): $($_.Detail)" }))
} else { Set-L 'L18' 'OPEN' 'no monitor report (Watch-CloudUserConformance.ps1 -Html)' }

# L19
$rb = @($runList | Where-Object { $_.Tool -eq 'Uninstall' -and -not $_.WhatIf -and ($_.Preset -or $_.Steps.Count -ge 6) }) | Select-Object -Last 1
if ($rb) {
    $re = @($installs | Where-Object { -not $_.WhatIf -and $_.Start -gt $rb.Start -and $_.Steps.Count -ge 8 }) | Select-Object -Last 1
    Set-L 'L19' $(if ($rb.Counts.FAIL) { 'FAIL' } elseif ($re) { 'REVIEW' } else { 'OPEN' }) ("rollback {0} (preset {1}): {2} DEL, {3} FAIL; reinstall {4} - confirm with -Record L19" -f $rb.Start.ToString('yyyy-MM-dd HH:mm'), $rb.Preset, $rb.Counts.DEL, $rb.Counts.FAIL, $(if ($re) { $re.Start.ToString('yyyy-MM-dd HH:mm') } else { 'not yet' })) @($rb.Samples)
} else { Set-L 'L19' 'OPEN' 'no applied rollback run found' }

# L20
$maxAge = [int]$cfg.Pso.MaxPasswordAgeDays
$startDate = $null
if ($manifest -and $manifest.Created) { $startDate = [datetime]$manifest.Created }
if ($journal.Count) { $j0 = [datetime]$journal[0].Time; if (-not $startDate -or $j0 -lt $startDate) { $startDate = $j0 } }
if (-not $startDate) { Set-L 'L20' 'OPEN' 'installation date unknown' }
elseif ((Get-Date) -lt $startDate.AddDays($maxAge + 5)) { Set-L 'L20' 'OPEN' ("not due yet: first rolling cycle completes around {0:yyyy-MM-dd} (installed {1:yyyy-MM-dd}, PSO max age {2} d)" -f $startDate.AddDays($maxAge + 5), $startDate, $maxAge) }
elseif (-not $monitor) { Set-L 'L20' 'OPEN' 'due - run Watch-CloudUserConformance.ps1 -Html' }
else {
    $k17 = @(@($monitor.Results) | Where-Object { $_.CheckId -eq 'USR-KERB-0x17' })
    $users = @($monitor.Users)
    $active = @($users | Where-Object { $_.LastLogon -and $_.LastLogon -ne '-' -and ([datetime]$_.LastLogon) -ge (Get-Date).AddDays(-$maxAge) })
    $stale = @($active | Where-Object { -not $_.SecretChanged -or $_.SecretChanged -eq '-' -or ([datetime]$_.SecretChanged) -lt (Get-Date).AddDays(-($maxAge + 5)) })
    Set-L 'L20' $(if ($k17.Count) { 'FAIL' } elseif ($stale.Count) { 'WARN' } else { 'PASS' }) ("{0} active user(s), {1} without a secret change within {2} days, Kerberos 0x17 results: {3}" -f $active.Count, $stale.Count, ($maxAge + 5), $k17.Count) @($stale | Select-Object -First 10 | ForEach-Object { "$($_.User): last logon $($_.LastLogon), secret changed $($_.SecretChanged)" })
}

# Combine with manual results (latest per item wins)
$latestManual = @{}
foreach ($m in ($manual | Where-Object { $_ } | Sort-Object Time)) { $latestManual[$m.Id] = $m }
$items = @(foreach ($c in $Catalogue) {
    $a = $auto[$c.Id]; $m = $latestManual[$c.Id]
    [pscustomobject]@{
        Id = $c.Id; Title = $c.Title; Status = $(if ($m) { $m.Result } else { $a.Status })
        Auto = $a.Status; AutoDetail = $a.Detail; Manual = $(if ($m) { "$($m.Result) ($(Format-Ts $m.Time)): $($m.Note)" } else { '' })
        Evidence = @($a.Evidence); How = $c.How; Expected = $c.Expected
    }
})
$notes = @($manual | Where-Object { $_ -and $_.Id -eq 'NOTE' } | ForEach-Object { "$(Format-Ts $_.Time): $($_.Note)" })
#endregion

#region --- Anonymizer -------------------------------------------------------------------------------
$anon = New-SoaAnonymizer -KeepNames @($cfg.PsoGroupName, $cfg.ExcludeGroupName, $cfg.PilotGroupName, $cfg.HostGroupName, $cfg.PsoName, $cfg.GmsaName, $cfg.RollingTestPsoName, $cfg.EventLogName,
                                        $cfg.KirGpoNamePrefix, $cfg.DiagnosticsGpoName, $cfg.AuditGpoName, $cfg.BatchLogonGpoNameDc, $cfg.BatchLogonGpoNameAgent)
$privDir = Join-Path $OutputPath 'private'
$cumulativeMap = Join-Path $privDir 'pseudonyms.csv'
$termsAuto = Join-Path (Split-Path $cfg.ConfigPath -Parent) 'SoaToolkit.terms.txt'
$extra = @()
$termSources = @()
if (-not $NoAnonymize) {
    if (-not $ResetPseudonyms -and (Test-Path -LiteralPath $cumulativeMap)) { Import-SoaAnonymizerMap -Anonymizer $anon -Entries @(Import-Csv -LiteralPath $cumulativeMap) }
    Add-SoaAnonymizerTerm -Anonymizer $anon -Kind DOMAIN -Value $ctx.DnsRoot
    if ($forest.RootDomain -ne $ctx.DnsRoot) { Add-SoaAnonymizerTerm -Anonymizer $anon -Kind DOMAIN -Value $forest.RootDomain }
    foreach ($d in @($forest.Domains) + @($forest.UPNSuffixes)) { if ($d) { Add-SoaAnonymizerTerm -Anonymizer $anon -Kind DOMAIN -Value "$d" } }   # UPN suffixes = typically the public mail domain
    Add-SoaAnonymizerTerm -Anonymizer $anon -Kind NETBIOS -Value $ctx.NetBios
    foreach ($d in $allDcs) { Add-SoaAnonymizerTerm -Anonymizer $anon -Kind DC -Value $d.HostName; if ($d.Site) { Add-SoaAnonymizerTerm -Anonymizer $anon -Kind TERM -Value $d.Site } }
    foreach ($h in @($cfg.AgentHosts) + @($env:COMPUTERNAME)) { if (-not (@($allDcs | Where-Object { $_.HostName -ieq $h -or $_.Name -ieq $h }).Count)) { Add-SoaAnonymizerTerm -Anonymizer $anon -Kind HOST -Value $h } }
    foreach ($g in $agents) { Add-SoaAnonymizerTerm -Anonymizer $anon -Kind GMSA -Value $g.Name }
    Add-SoaAnonymizerTerm -Anonymizer $anon -Kind ACCOUNT -Value $env:USERNAME
    $userNames = @($journal | ForEach-Object { $_.User }) + @($cfg.TestUser, $cfg.BreakGlassName) + @(if ($monitor) { @($monitor.Users) | ForEach-Object { $_.User } })
    $userObjs = @($provisioned | Where-Object { $userNames -contains $_.SamAccountName })
    foreach ($u in ($userNames | Where-Object { $_ } | Select-Object -Unique)) { Add-SoaAnonymizerTerm -Anonymizer $anon -Kind USER -Value $u }
    foreach ($u in $userObjs) { Add-SoaAnonymizerTerm -Anonymizer $anon -Kind USER -Value $u.Name; if ($u.UserPrincipalName) { Add-SoaAnonymizerTerm -Anonymizer $anon -Kind USER -Value $u.UserPrincipalName } }
    foreach ($tf in @($termsAuto, $TermsFile) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique) {
        $t = @(Read-SoaTermsFile -Path $tf); $extra += $t; $termSources += ("{0} ({1} term(s))" -f (Split-Path $tf -Leaf), $t.Count)
    }
    if ($AdditionalTerms.Count) { $extra += $AdditionalTerms; $termSources += ("-AdditionalTerms ({0})" -f $AdditionalTerms.Count) }
    foreach ($t in $extra) { Add-SoaAnonymizerTerm -Anonymizer $anon -Kind TERM -Value $t }
    if (-not $termSources.Count) { Add-CollectWarning "no terms file ($termsAuto) - company, site and project names are not replaced unless they appear in AD data. Template: SoaToolkit.terms.example.txt" }
}
function Protect([string]$Text) { if ($NoAnonymize) { $Text } else { ConvertTo-SoaAnonymizedText -Anonymizer $anon -Text $Text } }
function Write-BundleFile([string]$RelPath, [string]$Content) {
    $p = Join-Path $bundle $RelPath
    New-Item -Path (Split-Path $p -Parent) -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath $p -Value (Protect $Content) -Encoding UTF8
}
#endregion

#region --- Write the folder -------------------------------------------------------------------------
$inventory = New-Object System.Collections.Generic.List[object]
function Add-Artifact([string]$RelPath, [string]$Content, [string]$What, [string]$Source) {
    if ($null -eq $Content) { return }
    Write-BundleFile $RelPath $Content
    $inventory.Add([pscustomobject]@{ File = $RelPath; Content = $What; Source = $Source })
}
if ($prereqFile) { Add-Artifact 'artifacts\prerequisites-checks.csv' (Get-Content -LiteralPath $prereqFile.FullName -Raw) 'latest Test-SoaPrerequisites.ps1 checks' 'ReportPath\Prerequisites' }
if ($monitor) {
    $mon = $monitor | Select-Object Time, Overall, Counts, Results, Users
    if ($ExcludeUserDetails) { $mon.Users = @("$(@($monitor.Users).Count) user rows removed (-ExcludeUserDetails)") }
    Add-Artifact 'artifacts\monitor.json' ($mon | ConvertTo-Json -Depth 6) 'latest Watch-CloudUserConformance.ps1 -Scope All result' 'ReportPath\Monitor'
}
if ($tests.Count) { Add-Artifact 'artifacts\test-state.json' (ConvertTo-Json -InputObject $tests -Depth 4) 'Test-SoaBehavior.ps1 results (latest 20 per test)' 'ReportPath\Tests' }
if ($findings) { Add-Artifact 'artifacts\behavior-findings.json' ($findings | ConvertTo-Json -Depth 8) 'Test-SoaBehavior.ps1 findings (SCRIL matrix, rolling)' 'ReportPath\Tests' }
if ($impactFile) { Add-Artifact 'artifacts\impact-writer-summary.csv' (Get-Content -LiteralPath $impactFile.FullName -Raw) 'Get-SoaEnforcementImpact.ps1 writer summary' 'ReportPath\Impact' }
foreach ($f in $runLogs) { Add-Artifact "artifacts\logs\$($f.Name)" (Get-Content -LiteralPath $f.FullName -Raw) 'install / uninstall run log' 'ReportPath\State' }
if ($manifest) { Add-Artifact 'artifacts\manifest.json' ($manifest | ConvertTo-Json -Depth 8) 'install manifest (what the toolkit created / changed, previous values)' 'ReportPath\State' }
if ($manual.Count) { Add-Artifact 'artifacts\manual-results.json' (ConvertTo-Json -InputObject $manual -Depth 3) 'results recorded with -Record' 'ReportPath\Validation' }
if (Test-Path -LiteralPath $ConfigPath) { Add-Artifact 'artifacts\SoaToolkit.config.psd1' (Get-Content -LiteralPath $ConfigPath -Raw) 'configuration used' 'SoaToolkit.config.psd1' }
foreach ($h in $hosts) {
    if (-not $h.Ok) { continue }
    $short = Get-SoaShortName $h.Host
    $d = $h.Data | Select-Object OS, LastBoot, Hotfixes, PowerShell, Agent, ToolkitFiles, Tasks, EventLog, DirectoryService, Security
    Add-Artifact "artifacts\hosts\$short.json" ($d | ConvertTo-Json -Depth 6) 'OS / CU, agent version, tasks, SoaToolkit events, DS + Security event counts' "WinRM $($h.Host)"
    if ($h.Data.Journal.Count) { Add-Artifact "artifacts\hosts\$short-journal.jsonl" ((@($h.Data.Journal)) -join "`r`n") 'conformance journal (changes incl. previous flags)' "$($h.Host) DataPath\Journal" }
    if ($h.Data.Status.Conformance) { Add-Artifact "artifacts\hosts\$short-conformance-status.json" $h.Data.Status.Conformance 'last conformance run' "$($h.Host) DataPath\Status" }
    foreach ($l in @($h.Data.Logs)) { Add-Artifact "artifacts\hosts\$short-$($l.File)" ((@($l.Tail)) -join "`r`n") 'run log (last 200 lines)' "$($h.Host) DataPath\Logs" }
}
# The host file names contain host names - rename them to the pseudonyms
if (-not $NoAnonymize) {
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $artDir 'hosts') -File -ErrorAction SilentlyContinue)) {
        $new = Protect $f.Name
        if ($new -ne $f.Name) { Rename-Item -LiteralPath $f.FullName -NewName $new; foreach ($i in $inventory) { if ($i.File -eq "artifacts\hosts\$($f.Name)") { $i.File = "artifacts\hosts\$new" } } }
    }
}

# Problems for the bug report view
$problems = @()
if ($monitor) { $problems += @(@($monitor.Results) | Where-Object { $_.Status -in 'FAIL', 'WARN' } | ForEach-Object { "monitor [$($_.Status)] $($_.CheckId) $($_.Item): $($_.Detail)" }) }
foreach ($h in ($hosts | Where-Object { $_.Ok })) {
    $problems += @(@($h.Data.EventLog.Recent) | Where-Object { $_.Level -in 'Error', 'Warning', 'Fehler', 'Warnung' } | Select-Object -First 10 | ForEach-Object { "$($h.Host) event $($_.Id) $($_.Time): $($_.Message -replace '\s+', ' ')" })
    foreach ($l in @($h.Data.Logs)) { $problems += @(@($l.Tail) | Where-Object { $_ -match '\[(ERROR|WARN)\]' } | Select-Object -Last 5 | ForEach-Object { "$($h.Host) $($l.File): $_" }) }
}
foreach ($r in ($runList | Where-Object { $_.Counts.FAIL })) { $problems += @($r.Samples | Where-Object { $_ -like '`[FAIL`]*' } | ForEach-Object { "$($r.Tool) run $($r.Start.ToString('yyyy-MM-dd HH:mm')): $_" }) }

$localHash = @{}; foreach ($l in $localFiles) { $localHash[$l.File.ToLower()] = $l.Sha256 }
$hostSummary = @($hosts | ForEach-Object {
    $d = $_.Data
    $diff = @(if ($_.Ok) { @($d.ToolkitFiles) | Where-Object { $localHash.ContainsKey("$($_.File)".ToLower()) -and $localHash["$($_.File)".ToLower()] -ne $_.Sha256 } | ForEach-Object { $_.File } })
    [pscustomobject]@{
        Host = $_.Host; Roles = (@($(if ($_.IsDc) { 'DC' }), $(if ($_.IsAgent) { 'Agent' })) | Where-Object { $_ }) -join '+'
        Reachable = $_.Ok
        OS = $(if ($_.Ok) { "$($d.OS.Caption) $($d.OS.DisplayVersion) build $($d.OS.Build).$($d.OS.Ubr)" })
        LatestUpdate = $(if ($_.Ok -and $d.Hotfixes) { "$($d.Hotfixes[0].Id) ($($d.Hotfixes[0].InstalledOn))" })
        AgentVersion = $(if ($_.Ok -and $d.Agent) { "$($d.Agent.Version) ($($d.Agent.State))" } else { '-' })
        Tasks = $(if ($_.Ok) { (@($d.Tasks) | ForEach-Object { "$($_.Name)=$($_.State)/$($_.LastResult)" }) -join ', ' })
        LastHeartbeat = $(if ($_.Ok) { $d.EventLog.LastHeartbeat })
        DeployedScripts = $(if (-not $_.Ok) { '' } elseif (-not @($d.ToolkitFiles).Count) { 'not deployed' } elseif ($diff.Count) { 'differ from this workstation: ' + ($diff -join ', ') } else { 'identical to this workstation' })
    }
})

$report = [ordered]@{
    Format       = 'cloudsync-soa-toolkit report 1'
    Purpose      = $Purpose
    Anonymized   = (-not $NoAnonymize)
    WindowDays   = $Days
    Description  = $Description
    Environment  = $environment
    Hosts        = $hostSummary
    Validation   = $items
    Notes        = $notes
    Problems     = $problems
    Runs         = @($runList | ForEach-Object { [ordered]@{ Tool = $_.Tool; Start = $_.Start.ToString('s'); Version = $_.Version; Steps = $_.Steps; Preset = $_.Preset; WhatIf = $_.WhatIf; Ended = $_.Ended; Counts = $_.Counts } })
    CollectionWarnings = @($warnings)
}

# report.md
function ConvertTo-MdCell($v) { ("$v" -replace '\|', '\|' -replace '\r?\n', '<br>').Trim() }
$sym = @{ PASS = 'PASS'; FAIL = '**FAIL**'; WARN = '**WARN**'; OPEN = 'OPEN'; REVIEW = 'REVIEW'; SKIP = 'SKIP'; 'N/A' = 'N/A'; INFO = 'INFO' }
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# SOA Toolkit report - $Purpose")
[void]$md.AppendLine('')
[void]$md.AppendLine("Collected $($environment.Collected) with toolkit $($environment.ToolkitVersion), window $Days days. Anonymized: **$(-not $NoAnonymize)**.")
[void]$md.AppendLine('')
if ($Purpose -eq 'BugReport') {
    [void]$md.AppendLine('## Problem description'); [void]$md.AppendLine(''); [void]$md.AppendLine($(if ($Description) { $Description } else { '_(no -Description given - describe what you did, expected and observed)_' })); [void]$md.AppendLine('')
    [void]$md.AppendLine('## Recent problems'); [void]$md.AppendLine('')
    if ($problems.Count) { foreach ($p in ($problems | Select-Object -First 40)) { [void]$md.AppendLine("- $(ConvertTo-MdCell $p)") } } else { [void]$md.AppendLine('none found') }
    [void]$md.AppendLine('')
}
[void]$md.AppendLine('## Environment'); [void]$md.AppendLine('')
[void]$md.AppendLine('| Item | Value |'); [void]$md.AppendLine('|---|---|')
foreach ($k in 'Domain', 'DomainMode', 'ForestMode', 'AutomaticRolling', 'WritableDcs', 'ReadOnlyDcs', 'AgentHosts', 'AgentHostsOnDcs', 'PolicyPresent', 'PolicyMode', 'AllowListSids', 'ProvisionedUsers', 'MarkedUsers', 'WriteScope', 'PilotMode') { [void]$md.AppendLine("| $k | $(ConvertTo-MdCell $environment[$k]) |") }
[void]$md.AppendLine("| Agent gMSAs | $(ConvertTo-MdCell (@($environment.AgentGmsas) -join ', ')) |")
if ($environment.Pso) { [void]$md.AppendLine("| PSO | $(ConvertTo-MdCell (($environment.Pso.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')) |") }
[void]$md.AppendLine("| Admin workstation | $(ConvertTo-MdCell (($environment.AdminWorkstation.GetEnumerator() | ForEach-Object { "$($_.Key) $($_.Value)" }) -join ', ')) |")
$mod = @($localFiles | Where-Object { $_.Release -ne 'match' })
[void]$md.AppendLine("| Script integrity | $(if (-not $sums.Count) { 'no SHA256SUMS.txt next to the scripts' } elseif ($mod.Count) { 'deviations: ' + (($mod | ForEach-Object { "$($_.File) ($($_.Release))" }) -join ', ') } else { 'all scripts match the release' }) |")
[void]$md.AppendLine('')
[void]$md.AppendLine('| Host | Roles | OS | Latest update | Agent | Last heartbeat | Tasks | Deployed scripts |'); [void]$md.AppendLine('|---|---|---|---|---|---|---|---|')
foreach ($h in $hostSummary) { [void]$md.AppendLine("| $($h.Host) | $($h.Roles) | $(if ($h.Reachable) { ConvertTo-MdCell $h.OS } else { 'not reachable' }) | $(ConvertTo-MdCell $h.LatestUpdate) | $(ConvertTo-MdCell $h.AgentVersion) | $(ConvertTo-MdCell $h.LastHeartbeat) | $(ConvertTo-MdCell $h.Tasks) | $(ConvertTo-MdCell $h.DeployedScripts) |") }
foreach ($d in $environment.DomainControllers | Where-Object { -not (@($hostSummary | Where-Object { $_.Host -ieq $d.Host }).Count) }) { [void]$md.AppendLine("| $($d.Host) | DC ($(if ($hosts.Count) { 'not a toolkit host' } else { 'hosts not collected' })) | $(ConvertTo-MdCell "$($d.OS) $($d.OSVersion)") | | | | | |") }
[void]$md.AppendLine('')
[void]$md.AppendLine('## Validation L1-L20'); [void]$md.AppendLine('')
[void]$md.AppendLine('Status: PASS / FAIL / WARN = evaluated; REVIEW = evidence found, needs your confirmation (`-Record`); OPEN = no evidence yet. A recorded manual result overrides the automatic one.')
[void]$md.AppendLine('')
[void]$md.AppendLine('| # | Check | Status | Automatic evaluation | Manual record |'); [void]$md.AppendLine('|---|---|---|---|---|')
foreach ($i in $items) { [void]$md.AppendLine("| $($i.Id) | $(ConvertTo-MdCell $i.Title) | $($sym[$i.Status]) | $(ConvertTo-MdCell "$($i.Auto): $($i.AutoDetail)") | $(ConvertTo-MdCell $i.Manual) |") }
[void]$md.AppendLine('')
[void]$md.AppendLine('### Evidence per check'); [void]$md.AppendLine('')
foreach ($i in $items) {
    [void]$md.AppendLine("**$($i.Id) $($i.Title)** - expected: $($i.Expected). How: ``$($i.How)``")
    if ($i.Evidence.Count) { foreach ($e in $i.Evidence) { if ($e) { [void]$md.AppendLine("- $(ConvertTo-MdCell $e)") } } } else { [void]$md.AppendLine('- (no evidence)') }
    [void]$md.AppendLine('')
}
if ($notes.Count) { [void]$md.AppendLine('## Notes'); [void]$md.AppendLine(''); foreach ($n in $notes) { [void]$md.AppendLine("- $(ConvertTo-MdCell $n)") }; [void]$md.AppendLine('') }
if ($Purpose -ne 'BugReport' -and $problems.Count) { [void]$md.AppendLine('## Problems seen in the window'); [void]$md.AppendLine(''); foreach ($p in ($problems | Select-Object -First 40)) { [void]$md.AppendLine("- $(ConvertTo-MdCell $p)") }; [void]$md.AppendLine('') }
if ($warnings.Count) { [void]$md.AppendLine('## Collection warnings'); [void]$md.AppendLine(''); foreach ($w in $warnings) { [void]$md.AppendLine("- $(ConvertTo-MdCell $w)") } }

Write-BundleFile 'report.md' $md.ToString()
Write-BundleFile 'report.json' ($report | ConvertTo-Json -Depth 8)
$inventory.Insert(0, [pscustomobject]@{ File = 'report.json'; Content = 'everything above, machine-readable'; Source = 'this script' })
$inventory.Insert(0, [pscustomobject]@{ File = 'report.md'; Content = 'summary: environment, hosts, L1-L20 with evidence, problems'; Source = 'this script' })

# Pseudonym map (outside the folder) and leak check
$mapFile = Join-Path $privDir "$bundleName.map.csv"
$hits = @()
if (-not $NoAnonymize) {
    New-Item -Path $privDir -ItemType Directory -Force | Out-Null
    $mapRows = @(Get-SoaAnonymizerMap -Anonymizer $anon)
    $mapRows | Export-Csv -LiteralPath $mapFile -NoTypeInformation -Encoding UTF8
    $mapRows | Export-Csv -LiteralPath $cumulativeMap -NoTypeInformation -Encoding UTF8      # cumulative: earlier pseudonyms + new ones
    foreach ($f in (Get-ChildItem -LiteralPath $bundle -Recurse -File)) {
        foreach ($h in (Find-SoaResidualIdentifier -Anonymizer $anon -Text (Get-Content -LiteralPath $f.FullName -Raw) -MapEntries $mapRows)) { $hits += [pscustomobject]@{ File = $f.FullName.Substring($bundle.Length + 1); Type = $h.Type; Value = $h.Value } }
    }
} else {
    'This folder contains ORIGINAL names, SIDs and host names (created with -NoAnonymize). Do not share it outside your organisation.' | Set-Content -LiteralPath (Join-Path $bundle 'NOT-ANONYMIZED.txt') -Encoding UTF8
}
$kinds = @(if (-not $NoAnonymize) { Get-SoaAnonymizerMap -Anonymizer $anon | Group-Object Kind | Sort-Object Name | ForEach-Object { "$($_.Name): $($_.Count)" } })

# README-FIRST.md (written last; contains no original values except the leak-check findings, which are masked)
$rf = New-Object System.Text.StringBuilder
[void]$rf.AppendLine("# Read this first - $bundleName"); [void]$rf.AppendLine('')
[void]$rf.AppendLine('This folder was created by `Export-SoaReport.ps1` of the cloudsync-soa-toolkit. Nothing has been sent anywhere. **Review it before you share it.**'); [void]$rf.AppendLine('')
[void]$rf.AppendLine('## What was replaced'); [void]$rf.AppendLine('')
if ($NoAnonymize) { [void]$rf.AppendLine('**Nothing - this folder is NOT anonymized.** It is meant for internal use only.') }
else {
    [void]$rf.AppendLine('Identifiers were replaced by stable pseudonyms (the same original always gets the same pseudonym in this folder):'); [void]$rf.AppendLine('')
    [void]$rf.AppendLine('- domain and NetBIOS name -> `corp.example` / `CORP`; domain controllers -> `dc01`...; other hosts -> `host01`...; AD sites -> `term..`')
    [void]$rf.AppendLine('- users that appear in the toolkit data (sAMAccountName, name, UPN) -> `user001`...; the account that ran this script and other `DOMAIN\account` -> `account001`...; gMSAs -> `gmsa01$`...')
    [void]$rf.AppendLine('- `CN=` / `OU=` values of distinguished names -> `object001` / `OU-001` (well-known names such as `CN=Users` and the toolkit''s own default names stay)')
    [void]$rf.AppendLine('- domain SIDs -> `S-1-5-21-1000000000-0-0-<RID>`, GUIDs -> `00000000-0000-4000-8000-...` (schema GUIDs of the toolkit stay), e-mail addresses, IPv4 addresses, user profile paths')
    [void]$rf.AppendLine("- UPN suffixes and further domains of the forest -> ``domain2.example``...")
    [void]$rf.AppendLine("- your terms -> ``term001``...: $(if ($termSources.Count) { $termSources -join ', ' } else { '**none** - create SoaToolkit.terms.txt from SoaToolkit.terms.example.txt' })")
    [void]$rf.AppendLine(''); [void]$rf.AppendLine("Replacements by kind: $($kinds -join ', ')"); [void]$rf.AppendLine('')
    [void]$rf.AppendLine("The map original -> pseudonym is stored **outside** this folder: ``$(Protect $mapFile)``, and cumulatively in ``private\pseudonyms.csv`` (on this workstation). The same original gets the same pseudonym in every report from this workstation, unless -ResetPseudonyms is used. Keep the map to answer questions about the report; never attach it.")
}
[void]$rf.AppendLine(''); [void]$rf.AppendLine('## Leak check'); [void]$rf.AppendLine('')
if ($NoAnonymize) { [void]$rf.AppendLine('not performed (-NoAnonymize)') }
elseif ($hits.Count) {
    [void]$rf.AppendLine("**$($hits.Count) possible identifier(s) found** - fix them before packaging (re-run with -AdditionalTerms, or edit the file):"); [void]$rf.AppendLine('')
    foreach ($h in $hits) { [void]$rf.AppendLine("- $($h.File): $($h.Type) '$(if ($h.Value.Length -gt 4) { $h.Value.Substring(0, 2) + ('*' * ($h.Value.Length - 4)) + $h.Value.Substring($h.Value.Length - 2) } else { '****' })'") }
} else { [void]$rf.AppendLine('No original value of the pseudonym map and no identifier pattern (domain SID, GUID, e-mail address) was found in the files. This does **not** cover names the script cannot know - see the checklist.') }
[void]$rf.AppendLine(''); [void]$rf.AppendLine('## Your review checklist'); [void]$rf.AppendLine('')
[void]$rf.AppendLine('1. Open `report.md` - does the summary match what you did in the lab?')
[void]$rf.AppendLine('2. Search all files for your company name, product / project names, site or city names, person names, internal URLs and IP ranges. Anything found: re-run with `-AdditionalTerms`.')
[void]$rf.AppendLine('3. Look at `artifacts\SoaToolkit.config.psd1` and `artifacts\manifest.json` (OU structure, group names).')
[void]$rf.AppendLine('4. Remove files you do not want to share - the report stays usable.')
[void]$rf.AppendLine("5. Package: ``.\Export-SoaReport.ps1 -Package '$(Protect $bundle)'`` (runs the leak check again and asks for confirmation).")
[void]$rf.AppendLine(''); [void]$rf.AppendLine('## What is in this folder'); [void]$rf.AppendLine('')
[void]$rf.AppendLine('| File | Content | Source |'); [void]$rf.AppendLine('|---|---|---|')
foreach ($i in $inventory) { [void]$rf.AppendLine("| $($i.File) | $($i.Content) | $(Protect $i.Source) |") }
[void]$rf.AppendLine(''); [void]$rf.AppendLine('## What is never collected'); [void]$rf.AppendLine('')
[void]$rf.AppendLine('- passwords, password hashes or any secret attribute (the toolkit cannot read them and does not try)')
[void]$rf.AppendLine('- the user list of the domain (only users that appear in the toolkit''s own journals and reports)')
[void]$rf.AppendLine('- GPO contents, and event messages of other logs than `SoaToolkit` (Directory Service / Security: counts and, for 5136 on `msDS-ObjectSoa`, the writer account)')
Set-Content -LiteralPath (Join-Path $bundle 'README-FIRST.md') -Value $rf.ToString() -Encoding UTF8
#endregion

#region --- Console summary --------------------------------------------------------------------------
Write-SoaSection 'Validation L1-L20'
foreach ($i in $items) {
    $col = switch ($i.Status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'WARN' { 'Yellow' } 'REVIEW' { 'Yellow' } default { 'Gray' } }   # REVIEW: your confirmation is needed (-Record)
    Write-Host ("  {0,-4} {1,-7} {2,-40} {3}" -f $i.Id, $i.Status, $i.Title, $(if ($i.Manual) { "manual: $($i.Manual)" } else { $i.AutoDetail })) -ForegroundColor $col
}
Write-Host ''
Write-Host "Report folder : $bundle" -ForegroundColor Cyan
if (-not $NoAnonymize) {
    Write-Host "Pseudonym map : $mapFile  (private - never share)" -ForegroundColor Yellow
    if ($hits.Count) { Write-SoaLine WARN "leak check: $($hits.Count) possible identifier(s) - see README-FIRST.md" } else { Write-SoaLine PASS 'leak check: clean (names unknown to the script are not covered - review the files)' }
} else { Write-SoaLine WARN 'NOT anonymized (-NoAnonymize)' }
Write-Host "Next: review README-FIRST.md and report.md, then  .\Export-SoaReport.ps1 -Package '$bundle'" -ForegroundColor Cyan
#endregion
