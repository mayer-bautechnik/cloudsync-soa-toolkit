# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Shared functions of the SOA Toolkit (cloudsync-soa-toolkit).

.DESCRIPTION
    Imported by every script of the toolkit. Contains:
      - constants (toolkit version, UAC bits, schema GUIDs, audit subcategory GUIDs, GP client-side extensions)
      - configuration loading and validation (SoaToolkit.config.psd1)
      - domain context (writable DCs, PDC emulator, policy DN, host roles)
      - the "managed by SOA Toolkit" marker used on every object the toolkit creates
      - console output, event log and journal helpers
      - AD helpers (SIDs, ACEs, gMSAs, secret metadata, cloud user identification, write scope)
      - Group Policy helpers (GPT version, client-side extensions, security templates, WMI filters, ADMX parsing)
      - the installation manifest (what was created, which values existed before) for Uninstall-SoaToolkit.ps1
      - anonymization helpers for Export-SoaReport.ps1 (pseudonyms, leak check)

    The module never writes to AD on import. Functions that write are named Set-/Add-/New-/Remove-*.
#>

#region --- Constants --------------------------------------------------------------------------------
$script:SoaVersion     = '2.0.5'
$script:SoaReleaseDate = '2026-10-21'
$script:SoaProduct     = 'cloudsync-soa-toolkit'
$script:SoaTag         = '[SoaToolkit]'

$script:SoaUac = @{ Disabled = 0x2; Lockout = 0x10; DontExpire = 0x10000; Scril = 0x40000 }
$script:SoaUcc = @{ Locked = 0x10; Expired = 0x800000 }      # msDS-User-Account-Control-Computed

# Minimum ntdsai.dll versions documented by Microsoft for AD object enforcement (keyed by OS build)
$script:SoaMinNtdsai = @{
    20348 = [version]'10.0.20348.5257'      # Windows Server 2022
    26100 = [version]'10.0.26100.32995'     # Windows Server 2025
}
$script:SoaOsLabel = @{ 20348 = 'WS2022'; 26100 = 'WS2025' }

$script:SoaGuid = @{
    UserClass  = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
    GroupClass = [guid]'bf967a9c-0de6-11d0-a285-00aa003049e2'
    UacAttr    = [guid]'bf967a68-0de6-11d0-a285-00aa003049e2'
    MemberAttr = [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'
    ResetPwd   = [guid]'00299570-246d-11d0-a768-00aa006e0529'
    ChangePwd  = [guid]'ab721a53-1e2f-11d0-9819-00aa0040529b'
}

# Advanced audit policy subcategories used by the toolkit (value: 1 = Success, 2 = Failure, 3 = both)
$script:SoaAuditSubcategories = @(
    [pscustomobject]@{ Key = 'UserAccountManagement';         Name = 'Audit User Account Management';         Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Required = 1; Why = 'event 4720 (user created) - onboarding trigger' }
    [pscustomobject]@{ Key = 'DirectoryServiceChanges';       Name = 'Audit Directory Service Changes';       Guid = '{0CCE923C-69AE-11D9-BED3-505054503030}'; Required = 1; Why = 'event 5136 on msDS-ObjectSoa - trigger for SOA-converted users' }
    [pscustomobject]@{ Key = 'KerberosAuthenticationService'; Name = 'Audit Kerberos Authentication Service'; Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Required = 2; Why = 'events 4768/4771 failures (0x17, 0x12) - monitoring' }
)

# Group Policy client-side extensions [CSE][tool]
$script:SoaCse = @{
    Security = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    Audit    = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'
}

$script:SoaKirOverridesKey   = 'SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides'
$script:SoaAgentService      = 'AADConnectProvisioningAgent'
$script:SoaNtdsDiagKey       = 'SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
$script:SoaNtdsDiagValue     = '2 Security Events'
$script:SoaSid = @{
    Everyone          = 'S-1-1-0'
    Self              = 'S-1-5-10'
    System            = 'S-1-5-18'
    Administrators    = 'S-1-5-32-544'
    EventLogReaders   = 'S-1-5-32-573'
    AuthenticatedUsers = 'S-1-5-11'
}
$script:SoaStatusRank = @{ PASS = 0; INFO = 0; WARN = 1; FAIL = 2 }
$script:SoaColors     = @{ PASS = 'Green'; INFO = 'Gray'; WARN = 'Yellow'; FAIL = 'Red' }

# Event IDs written to the 'SoaToolkit' event log
$script:SoaEventId = @{
    ConformanceChanged = 1000; ConformanceWarning = 1001; ConformanceError = 1002; ConformanceSummary = 1010
    MonitorHeartbeat   = 2000; MonitorWarning     = 2001; MonitorFailure   = 2002
    InstallStep        = 3000; InstallWarning     = 3001; InstallError     = 3002
    UninstallStep      = 3100; UninstallWarning   = 3101; UninstallError   = 3102
}
#endregion

#region --- Version / marker ----------------------------------------------------------------------
function Get-SoaVersion {
    [pscustomobject]@{ Product = $script:SoaProduct; Version = $script:SoaVersion; ReleaseDate = $script:SoaReleaseDate }
}

function Get-SoaConstant([string]$Name) {
    switch ($Name) {
        'Uac'      { $script:SoaUac }
        'Ucc'      { $script:SoaUcc }
        'Guid'     { $script:SoaGuid }
        'Sid'      { $script:SoaSid }
        'MinNtdsai' { $script:SoaMinNtdsai }
        'OsLabel'  { $script:SoaOsLabel }
        'Audit'    { $script:SoaAuditSubcategories }
        'Cse'      { $script:SoaCse }
        'EventId'  { $script:SoaEventId }
        'KirKey'   { $script:SoaKirOverridesKey }
        'AgentService' { $script:SoaAgentService }
        'Tag'      { $script:SoaTag }
        default    { throw "Unknown constant '$Name'." }
    }
}

<#
    Marker text written to every object the toolkit creates.
    -Short : for attributes with little space (description, GPO comment first line)
    -Purpose : one sentence what the object is for
#>
function Get-SoaMarker {
    param(
        $Config,                 # optional: without a configuration (scripts used on their own) the default project URL is used
        [string] $Purpose,
        [switch] $Short
    )
    $p = if ($Purpose) { " $Purpose." } else { '' }
    $url = if ($Config -and $Config.ProjectUrl) { $Config.ProjectUrl } else { $script:SoaConfigDefaults.ProjectUrl }
    if ($Short) {
        return ('{0} Managed by SOA Toolkit - do not modify manually.{1} {2}' -f $script:SoaTag, $p, $url).Trim()
    }
    $who = try { [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
    ('{0} Managed by SOA Toolkit ({1} {2}) - do not modify manually.{3} Created {4:yyyy-MM-dd} by {5}. ' +
     'Changes are detected by Watch-CloudUserConformance.ps1; Uninstall-SoaToolkit.ps1 removes this object. {6}') -f
        $script:SoaTag, $script:SoaProduct, $script:SoaVersion, $p, (Get-Date), $who, $url
}

<#
    State of the NTDS diagnostics item ("2 Security Events") in a GPP Registry.xml: does the item exist, is
    "Remove this item when it is no longer applied" (removePolicy="1") set, and does its description (attribute
    desc, GPMC tab Common) carry the marker. Used by Set-SoaDiagnosticsGpo.ps1 and Install-SoaToolkit.ps1 (adoption
    of the toolkit 1.x GPO).
#>
function Get-SoaDiagnosticsItemState {
    param([Parameter(Mandatory)][string]$RegistryXmlPath, [string]$ValueName = '2 Security Events')
    $state = [pscustomobject]@{ Path = $RegistryXmlPath; Readable = $false; Count = 0; RemovePolicy = $false; Action = $null; Marked = $false }
    try { [xml]$xml = Get-Content -LiteralPath $RegistryXmlPath -Raw -ErrorAction Stop } catch { return $state }
    $state.Readable = $true
    $items = @($xml.SelectNodes("//Registry[Properties[@name='$ValueName']]"))
    $state.Count = $items.Count
    if ($items.Count -eq 1) {
        $state.RemovePolicy = ($items[0].GetAttribute('removePolicy') -eq '1')
        $state.Action = $items[0].SelectSingleNode('Properties').GetAttribute('action')
        $state.Marked = Test-SoaMarker $items[0].GetAttribute('desc')
    }
    $state
}

function Test-SoaMarker([string]$Text) {
    [bool]($Text -and $Text.Contains($script:SoaTag))
}
#endregion

#region --- Configuration ---------------------------------------------------------------------------
$script:SoaConfigDefaults = [ordered]@{
    ProjectUrl              = 'https://github.com/mayer-bautechnik/cloudsync-soa-toolkit'
    AgentHosts              = @()
    AgentGmsaNames          = @()
    WriteScope              = 'AgentScope'
    ExcludeOUs              = @()
    PilotMode               = $false
    ToolkitGroupOU          = ''
    GmsaName                = 'gmsaSoaToolkit'
    HostGroupName           = 'SOA-Toolkit-Hosts'
    PsoGroupName            = 'SOA-CloudUsers-PSO'
    ExcludeGroupName        = 'SOA-CloudUsers-Exclude'
    PilotGroupName          = 'SOA-CloudUsers-Pilot'
    PsoName                 = 'PSO-SOA-CloudUsers'
    Pso                     = @{
        Precedence = 10; MaxPasswordAgeDays = 30; MinPasswordAgeDays = 1; MinPasswordLength = 64
        ComplexityEnabled = $true; PasswordHistoryCount = 24; ReversibleEncryptionEnabled = $false
        LockoutThreshold = 0; LockoutDurationMinutes = 15; LockoutObservationWindowMinutes = 15
    }
    KirGpoNamePrefix        = 'SOA Toolkit - DC - KIR AD Object Enforcement'
    DiagnosticsGpoName      = 'SOA Toolkit - DC - NTDS Security Diagnostics'
    AuditGpoName            = 'SOA Toolkit - DC - Audit'
    BatchLogonGpoNameDc     = 'SOA Toolkit - DC - Batch Logon'
    BatchLogonGpoNameAgent  = 'SOA Toolkit - Agent Hosts - Batch Logon'
    TaskFolder              = '\SoaToolkit\'
    EventLogName            = 'SoaToolkit'
    EventLogMaxSizeMB       = 64
    EventLogAllowWef        = $false
    ScriptInstallPath       = 'C:\Program Files\SoaToolkit'
    DataPath                = 'C:\ProgramData\SoaToolkit'
    ReconcileMinutes        = 60
    MonitorMinutes          = 60
    EventTriggerDelaySeconds = 30
    SigningCertThumbprint   = ''
    SigningTimestampUrl     = ''
    BreakGlassName          = ''
    BreakGlassOU            = ''
    TestUser                = ''
    ReportPath              = 'C:\SoaToolkitAdmin\Reports'
    KrbtgtAzureAdWarnDays   = 180
    NewUserGraceMinutes     = 120
    RollingTestMinutes      = 15
    RollingTestPsoName      = 'PSO-SOA-RollingTest'
    LegacyJobHost           = ''
    LegacyGmsaName          = ''
    LegacyTargetUserOUs     = @()
    LegacyScriptFolder      = 'C:\Scripts\SoaEnforcement'
    LegacyDiagnosticsGpoName = 'DC - NTDS Diagnostics - Security Events'
}

<#
    Loads SoaToolkit.config.psd1, applies defaults and validates the values.
    Returns a PSCustomObject (property access works the same in all scripts).
#>
function Import-SoaConfig {
    param([string]$Path)
    if (-not $Path) { throw 'Config path is empty.' }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Configuration file not found: $Path" }
    $raw = Import-PowerShellDataFile -Path $Path
    $cfg = [ordered]@{}
    foreach ($k in $script:SoaConfigDefaults.Keys) { $cfg[$k] = $script:SoaConfigDefaults[$k] }
    foreach ($k in $raw.Keys) {
        if ($k -eq 'Pso') {
            $merged = @{}
            foreach ($pk in $script:SoaConfigDefaults.Pso.Keys) { $merged[$pk] = $script:SoaConfigDefaults.Pso[$pk] }
            foreach ($pk in $raw.Pso.Keys) { $merged[$pk] = $raw.Pso[$pk] }
            $cfg.Pso = $merged
        } else {
            $cfg[$k] = $raw[$k]
        }
    }
    $unknown = @($raw.Keys | Where-Object { -not $script:SoaConfigDefaults.Contains($_) })
    $legacy  = @('TargetUserOUs', 'TargetGroupOUs', 'JobGmsaName', 'JobHost', 'JobScriptPath', 'JobDataPath', 'JobIntervalMinutes',
                 'RotationDays', 'RotationTime', 'RotationMethod', 'EnforceDenyChangePassword', 'ScrilExclude', 'SecretAgeWarnDays',
                 'HashAgeWarnDays', 'ScrilTestPsoName')
    $legacyFound = @($unknown | Where-Object { $legacy -contains $_ })
    if ($legacyFound.Count) {
        Write-Warning ("Configuration contains settings of toolkit 1.x that are no longer used: {0}. See CHANGELOG.md (migration 1.x -> 2.0)." -f ($legacyFound -join ', '))
    }
    $other = @($unknown | Where-Object { $legacy -notcontains $_ })
    if ($other.Count) { Write-Warning ("Unknown configuration keys ignored: {0}" -f ($other -join ', ')) }

    $errors = @()
    if (-not @($cfg.AgentHosts).Count) { $errors += 'AgentHosts is empty (list every host running the Cloud Sync provisioning agent).' }
    if ($cfg.GmsaName.Length -gt 15) { $errors += "GmsaName '$($cfg.GmsaName)' is longer than 15 characters." }
    if ($cfg.TaskFolder -notmatch '^\\.*\\$') { $errors += "TaskFolder must start and end with a backslash (e.g. '\SoaToolkit\')." }
    if ([int]$cfg.Pso.MinPasswordLength -gt 255) { $errors += 'Pso.MinPasswordLength must be <= 255.' }
    if ([int]$cfg.Pso.MaxPasswordAgeDays -le 0) { $errors += 'Pso.MaxPasswordAgeDays must be > 0 (automatic rolling needs an expiring password).' }
    if ([int]$cfg.Pso.MaxPasswordAgeDays -gt 60) { Write-Warning 'Pso.MaxPasswordAgeDays > 60: DISA STIG V-243476 requires rotation of SCRIL secrets at least every 60 days.' }
    if ([int]$cfg.EventLogMaxSizeMB -lt 1 -or [int]$cfg.EventLogMaxSizeMB -gt 4000) { $errors += 'EventLogMaxSizeMB must be between 1 and 4000.' }
    if ([int]$cfg.ReconcileMinutes -lt 0) { $errors += 'ReconcileMinutes must be >= 0 (0 = reconcile task registered but disabled).' }
    $ws = $cfg.WriteScope
    if (-not ($ws -is [array]) -and @('AgentScope', 'Domain') -notcontains "$ws") { $errors += "WriteScope must be 'AgentScope', 'Domain' or an array of distinguished names." }
    if ($errors.Count) { throw ("Invalid configuration ({0}):`n - {1}" -f $Path, ($errors -join "`n - ")) }

    $cfg.ConfigPath = (Resolve-Path -LiteralPath $Path).Path
    [pscustomobject]$cfg
}
<#
    Finds the configuration file:
      1. -ConfigPath, if given
      2. next to the script (deployed copy on the toolkit hosts; also the layout of toolkit <= 2.0.3)
      3. one folder up (repository / release layout since 2.0.4: SoaToolkit.config.psd1 at the top level, next to
         SoaToolkit.config.example.psd1)
    Two configuration files at 2. and 3. are refused, so that a stale copy is never used silently.
#>
function Resolve-SoaConfigPath {
    param([string]$ConfigPath, [Parameter(Mandatory)][string]$ScriptRoot, [switch]$Optional)
    if ($ConfigPath) { return $ConfigPath }
    $name   = 'SoaToolkit.config.psd1'
    $parent = Split-Path $ScriptRoot -Parent
    $here   = Join-Path $ScriptRoot $name
    $up     = if ($parent) { Join-Path $parent $name } else { $null }
    $found  = @(@($here, $up) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($found.Count -gt 1) { throw "Two configuration files found: '$here' and '$up'. Keep one (recommended: the top-level '$up') or pass -ConfigPath." }
    if ($found.Count -eq 1) {
        if ($found[0] -eq $here -and $parent -and (Test-Path -LiteralPath (Join-Path $parent 'SoaToolkit.config.example.psd1'))) {
            Write-Warning "Configuration found in the scripts folder ($here). Since toolkit 2.0.4 it belongs to the top level of the toolkit folder: move it to $up."
        }
        return $found[0]
    }
    if ($Optional) { return $null }
    $example = @(@((Join-Path $ScriptRoot 'SoaToolkit.config.example.psd1'), $(if ($parent) { Join-Path $parent 'SoaToolkit.config.example.psd1' })) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }) | Select-Object -First 1
    $target  = if ($example) { Join-Path (Split-Path $example -Parent) $name } else { $up }
    throw ("No configuration found. Copy '{0}' to '{1}' and adjust it (docs/SETUP.md), or pass -ConfigPath." -f $(if ($example) { $example } else { 'SoaToolkit.config.example.psd1' }), $target)
}

# Path containment on Windows paths (case-insensitive, separator-neutral, no file system access)
function Test-SoaPathInside {
    param([string]$Path, [string]$Parent)
    if (-not $Path -or -not $Parent) { return $false }
    $p = ($Path -replace '/', '\').TrimEnd('\') + '\'
    $q = ($Parent -replace '/', '\').TrimEnd('\') + '\'
    $p.StartsWith($q, [StringComparison]::OrdinalIgnoreCase)
}

# Is this computer part of the solution (a DC or a configured agent host)?
function Test-SoaToolkitHost {
    param([Parameter(Mandatory)] $Config)
    $fq = Get-SoaLocalFqdn
    $me = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
    if (@(@($Config.AgentHosts) | Where-Object { $_ -and ($_.ToLower() -eq $fq -or (Get-SoaShortName $_) -ieq $me) }).Count) { return $true }
    try { return ([int](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole -ge 4) } catch { return $false }
}

<#
    Admin scripts may run on a DC or agent host (no separate PAW). Then two layouts are unsafe:
      - ReportPath inside DataPath / ScriptInstallPath: DeployTasks gives the toolkit gMSA modify rights on the
        manifest and the reports, and Uninstall -Step RemoveTasks deletes them in the middle of the rollback
      - running the admin scripts from the deployed copy (ScriptInstallPath): RemoveTasks deletes it
    On a toolkit host this stops the script; elsewhere it only warns (harmless there, but the configuration is shared).
#>
function Assert-SoaAdminPaths {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)][string]$ScriptRoot)
    $problems = @()
    foreach ($pair in @(@('DataPath', $Config.DataPath), @('ScriptInstallPath', $Config.ScriptInstallPath))) {
        if (Test-SoaPathInside -Path $Config.ReportPath -Parent $pair[1]) {
            $problems += "ReportPath '$($Config.ReportPath)' is inside $($pair[0]) '$($pair[1])'. Set ReportPath to a separate folder (default C:\SoaToolkitAdmin\Reports) and move the existing folder there - it contains State\manifest.json."
        }
    }
    if (Test-SoaPathInside -Path $ScriptRoot -Parent $Config.ScriptInstallPath) {
        $problems += "The script runs from the deployed copy '$ScriptRoot'. Run the admin scripts from your own copy of the toolkit (e.g. C:\SoaToolkitAdmin\cloudsync-soa-toolkit)."
    }
    if (-not $problems.Count) { return }
    if (Test-SoaToolkitHost -Config $Config) { throw ("Unsafe paths on a toolkit host (docs/SETUP.md, 'Without a separate admin workstation'):`n - " + ($problems -join "`n - ")) }
    foreach ($x in $problems) { Write-Warning "$x (not blocking on this computer, but blocking on a DC or agent host)" }
}

# Creates ReportPath on first use and restricts it to Administrators and SYSTEM (reports contain names of the environment)
function Initialize-SoaReportPath {
    param([Parameter(Mandatory)] $Config)
    $p = $Config.ReportPath
    if (-not $p -or (Test-Path -LiteralPath $p)) { return }
    New-Item -Path $p -ItemType Directory -Force | Out-Null
    if ($env:OS -eq 'Windows_NT') {
        & icacls.exe $p /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
        Write-Verbose "ReportPath $p created (Administrators and SYSTEM only)"
    }
}
#endregion

#region --- Context ---------------------------------------------------------------------------------
<#
    Domain context. All writes of the setup scripts go to the PDC emulator (single, predictable target for
    ACL and GPO operations); the runtime scripts use Select-SoaTargetDc instead.
#>
function Get-SoaContext {
    param([string]$Server)
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    $domain = if ($Server) { Get-ADDomain -Server $Server } else { Get-ADDomain }
    $pdc    = $domain.PDCEmulator
    # Reads go to -Server if given (runtime: no dependency on the PDC emulator), otherwise to the PDC emulator (setup)
    $q      = if ($Server) { $Server } else { $pdc }
    $dcObjs = @(Get-ADDomainController -Filter * -Server $q | Where-Object { -not $_.IsReadOnly } | Sort-Object HostName)
    $rootDse = Get-ADRootDSE -Server $q
    [pscustomobject]@{
        Domain       = $domain
        DnsRoot      = $domain.DNSRoot
        NetBios      = $domain.NetBIOSName
        DomainDN     = $domain.DistinguishedName
        DomainSid    = $domain.DomainSID.Value
        Pdc          = $pdc
        DcOu         = $domain.DomainControllersContainer
        WritableDcs  = @($dcObjs | ForEach-Object { $_.HostName })
        WritableDcObjects = $dcObjs
        ContainerDN  = "CN=SOA-Policies,CN=System,$($domain.DistinguishedName)"
        PolicyDN     = "CN=Cloud,CN=SOA-Policies,CN=System,$($domain.DistinguishedName)"
        PscDN        = "CN=Password Settings Container,CN=System,$($domain.DistinguishedName)"
        SomDN        = "CN=SOM,CN=WMIPolicy,CN=System,$($domain.DistinguishedName)"
        ConfigNC     = $rootDse.configurationNamingContext
        SchemaNC     = $rootDse.schemaNamingContext
        Server       = $q
    }
}

function Get-SoaShortName([string]$Fqdn) { ($Fqdn -split '\.')[0] }

function Get-SoaLocalFqdn {
    $n = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
    try { [System.Net.Dns]::GetHostEntry($n).HostName.ToLower() } catch { $n.ToLower() }
}

<#
    Host roles: every writable DC is a 'Dc' host (event-triggered onboarding + DC-local monitoring);
    every agent host is an 'Agent' host (reconcile + agent/domain-wide monitoring). A host can be both.
#>
function Get-SoaHostRoles {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] $Context)
    $dcSet = @{}; foreach ($d in $Context.WritableDcs) { $dcSet[$d.ToLower()] = $true }
    $agSet = @{}; foreach ($a in @($Config.AgentHosts)) { $agSet[$a.ToLower()] = $true }
    $all   = @(@($Context.WritableDcs) + @($Config.AgentHosts) | ForEach-Object { $_.ToLower() } | Select-Object -Unique | Sort-Object)
    foreach ($h in $all) {
        $isAgent = $agSet.ContainsKey($h)
        [pscustomobject]@{
            Host        = $h
            IsDc        = $dcSet.ContainsKey($h)
            IsAgent     = $isAgent
            AgentIndex  = $(if ($isAgent) { [array]::IndexOf(@($Config.AgentHosts | ForEach-Object { $_.ToLower() }), $h) } else { -1 })
        }
    }
}

<#
    Target DC for runtime reads/writes: the local DC if this host is a writable DC (events are local to the DC that
    processed the write, so the object is guaranteed to exist there), otherwise a discovered writable DC.
#>
function Select-SoaTargetDc {
    param([string]$Preferred)
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    if ($Preferred) { return $Preferred }
    $local = Get-SoaLocalFqdn
    try {
        $me = Get-ADDomainController -Identity $env:COMPUTERNAME -Server $local -ErrorAction Stop
        if ($me -and -not $me.IsReadOnly) { return $me.HostName }
    } catch { }
    $dc = Get-ADDomainController -Discover -Writable -ErrorAction Stop
    "$(@($dc.HostName)[0])"
}
#endregion

#region --- Console output --------------------------------------------------------------------------
function Write-SoaSection([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 100) -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 100) -ForegroundColor DarkCyan
}

# Optional copy of every Write-SoaLine to a run log (Install / Uninstall); evaluated by Export-SoaReport.ps1
$script:SoaLineLog = $null
function Set-SoaLineLog {
    param([string]$Path, [string]$Prefix)
    $script:SoaLineLog = if ($Path) { [pscustomobject]@{ Path = $Path; Prefix = $Prefix } } else { $null }
}

function Write-SoaLine {
    param([ValidateSet('PASS', 'INFO', 'WARN', 'FAIL', 'ADD', 'SAME', 'DEL', 'SKIP')][string]$Status, [string]$Text)
    $map = @{ PASS = 'Green'; INFO = 'Gray'; WARN = 'Yellow'; FAIL = 'Red'; ADD = 'Green'; SAME = 'DarkGray'; DEL = 'Magenta'; SKIP = 'DarkGray' }
    $sym = @{ PASS = '[PASS]'; INFO = '[INFO]'; WARN = '[WARN]'; FAIL = '[FAIL]'; ADD = '  +'; SAME = '  ='; DEL = '  -'; SKIP = '  ~' }
    Write-Host ('{0} {1}' -f $sym[$Status], $Text) -ForegroundColor $map[$Status]
    if ($script:SoaLineLog) {
        try { Add-Content -Path $script:SoaLineLog.Path -Value ('{0:s} {1} [{2}] {3}' -f (Get-Date), $script:SoaLineLog.Prefix, $Status, $Text) -Encoding UTF8 } catch { Write-Verbose "Run log write failed: $($_.Exception.Message)" }
    }
}

function Get-SoaWorstStatus([string[]]$Statuses) {
    $w = 'PASS'
    foreach ($s in @($Statuses)) {
        if (-not $s) { continue }
        if ($script:SoaStatusRank[$s] -gt $script:SoaStatusRank[$w] -or ($s -eq 'INFO' -and $w -eq 'PASS')) { $w = $s }
    }
    $w
}

function Get-SoaStatusRank([string]$Status) { $script:SoaStatusRank[$Status] }
function Get-SoaStatusColor([string]$Status) { $script:SoaColors[$Status] }

function ConvertTo-SoaHtmlTable {
    param($Rows, [string[]]$Properties)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table><tr>')
    foreach ($p in $Properties) { [void]$sb.Append("<th>$([Net.WebUtility]::HtmlEncode($p))</th>") }
    [void]$sb.Append('</tr>')
    foreach ($r in @($Rows)) {
        $cls = if ($r.PSObject.Properties.Name -contains 'Status') { " class=`"$($r.Status)`"" } else { '' }
        [void]$sb.Append("<tr$cls>")
        foreach ($p in $Properties) { [void]$sb.Append('<td>{0}</td>' -f [Net.WebUtility]::HtmlEncode("$($r.$p)")) }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</table>')
    $sb.ToString()
}

function Get-SoaHtmlStyle {
    '<style>body{font-family:Calibri,"Segoe UI",sans-serif;margin:24px;font-size:14px;color:#1b1b1b}h1,h2,h3{color:#1f3864}' +
    'table{border-collapse:collapse;margin-bottom:22px}th{background:#1f3864;color:#fff;padding:6px 10px;text-align:left}' +
    'td{border:1px solid #c8c8c8;padding:4px 10px;vertical-align:top}.PASS{background:#d4edda}.WARN{background:#fff3cd}' +
    '.FAIL{background:#f8d7da}.INFO{background:#e7e9ec}.box{border-left:4px solid #1f3864;background:#eef2f8;padding:8px 14px;margin:8px 0 16px}</style>'
}
#endregion

#region --- Event log / journal / status -----------------------------------------------------------
<#
    Creates the event log 'SoaToolkit' with source 'SoaToolkit' (requires local administrator; done by DeployTasks).
#>
function Initialize-SoaEventLog {
    param([string]$LogName = 'SoaToolkit')
    if (-not [Diagnostics.EventLog]::SourceExists($LogName)) {
        [Diagnostics.EventLog]::CreateEventSource($LogName, $LogName)
    }
}

<#
    Writes an event. Message = human-readable text followed by a JSON line (machine-readable for SIEM / monitoring).
    Never throws (logging must not break the run).
#>
function Write-SoaEvent {
    param(
        [Parameter(Mandatory)][int] $Id,
        [ValidateSet('Information', 'Warning', 'Error')][string] $Level = 'Information',
        [Parameter(Mandatory)][string] $Message,
        [hashtable] $Data,
        [string] $LogName = 'SoaToolkit'
    )
    try {
        # Registry check instead of EventLog.SourceExists (which needs rights on the Security log for non-admins)
        if (-not (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$LogName\$LogName")) { return }
        $text = $Message
        if ($Data) {
            $d = [ordered]@{ Toolkit = "$($script:SoaProduct) $($script:SoaVersion)"; Host = $env:COMPUTERNAME }
            foreach ($k in $Data.Keys) { $d[$k] = $Data[$k] }
            $text += "`r`n`r`n" + ($d | ConvertTo-Json -Depth 5 -Compress)
        }
        if ($text.Length -gt 31000) { $text = $text.Substring(0, 31000) + ' ...(truncated)' }
        [Diagnostics.EventLog]::WriteEntry($LogName, $text, [Diagnostics.EventLogEntryType]::$Level, $Id)
    } catch { }
}

function Add-SoaJournal {
    param([Parameter(Mandatory)][string]$DataPath, [Parameter(Mandatory)] $Entry)
    try {
        $dir = Join-Path $DataPath 'Journal'
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        $file = Join-Path $dir ('journal-{0:yyyyMM}.jsonl' -f (Get-Date))
        Add-Content -Path $file -Value ($Entry | ConvertTo-Json -Depth 5 -Compress) -Encoding UTF8
    } catch { Write-Warning "Journal write failed: $($_.Exception.Message)" }
}

function Write-SoaLog {
    param([Parameter(Mandatory)][string]$DataPath, [Parameter(Mandatory)][string]$Name, [string]$Message, [string]$Level = 'INFO')
    try {
        $dir = Join-Path $DataPath 'Logs'
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        Add-Content -Path (Join-Path $dir ('{0}_{1:yyyyMMdd}.log' -f $Name, (Get-Date))) -Value ('{0:s} [{1}] {2}' -f (Get-Date), $Level, $Message) -Encoding UTF8
    } catch { }
}

<#
    Reads a JSON file that holds an array and returns its elements one by one. Windows PowerShell 5.1 does not
    enumerate arrays returned by ConvertFrom-Json, so @(Get-Content | ConvertFrom-Json) can yield a nested array.
#>
function Read-SoaJsonArray {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $x = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    foreach ($i in @($x)) { if ($null -ne $i) { $i } }
}

function Save-SoaStatus {
    param([Parameter(Mandatory)][string]$DataPath, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)] $Status)
    $dir = Join-Path $DataPath 'Status'
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    $json = $Status | ConvertTo-Json -Depth 6
    Set-Content -Path (Join-Path $dir "$Name.json") -Value $json -Encoding UTF8
}
#endregion

#region --- Generic AD helpers -----------------------------------------------------------------------
function ConvertFrom-SoaFileTime($Value) {
    if ($null -eq $Value) { return $null }
    try { $i = [int64]$Value } catch { return $null }
    if ($i -le 0 -or $i -ge [int64]::MaxValue) { return $null }
    try { [datetime]::FromFileTime($i) } catch { $null }
}

function ConvertTo-SoaLdapValue([string]$Value) {
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Resolve-SoaSid {
    param([Parameter(Mandatory)][string]$Sid, [Parameter(Mandatory)][string]$Server, [string]$NetBios)
    try {
        $o = Get-ADObject -Server $Server -LDAPFilter "(objectSid=$Sid)" -Properties sAMAccountName
        if ($o) { return $(if ($NetBios) { "$NetBios\$($o.sAMAccountName)" } else { "$($o.sAMAccountName)" }) }
    } catch { }
    try { return ([Security.Principal.SecurityIdentifier]$Sid).Translate([Security.Principal.NTAccount]).Value } catch { return $null }
}

function Get-SoaServerFromNtdsDn([string]$Dn) {
    if ($Dn -match 'CN=NTDS Settings,CN=([^,]+)') { $Matches[1] } else { $Dn }
}

function Test-SoaDnInScope {
    param([Parameter(Mandatory)][string]$Dn, [string[]]$ScopeDns)
    foreach ($s in @($ScopeDns)) {
        if (-not $s) { continue }
        if ($Dn.ToLower() -eq $s.ToLower() -or $Dn.ToLower().EndsWith(',' + $s.ToLower())) { return $true }
    }
    $false
}

<#
    AD: drive bound to one server for ACL operations (Get-Acl / Set-Acl on AD objects).
#>
function Initialize-SoaAdDrive {
    param([Parameter(Mandatory)][string]$Server, [string]$Name = 'SOAAD')
    $existing = Get-PSDrive -Name $Name -ErrorAction SilentlyContinue
    if ($existing -and $existing.Server -ne $Server) { Remove-PSDrive -Name $Name -Force }
    if (-not (Get-PSDrive -Name $Name -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name $Name -PSProvider ActiveDirectory -Root '//RootDSE/' -Server $Server -Scope Global | Out-Null
    }
    "${Name}:"
}

function Get-SoaAttributeGuid {
    param([Parameter(Mandatory)][string]$LdapDisplayName, [Parameter(Mandatory)] $Context)
    $srv = if ($Context.PSObject.Properties.Name -contains 'Server' -and $Context.Server) { $Context.Server } else { $Context.Pdc }
    $o = Get-ADObject -Server $srv -SearchBase $Context.SchemaNC -LDAPFilter "(lDAPDisplayName=$LdapDisplayName)" -Properties schemaIDGUID
    if (-not $o) { throw "Attribute $LdapDisplayName not found in the schema." }
    [guid]$o.schemaIDGUID
}

<#
    Adds an allow ACE if not present. Returns a descriptor of the ACE (for the manifest) or $null if it existed.
#>
function Add-SoaAce {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string] $TargetDn,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier] $Sid,
        [Parameter(Mandatory)][DirectoryServices.ActiveDirectoryRights] $Rights,
        [guid] $ObjectType = [guid]::Empty,
        [DirectoryServices.ActiveDirectorySecurityInheritance] $Inheritance = 'None',
        [guid] $InheritedObjectType = [guid]::Empty,
        [string] $Label,
        [string] $Drive = 'SOAAD:'
    )
    $path  = "$Drive\$TargetDn"
    $acl   = Get-Acl -Path $path
    $exist = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.IdentityReference -eq $Sid -and "$($_.AccessControlType)" -eq 'Allow' -and
        (($_.ActiveDirectoryRights -band $Rights) -eq $Rights) -and $_.ObjectType -eq $ObjectType -and
        $_.InheritanceType -eq $Inheritance -and $_.InheritedObjectType -eq $InheritedObjectType
    })
    if ($exist.Count) { Write-SoaLine SAME "present : $Label  [$TargetDn]"; return $null }
    if ($PSCmdlet.ShouldProcess($TargetDn, "Grant $Label")) {
        $acl.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($Sid, $Rights, 'Allow', $ObjectType, $Inheritance, $InheritedObjectType)))
        Set-Acl -Path $path -AclObject $acl
        Write-SoaLine ADD "granted : $Label  [$TargetDn]"
        return [pscustomobject]@{ Kind = 'Ace'; TargetDn = $TargetDn; Sid = $Sid.Value; Rights = "$Rights"; ObjectType = "$ObjectType"; Inheritance = "$Inheritance"; InheritedObjectType = "$InheritedObjectType"; Label = $Label }
    }
    $null
}

<#
    Removes all explicit ACEs (allow and deny) of one trustee from an object. Returns the number removed.
#>
function Remove-SoaTrusteeAces {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$TargetDn, [Parameter(Mandatory)][string]$Sid, [string]$Drive = 'SOAAD:', [switch]$Audit)
    $path = "$Drive\$TargetDn"
    $acl  = if ($Audit) { Get-Acl -Path $path -Audit } else { Get-Acl -Path $path }
    $rules = if ($Audit) { @($acl.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier])) } else { @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) }
    $mine = @($rules | Where-Object { $_.IdentityReference.Value -eq $Sid })
    if (-not $mine.Count) { return 0 }
    if ($PSCmdlet.ShouldProcess($TargetDn, "Remove $($mine.Count) $(if ($Audit) { 'audit' } else { 'access' }) rule(s) of $Sid")) {
        foreach ($r in $mine) {
            if ($Audit) { [void]$acl.RemoveAuditRuleSpecific($r) } else { [void]$acl.RemoveAccessRuleSpecific($r) }
        }
        Set-Acl -Path $path -AclObject $acl
    }
    $mine.Count
}

<#
    SACL entry of the toolkit (trigger for SOA-converted users: event 5136 on writes to msDS-ObjectSoa).
    ACEs and SACL entries cannot carry a description, so the toolkit's entry is identified by its exact fingerprint:
      trustee Everyone (S-1-1-0), audit Success only, right WriteProperty only, object type = msDS-ObjectSoa,
      inheritance Descendents, inherited object type = user, explicit (not inherited)
    and by the manifest (kind 'Sacl'). Broader audit rules (e.g. "Write all properties" from a diagnosis) also
    produce 5136, but the toolkit never relies on them: they may be removed at any time by their owner.
#>
function Test-SoaSaclFingerprint {
    param([Parameter(Mandatory)] $Rule, [Parameter(Mandatory)][guid]$AttributeGuid)
    ($Rule.IdentityReference.Value -eq $script:SoaSid.Everyone) -and
    ("$($Rule.AuditFlags)" -eq 'Success') -and
    ($Rule.ActiveDirectoryRights -eq [DirectoryServices.ActiveDirectoryRights]::WriteProperty) -and
    ($Rule.ObjectType -eq $AttributeGuid) -and
    ("$($Rule.InheritanceType)" -eq 'Descendents') -and
    ($Rule.InheritedObjectType -eq $script:SoaGuid.UserClass)
}

function New-SoaSaclRule {
    param([Parameter(Mandatory)][guid]$AttributeGuid)
    New-Object DirectoryServices.ActiveDirectoryAuditRule(([Security.Principal.SecurityIdentifier]$script:SoaSid.Everyone),
        'WriteProperty', 'Success', $AttributeGuid, 'Descendents', $script:SoaGuid.UserClass)
}

<#
    Reads the SACL of a container (needs "Manage auditing and security log" on the DC - Domain Admins have it,
    the toolkit gMSA does not). Returns whether the toolkit entry is present and which other rules would also audit
    writes to msDS-ObjectSoa on users (informational only).
#>
function Get-SoaSaclState {
    param([Parameter(Mandatory)][string]$Dn, [Parameter(Mandatory)][guid]$AttributeGuid, [string]$Drive = 'SOAAD:')
    $acl = Get-Acl -Path "$Drive\$Dn" -Audit
    $all = @($acl.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $toolkit   = @($all | Where-Object { -not $_.IsInherited -and (Test-SoaSaclFingerprint -Rule $_ -AttributeGuid $AttributeGuid) })
    $inherited = @($all | Where-Object { $_.IsInherited -and (Test-SoaSaclFingerprint -Rule $_ -AttributeGuid $AttributeGuid) })
    $broad = @($all | Where-Object {
        -not (Test-SoaSaclFingerprint -Rule $_ -AttributeGuid $AttributeGuid) -and
        (($_.AuditFlags -band [Security.AccessControl.AuditFlags]::Success) -ne 0) -and
        (($_.ActiveDirectoryRights -band ([DirectoryServices.ActiveDirectoryRights]'WriteProperty, GenericWrite, GenericAll')) -ne 0) -and
        ($_.ObjectType -eq [guid]::Empty -or $_.ObjectType -eq $AttributeGuid) -and
        ("$($_.InheritanceType)" -in 'All', 'Descendents') -and
        ($_.InheritedObjectType -eq [guid]::Empty -or $_.InheritedObjectType -eq $script:SoaGuid.UserClass)
    } | ForEach-Object {
        $who = try { $_.IdentityReference.Translate([Security.Principal.NTAccount]).Value } catch { $_.IdentityReference.Value }
        '{0}: {1} ({2}), object type {3}, {4}{5}' -f $who, $_.ActiveDirectoryRights, $_.AuditFlags,
            $(if ($_.ObjectType -eq [guid]::Empty) { 'all properties' } else { 'msDS-ObjectSoa' }), $_.InheritanceType, $(if ($_.IsInherited) { ', inherited' } else { '' })
    })
    [pscustomobject]@{ Dn = $Dn; Toolkit = ($toolkit.Count -gt 0); ToolkitInherited = ($inherited.Count -gt 0); Broad = $broad; Acl = $acl }
}

function Get-SoaJobGmsa {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] $Context)
    try { Get-ADServiceAccount -Identity $Config.GmsaName -Server $Context.Pdc -Properties Description, PrincipalsAllowedToRetrieveManagedPassword } catch { $null }
}

<#
    gMSA(s) of the Cloud Sync provisioning agents. AgentGmsaNames (config) wins; otherwise the service account of
    the 'AADConnectProvisioningAgent' service is read from every agent host via WinRM. Each agent host may use its
    own gMSA - all of them must be allow-listed and are part of the event-trigger filter.
#>
function Get-SoaAgentGmsa {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] $Context, [switch]$Quiet)
    $names = @()
    if (@($Config.AgentGmsaNames).Count) {
        $names = @($Config.AgentGmsaNames)
    } else {
        $local = Get-SoaLocalFqdn
        foreach ($h in @($Config.AgentHosts)) {
            try {
                $sb = { (Get-CimInstance -ClassName Win32_Service -Filter "Name='AADConnectProvisioningAgent'").StartName }
                $n = if ($h.ToLower() -eq $local -or (Get-SoaShortName $h) -eq $env:COMPUTERNAME) { & $sb } else { Invoke-Command -ComputerName $h -ScriptBlock $sb -ErrorAction Stop }
                if ($n) { $names += "$n" } elseif (-not $Quiet) { Write-Warning "No provisioning agent service found on $h." }
            } catch { if (-not $Quiet) { Write-Warning "Agent gMSA not readable on ${h}: $($_.Exception.Message)" } }
        }
    }
    foreach ($n in @($names | Select-Object -Unique)) {
        $sam = ($n -split '\\')[-1]
        if ($sam -notlike '*$') { $sam += '$' }
        $acc = Get-ADServiceAccount -Filter "SamAccountName -eq '$sam'" -Server $Context.Pdc
        if ($acc) { [pscustomobject]@{ Name = $sam; Sid = $acc.SID.Value; DistinguishedName = $acc.DistinguishedName } }
        elseif (-not $Quiet) { Write-Warning "Provisioning agent runs as '$n', which is not a gMSA of this domain." }
    }
}

function Get-SoaPolicy {
    param([Parameter(Mandatory)] $Context, [string]$Server)
    if (-not $Server) { $Server = $Context.Pdc }
    try { Get-ADObject -Identity $Context.PolicyDN -Server $Server -Properties keywords, 'msDS-Settings', serviceBindingInformation, description, whenChanged, whenCreated } catch { $null }
}

function Get-SoaPolicyMode {
    param([Parameter(Mandatory)] $Context, [string]$Server)
    $p = Get-SoaPolicy -Context $Context -Server $Server
    if ($p) { (@($p.keywords) -join ',') } else { $null }
}

<#
    Replication metadata of the secret and related attributes (metadata only - secret values are never readable).
#>
function Get-SoaSecretMeta {
    param([Parameter(Mandatory)][string]$Dn, [Parameter(Mandatory)][string]$Server)
    $md = @(Get-ADReplicationAttributeMetadata -Object $Dn -Server $Server)
    $u  = $md | Where-Object { $_.AttributeName -eq 'unicodePwd' } | Select-Object -First 1
    $p  = $md | Where-Object { $_.AttributeName -eq 'pwdLastSet' } | Select-Object -First 1
    $a  = $md | Where-Object { $_.AttributeName -eq 'userAccountControl' } | Select-Object -First 1
    $x  = $md | Where-Object { $_.AttributeName -eq 'msDS-ExternalDirectoryObjectId' } | Select-Object -First 1
    [pscustomobject]@{
        SecretVersion     = $(if ($u) { [int]$u.Version } else { 0 })
        SecretTime        = $(if ($u) { $u.LastOriginatingChangeTime } else { $null })
        SecretOrigin      = $(if ($u) { Get-SoaServerFromNtdsDn $u.LastOriginatingChangeDirectoryServerIdentity } else { $null })
        PwdLastSetVersion = $(if ($p) { [int]$p.Version } else { 0 })
        PwdLastSetTime    = $(if ($p) { $p.LastOriginatingChangeTime } else { $null })
        UacVersion        = $(if ($a) { [int]$a.Version } else { 0 })
        UacOrigin         = $(if ($a) { Get-SoaServerFromNtdsDn $a.LastOriginatingChangeDirectoryServerIdentity } else { $null })
        AnchorTime        = $(if ($x) { $x.LastOriginatingChangeTime } else { $null })
    }
}

<#
    Origin heuristic: the anchor (msDS-ExternalDirectoryObjectId) stamped within 10 minutes of object creation means
    the object was created by provisioning (cloud-native); stamped later means a pre-existing object was taken over
    (SOA-converted).
#>
function Get-SoaOriginKind {
    param([datetime]$WhenCreated, $AnchorTime)
    if (-not $AnchorTime) { return 'unknown' }
    if ([Math]::Abs(([datetime]$AnchorTime - $WhenCreated).TotalMinutes) -le 10) { 'cloud-native' } else { 'SOA-converted' }
}
#endregion

#region --- Cloud users / scope ---------------------------------------------------------------------
$script:SoaCloudUserFilter = '(&(objectCategory=person)(objectClass=user)(msDS-ExternalDirectoryObjectId=User_*))'

function Get-SoaCloudUserFilter { $script:SoaCloudUserFilter }

<#
    All users provisioned by Entra Cloud Sync (anchor User_*), domain-wide. The scope of the toolkit is
    "provisioned AND marked (msDS-ObjectSoa = Cloud)"; provisioned-but-unmarked users are reported, not changed.
#>
function Get-SoaCloudUser {
    param([Parameter(Mandatory)][string]$Server, [string[]]$Properties = @(), [string]$SearchBase)
    $props = @('userAccountControl', 'msDS-ObjectSoa', 'msDS-ExternalDirectoryObjectId', 'pwdLastSet', 'whenCreated', 'objectGUID', 'objectSid', 'memberOf') + $Properties | Select-Object -Unique
    $p = @{ Server = $Server; LDAPFilter = $script:SoaCloudUserFilter; Properties = $props; ResultPageSize = 500 }
    if ($SearchBase) { $p.SearchBase = $SearchBase }
    @(Get-ADUser @p)
}

function Test-SoaCloudMarked($User) {
    [bool](@($User.'msDS-ObjectSoa') -contains 'Cloud')
}

<#
    DNs below which the job gMSA may write.
      'AgentScope' : containers where a Cloud Sync agent gMSA holds explicit write ACEs (same scope as the agent)
      'Domain'     : the domain root
      array        : the given DNs
#>
function Get-SoaWriteScope {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] $Context, $AgentGmsa)
    $ws = $Config.WriteScope
    if ($ws -is [array]) { return @($ws) }
    if ("$ws" -eq 'Domain') { return @($Context.DomainDN) }
    if (-not $AgentGmsa) { $AgentGmsa = @(Get-SoaAgentGmsa -Config $Config -Context $Context -Quiet) }
    $sids = @($AgentGmsa | ForEach-Object { $_.Sid })
    if (-not $sids.Count) { Write-Warning 'WriteScope AgentScope: no agent gMSA found - falling back to the domain root.'; return @($Context.DomainDN) }
    $drive = Initialize-SoaAdDrive -Server $Context.Pdc
    $writeMask = [DirectoryServices.ActiveDirectoryRights]'WriteProperty, CreateChild, GenericAll, GenericWrite'
    $candidates = @($Context.DomainDN) + @(Get-ADOrganizationalUnit -Filter * -Server $Context.Pdc | ForEach-Object { $_.DistinguishedName }) +
                  @(Get-ADObject -Server $Context.Pdc -SearchBase $Context.DomainDN -SearchScope OneLevel -LDAPFilter '(objectClass=container)' | ForEach-Object { $_.DistinguishedName })
    $scope = foreach ($dn in $candidates) {
        try {
            $acl = Get-Acl -Path "$drive\$dn"
            $hit = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object {
                "$($_.AccessControlType)" -eq 'Allow' -and $sids -contains $_.IdentityReference.Value -and ($_.ActiveDirectoryRights -band $writeMask) })
            if ($hit.Count) { $dn }
        } catch { }
    }
    $scope = @($scope | Select-Object -Unique)
    # Drop DNs that are below another scope DN
    @($scope | Where-Object { $d = $_; -not @($scope | Where-Object { $_ -ne $d -and (Test-SoaDnInScope -Dn $d -ScopeDns @($_)) }).Count })
}

function Get-SoaGroupMemberSet {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Server, [switch]$Recursive)
    $set = @{}
    try {
        $g = Get-ADGroup -Identity $Name -Server $Server -Properties member
        if ($Recursive) {
            foreach ($m in Get-ADGroupMember -Identity $g -Server $Server -Recursive) { $set[$m.distinguishedName.ToLower()] = $true }
        } else {
            foreach ($m in @($g.member)) { $set["$m".ToLower()] = $true }
        }
    } catch { }
    $set
}

<#
    Desired-state evaluation of one cloud user (no writes). Returns what has to change.
#>
function Get-SoaUserConformance {
    param(
        [Parameter(Mandatory)] $User,
        [Parameter(Mandatory)] $Config,
        [hashtable] $PsoMembers,
        [hashtable] $ExcludeMembers,
        [hashtable] $PilotMembers,
        [string[]] $WriteScope
    )
    $uac   = [int]$User.userAccountControl
    $dnKey = $User.DistinguishedName.ToLower()
    $marked = Test-SoaCloudMarked $User
    $excluded = $false; $reason = $null
    if ($ExcludeMembers -and $ExcludeMembers.ContainsKey($dnKey)) { $excluded = $true; $reason = "member of $($Config.ExcludeGroupName)" }
    elseif ($Config.BreakGlassName -and $User.SamAccountName -eq $Config.BreakGlassName) { $excluded = $true; $reason = 'break-glass account' }
    elseif (@($Config.ExcludeOUs).Count -and (Test-SoaDnInScope -Dn $User.DistinguishedName -ScopeDns @($Config.ExcludeOUs))) { $excluded = $true; $reason = 'ExcludeOUs' }
    $pilotOut = ($Config.PilotMode -and -not ($PilotMembers -and $PilotMembers.ContainsKey($dnKey)))
    $inScope  = $marked -and -not $excluded -and -not $pilotOut
    $writable = if ($WriteScope) { Test-SoaDnInScope -Dn $User.DistinguishedName -ScopeDns $WriteScope } else { $true }
    $inPso    = [bool]($PsoMembers -and $PsoMembers.ContainsKey($dnKey))
    [pscustomobject]@{
        Sam          = $User.SamAccountName
        Dn           = $User.DistinguishedName
        Marked       = $marked
        Excluded     = $excluded
        ExcludeReason = $reason
        PilotOut     = $pilotOut
        InScope      = $inScope
        Writable     = $writable
        Scril        = [bool]($uac -band $script:SoaUac.Scril)
        Pne          = [bool]($uac -band $script:SoaUac.DontExpire)
        Disabled     = [bool]($uac -band $script:SoaUac.Disabled)
        InPsoGroup   = $inPso
        NeedScril    = $inScope -and -not ($uac -band $script:SoaUac.Scril)
        NeedPneClear = $inScope -and [bool]($uac -band $script:SoaUac.DontExpire)
        NeedGroupAdd = $inScope -and -not $inPso
        NeedGroupRemove = (-not $inScope) -and $inPso
    }
}

<#
    Atomic update of userAccountControl: LDAP modify with "delete <old value>" + "add <new value>" in ONE request.
    If the value changed in the meantime (e.g. Cloud Sync toggled 'disabled'), the delete fails and the update is
    retried with the fresh value - so no concurrent change is overwritten. Falls back to replace if the server
    rejects the compare-and-swap form while the value is unchanged.
#>
function Set-SoaUacFlags {
    param(
        [Parameter(Mandatory)][string]$Dn,
        [Parameter(Mandatory)][string]$Server,
        [int]$SetBits = 0,
        [int]$ClearBits = 0
    )
    for ($i = 1; $i -le 4; $i++) {
        $old = [int](Get-ADUser -Identity $Dn -Server $Server -Properties userAccountControl).userAccountControl
        $new = ($old -bor $SetBits) -band (-bnot $ClearBits)
        if ($new -eq $old) { return [pscustomobject]@{ Old = $old; New = $new; Changed = $false; Method = 'none' } }
        try {
            Set-ADUser -Identity $Dn -Server $Server -Remove @{ userAccountControl = $old } -Add @{ userAccountControl = $new } -ErrorAction Stop
            return [pscustomobject]@{ Old = $old; New = $new; Changed = $true; Method = 'compare-and-swap' }
        } catch {
            $now = [int](Get-ADUser -Identity $Dn -Server $Server -Properties userAccountControl).userAccountControl
            if ($now -ne $old) { Start-Sleep -Milliseconds (300 * $i); continue }      # concurrent change -> retry
            if ($i -ge 2) {
                Set-ADUser -Identity $Dn -Server $Server -Replace @{ userAccountControl = (($now -bor $SetBits) -band (-bnot $ClearBits)) } -ErrorAction Stop
                return [pscustomobject]@{ Old = $now; New = (($now -bor $SetBits) -band (-bnot $ClearBits)); Changed = $true; Method = 'replace (fallback)' }
            }
            Start-Sleep -Milliseconds 300
        }
    }
    throw "userAccountControl of $Dn could not be updated (value kept changing)."
}

function New-SoaRandomSecret {
    param([int]$Length = 120)
    $sets = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#%+-=?@_~'
    $all  = -join $sets
    $rng  = [Security.Cryptography.RandomNumberGenerator]::Create()
    $buf  = New-Object byte[] 4
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($s in $sets) { $rng.GetBytes($buf); $chars.Add($s[[BitConverter]::ToUInt32($buf, 0) % $s.Length]) }
    while ($chars.Count -lt $Length) { $rng.GetBytes($buf); $chars.Add($all[[BitConverter]::ToUInt32($buf, 0) % $all.Length]) }
    $sec = New-Object Security.SecureString
    foreach ($c in ($chars | Sort-Object { $rng.GetBytes($buf); [BitConverter]::ToUInt32($buf, 0) })) { $sec.AppendChar($c) }
    $sec.MakeReadOnly()
    $sec
}
#endregion

#region --- Group Policy helpers --------------------------------------------------------------------
function Get-SoaGpoAdPath { param([guid]$Id, $Context) "CN={$Id},CN=Policies,CN=System,$($Context.DomainDN)" }
function Get-SoaGpoSysvolPath { param([guid]$Id, $Context, [string]$Server) if (-not $Server) { $Server = $Context.Pdc }; "\\$Server\SYSVOL\$($Context.DnsRoot)\Policies\{$Id}" }

function Get-SoaGpo {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)] $Context)
    try { Get-GPO -Name $Name -Domain $Context.DnsRoot -Server $Context.Pdc -ErrorAction Stop } catch { $null }
}

<#
    Creates a GPO (computer part only) with the marker comment, or returns the existing one.
#>
function New-SoaGpo {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)] $Config, [Parameter(Mandatory)] $Context, [string]$Purpose)
    $g = Get-SoaGpo -Name $Name -Context $Context
    if ($g) { return [pscustomobject]@{ Gpo = $g; Created = $false } }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Create GPO')) { return $null }
    $comment = Get-SoaMarker -Config $Config -Purpose $Purpose
    if ($comment.Length -gt 2000) { $comment = $comment.Substring(0, 2000) }
    $g = New-GPO -Name $Name -Domain $Context.DnsRoot -Server $Context.Pdc -Comment $comment
    $g.GpoStatus = 'UserSettingsDisabled'
    Write-SoaLine ADD "GPO '$Name' created ($($g.Id))"
    [pscustomobject]@{ Gpo = $g; Created = $true }
}

<#
    Increments the computer version of a GPO in AD (versionNumber) and SYSVOL (GPT.INI) after files were written
    directly to SYSVOL, and registers client-side extensions in gPCMachineExtensionNames (sorted, merged).
#>
function Update-SoaGpoMachineVersion {
    param([Parameter(Mandatory)][guid]$Id, [Parameter(Mandatory)] $Context, [string[]]$AddCse = @())
    $dn  = Get-SoaGpoAdPath -Id $Id -Context $Context
    $obj = Get-ADObject -Identity $dn -Server $Context.Pdc -Properties versionNumber, gPCMachineExtensionNames
    $ver = [int]$obj.versionNumber
    $user = ($ver -shr 16) -band 0xFFFF
    $mach = ($ver -band 0xFFFF) + 1
    if ($mach -gt 0xFFFF) { $mach = 1 }
    $newVer = ($user -shl 16) -bor $mach

    $replace = @{ versionNumber = $newVer }
    if ($AddCse.Count) {
        $existing = @()
        if ($obj.gPCMachineExtensionNames) { $existing = @([regex]::Matches($obj.gPCMachineExtensionNames, '\[[^\]]+\]') | ForEach-Object { $_.Value }) }
        $merged = @{}
        foreach ($e in @($existing) + @($AddCse)) {
            $m = [regex]::Matches($e, '\{[0-9A-Fa-f-]+\}') | ForEach-Object { $_.Value.ToUpper() }
            $cse = @($m)[0]
            if (-not $merged.ContainsKey($cse)) { $merged[$cse] = New-Object System.Collections.Generic.List[string] }
            foreach ($t in @($m | Select-Object -Skip 1)) { if (-not $merged[$cse].Contains($t)) { $merged[$cse].Add($t) } }
        }
        $value = -join ($merged.Keys | Sort-Object | ForEach-Object { '[' + $_ + (-join (@($merged[$_]) | Sort-Object)) + ']' })
        $replace.gPCMachineExtensionNames = $value
    }
    Set-ADObject -Identity $dn -Server $Context.Pdc -Replace $replace

    $ini = Join-Path (Get-SoaGpoSysvolPath -Id $Id -Context $Context) 'GPT.INI'
    $content = if (Test-Path -LiteralPath $ini) { Get-Content -LiteralPath $ini -Raw } else { "[General]`r`n" }
    if ($content -match '(?im)^Version=\d+') { $content = $content -replace '(?im)^Version=\d+', "Version=$newVer" }
    else { $content = $content.TrimEnd() + "`r`nVersion=$newVer`r`n" }
    Set-Content -LiteralPath $ini -Value $content -Encoding ASCII -NoNewline
    $newVer
}

<#
    Writes Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf (UTF-16 LE, as written by the Group Policy editor).
    $Sections: ordered hashtable SectionName -> array of lines
#>
function Set-SoaGpoSecurityTemplate {
    param([Parameter(Mandatory)][guid]$Id, [Parameter(Mandatory)] $Context, [Parameter(Mandatory)][System.Collections.IDictionary]$Sections)
    $dir = Join-Path (Get-SoaGpoSysvolPath -Id $Id -Context $Context) 'Machine\Microsoft\Windows NT\SecEdit'
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1')
    foreach ($s in $Sections.Keys) { $lines += "[$s]"; $lines += @($Sections[$s]) }
    Set-Content -LiteralPath (Join-Path $dir 'GptTmpl.inf') -Value $lines -Encoding Unicode
}

function Get-SoaGpoSecurityTemplate {
    param([Parameter(Mandatory)][guid]$Id, [Parameter(Mandatory)] $Context)
    $f = Join-Path (Get-SoaGpoSysvolPath -Id $Id -Context $Context) 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    if (Test-Path -LiteralPath $f) { Get-Content -LiteralPath $f } else { @() }
}

<#
    Writes Machine\Microsoft\Windows NT\Audit\audit.csv (advanced audit policy).
    $Settings: objects with Name, Guid, Value (1/2/3)
#>
function Set-SoaGpoAuditCsv {
    param([Parameter(Mandatory)][guid]$Id, [Parameter(Mandatory)] $Context, [Parameter(Mandatory)] $Settings)
    $dir = Join-Path (Get-SoaGpoSysvolPath -Id $Id -Context $Context) 'Machine\Microsoft\Windows NT\Audit'
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
    $text = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
    $lines = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($s in @($Settings)) { $lines += (',System,{0},{1},{2},,{3}' -f $s.Name, $s.Guid, $text[[int]$s.Value], [int]$s.Value) }
    Set-Content -LiteralPath (Join-Path $dir 'audit.csv') -Value $lines -Encoding ASCII
}

function Get-SoaGpoAuditCsv {
    param([Parameter(Mandatory)][guid]$Id, [Parameter(Mandatory)] $Context)
    $f = Join-Path (Get-SoaGpoSysvolPath -Id $Id -Context $Context) 'Machine\Microsoft\Windows NT\Audit\audit.csv'
    if (-not (Test-Path -LiteralPath $f)) { return @() }
    foreach ($l in (Get-Content -LiteralPath $f | Select-Object -Skip 1)) {
        $x = $l -split ','
        if ($x.Count -ge 7 -and $x[3] -match '^\{[0-9A-Fa-f-]+\}$') { [pscustomobject]@{ Name = $x[2]; Guid = $x[3].ToUpper(); Value = [int]$x[6] } }
    }
}

function Get-SoaGpoLinkState {
    param([Parameter(Mandatory)][guid]$Id, [Parameter(Mandatory)][string]$Target, [Parameter(Mandatory)] $Context)
    $l = (Get-GPInheritance -Target $Target -Domain $Context.DnsRoot -Server $Context.Pdc).GpoLinks | Where-Object { $_.GpoId -eq $Id } | Select-Object -First 1
    if ($l) { [pscustomobject]@{ Linked = $true; Enabled = $l.Enabled; Order = $l.Order } } else { [pscustomobject]@{ Linked = $false; Enabled = $false; Order = $null } }
}

function Set-SoaGpoLink {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][guid]$Id, [Parameter(Mandatory)][string]$Target, [Parameter(Mandatory)] $Context, [int]$Order = 1, [switch]$Disabled)
    $state = Get-SoaGpoLinkState -Id $Id -Target $Target -Context $Context
    $enabled = if ($Disabled) { 'No' } else { 'Yes' }
    if (-not $state.Linked) {
        if ($PSCmdlet.ShouldProcess($Target, "Link GPO $Id (order $Order, enabled $enabled)")) {
            New-GPLink -Guid $Id -Target $Target -LinkEnabled $enabled -Order $Order -Domain $Context.DnsRoot -Server $Context.Pdc | Out-Null
            Write-SoaLine ADD "linked to $Target (order $Order, enabled $enabled)"
        }
    } else {
        if ($state.Order -ne $Order -or ($state.Enabled -ne (-not $Disabled))) {
            if ($PSCmdlet.ShouldProcess($Target, "Update link of GPO $Id (order $Order, enabled $enabled)")) {
                Set-GPLink -Guid $Id -Target $Target -LinkEnabled $enabled -Order $Order -Domain $Context.DnsRoot -Server $Context.Pdc | Out-Null
                Write-SoaLine ADD "link updated on $Target (order $Order, enabled $enabled)"
            }
        } else { Write-SoaLine SAME "link on $Target (order $Order, enabled $enabled)" }
    }
}

<#
    Creates (or returns) a WMI filter (msWMI-Som) and returns its GUID string '{...}'.
#>
function New-SoaWmiFilter {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)] $Config, [Parameter(Mandatory)] $Context, [string]$Description)
    $existing = Get-ADObject -Server $Context.Pdc -SearchBase $Context.SomDN -LDAPFilter "(&(objectClass=msWMI-Som)(msWMI-Name=$(ConvertTo-SoaLdapValue $Name)))" -Properties 'msWMI-ID', 'msWMI-Parm2'
    if ($existing) { return [pscustomobject]@{ Id = "$($existing.'msWMI-ID')"; Dn = $existing.DistinguishedName; Created = $false } }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Create WMI filter')) { return $null }
    $id    = '{' + ([guid]::NewGuid().ToString().ToUpper()) + '}'
    $now   = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff-000')
    $ns    = 'root\CIMv2'
    $parm2 = '1;3;{0};{1};WQL;{2};{3};' -f $ns.Length, $Query.Length, $ns, $Query
    $desc  = if ($Description) { $Description } else { Get-SoaMarker -Config $Config -Short }
    $attrs = @{
        'msWMI-Name' = $Name; 'msWMI-Parm1' = $desc; 'msWMI-Parm2' = $parm2; 'msWMI-Author' = "$env:USERNAME@$($Context.DnsRoot)"
        'msWMI-ID' = $id; 'instanceType' = 4; 'showInAdvancedViewOnly' = 'TRUE'; 'msWMI-ChangeDate' = $now; 'msWMI-CreationDate' = $now
    }
    New-ADObject -Name $id -Type 'msWMI-Som' -Path $Context.SomDN -OtherAttributes $attrs -Server $Context.Pdc
    Write-SoaLine ADD "WMI filter '$Name' created ($id)"
    [pscustomobject]@{ Id = $id; Dn = "CN=$id,$($Context.SomDN)"; Created = $true }
}

function Set-SoaGpoWmiFilter {
    param([Parameter(Mandatory)][guid]$GpoId, [Parameter(Mandatory)][string]$FilterId, [Parameter(Mandatory)] $Context)
    $dn = Get-SoaGpoAdPath -Id $GpoId -Context $Context
    Set-ADObject -Identity $dn -Server $Context.Pdc -Replace @{ gPCWQLFilter = ('[{0};{1};0]' -f $Context.DnsRoot, $FilterId) }
}

<#
    Parses a KIR / feature-enablement ADMX: returns every policy that writes FeatureManagement override values,
    with its feature IDs and enabled/disabled values. Supports both ADMX patterns (single valueName and
    enabledList/disabledList, as used by "Feature Preview" packages).
#>
function Get-SoaKirDefinition {
    param([Parameter(Mandatory)][string]$AdmxPath)
    [xml]$admx = Get-Content -LiteralPath $AdmxPath -Raw
    $strings = @{}
    $dir = Split-Path -Path $AdmxPath -Parent
    $base = [IO.Path]::GetFileNameWithoutExtension($AdmxPath)
    foreach ($cand in @((Join-Path $dir "en-US\$base.adml"), (Join-Path $dir "$base.adml"))) {
        if (Test-Path -LiteralPath $cand) {
            try {
                [xml]$adml = Get-Content -LiteralPath $cand -Raw
                foreach ($s in $adml.SelectNodes("//*[local-name()='string']")) { $strings[$s.GetAttribute('id')] = $s.InnerText }
            } catch { }
            break
        }
    }
    $pols = @($admx.SelectNodes("//*[local-name()='policy']") | Where-Object {
        ($_.GetAttribute('key') -like '*FeatureManagement\Overrides*') -or
        (@($_.SelectNodes("./*[local-name()='enabledList']/*[local-name()='item']") | Where-Object { $_.GetAttribute('key') -like '*FeatureManagement\Overrides*' }).Count -gt 0)
    })
    foreach ($p in $pols) {
        $ref  = $p.GetAttribute('displayName') -replace '^\$\(string\.(.+)\)$', '$1'
        $disp = if ($strings.ContainsKey($ref)) { $strings[$ref] } else { $p.GetAttribute('displayName') }
        $key  = $p.GetAttribute('key')
        $items = @()
        if ($p.GetAttribute('valueName') -and $key -like '*FeatureManagement\Overrides*') {
            $en = $p.SelectSingleNode("./*[local-name()='enabledValue']/*[local-name()='decimal']")
            $di = $p.SelectSingleNode("./*[local-name()='disabledValue']/*[local-name()='decimal']")
            $items += [pscustomobject]@{ Key = $key; FeatureId = $p.GetAttribute('valueName'); Enabled = $(if ($en) { [int]$en.GetAttribute('value') } else { 1 }); Disabled = $(if ($di) { [int]$di.GetAttribute('value') } else { 0 }) }
        }
        $disabledMap = @{}
        foreach ($it in $p.SelectNodes("./*[local-name()='disabledList']/*[local-name()='item']")) {
            $dv = $it.SelectSingleNode(".//*[local-name()='decimal']")
            $disabledMap[$it.GetAttribute('valueName')] = $(if ($dv) { [int]$dv.GetAttribute('value') } else { 0 })
        }
        foreach ($it in $p.SelectNodes("./*[local-name()='enabledList']/*[local-name()='item']")) {
            $ik = $it.GetAttribute('key'); if (-not $ik) { $ik = $key }
            if ($ik -notlike '*FeatureManagement\Overrides*') { continue }
            $ev = $it.SelectSingleNode(".//*[local-name()='decimal']")
            $vn = $it.GetAttribute('valueName')
            $items += [pscustomobject]@{ Key = $ik; FeatureId = $vn; Enabled = $(if ($ev) { [int]$ev.GetAttribute('value') } else { 1 }); Disabled = $(if ($disabledMap.ContainsKey($vn)) { $disabledMap[$vn] } else { 0 }) }
        }
        [pscustomobject]@{
            AdmxFile    = [IO.Path]::GetFileName($AdmxPath)
            PolicyName  = $p.GetAttribute('name')
            DisplayName = $disp
            Class       = $p.GetAttribute('class')
            Items       = $items
        }
    }
}

<#
    Effective "Log on as a batch job" list on the local host, as SIDs (secedit export, names translated).
#>
$script:SoaBatchRightBlock = {
    $tmp = Join-Path $env:TEMP ('soa_ur_{0}.inf' -f [guid]::NewGuid().ToString('N'))
    & secedit.exe /export /areas USER_RIGHTS /cfg $tmp /quiet | Out-Null
    $line = Get-Content -Path $tmp -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*SeBatchLogonRight\s*=' } | Select-Object -First 1
    Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    $out = @()
    if ($line) {
        foreach ($e in (($line -split '=', 2)[1] -split ',')) {
            $e = $e.Trim()
            if (-not $e) { continue }
            if ($e.StartsWith('*')) { $out += $e.Substring(1) }
            else { try { $out += ([Security.Principal.NTAccount]$e).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $out += "UNRESOLVED:$e" } }
        }
    }
    $out
}
function Get-SoaBatchRightBlock { $script:SoaBatchRightBlock }

<#
    Language-independent audit policy (auditpol /backup): returns hashtable GUID -> value (0..3).
#>
$script:SoaAuditPolicyBlock = {
    $tmp = Join-Path $env:TEMP ('soa_ap_{0}.csv' -f [guid]::NewGuid().ToString('N'))
    & auditpol.exe /backup /file:$tmp | Out-Null
    $map = @{}
    foreach ($l in (Get-Content -Path $tmp -ErrorAction SilentlyContinue | Select-Object -Skip 1)) {
        $f = $l -split ','
        if ($f.Count -ge 7 -and $f[3] -match '^\{[0-9A-Fa-f-]+\}$') { $map[$f[3].ToUpper()] = [int]$f[6] }
    }
    Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Subcategories = $map
        ForceSubcategory = $(if ($lsa -and ($lsa.PSObject.Properties.Name -contains 'SCENoApplyLegacyAuditPolicy')) { [int]$lsa.SCENoApplyLegacyAuditPolicy } else { $null })
    }
}
function Get-SoaAuditPolicyBlock { $script:SoaAuditPolicyBlock }
#endregion

#region --- Event trigger subscriptions ------------------------------------------------------------
<#
    XPath subscriptions for the onboarding task. Only writes by the Cloud Sync agent gMSA(s) trigger:
      4720  user created                        (new cloud-native users)
      5136  msDS-ObjectSoa written (value added) (SOA-converted users; needs SACL + 'Directory Service Changes')
#>
function Get-SoaEventSubscription {
    param([Parameter(Mandatory)][string[]]$AgentSids)
    $subj = ($AgentSids | ForEach-Object { "Data[@Name='SubjectUserSid']='$_'" }) -join ' or '
    $q4720 = "*[System[(EventID=4720)]] and *[EventData[$subj]]"
    $q5136 = "*[System[(EventID=5136)]] and *[EventData[Data[@Name='AttributeLDAPDisplayName']='msDS-ObjectSoa']] and *[EventData[$subj]]"
    $wrap = { param($q) "<QueryList><Query Id=`"0`" Path=`"Security`"><Select Path=`"Security`">$q</Select></Query></QueryList>" }
    [pscustomobject]@{
        UserCreated = (& $wrap $q4720)
        SoaWritten  = (& $wrap $q5136)
        XPathUserCreated = $q4720
        XPathSoaWritten  = $q5136
    }
}
#endregion

#region --- Manifest --------------------------------------------------------------------------------
<#
    The manifest records everything Install-SoaToolkit.ps1 created or changed, incl. previous values, so that
    Uninstall-SoaToolkit.ps1 can restore the original state step by step. It is stored next to the reports
    (StatePath) and copied to every toolkit host by DeployTasks (redundancy).
#>
function Get-SoaManifestPath { param([Parameter(Mandatory)] $Config) Join-Path (Join-Path $Config.ReportPath 'State') 'manifest.json' }

function Get-SoaManifest {
    param([Parameter(Mandatory)] $Config)
    $p = Get-SoaManifestPath -Config $Config
    if (Test-Path -LiteralPath $p) {
        $j = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
        $entries = New-Object System.Collections.Generic.List[object]
        foreach ($e in @($j.Entries)) { if ($e) { $entries.Add($e) } }
        return [pscustomobject]@{ Product = $j.Product; Version = $j.Version; Created = $j.Created; Updated = $j.Updated; Domain = $j.Domain; Entries = $entries }
    }
    [pscustomobject]@{ Product = $script:SoaProduct; Version = $script:SoaVersion; Created = (Get-Date).ToString('s'); Updated = $null; Domain = $null; Entries = (New-Object System.Collections.Generic.List[object]) }
}

function Save-SoaManifest {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] $Manifest, $Context)
    $p = Get-SoaManifestPath -Config $Config
    $d = Split-Path -Path $p -Parent
    if (-not (Test-Path -LiteralPath $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
    $Manifest.Updated = (Get-Date).ToString('s')
    $Manifest.Version = $script:SoaVersion
    if ($Context) { $Manifest.Domain = $Context.DnsRoot }
    $entries = New-Object System.Collections.ArrayList
    foreach ($e in $Manifest.Entries) { [void]$entries.Add($e) }
    $out = [ordered]@{ Product = $Manifest.Product; Version = $Manifest.Version; Created = $Manifest.Created; Updated = $Manifest.Updated; Domain = $Manifest.Domain }
    $out.Entries = $entries
    ConvertTo-Json -InputObject ([pscustomobject]$out) -Depth 8 | Set-Content -LiteralPath $p -Encoding UTF8
}

<#
    Adds or replaces an entry identified by (Kind, Key). Keeps the FIRST recorded 'Previous' value, so repeated
    installs never overwrite the original state.
#>
function Set-SoaManifestEntry {
    param(
        [Parameter(Mandatory)] $Manifest,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Key,
        [ValidateSet('Created', 'Changed', 'PreExisting', 'Adopted')][string]$Action = 'Created',
        $Data,
        $Previous
    )
    $old = $Manifest.Entries | Where-Object { $_.Kind -eq $Kind -and $_.Key -eq $Key } | Select-Object -First 1
    $prev = $Previous
    $act  = $Action
    if ($old) {
        if ($old.PSObject.Properties.Name -contains 'Previous' -and $null -ne $old.Previous) { $prev = $old.Previous }
        if ($old.Action -in 'Created', 'PreExisting') { $act = $old.Action }
        [void]$Manifest.Entries.Remove($old)
    }
    $Manifest.Entries.Add([pscustomobject]@{ Kind = $Kind; Key = $Key; Action = $act; Time = (Get-Date).ToString('s'); Data = $Data; Previous = $prev })
}

function Get-SoaManifestEntry {
    param([Parameter(Mandatory)] $Manifest, [string]$Kind, [string]$Key)
    @($Manifest.Entries | Where-Object { (-not $Kind -or $_.Kind -eq $Kind) -and (-not $Key -or $_.Key -eq $Key) })
}

function Remove-SoaManifestEntry {
    param([Parameter(Mandatory)] $Manifest, [Parameter(Mandatory)][string]$Kind, [string]$Key)
    foreach ($e in @($Manifest.Entries | Where-Object { $_.Kind -eq $Kind -and (-not $Key -or $_.Key -eq $Key) })) { [void]$Manifest.Entries.Remove($e) }
}
#endregion

#region --- Remoting helpers ------------------------------------------------------------------------
<#
    Runs a script block on a host: locally if the host is this computer, otherwise via WinRM.
    Returns @{ Host; Ok; Result; Error }.
#>
#region --- Anonymization (Export-SoaReport.ps1) ------------------------------------------------------
<#
    Replaces environment-specific identifiers with stable pseudonyms before data leaves the environment.
    Two layers:
      1. known terms registered from AD and the configuration (domain, NetBIOS name, DCs, hosts, users, groups,
         gMSAs, extra terms of the operator) - longest first, case-insensitive, whole tokens only
      2. patterns: CN= / OU= values of distinguished names, DOMAIN\account, domain SIDs, GUIDs, e-mail addresses,
         IPv4 addresses, user profile paths
    The map (original -> pseudonym) never leaves the environment; Export-SoaReport.ps1 stores it separately.
#>
$script:SoaKeepCn = @(
    'Users', 'Computers', 'System', 'Builtin', 'Domain Controllers', 'Configuration', 'Schema', 'Policies', 'Machine', 'User',
    'Password Settings Container', 'SOA-Policies', 'Cloud', 'ForeignSecurityPrincipals', 'Managed Service Accounts',
    'WMIPolicy', 'SOM', 'Program Data', 'Microsoft', 'Sites', 'Services', 'Partitions', 'NTDS Settings', 'Servers',
    'Directory Service', 'Windows NT', 'Default Domain Policy', 'Default Domain Controllers Policy', 'Administrator',
    'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Event Log Readers', 'krbtgt',
    'AzureADKerberos', 'Read-only Domain Controllers', 'Allowed RODC Password Replication Group',
    'Denied RODC Password Replication Group', 'Domain Users', 'Domain Computers', 'Protected Users', 'Key Admins',
    'Enterprise Key Admins', 'Group Policy Creator Owners'
)

function New-SoaAnonymizer {
    param([string[]]$KeepNames = @())
    $keepGuids = @{}
    foreach ($g in $script:SoaGuid.Values) { $keepGuids["$g".ToLower()] = $true }
    foreach ($a in $script:SoaAuditSubcategories) { $keepGuids[$a.Guid.Trim('{}').ToLower()] = $true }
    foreach ($c in $script:SoaCse.Values) { foreach ($m in [regex]::Matches($c, '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')) { $keepGuids[$m.Value.ToLower()] = $true } }
    $keep = @{}
    foreach ($n in @($script:SoaKeepCn) + @($KeepNames)) { if ($n) { $keep[$n.ToLower()] = $true } }
    [pscustomobject]@{
        Terms     = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase))
        Map       = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase))
        Counters  = @{}
        KeepNames = $keep
        KeepGuids = $keepGuids
        DomainSids = @{}
        Compiled  = $null
    }
}

function Get-SoaPseudonym {
    param([Parameter(Mandatory)] $Anonymizer, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Original)
    if ($Anonymizer.Map.ContainsKey("$Kind|$Original")) { return $Anonymizer.Map["$Kind|$Original"].Pseudonym }
    $n = 1 + [int]$Anonymizer.Counters[$Kind]; $Anonymizer.Counters[$Kind] = $n
    $p = switch ($Kind) {
        'DOMAIN'  { if ($n -eq 1) { 'corp.example' } else { 'domain{0}.example' -f $n } }
        'NETBIOS' { if ($n -eq 1) { 'CORP' } else { 'DOMAIN{0}' -f $n } }
        'DC'      { 'dc{0:00}' -f $n }
        'HOST'    { 'host{0:00}' -f $n }
        'USER'    { 'user{0:000}' -f $n }
        'GROUP'   { 'group{0:000}' -f $n }
        'GMSA'    { 'gmsa{0:00}' -f $n }
        'ACCOUNT' { 'account{0:000}' -f $n }
        'OU'      { 'OU-{0:000}' -f $n }
        'CN'      { 'object{0:000}' -f $n }
        'GUID'    { '00000000-0000-4000-8000-{0:000000000000}' -f $n }
        'SID'     { 'S-1-5-21-{0}000000000-0-0' -f $n }
        'MAIL'    { 'mail{0:000}@example.invalid' -f $n }
        'IP'      { '192.0.2.{0}' -f ($n % 254 + 1) }
        'PROFILE' { 'profile{0:00}' -f $n }
        default   { 'term{0:000}' -f $n }
    }
    $Anonymizer.Map["$Kind|$Original"] = [pscustomobject]@{ Kind = $Kind; Original = $Original; Pseudonym = $p }
    $p
}

<#
    Registers a known identifier. Kinds: DOMAIN (DNS name), DOMAINDN, NETBIOS, DC, HOST, USER, GROUP, GMSA, ACCOUNT, TERM.
    Hosts are registered with FQDN and short name; a DOMAIN also registers its DN form.
#>
function Add-SoaAnonymizerTerm {
    param([Parameter(Mandatory)] $Anonymizer, [Parameter(Mandatory)][ValidateSet('DOMAIN', 'NETBIOS', 'DC', 'HOST', 'USER', 'GROUP', 'GMSA', 'ACCOUNT', 'TERM')][string]$Kind,
          [AllowEmptyString()][string]$Value, [string]$DomainDns)
    if (-not $Value -or $Value.Trim().Length -lt 2) { return }
    $v = $Value.Trim()
    if ($Anonymizer.KeepNames.ContainsKey($v.ToLower())) { return }
    switch ($Kind) {
        'DOMAIN' {
            $p = Get-SoaPseudonym -Anonymizer $Anonymizer -Kind 'DOMAIN' -Original $v
            $Anonymizer.Terms[$v] = $p
            $dn  = ($v.Split('.') | ForEach-Object { "DC=$_" }) -join ','
            $pdn = ($p.Split('.') | ForEach-Object { "DC=$_" }) -join ','
            $Anonymizer.Terms[$dn] = $pdn
            $Anonymizer.Map["DOMAINDN|$dn"] = [pscustomobject]@{ Kind = 'DOMAINDN'; Original = $dn; Pseudonym = $pdn }
        }
        { $_ -in 'DC', 'HOST' } {
            $short = ($v -split '\.')[0]
            $p = Get-SoaPseudonym -Anonymizer $Anonymizer -Kind $Kind -Original $short.ToLower()
            $Anonymizer.Terms[$short] = $p
            if ($v.Contains('.')) {
                $dom = $v.Substring($short.Length + 1)
                $pd = if ($Anonymizer.Terms.ContainsKey($dom)) { $Anonymizer.Terms[$dom] } else { Get-SoaPseudonym -Anonymizer $Anonymizer -Kind 'DOMAIN' -Original $dom }
                $Anonymizer.Terms[$v] = "$p.$pd"
            }
        }
        'GMSA' {
            $base = $v.TrimEnd('$')
            $p = Get-SoaPseudonym -Anonymizer $Anonymizer -Kind 'GMSA' -Original $base.ToLower()
            $Anonymizer.Terms["$base`$"] = "$p`$"
            $Anonymizer.Terms[$base] = $p
        }
        default {
            $Anonymizer.Terms[$v] = Get-SoaPseudonym -Anonymizer $Anonymizer -Kind $Kind -Original $v
        }
    }
    $Anonymizer.Compiled = $null
}

function ConvertTo-SoaAnonymizedText {
    param([Parameter(Mandatory)] $Anonymizer, [AllowNull()][AllowEmptyString()][string]$Text)
    if (-not $Text) { return $Text }
    $a = $Anonymizer
    $opt = [Text.RegularExpressions.RegexOptions]::IgnoreCase

    # 1. known terms, longest first, as whole tokens
    if (-not $a.Compiled -and $a.Terms.Count) {
        $keys = @($a.Terms.Keys | Sort-Object { $_.Length } -Descending | ForEach-Object { [regex]::Escape($_) })
        $a.Compiled = New-Object Text.RegularExpressions.Regex ('(?<![\w])(' + ($keys -join '|') + ')(?![\w])'), $opt
    }
    if ($a.Compiled) { $Text = $a.Compiled.Replace($Text, { param($m) $a.Terms[$m.Value] }) }

    # 2. DOMAIN\account - the NetBIOS name is already a pseudonym after step 1 (CORP / DOMAINn)
    #    (one or two backslashes: plain text and JSON)
    $Text = [regex]::Replace($Text, '(?<![\w\\])(CORP|DOMAIN\d+)(\\{1,2})([A-Za-z0-9._$-]{2,64})', {
        param($m)
        $pd = $m.Groups[1].Value; $sep = $m.Groups[2].Value; $acc = $m.Groups[3].Value
        if ($acc -match '^(user|account|gmsa|host|dc)\d' -or $a.KeepNames.ContainsKey($acc.TrimEnd('$').ToLower()) -or $a.KeepNames.ContainsKey($acc.ToLower())) { return $m.Value }
        $pa = if ($acc.EndsWith('$')) { (Get-SoaPseudonym -Anonymizer $a -Kind 'GMSA' -Original $acc.TrimEnd('$').ToLower()) + '$' } else { Get-SoaPseudonym -Anonymizer $a -Kind 'ACCOUNT' -Original $acc.ToLower() }
        "$pd$sep$pa"
    })

    # 3. CN= / OU= values of distinguished names
    $Text = [regex]::Replace($Text, '(?<![\w])(CN|OU)=((?:\\,|[^,=;"\r\n<>])+?)(?=,|;|"|\r|\n|<|>|$)', {
        param($m)
        $type = $m.Groups[1].Value; $val = $m.Groups[2].Value
        if ($a.KeepNames.ContainsKey($val.ToLower()) -or $val -match '^\{[0-9A-Fa-f-]{36}\}$' -or $val -match '^(user|object|group|gmsa|term|account|profile)\d{2,3}\$?$|^OU-\d{3}$|^(dc|host)\d{2}$') { return $m.Value }
        if ($val -match '^(ms-|ms[A-Z])' -or $val -match '^SOA-') { return $m.Value }
        $kind = if ($type -ieq 'OU') { 'OU' } else { 'CN' }
        "$type=$(Get-SoaPseudonym -Anonymizer $a -Kind $kind -Original $val)"
    }, $opt)

    # 4. domain SIDs (keep the RID), GUIDs, e-mail addresses, IPv4, user profile paths
    $Text = [regex]::Replace($Text, 'S-1-5-21-(\d{1,10})-(\d{1,10})-(\d{1,10})', {
        param($m) if ($m.Value -match '^S-1-5-21-\d000000000-0-0$') { return $m.Value }; Get-SoaPseudonym -Anonymizer $a -Kind 'SID' -Original $m.Value })
    $Text = [regex]::Replace($Text, '(?<![0-9A-Fa-f-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f-])', {
        param($m)
        $g = $m.Value.ToLower()
        if ($a.KeepGuids.ContainsKey($g) -or $g -like '00000000-0000-4000-8000-*' -or $g -eq '00000000-0000-0000-0000-000000000000') { return $m.Value }
        Get-SoaPseudonym -Anonymizer $a -Kind 'GUID' -Original $g })
    $Text = [regex]::Replace($Text, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', {
        param($m) if ($m.Value -match '@(corp|domain\d+)\.example$|@example\.invalid$') { return $m.Value }; Get-SoaPseudonym -Anonymizer $a -Kind 'MAIL' -Original $m.Value.ToLower() })
    $Text = [regex]::Replace($Text, '(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])', {
        param($m)
        $o = @(1..4 | ForEach-Object { [int]$m.Groups[$_].Value })
        if (@($o | Where-Object { $_ -gt 255 }).Count) { return $m.Value }                  # version numbers etc.
        if ($m.Value -match '^(127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.255|192\.0\.2\.\d+)$') { return $m.Value }
        if ($o[0] -le 1) { return $m.Value }                                                 # version numbers such as 1.0.1.0
        Get-SoaPseudonym -Anonymizer $a -Kind 'IP' -Original $m.Value })
    $Text = [regex]::Replace($Text, '(?i)([A-Z]:\\{1,2}Users\\{1,2})([^\\/\s"'']+)', {
        param($m) if ($m.Groups[2].Value -match '^(Public|Default|All Users|profile\d+|(user|account)\d{3})$') { return $m.Value }; $m.Groups[1].Value + (Get-SoaPseudonym -Anonymizer $a -Kind 'PROFILE' -Original $m.Groups[2].Value.ToLower()) })
    $Text
}

<#
    Loads the pseudonyms of earlier reports (cumulative map), so that the same original keeps the same pseudonym in
    every report created on this workstation. Entries: objects with Kind, Original, Pseudonym (Get-SoaAnonymizerMap).
#>
function Import-SoaAnonymizerMap {
    param([Parameter(Mandatory)] $Anonymizer, [object[]]$Entries)
    foreach ($e in @($Entries)) {
        if (-not $e -or -not "$($e.Kind)" -or -not "$($e.Original)") { continue }
        $kind = "$($e.Kind)"; $orig = "$($e.Original)"; $pseu = "$($e.Pseudonym)"
        if ($Anonymizer.Map.ContainsKey("$kind|$orig")) { continue }
        $Anonymizer.Map["$kind|$orig"] = [pscustomobject]@{ Kind = $kind; Original = $orig; Pseudonym = $pseu }
        if ($kind -ne 'DOMAINDN') { $Anonymizer.Counters[$kind] = 1 + [int]$Anonymizer.Counters[$kind] }
        if ($kind -in 'DOMAIN', 'DOMAINDN', 'NETBIOS', 'USER', 'GROUP', 'ACCOUNT', 'TERM', 'DC', 'HOST') { $Anonymizer.Terms[$orig] = $pseu }
        elseif ($kind -eq 'GMSA') { $Anonymizer.Terms[$orig] = $pseu; $Anonymizer.Terms["$orig`$"] = "$pseu`$" }
    }
    $Anonymizer.Compiled = $null
}

<#
    Reads a terms file (SoaToolkit.terms.txt): one term per line, '#' starts a comment line, empty lines are ignored.
    The same file serves Export-SoaReport.ps1 (terms to pseudonymize) and tools\Test-SoaRepoHygiene.ps1 (terms that
    must never appear in the repository).
#>
function Read-SoaTermsFile {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    foreach ($l in (Get-Content -LiteralPath $Path)) { $t = "$l".Trim(); if ($t -and -not $t.StartsWith('#')) { $t } }
}

function Get-SoaAnonymizerMap {
    param([Parameter(Mandatory)] $Anonymizer)
    @($Anonymizer.Map.Values | Sort-Object Kind, Pseudonym)
}

<#
    Leak check for a text that has been anonymized: every original value of the map must be gone, and no pattern of
    a real identifier may remain (domain SID, GUID outside the keep list, e-mail address, IPv4 address).
#>
function Find-SoaResidualIdentifier {
    param([Parameter(Mandatory)] $Anonymizer, [AllowEmptyString()][string]$Text, [object[]]$MapEntries)
    if (-not $Text) { return @() }
    $hits = New-Object System.Collections.Generic.List[object]
    $entries = if ($MapEntries) { $MapEntries } else { Get-SoaAnonymizerMap -Anonymizer $Anonymizer }
    foreach ($e in $entries) {
        $o = "$($e.Original)"
        if ($o.Length -lt 3 -or $e.Kind -in 'IP') { continue }
        if ($o -ieq "$($e.Pseudonym)" -or $o -match '^((user|account|gmsa|host|dc|term|object|group|profile)\d+\$?|OU-\d+)$') { continue }   # original was already a pseudonym
        if ($e.Kind -in 'OU', 'CN') {
            # generic words (e.g. 'Groups') are only a leak in a distinguished name
            if ([regex]::IsMatch($Text, '(?<![\w])(OU|CN)=' + [regex]::Escape($o) + '(?=,|"|$)', 'IgnoreCase')) { $hits.Add([pscustomobject]@{ Type = "known $($e.Kind)"; Value = $o }) }
            continue
        }
        if ([regex]::IsMatch($Text, '(?<![\w])' + [regex]::Escape($o) + '(?![\w])', 'IgnoreCase')) { $hits.Add([pscustomobject]@{ Type = "known $($e.Kind)"; Value = $o }) }
        elseif ($e.Kind -in 'DOMAIN', 'NETBIOS', 'TERM' -and $o.Length -ge 4 -and $Text.IndexOf($o, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hits.Add([pscustomobject]@{ Type = "embedded $($e.Kind) (check)"; Value = $o }) }
    }
    foreach ($m in [regex]::Matches($Text, 'S-1-5-21-\d{1,10}-\d{1,10}-\d{1,10}')) { if ($m.Value -notmatch '^S-1-5-21-\d000000000-0-0$') { $hits.Add([pscustomobject]@{ Type = 'domain SID'; Value = $m.Value }) } }
    foreach ($m in [regex]::Matches($Text, '(?<![0-9A-Fa-f-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f-])')) {
        $g = $m.Value.ToLower(); if (-not ($Anonymizer.KeepGuids.ContainsKey($g) -or $g -like '00000000-0000-4000-8000-*' -or $g -eq '00000000-0000-0000-0000-000000000000')) { $hits.Add([pscustomobject]@{ Type = 'GUID'; Value = $m.Value }) } }
    foreach ($m in [regex]::Matches($Text, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')) { if ($m.Value -notmatch '@(corp|domain\d+)\.example$|@example\.invalid$') { $hits.Add([pscustomobject]@{ Type = 'e-mail'; Value = $m.Value }) } }
    @($hits | Sort-Object Type, Value -Unique)
}
#endregion

function Invoke-SoaOnHost {
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][scriptblock]$ScriptBlock, [object[]]$ArgumentList = @())
    $local = Get-SoaLocalFqdn
    try {
        $r = if ($ComputerName.ToLower() -eq $local -or (Get-SoaShortName $ComputerName) -ieq $env:COMPUTERNAME) {
            & $ScriptBlock @ArgumentList
        } else {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
        }
        [pscustomobject]@{ Host = $ComputerName; Ok = $true; Result = $r; Error = $null }
    } catch {
        [pscustomobject]@{ Host = $ComputerName; Ok = $false; Result = $null; Error = $_.Exception.Message }
    }
}
#endregion

Export-ModuleMember -Function *-Soa*
