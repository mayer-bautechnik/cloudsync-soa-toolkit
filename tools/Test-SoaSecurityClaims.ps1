#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Static check of the security claims S1-S5 in SECURITY.md against the PowerShell code in scripts\.

.DESCRIPTION
    Parses every script with the PowerShell parser (no code is executed) and checks:
      S1  no secret material is requested: no password-history / supplemental-credential / gMSA / LAPS / BitLocker
          secret attributes, no unicodePwd in AD cmdlet calls, no replication / offline-database tooling
      S2  passwords are set only by the test paths (Test-SoaBehavior.ps1, Invoke-CloudUserConformance.ps1 -Mode Test),
          and both paths contain their TestUser guard
      S3  the production conformance path sets only SCRIL and clears only "password never expires"
      S5  no network download / upload, no dynamic code: Invoke-WebRequest / RestMethod, WebClient, HttpClient,
          sockets, BITS, Invoke-Expression, Add-Type, encoded commands, Base64 decoding
    and prints an inventory of every write operation (AD, ACL, GPO, scheduled task, registry, file system) for
    human or AI review.

    Comments and help text are not code and are not checked. This file itself is not scanned.

.PARAMETER Path
    Folder with the toolkit scripts (default: ..\scripts).

.PARAMETER Json
    Writes the result (claims + inventory) as JSON to this file.

.EXAMPLE
    .\tools\Test-SoaSecurityClaims.ps1
    .\tools\Test-SoaSecurityClaims.ps1 -Json .\claims.json

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.0.5 (2026-10-21)
    Exit code 0 = all claims hold, 1 = at least one violation.
#>
[CmdletBinding()]
param(
    [string] $Path,
    [string] $Json
)
$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
if (-not $Path) { $Path = Join-Path (Split-Path $ScriptRoot -Parent) 'scripts' }

$files = @(Get-ChildItem -LiteralPath $Path -File | Where-Object { $_.Extension -in '.ps1', '.psm1' } | Sort-Object Name)
$violations = New-Object System.Collections.Generic.List[object]
$inventory  = New-Object System.Collections.Generic.List[object]
$checked    = New-Object System.Collections.Generic.List[object]
function Add-Violation([string]$Claim, [string]$File, [int]$Line, [string]$Text) { $violations.Add([pscustomobject]@{ Claim = $Claim; File = $File; Line = $Line; Text = $Text.Trim() }) }

$secretAttrs = 'ntPwdHistory', 'lmPwdHistory', 'dBCSPwd', 'supplementalCredentials', 'msDS-ManagedPassword', 'ms-Mcs-AdmPwd', 'msLAPS-Password',
               'msLAPS-EncryptedPassword', 'msLAPS-EncryptedDSRMPassword', 'msFVE-RecoveryPassword', 'priorValue', 'currentValue', 'trustAuthIncoming', 'trustAuthOutgoing'
$secretRx    = '(?i)(?<![A-Za-z-])(' + (($secretAttrs | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?![A-Za-z])'
$toolingRx   = '(?i)(DSInternals|Get-ADReplAccount|Get-ADDBAccount|mimikatz|secretsdump|ntdsutil|vssadmin|esentutl|ntds\.dit|DRSGetNCChanges|\breg(\.exe)?\s+save\b)'
$netCommands = 'Invoke-WebRequest', 'Invoke-RestMethod', 'iwr', 'irm', 'curl', 'wget', 'Start-BitsTransfer', 'Invoke-Expression', 'iex', 'Add-Type',
               'New-WebServiceProxy', 'Send-MailMessage', 'Invoke-CimMethod'
$netTypesRx  = '(?i)^(System\.)?Net\.(WebClient|Http\.|Sockets\.|WebRequest|HttpWebRequest|FtpWebRequest)'
$writeRx     = '^(Set|New|Remove|Add|Move|Rename|Enable|Disable|Clear|Unregister|Register|Restore|Install|Uninstall)-(AD|Acl|GP|ScheduledTask|Item|ItemProperty|Content|SoaUacFlags|SoaAce|SoaGpo|SoaWmiFilter|SoaManifest|LocalGroupMember|Service|EventLog|WinEvent)|^(Set-Content|Add-Content|Out-File|Copy-Item|Remove-Item|Rename-Item|Set-Acl|icacls(\.exe)?|wevtutil(\.exe)?|secedit(\.exe)?|auditpol(\.exe)?|Compress-Archive)$'

foreach ($f in $files) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { Add-Violation 'PARSE' $f.Name $errors[0].Extent.StartLineNumber $errors[0].Message; continue }

    # S1 - secret attributes and tooling in any string / command / member name of the code
    $strings = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)
    foreach ($s in $strings) {
        $v = if ($s -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $s.Value } else { $s.Value }
        if ($v -match $secretRx) { Add-Violation 'S1' $f.Name $s.Extent.StartLineNumber "secret attribute '$($Matches[1])': $($s.Extent.Text)" }
        if ($v -match $toolingRx) { Add-Violation 'S1' $f.Name $s.Extent.StartLineNumber "credential tooling '$($Matches[1])': $($s.Extent.Text)" }
    }
    $commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in $commands) {
        $name = $c.GetCommandName()
        if (-not $name) { continue }
        if ($name -match $toolingRx) { Add-Violation 'S1' $f.Name $c.Extent.StartLineNumber "credential tooling: $name" }
        if ($name -like '*-AD*' -and $c.Extent.Text -match '(?i)unicodePwd') { Add-Violation 'S1' $f.Name $c.Extent.StartLineNumber "unicodePwd in an AD cmdlet call: $($c.Extent.Text)" }
        if ($netCommands -contains $name) { Add-Violation 'S5' $f.Name $c.Extent.StartLineNumber "network / dynamic code command: $name" }
        if ($c.Extent.Text -match '(?i)\s-(EncodedCommand|enc|e)\s+[A-Za-z0-9+/=]{16,}') { Add-Violation 'S5' $f.Name $c.Extent.StartLineNumber 'encoded command' }

        # S2 - password set only in the test paths
        if ($name -eq 'Set-ADAccountPassword' -or ($name -like 'Set-AD*' -and $c.Extent.Text -match '(?i)unicodePwd')) {
            $ok = $false
            if ($f.Name -eq 'Test-SoaBehavior.ps1') { $ok = $true }
            elseif ($f.Name -eq 'Invoke-CloudUserConformance.ps1') {
                $p = $c.Parent
                while ($p) { if ($p -is [System.Management.Automation.Language.IfStatementAst] -and $p.Clauses[0].Item1.Extent.Text -match "\`$Mode -eq 'Test'") { $ok = $true; break }; $p = $p.Parent }
            }
            if (-not $ok) { Add-Violation 'S2' $f.Name $c.Extent.StartLineNumber "password set outside the test paths: $($c.Extent.Text)" }
            else { $checked.Add([pscustomobject]@{ Claim = 'S2'; File = $f.Name; Line = $c.Extent.StartLineNumber; Text = 'password set in a test path (TestUser only)' }) }
        }

        # Inventory of write operations
        if ($name -match $writeRx) { $inventory.Add([pscustomobject]@{ File = $f.Name; Line = $c.Extent.StartLineNumber; Command = $name; Text = (($c.Extent.Text -replace '\s+', ' ').Substring(0, [Math]::Min(160, ($c.Extent.Text -replace '\s+', ' ').Length))) }) }
    }
    # S5 - .NET network types and Base64 decoding
    $types = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] -or $n -is [System.Management.Automation.Language.TypeConstraintAst] }, $true)
    foreach ($t in $types) { if ($t.TypeName.FullName -match $netTypesRx) { Add-Violation 'S5' $f.Name $t.Extent.StartLineNumber "network type [$($t.TypeName.FullName)]" } }
    foreach ($s in $strings) { if ($s.Value -match $netTypesRx -and $s.Parent -is [System.Management.Automation.Language.CommandParameterAst] -eq $false -and ($s.Parent.Extent.Text -match '(?i)New-Object')) { Add-Violation 'S5' $f.Name $s.Extent.StartLineNumber "New-Object $($s.Value)" } }
    $members = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)
    foreach ($m in $members) { if ("$($m.Member)" -match '^(FromBase64String|DownloadString|DownloadFile|UploadString|UploadFile|GetResponse)$') { Add-Violation 'S5' $f.Name $m.Extent.StartLineNumber "member $($m.Member)" } }
}

# S2 - guards present
$tsb = Join-Path $Path 'Test-SoaBehavior.ps1'; $icc = Join-Path $Path 'Invoke-CloudUserConformance.ps1'
if ((Test-Path $tsb) -and -not (Select-String -LiteralPath $tsb -Pattern 'only allowed on the configured TestUser' -SimpleMatch -Quiet)) { Add-Violation 'S2' 'Test-SoaBehavior.ps1' 0 'TestUser guard missing' }
if ((Test-Path $icc) -and -not (Select-String -LiteralPath $icc -Pattern 'Test actions are only allowed on the configured TestUser' -SimpleMatch -Quiet)) { Add-Violation 'S2' 'Invoke-CloudUserConformance.ps1' 0 'TestUser guard missing' }

# S3 - production conformance path: only SCRIL set, only PNE cleared
if (Test-Path $icc) {
    $t = Get-Content -LiteralPath $icc -Raw
    $setOk = $t -match [regex]::Escape('$set = if ($e.NeedScril) { $Uac.Scril } else { 0 }')
    $clrOk = $t -match [regex]::Escape('$clr = if ($e.NeedPneClear) { $Uac.DontExpire } else { 0 }')
    $calls = @([regex]::Matches($t, 'Set-SoaUacFlags[^\r\n]*') | ForEach-Object { $_.Value } | Where-Object { $_ -notmatch '\$Uac\.(Scril|DontExpire)' })
    if (-not ($setOk -and $clrOk) -or $calls.Count -ne 1) { Add-Violation 'S3' 'Invoke-CloudUserConformance.ps1' 0 'production userAccountControl change is not limited to SCRIL set / PNE clear' }
    else { $checked.Add([pscustomobject]@{ Claim = 'S3'; File = 'Invoke-CloudUserConformance.ps1'; Line = 0; Text = 'production path: SetBits = SCRIL or 0, ClearBits = PNE or 0' }) }
}

$claims = @(
    [pscustomobject]@{ Claim = 'S1'; Text = 'No password hash or secret attribute is requested; no replication or offline-database tooling' }
    [pscustomobject]@{ Claim = 'S2'; Text = 'Passwords are set only by the test paths, on the configured TestUser' }
    [pscustomobject]@{ Claim = 'S3'; Text = 'Production changes to userAccountControl: set SCRIL, clear "password never expires" - nothing else' }
    [pscustomobject]@{ Claim = 'S5'; Text = 'No network download / upload and no dynamic code execution' }
) | ForEach-Object { $c = $_; $v = @($violations | Where-Object { $_.Claim -eq $c.Claim }); $c | Add-Member -NotePropertyName Result -NotePropertyValue $(if ($v.Count) { 'FAIL' } else { 'PASS' }) -PassThru }

Write-Host ("Security claims - {0} file(s) in {1}" -f $files.Count, $Path) -ForegroundColor Cyan
foreach ($c in $claims) { Write-Host ("  [{0}] {1}  {2}" -f $c.Result, $c.Claim, $c.Text) -ForegroundColor $(if ($c.Result -eq 'PASS') { 'Green' } else { 'Red' }) }
foreach ($v in $violations) { Write-Host ("    {0} {1}:{2} {3}" -f $v.Claim, $v.File, $v.Line, $v.Text) -ForegroundColor Red }
foreach ($c in $checked) { Write-Host ("    ok {0} {1}:{2} {3}" -f $c.Claim, $c.File, $c.Line, $c.Text) -ForegroundColor DarkGray }
Write-Host ''
Write-Host ("Write operations (inventory for review): {0}" -f $inventory.Count) -ForegroundColor Cyan
foreach ($g in ($inventory | Group-Object File)) { Write-Host ("  {0,-34} {1}" -f $g.Name, (($g.Group | Group-Object Command | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ')) -ForegroundColor DarkGray }
if ($Json) { [pscustomobject]@{ Claims = $claims; Violations = $violations; Checked = $checked; WriteInventory = $inventory } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Json -Encoding UTF8 }
exit $(if ($violations.Count) { 1 } else { 0 })
