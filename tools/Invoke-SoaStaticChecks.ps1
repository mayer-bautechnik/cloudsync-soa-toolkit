#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Runs every check that needs no domain: parser, PSScriptAnalyzer, unit tests, security claims, repository hygiene.

.DESCRIPTION
    Used by the CI workflow (.github/workflows/ci.yml) and before every release (docs/RELEASING.md).
    PSScriptAnalyzer is used if installed (Install-Module PSScriptAnalyzer -Scope CurrentUser); otherwise skipped
    with a warning unless -RequireAnalyzer is set.
    Started from PowerShell 7 on Windows, the tests and the claims check run a second time under Windows PowerShell 5.1
    (powershell.exe), because the scheduled tasks use 5.1.

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.0.3 (2026-10-21)
    Exit code 0 = all checks passed.
#>
[CmdletBinding()]
param([switch] $RequireAnalyzer)
$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
$root = Split-Path $ScriptRoot -Parent
$results = [ordered]@{}
$ps = @(Get-ChildItem -LiteralPath $root -Recurse -File -Include *.ps1, *.psm1, *.psd1 | Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' })

# 1. Parser
$parseErrors = 0
foreach ($f in $ps) {
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
    foreach ($x in $e) { $parseErrors++; Write-Host ("  parse {0}:{1} {2}" -f $f.Name, $x.Extent.StartLineNumber, $x.Message) -ForegroundColor Red }
}
$results['Parser'] = ($parseErrors -eq 0)

# 2. PSScriptAnalyzer (Error and Warning; settings file of the repository; scripts and tools - tests are parsed only)
if (Get-Module -ListAvailable PSScriptAnalyzer) {
    Import-Module PSScriptAnalyzer
    $settings = Join-Path $root 'PSScriptAnalyzerSettings.psd1'
    $issues = @(foreach ($f in ($ps | Where-Object { $_.Extension -ne '.psd1' -and $_.FullName -notmatch '[\\/]tests[\\/]' })) { Invoke-ScriptAnalyzer -Path $f.FullName -Settings $settings -Severity Error, Warning })
    $blocking = @($issues | Where-Object { $_.RuleName -notin 'PSAvoidUsingEmptyCatchBlock', 'PSUseUsingScopeModifierInNewRunspaces' })
    foreach ($i in $blocking) { Write-Host ("  pssa {0}:{1} {2} {3}" -f $i.ScriptName, $i.Line, $i.RuleName, $i.Message) -ForegroundColor Red }
    Write-Host ("  PSScriptAnalyzer: {0} finding(s), {1} blocking (empty catch blocks and remote-scope hints are reviewed, not blocking)" -f $issues.Count, $blocking.Count)
    $results['PSScriptAnalyzer'] = ($blocking.Count -eq 0)
} elseif ($RequireAnalyzer) { Write-Host '  PSScriptAnalyzer not installed' -ForegroundColor Red; $results['PSScriptAnalyzer'] = $false }
else { Write-Warning 'PSScriptAnalyzer not installed - skipped'; $results['PSScriptAnalyzer'] = $true }

# 3-5. Unit tests, claims, hygiene (separate processes: clean scope, own exit code)
$exe = (Get-Process -Id $PID).Path
foreach ($s in @(@('Unit tests', (Join-Path (Join-Path $root 'tests') 'Invoke-SoaUnitTests.ps1')), @('Security claims', (Join-Path $ScriptRoot 'Test-SoaSecurityClaims.ps1')), @('Repository hygiene', (Join-Path $ScriptRoot 'Test-SoaRepoHygiene.ps1')))) {
    Write-Host ''; Write-Host "== $($s[0])" -ForegroundColor Cyan
    & $exe -NoProfile -ExecutionPolicy Bypass -File $s[1]
    $results[$s[0]] = ($LASTEXITCODE -eq 0)
}

# 6. Windows PowerShell 5.1 as well, when started from PowerShell 7 on Windows
$desktop = if ($env:SystemRoot) { Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' } else { $null }
if ($PSVersionTable.PSEdition -eq 'Core' -and $IsWindows -and $desktop -and (Test-Path -LiteralPath $desktop)) {
    foreach ($s in @(@('Unit tests (Windows PowerShell 5.1)', (Join-Path (Join-Path $root 'tests') 'Invoke-SoaUnitTests.ps1')), @('Security claims (Windows PowerShell 5.1)', (Join-Path $ScriptRoot 'Test-SoaSecurityClaims.ps1')))) {
        Write-Host ''; Write-Host "== $($s[0])" -ForegroundColor Cyan
        & $desktop -NoProfile -ExecutionPolicy Bypass -File $s[1]
        $results[$s[0]] = ($LASTEXITCODE -eq 0)
    }
} elseif ($PSVersionTable.PSEdition -ne 'Desktop') { Write-Host ''; Write-Host '  (Windows PowerShell 5.1 not available here - the CI job on Windows covers it)' -ForegroundColor DarkGray }

Write-Host ''
foreach ($k in $results.Keys) { Write-Host ("[{0}] {1}" -f $(if ($results[$k]) { 'PASS' } else { 'FAIL' }), $k) -ForegroundColor $(if ($results[$k]) { 'Green' } else { 'Red' }) }
exit $(if (@($results.Values | Where-Object { -not $_ }).Count) { 1 } else { 0 })
