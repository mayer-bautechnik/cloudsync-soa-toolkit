#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Writes the table of monitor checks (docs/CHECKS.md) from the check origin table in SoaToolkit.psm1.

.DESCRIPTION
    One Markdown table row per check of Watch-CloudUserConformance.ps1: where its target state comes from and how a
    FAIL / WARN is assessed (Get-SoaCheckAssessment). Without -Update the rows are written to the output; with -Update
    the table between the markers <!-- checks:begin --> and <!-- checks:end --> in docs/CHECKS.md is replaced.
    The hygiene check H7 fails when docs/CHECKS.md differs from this output.

.PARAMETER Update
    Replace the table in docs/CHECKS.md.

.EXAMPLE
    .\tools\Export-SoaCheckTable.ps1 -Update
#>
[CmdletBinding()]
param([switch] $Update)
$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
$root = Split-Path $ScriptRoot -Parent
Import-Module (Join-Path (Join-Path $root 'scripts') 'SoaToolkit.psm1') -DisableNameChecking -Force
$origin = Get-SoaConstant 'CheckOrigin'
$className = @{ Prereq = 'BLOCKER'; Review = 'REVIEW'; FollowUp = 'FOLLOW-UP' }
$rows = @(
    '| Check | Area | Target state from | FAIL / WARN is assessed as | What to do |'
    '|---|---|---|---|---|'
    foreach ($id in $origin.Keys) {
        $o = $origin[$id]
        $from = switch ($o.Kind) {
            'Step'     { 'install step ' + ((@($o.Steps) | ForEach-Object { '`' + $_ + '`' }) -join ' / ') + $(if ($o.Follow) { ', then: ' + $o.Follow } else { '' }) }
            'FollowUp' { 'after the installation' }
            'Prereq'   { 'outside the toolkit' }
            'Review'   { 'operation' }
            'Summary'  { 'summary of the user checks' }
            default    { '-' }
        }
        $class = switch ($o.Kind) {
            'Step'     { 'PLANNED if the step is part of the dry run, else ACTION' }
            'FollowUp' { 'FOLLOW-UP' }
            'Prereq'   { 'BLOCKER' }
            'Review'   { 'REVIEW' }
            'Summary'  { '-' }
            default    { '- (PASS / INFO only)' }
        }
        if ($o.FailKind) { $class += '; FAIL: ' + $className[$o.FailKind] }
        if ($o.WarnKind) { $class += '; WARN: ' + $className[$o.WarnKind] }
        $fix = @()
        if ($o.Fix) { $fix += $o.Fix }
        if ($o.WarnFix) { $fix += 'WARN: ' + $o.WarnFix }
        if ($o.FailFix) { $fix += 'FAIL: ' + $o.FailFix }
        '| `{0}` | {1} | {2} | {3} | {4} |' -f $id, $o.Area, $from, $class, ((($fix -join '; ') -replace '\|', '/') -replace '\\', '\\')
    }
)
$table = $rows -join "`n"
if (-not $Update) { return $table }
$doc = Join-Path (Join-Path $root 'docs') 'CHECKS.md'
$text = [IO.File]::ReadAllText($doc).Replace("`r`n", "`n")
$m = [regex]::Match($text, '(?s)<!-- checks:begin -->.*?<!-- checks:end -->')
if (-not $m.Success) { throw 'markers <!-- checks:begin --> / <!-- checks:end --> not found in docs/CHECKS.md' }
$new = $text.Substring(0, $m.Index) + "<!-- checks:begin -->`n" + $table + "`n<!-- checks:end -->" + $text.Substring($m.Index + $m.Length)
[IO.File]::WriteAllText($doc, $new, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "docs/CHECKS.md: $($origin.Count) check(s)" -ForegroundColor Green
