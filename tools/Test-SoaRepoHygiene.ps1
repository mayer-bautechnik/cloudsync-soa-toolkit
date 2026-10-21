#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Repository hygiene: hidden characters, encodings / line endings, license headers, e-mail addresses,
    locally forbidden terms and version consistency.

.DESCRIPTION
    H1  no invisible or bidirectional control characters ("Trojan Source", CVE-2021-42574) in any text file
    H2  PowerShell files: UTF-8 with BOM and CRLF; Markdown / HTML / YAML / Python: LF
    H3  MPL-2.0 header with copyright line and repository link in every source file (ps1, psm1, psd1, py, html, yml)
    H4  no e-mail addresses (except placeholders such as *@example.* / *.invalid / users.noreply.github.com)
    H5  no term of tools\forbidden-terms.local.txt (one term per line; the file is git-ignored and never published -
        put company domains, internal host names etc. there)
    H6  one version everywhere: SoaToolkit.psm1, script .NOTES, configuration header, README status, CHANGELOG

.PARAMETER Root
    Repository root (default: parent of tools\).

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.0.2 (2026-10-21)
    Exit code 0 = clean, 1 = findings.
#>
[CmdletBinding()]
param([string] $Root = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference = 'Stop'
$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Id, [string]$File, [string]$Text) { $findings.Add([pscustomobject]@{ Id = $Id; File = $File; Text = $Text }) }

$textExt = '.ps1', '.psm1', '.psd1', '.md', '.html', '.yml', '.yaml', '.py', '.json', '.txt', '.csv', '.admx', '.adml', '.gitignore', '.gitattributes', '.svg'
$skipDirs = '\\.git\\|/\.git/|\\reports\\|/reports/|node_modules'
$files = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force | Where-Object {
    $_.FullName -notmatch $skipDirs -and ($textExt -contains $_.Extension.ToLower() -or $_.Name -in '.gitignore', '.gitattributes', 'LICENSE', 'CODEOWNERS', 'allowed_signers') -and $_.Name -ne 'forbidden-terms.local.txt' })
$forbiddenFile = Join-Path $PSScriptRoot 'forbidden-terms.local.txt'
$forbidden = @(if (Test-Path -LiteralPath $forbiddenFile) { Get-Content -LiteralPath $forbiddenFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') } })
$hidden = '[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\u00AD\uFEFF]'
$mailRx = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
$mailOk = '@(example\.(com|org|net)|[a-z0-9.-]*\.example|example\.invalid|contoso\.com|fabrikam\.com|users\.noreply\.github\.com|anthropic\.com)$'

foreach ($f in $files) {
    $rel = $f.FullName.Substring($Root.Length).TrimStart('\', '/')
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if ($hasBom) { $text = $text.Substring(1) }
    # H1
    $m = [regex]::Matches($text, $hidden)
    if ($m.Count) { Add-Finding 'H1' $rel ("{0} hidden / bidi character(s), first U+{1:X4} at offset {2}" -f $m.Count, [int][char]$m[0].Value, $m[0].Index) }
    # H2
    $crlf = ([regex]::Matches($text, "`r`n")).Count; $lf = ([regex]::Matches($text, "(?<!`r)`n")).Count
    if ($f.Extension -in '.ps1', '.psm1', '.psd1') {
        if (-not $hasBom) { Add-Finding 'H2' $rel 'PowerShell file without UTF-8 BOM' }
        if ($lf) { Add-Finding 'H2' $rel "PowerShell file with $lf LF-only line ending(s)" }
    } elseif ($f.Extension -in '.md', '.html', '.yml', '.yaml', '.py' -and $crlf) { Add-Finding 'H2' $rel "$crlf CRLF line ending(s) (expected LF)" }
    # H3
    if ($f.Extension -in '.ps1', '.psm1', '.psd1', '.py', '.html', '.yml', '.yaml' -and $f.Name -ne 'PSScriptAnalyzerSettings.psd1') {
        $head = ($text -split "`n" | Select-Object -First 14) -join "`n"
        if ($head -notmatch 'Mozilla Public License, v\. 2\.0' -or $head -notmatch 'Copyright \(c\) 20\d\d GEBR\. MAYER GmbH \+ Co\. KG and Johannes L' -or $head -notmatch 'github\.com/mayer-bautechnik/cloudsync-soa-toolkit') { Add-Finding 'H3' $rel 'MPL-2.0 header incomplete (license, copyright, repository link)' }
    }
    # H4
    foreach ($x in [regex]::Matches($text, $mailRx)) { if ($x.Value -notmatch $mailOk) { Add-Finding 'H4' $rel "e-mail address '$($x.Value)'" } }
    # H5
    foreach ($t in $forbidden) { if ($text.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) { Add-Finding 'H5' $rel "forbidden term (tools\forbidden-terms.local.txt line '$($t.Substring(0,1))...')" } }
}

# H6 - version consistency
$psm = Join-Path $Root 'scripts\SoaToolkit.psm1'
if (Test-Path -LiteralPath $psm) {
    $v = if ((Get-Content -LiteralPath $psm -Raw) -match "\`$script:SoaVersion\s*=\s*'([^']+)'") { $Matches[1] } else { $null }
    $d = if ((Get-Content -LiteralPath $psm -Raw) -match "\`$script:SoaReleaseDate\s*=\s*'([^']+)'") { $Matches[1] } else { $null }
    foreach ($s in @(Get-ChildItem -LiteralPath (Join-Path $Root 'scripts') -Filter '*.ps1') + @(Get-ChildItem -LiteralPath (Join-Path $Root 'tools') -Filter '*.ps1') + @(Get-ChildItem -LiteralPath (Join-Path $Root 'tests') -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        $t = Get-Content -LiteralPath $s.FullName -Raw
        if ($t -match 'Toolkit: cloudsync-soa-toolkit (\S+) \((\d{4}-\d{2}-\d{2})\)') { if ($Matches[1] -ne $v -or $Matches[2] -ne $d) { Add-Finding 'H6' $s.Name "help says $($Matches[1]) ($($Matches[2])), module says $v ($d)" } }
        elseif ($s.DirectoryName -like '*scripts') { Add-Finding 'H6' $s.Name 'no "Toolkit: cloudsync-soa-toolkit <version> (<date>)" line in the help' }
    }
    $cfgFile = Join-Path $Root 'scripts\SoaToolkit.config.psd1'
    if ((Get-Content -LiteralPath $cfgFile -Raw) -notmatch "cloudsync-soa-toolkit $([regex]::Escape($v))\)") { Add-Finding 'H6' 'SoaToolkit.config.psd1' "header does not name version $v" }
    if ((Get-Content -LiteralPath (Join-Path $Root 'README.md') -Raw) -notmatch "Status: $([regex]::Escape($v)) \($d\)") { Add-Finding 'H6' 'README.md' "status line does not say $v ($d)" }
    if ((Get-Content -LiteralPath (Join-Path $Root 'CHANGELOG.md') -Raw) -notmatch "(?m)^## $([regex]::Escape($v)) ") { Add-Finding 'H6' 'CHANGELOG.md' "no entry for $v" }
}

Write-Host ("Repository hygiene - {0} text file(s), {1} local forbidden term(s)" -f $files.Count, $forbidden.Count) -ForegroundColor Cyan
if (-not $forbidden.Count) { Write-Host '  (no tools\forbidden-terms.local.txt - H5 checks nothing; create it locally, it is git-ignored)' -ForegroundColor DarkGray }
foreach ($id in 'H1', 'H2', 'H3', 'H4', 'H5', 'H6') {
    $x = @($findings | Where-Object { $_.Id -eq $id })
    Write-Host ("  [{0}] {1}" -f $(if ($x.Count) { 'FAIL' } else { 'PASS' }), $id) -ForegroundColor $(if ($x.Count) { 'Red' } else { 'Green' })
    foreach ($y in $x) { Write-Host ("      {0}: {1}" -f $y.File, $y.Text) -ForegroundColor Red }
}
exit $(if ($findings.Count) { 1 } else { 0 })
