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
    H5  no term of SoaToolkit.terms.txt (top level of the repository; git-ignored, never published - the same file
        that Export-SoaReport.ps1 uses for pseudonyms: company names, mail / UPN domains, host names, sites ...).
        The former tools\forbidden-terms.local.txt is still read.
    Scanned are the files git would publish (git ls-files: tracked + new, not ignored); without git all files except
    the local ones (configuration, terms, maps, reports).
    H6  one version everywhere, as tools\Set-SoaVersion.ps1 sets it: SoaToolkit.psm1, the "Toolkit:" help line of
        every script in scripts\ (and of no file in tools\ or tests\ - they are not deployed), configuration header,
        README status, PDF keywords; CHANGELOG starts with '## Unreleased' and has '## <version> – <date>'; the
        release notes .github\release-notes\v<version>.md exist and contain no TODO-RELEASE-NOTES
    H7  every check of Watch-CloudUserConformance.ps1 is in the check origin table of SoaToolkit.psm1, and the table in
        docs/CHECKS.md is the one tools\Export-SoaCheckTable.ps1 writes from it

.PARAMETER Root
    Repository root (default: parent of tools\).

.NOTES
    Exit code 0 = clean, 1 = findings.
#>
[CmdletBinding()]
param([string] $Root)
$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
if (-not $Root) { $Root = Split-Path $ScriptRoot -Parent }
$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Id, [string]$File, [string]$Text) { $findings.Add([pscustomobject]@{ Id = $Id; File = $File; Text = $Text }) }

$textExt = '.ps1', '.psm1', '.psd1', '.md', '.html', '.yml', '.yaml', '.py', '.json', '.txt', '.csv', '.admx', '.adml', '.gitignore', '.gitattributes', '.svg'
$skipDirs = '\\.git\\|/\.git/|\\reports\\|/reports/|node_modules'
$localRx = '(^|[\\/])(SoaToolkit\.config\.psd1|SoaToolkit\.config\..+\.psd1|[^\\/]*\.terms\.txt|forbidden-terms[^\\/]*\.txt|[^\\/]*\.local\.[^\\/]+|[^\\/]*\.map\.csv|pseudonyms\.csv)$'
$candidates = $null
$git = Get-Command git -ErrorAction SilentlyContinue
if ($git -and (Test-Path -LiteralPath (Join-Path $Root '.git'))) {
    $list = @(& git -C $Root ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -eq 0) { $candidates = @($list | ForEach-Object { Get-Item -LiteralPath (Join-Path $Root $_) -Force -ErrorAction SilentlyContinue } | Where-Object { $_ }) }
}
if ($null -eq $candidates) { $candidates = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force | Where-Object { $_.FullName -notmatch $skipDirs }) }
$files = @($candidates | Where-Object {
    ($textExt -contains $_.Extension.ToLower() -or $_.Name -in '.gitignore', '.gitattributes', 'LICENSE', 'CODEOWNERS', 'allowed_signers') -and
    ($_.Name -match '\.example\.' -or $_.FullName.Substring($Root.Length) -notmatch $localRx) })
$termFiles = @((Join-Path $Root 'SoaToolkit.terms.txt'), (Join-Path $ScriptRoot 'forbidden-terms.local.txt')) | Where-Object { Test-Path -LiteralPath $_ }
Import-Module (Join-Path (Join-Path $Root 'scripts') 'SoaToolkit.psm1') -Force -DisableNameChecking
$forbidden = @(foreach ($tf in $termFiles) { Read-SoaTermsFile -Path $tf }) | Select-Object -Unique
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
    foreach ($t in $forbidden) { if ($text.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) { Add-Finding 'H5' $rel "term from SoaToolkit.terms.txt ('$($t.Substring(0,1))...')" } }
}

# H6 - version consistency
$psm = Join-Path (Join-Path $Root 'scripts') 'SoaToolkit.psm1'
if (Test-Path -LiteralPath $psm) {
    $v = if ((Get-Content -LiteralPath $psm -Raw) -match "\`$script:SoaVersion\s*=\s*'([^']+)'") { $Matches[1] } else { $null }
    $d = if ((Get-Content -LiteralPath $psm -Raw) -match "\`$script:SoaReleaseDate\s*=\s*'([^']+)'") { $Matches[1] } else { $null }
    foreach ($s in @(Get-ChildItem -LiteralPath (Join-Path $Root 'scripts') -Filter '*.ps1') + @(Get-ChildItem -LiteralPath (Join-Path $Root 'tools') -Filter '*.ps1') + @(Get-ChildItem -LiteralPath (Join-Path $Root 'tests') -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        $t = Get-Content -LiteralPath $s.FullName -Raw
        $deployed = ((Split-Path $s.DirectoryName -Leaf) -eq 'scripts')
        if ($t -match 'Toolkit: cloudsync-soa-toolkit (\S+) \((\d{4}-\d{2}-\d{2})\)') {
            if (-not $deployed) { Add-Finding 'H6' $s.Name 'version line in a file that is not deployed - only scripts\ carry it (remove the line)' }
            elseif ($Matches[1] -ne $v -or $Matches[2] -ne $d) { Add-Finding 'H6' $s.Name "help says $($Matches[1]) ($($Matches[2])), module says $v ($d) - tools\Set-SoaVersion.ps1" }
        }
        elseif ($deployed) { Add-Finding 'H6' $s.Name 'no "Toolkit: cloudsync-soa-toolkit <version> (<date>)" line in the help' }
    }
    $cfgFile = Join-Path $Root 'SoaToolkit.config.example.psd1'
    if ((Get-Content -LiteralPath $cfgFile -Raw) -notmatch "cloudsync-soa-toolkit $([regex]::Escape($v))\)") { Add-Finding 'H6' 'SoaToolkit.config.example.psd1' "header does not name version $v" }
    if ((Get-Content -LiteralPath (Join-Path $Root 'README.md') -Raw) -notmatch "Status: $([regex]::Escape($v)) \($d\)") { Add-Finding 'H6' 'README.md' "status line does not say $v ($d)" }
    $changelog = Get-Content -LiteralPath (Join-Path $Root 'CHANGELOG.md') -Raw -Encoding UTF8
    $firstSection = [regex]::Match($changelog, '(?m)^## .*$').Value.Trim()
    if ($firstSection -ne '## Unreleased') { Add-Finding 'H6' 'CHANGELOG.md' "first section is '$firstSection' - it must be '## Unreleased' (new entries go there; tools\Set-SoaVersion.ps1 turns them into the version section)" }
    if ($changelog -notmatch ("(?m)^## $([regex]::Escape($v)) " + [char]0x2013 + " $([regex]::Escape($d))\s*$")) { Add-Finding 'H6' 'CHANGELOG.md' "no section '## $v – $d'" }
    $notesFile = Join-Path (Join-Path (Join-Path $Root '.github') 'release-notes') "v$v.md"
    if (-not (Test-Path -LiteralPath $notesFile)) { Add-Finding 'H6' "v$v.md" 'release notes of the current version missing in .github\release-notes' }
    elseif ((Get-Content -LiteralPath $notesFile -Raw -Encoding UTF8) -match 'TODO-RELEASE-NOTES') { Add-Finding 'H6' "v$v.md" 'release notes still contain TODO-RELEASE-NOTES' }
    $pdfFile = Join-Path (Join-Path $Root 'docs') 'Consolidated-Findings.pdf'
    if ((Test-Path -LiteralPath $pdfFile) -and -not ([Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($pdfFile)).Contains("cloudsync-soa-toolkit-version=$v release-date=$d"))) {
        Add-Finding 'H6' 'Consolidated-Findings.pdf' "PDF keywords do not say version $v ($d) - python docs/src/build_findings_pdf.py (tools\Set-SoaVersion.ps1 does it)"
    }
}

# H7 - monitor checks documented
$watchFile = Join-Path (Join-Path $Root 'scripts') 'Watch-CloudUserConformance.ps1'
$checksDoc = Join-Path (Join-Path $Root 'docs') 'CHECKS.md'
$exporter  = Join-Path (Join-Path $Root 'tools') 'Export-SoaCheckTable.ps1'
if ((Test-Path -LiteralPath $watchFile) -and (Test-Path -LiteralPath $exporter)) {
    Import-Module (Join-Path (Join-Path $Root 'scripts') 'SoaToolkit.psm1') -DisableNameChecking -Force
    $origin = Get-SoaConstant 'CheckOrigin'
    $wt = Get-Content -LiteralPath $watchFile -Raw
    $ids = @(@([regex]::Matches($wt, "Add-Result '([A-Z][A-Z0-9-]+)'") | ForEach-Object { $_.Groups[1].Value }) + @([regex]::Matches($wt, "'(USR-[A-Z][A-Z0-9-]*)'") | ForEach-Object { $_.Groups[1].Value }) +
             @([regex]::Matches($wt, '"([A-Z]+-KERB-)\$\(') | ForEach-Object { $_.Groups[1].Value + '*' }) | Sort-Object -Unique)
    foreach ($id in $ids) { if (-not $origin.Contains($id)) { Add-Finding 'H7' 'Watch-CloudUserConformance.ps1' "check $id is not in the check origin table (SoaToolkit.psm1)" } }
    $want = (& $exporter) -join "`n"
    $docText = if (Test-Path -LiteralPath $checksDoc) { [IO.File]::ReadAllText($checksDoc).Replace("`r`n", "`n") } else { '' }
    $m = [regex]::Match($docText, '(?s)<!-- checks:begin -->\n(.*?)\n<!-- checks:end -->')
    if (-not $m.Success) { Add-Finding 'H7' 'CHECKS.md' 'table markers missing' }
    elseif ($m.Groups[1].Value -cne $want) { Add-Finding 'H7' 'CHECKS.md' 'table differs from the check origin table - .\tools\Export-SoaCheckTable.ps1 -Update' }
}

Write-Host ("Repository hygiene - {0} text file(s), {1} term(s) from SoaToolkit.terms.txt" -f $files.Count, $forbidden.Count) -ForegroundColor Cyan
if (-not $forbidden.Count) { Write-Host '  (no SoaToolkit.terms.txt at the top level - H5 checks nothing; create it from SoaToolkit.terms.example.txt, it is git-ignored)' -ForegroundColor DarkGray }
foreach ($id in 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'H7') {
    $x = @($findings | Where-Object { $_.Id -eq $id })
    Write-Host ("  [{0}] {1}" -f $(if ($x.Count) { 'FAIL' } else { 'PASS' }), $id) -ForegroundColor $(if ($x.Count) { 'Red' } else { 'Green' })
    foreach ($y in $x) { Write-Host ("      {0}: {1}" -f $y.File, $y.Text) -ForegroundColor Red }
}
exit $(if ($findings.Count) { 1 } else { 0 })
