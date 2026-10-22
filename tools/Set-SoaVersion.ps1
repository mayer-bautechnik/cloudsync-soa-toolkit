#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Prepares the release commit: sets the version everywhere, turns '## Unreleased' into the version section of the
    CHANGELOG and rebuilds the PDF. The only supported way to change the version (docs/RELEASING.md, phase 2).

.DESCRIPTION
    1. Refuses a version that is lower than the current one, and a version that already exists as a tag (local or on
       origin) or as a GitHub release, including drafts. A version that has been published is never changed; fix
       forward with the next version. -SkipRemoteCheck skips the check against origin / GitHub (offline preparation);
       the check must then run before the tag, by running this script again without the switch.
    2. Sets $script:SoaVersion / $script:SoaReleaseDate in scripts\SoaToolkit.psm1, the "Toolkit:" line in the help of
       every script in scripts\, the header of SoaToolkit.config.example.psd1 and the README status line.
    3. CHANGELOG.md: moves the entries under '## Unreleased' into '## <version> – <date>' and leaves an empty
       '## Unreleased' above it. Refuses if '## Unreleased' is empty (nothing to release).
    4. Creates .github\release-notes\v<version>.md from a template if it does not exist yet. The template contains the
       marker TODO-RELEASE-NOTES; the hygiene check H6 fails until the notes are written. The first line carries the
       release title as an HTML comment: <!-- title: v<version> – <summary> -->.
    5. Rebuilds docs\Consolidated-Findings.pdf (Python 3 with reportlab) if its version stamp differs (-SkipPdf: later).
    6. Runs tools\Invoke-SoaStaticChecks.ps1 (-SkipChecks: not) and stages the changed files with git add (-NoStage:
       not). It never commits, tags or pushes.

    Running it again with the same version is safe: on a tree that is already prepared it changes nothing (with -Date
    only the date) and repeats the checks - for example on a release commit that was prepared elsewhere.

.PARAMETER Version
    New version, x.y.z (Semantic Versioning: patch for fixes, minor for new features, major for breaking changes).

.PARAMETER Date
    Release date, yyyy-MM-dd. Default: today.

.PARAMETER SkipRemoteCheck
    Do not ask origin and GitHub whether the version exists already (offline preparation).

.PARAMETER NoStage
    Do not run git add.

.PARAMETER SkipPdf
    Do not rebuild the PDF (H6 reports it until it is rebuilt).

.PARAMETER SkipChecks
    Do not run Invoke-SoaStaticChecks.ps1.

.PARAMETER Root
    Repository root (default: parent of tools\).

.EXAMPLE
    .\tools\Set-SoaVersion.ps1 -Version 2.0.8
    .\tools\Set-SoaVersion.ps1 -Version 2.0.8 -WhatIf      # shows what would change

.NOTES
    Exit code 0 = prepared or nothing to change, 1 = refused or failed.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')] [string] $Version,
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')] [string] $Date,
    [switch] $SkipRemoteCheck,
    [switch] $NoStage,
    [switch] $SkipPdf,
    [switch] $SkipChecks,
    [string] $Root
)
$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
if (-not $Root) { $Root = Split-Path $ScriptRoot -Parent }
if (-not $Date) { $Date = Get-Date -Format 'yyyy-MM-dd' }
$Cmdlet = $PSCmdlet
$tag = "v$Version"
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Stop-Release([string]$Message) { Write-Host "[FAIL] $Message" -ForegroundColor Red; exit 1 }
function Read-TextFile([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $bom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $skip = if ($bom) { 3 } else { 0 }
    $text = $utf8.GetString($bytes, $skip, $bytes.Length - $skip)
    [pscustomobject]@{ Path = $Path; Bom = $bom; Text = $text; Original = $text; Nl = $(if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }) }
}
$changed = New-Object System.Collections.Generic.List[string]
function Save-TextFile {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param($File)
    if ($File.Text -ceq $File.Original) { return }
    $rel = $File.Path.Substring($Root.Length).TrimStart('\', '/')
    if ($PSCmdlet.ShouldProcess($rel, "Set version $Version ($Date)")) {
        [IO.File]::WriteAllText($File.Path, $File.Text, (New-Object System.Text.UTF8Encoding($File.Bom)))
        Write-Host "  + $rel" -ForegroundColor Green
    }
    $changed.Add($File.Path)
}
function Invoke-Git([string[]]$Arguments) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'   # Windows PowerShell 5.1: stderr of git must not stop the script
    try { $out = & git -C $Root @Arguments 2>&1 } finally { $ErrorActionPreference = $prev }
    [pscustomobject]@{ Code = $LASTEXITCODE; Out = @($out | ForEach-Object { "$_" }) }
}

# --- Current state ----------------------------------------------------------------------------------
$psmPath = Join-Path (Join-Path $Root 'scripts') 'SoaToolkit.psm1'
$psm = Read-TextFile $psmPath
if ($psm.Text -notmatch "\`$script:SoaVersion\s*=\s*'([^']+)'") { Stop-Release 'version not found in scripts\SoaToolkit.psm1' }
$current = $Matches[1]
if ($psm.Text -notmatch "\`$script:SoaReleaseDate\s*=\s*'([^']+)'") { Stop-Release 'release date not found in scripts\SoaToolkit.psm1' }
$currentDate = $Matches[1]
$same = ([version]$Version -eq [version]$current)
if ([version]$Version -lt [version]$current) { Stop-Release "version $Version is lower than the current version $current" }
Write-Host ("Set-SoaVersion: {0} ({1}) -> {2} ({3}){4}" -f $current, $currentDate, $Version, $Date, $(if ($same) { ' - same version: repeat / date only' } else { '' })) -ForegroundColor Cyan

# --- 1. Does the version exist already? ----------------------------------------------------------------
$git = Get-Command git -ErrorAction SilentlyContinue
if ($git -and (Invoke-Git @('rev-parse', '--is-inside-work-tree')).Code -eq 0) {
    if ((Invoke-Git @('tag', '--list', $tag)).Out -contains $tag) { Stop-Release "tag $tag exists locally - if it was not pushed and no release uses it: git tag -d $tag" }
    $dirty = @((Invoke-Git @('status', '--porcelain')).Out | Where-Object { $_ })
    if ($dirty.Count) { Write-Host ("  ({0} uncommitted path(s) in the working copy - they will be part of the release commit if you commit them)" -f $dirty.Count) -ForegroundColor DarkGray }
} elseif (-not $SkipRemoteCheck) { Stop-Release 'not a git work tree (or git not found) - the remote check needs git; use -SkipRemoteCheck for an offline preparation' }
if ($SkipRemoteCheck) {
    Write-Host "[WARN] remote check skipped - run this script again without -SkipRemoteCheck before you create the tag" -ForegroundColor Yellow
} else {
    $remote = Invoke-Git @('ls-remote', '--tags', 'origin', "refs/tags/$tag")
    if ($remote.Code -ne 0) { Stop-Release ("git ls-remote origin failed: {0}" -f ($remote.Out -join ' ')) }
    if (@($remote.Out | Where-Object { $_ }).Count) { Stop-Release "tag $tag exists on origin - this version is released or being released; use the next version" }
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $gh) { Stop-Release 'GitHub CLI (gh) not found - install it and run gh auth login (a draft release can exist without a pushed tag), or use -SkipRemoteCheck and check the releases page yourself' }
    Push-Location $Root
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $relJson = & gh release list --limit 200 --json tagName,isDraft 2>&1; $relCode = $LASTEXITCODE } finally { $ErrorActionPreference = $prev; Pop-Location }
    if ($relCode -ne 0) { Stop-Release ("gh release list failed (gh auth login?): {0}" -f ($relJson -join ' ')) }
    $existing = @(($relJson -join "`n") | ConvertFrom-Json | ForEach-Object { $_ } | Where-Object { $_.tagName -eq $tag })
    if ($existing.Count) { Stop-Release ("a GitHub release for {0} exists ({1}) - use the next version, or delete the draft if it was never published" -f $tag, $(if ($existing[0].isDraft) { 'draft' } else { 'published' })) }
    Write-Host "[PASS] $tag is neither tagged on origin nor released on GitHub" -ForegroundColor Green
}

# --- 2. Version and date in code and docs ----------------------------------------------------------------
$psm.Text = $psm.Text -replace "(\`$script:SoaVersion\s*=\s*')[^']+'", "`${1}$Version'"
$psm.Text = $psm.Text -replace "(\`$script:SoaReleaseDate\s*=\s*')[^']+'", "`${1}$Date'"
Save-TextFile $psm
foreach ($s in @(Get-ChildItem -LiteralPath (Join-Path $Root 'scripts') -Filter '*.ps1' -File | Sort-Object Name)) {
    $f = Read-TextFile $s.FullName
    $f.Text = $f.Text -replace 'Toolkit: cloudsync-soa-toolkit \S+ \(\d{4}-\d{2}-\d{2}\)', "Toolkit: cloudsync-soa-toolkit $Version ($Date)"
    Save-TextFile $f
}
$f = Read-TextFile (Join-Path $Root 'SoaToolkit.config.example.psd1')
$f.Text = $f.Text -replace '\(cloudsync-soa-toolkit [0-9][^)\s]*\)', "(cloudsync-soa-toolkit $Version)"
Save-TextFile $f
$f = Read-TextFile (Join-Path $Root 'README.md')
$f.Text = $f.Text -replace 'Status: [0-9][^ ]* \(\d{4}-\d{2}-\d{2}\)', "Status: $Version ($Date)"
Save-TextFile $f

# --- 3. CHANGELOG --------------------------------------------------------------------------------------
$cl = Read-TextFile (Join-Path $Root 'CHANGELOG.md')
$nl = $cl.Nl
$m = [regex]::Match($cl.Text, '(?ms)^## Unreleased[ \t]*\r?\n(.*?)(?=^## |\z)')
if (-not $m.Success) { Stop-Release "CHANGELOG.md has no '## Unreleased' section" }
$body = $m.Groups[1].Value.Trim()
$versionHeading = '(?m)^## ' + [regex]::Escape($Version) + ' – (\d{4}-\d{2}-\d{2})[ \t]*$'
if ([regex]::IsMatch($cl.Text, $versionHeading)) {
    if (-not $same) { Stop-Release "CHANGELOG.md already has a section $Version" }
    $cl.Text = [regex]::Replace($cl.Text, $versionHeading, "## $Version – $Date")
    if ($body) { Write-Host "[WARN] entries under '## Unreleased' are not part of $Version (they stay there for the next version)" -ForegroundColor Yellow }
} else {
    if (-not $body) { Stop-Release "nothing under '## Unreleased' in CHANGELOG.md - write the entries first" }
    $cl.Text = $cl.Text.Substring(0, $m.Index) + "## Unreleased$nl$nl## $Version – $Date$nl$nl$body$nl$nl" + $cl.Text.Substring($m.Index + $m.Length)
}
Save-TextFile $cl

# --- 4. Release notes ------------------------------------------------------------------------------------
$notesPath = Join-Path (Join-Path (Join-Path $Root '.github') 'release-notes') "$tag.md"
if (Test-Path -LiteralPath $notesPath) {
    $n = Read-TextFile $notesPath
    if ($n.Text -notmatch '^<!-- title: .+ -->') { Write-Host "[WARN] $tag.md: first line is not '<!-- title: $tag – <summary> -->' - the release workflow needs it" -ForegroundColor Yellow }
    if ($n.Text -match 'TODO-RELEASE-NOTES') { Write-Host "[WARN] $tag.md still contains TODO-RELEASE-NOTES" -ForegroundColor Yellow }
} else {
    $prev = Join-Path (Split-Path $notesPath -Parent) "v$current.md"
    $footer = if (Test-Path -LiteralPath $prev) { ((Read-TextFile $prev).Text -split '\r?\n' | Where-Object { $_ -like 'Licensed under MPL-2.0*' } | Select-Object -Last 1) -replace "/blob/v$([regex]::Escape($current))/", "/blob/$tag/" } else { '' }
    $repo = 'https://github.com/mayer-bautechnik/cloudsync-soa-toolkit'
    $template = @(
        "<!-- title: $tag – TODO-RELEASE-NOTES summary, at most about 60 characters -->"
        '**TODO-RELEASE-NOTES: what this release brings, in one or two sentences.**'
        ''
        "TODO-RELEASE-NOTES: write the sections below from the CHANGELOG section $Version. Keep what applies, remove the rest."
        ''
        '## Fixed'
        ''
        '## Changed'
        ''
        '## New'
        ''
        "## Upgrade from $current"
        ''
        '1. Replace the toolkit files and keep your `SoaToolkit.config.psd1`.'
        '2. Run `.\Install-SoaToolkit.ps1 -Step All -WhatIf`, then without `-WhatIf`.'
        ''
        "Details: [CHANGELOG]($repo/blob/$tag/CHANGELOG.md)"
        ''
        '## Verify the download'
        ''
        'Compare the SHA-256 of the asset with the digest GitHub shows next to it. The zip contains `SHA256SUMS.txt` for every file:'
        ''
        '```powershell'
        "Get-FileHash .\cloudsync-soa-toolkit-$Version.zip -Algorithm SHA256"
        'Get-ChildItem -Recurse | Unblock-File'
        '```'
        ''
        "**Full changelog:** $repo/compare/v$current...$tag"
        ''
        '---'
        ''
        $footer
    )
    if ($Cmdlet.ShouldProcess(".github/release-notes/$tag.md", 'Create release notes template')) {
        [IO.File]::WriteAllText($notesPath, (($template -join "`n").TrimEnd() + "`n"), $utf8)
        Write-Host "  + .github/release-notes/$tag.md (template - write the notes, the TODO-RELEASE-NOTES markers make H6 fail)" -ForegroundColor Yellow
    }
    $changed.Add($notesPath)
}

# --- 5. PDF ------------------------------------------------------------------------------------------------
$pdf = Join-Path (Join-Path $Root 'docs') 'Consolidated-Findings.pdf'
$stamp = "cloudsync-soa-toolkit-version=$Version release-date=$Date"
$pdfOk = (Test-Path -LiteralPath $pdf) -and ([Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($pdf)).Contains($stamp))
if ($pdfOk) { Write-Host '  = docs/Consolidated-Findings.pdf (stamp current)' -ForegroundColor DarkGray }
elseif ($SkipPdf) { Write-Host '[WARN] PDF not rebuilt (-SkipPdf) - H6 fails until: python docs/src/build_findings_pdf.py' -ForegroundColor Yellow }
elseif ($Cmdlet.ShouldProcess('docs/Consolidated-Findings.pdf', 'Rebuild (python docs/src/build_findings_pdf.py)')) {
    $candidates = if ($env:OS -eq 'Windows_NT') { 'py', 'python', 'python3' } else { 'python3', 'python' }   # Windows: the py launcher first (python3.exe is often the Store alias)
    $py = $candidates | ForEach-Object { Get-Command $_ -CommandType Application -ErrorAction SilentlyContinue } | Select-Object -First 1
    if (-not $py) { Stop-Release 'Python not found - install Python 3 with reportlab, or use -SkipPdf and rebuild the PDF elsewhere' }
    $pyArgs = @(); if ($py.Name -like 'py*.exe' -and $py.Name -notlike 'python*') { $pyArgs += '-3' }
    & $py.Source @pyArgs (Join-Path (Join-Path (Join-Path $Root 'docs') 'src') 'build_findings_pdf.py')
    if ($LASTEXITCODE -ne 0) { Stop-Release 'PDF build failed (reportlab installed? DejaVu fonts / SOA_FONT_DIR?) - or use -SkipPdf' }
    $changed.Add($pdf)
}

# --- 6. Checks and staging ------------------------------------------------------------------------------------
if ($WhatIfPreference) { Write-Host 'WhatIf: nothing written, no checks run.' -ForegroundColor Cyan; exit 0 }
if (-not $changed.Count) { Write-Host "Nothing to change - the tree is prepared for $Version ($Date)." -ForegroundColor Green }
if (-not $SkipChecks) {
    & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File (Join-Path $ScriptRoot 'Invoke-SoaStaticChecks.ps1')
    if ($LASTEXITCODE -ne 0) { Stop-Release 'static checks failed - fix the findings and run this script again (it is safe to repeat)' }
}
if ($changed.Count -and -not $NoStage -and $git) {
    $add = Invoke-Git (@('add', '--') + @($changed | ForEach-Object { $_.Substring($Root.Length).TrimStart('\', '/') }))
    if ($add.Code -ne 0) { Stop-Release ("git add failed: {0}" -f ($add.Out -join ' ')) }
    Write-Host ("Staged {0} file(s)." -f $changed.Count) -ForegroundColor Green
}

Write-Host ''
Write-Host 'Next (docs/RELEASING.md):' -ForegroundColor Cyan
Write-Host "  1. Commit 'Release $Version' (signed off), push, wait until both CI jobs are green."
Write-Host "  2. Tag:   git tag -s $tag -m `"cloudsync-soa-toolkit $Version`"     (until signing is set up: git tag -a ...)"
Write-Host "  3. Check: .\tools\Test-SoaReleaseTag.ps1 -Tag $tag                   (add -AllowUnsigned for an unsigned tag)"
Write-Host "  4. Push:  git push origin $tag   - the release workflow builds the asset and creates the draft release."
exit 0
