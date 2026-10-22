#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Builds the release asset cloudsync-soa-toolkit-<version>.zip with SHA256SUMS.txt inside and a .sha256 next to it.

.DESCRIPTION
    Source of the files:
      - inside a git work tree: 'git archive' of -Ref (default HEAD) - honours export-ignore in .gitattributes and
        contains exactly what is committed (run it on the signed tag: -Ref v<version>)
      - CI gate: the GitHub CLI (gh) is asked for the runs of the CI workflow (.github/workflows/ci.yml) for the
        commit; the build is refused unless all of them completed successfully (-SkipCiCheck only when gh is
        unavailable and CI was verified manually). Other workflows - such as the release workflow that calls this
        script - are not counted.
      - otherwise: the working folder minus the export-ignore paths and local files (.git, reports, *.local.*)
    Then:
      - SHA256SUMS.txt (sha256sum format) for every file -> Export-SoaReport.ps1 compares the deployed scripts with it
      - zip with forward slashes (portable) and the prefix folder cloudsync-soa-toolkit/; every entry carries the
        release date (00:00) as its time, so the timestamps do not depend on when or where the zip was built
      - <zip>.sha256; the digest is also shown by GitHub next to the asset
    Version and date are read from scripts/SoaToolkit.psm1 of the packaged content (the tag), not of the working tree.

    Comparing two builds of the same commit (release workflow, maintainer, AI assistant): the contents digest
    (SHA-256 of SHA256SUMS.txt) is identical when every file is identical. The zip digest can still differ between
    machines, because the deflate implementation differs between .NET versions (Windows PowerShell 5.1 /
    PowerShell 7.x).

.PARAMETER Ref
    Git reference to package (tag or commit). Default HEAD.

.PARAMETER OutputPath
    Target folder (default: the parent folder of the repository).

.PARAMETER SkipCiCheck
    Do not ask GitHub for the CI result of the commit. Only when the GitHub CLI is not available - verify CI manually.

.NOTES
    Run tools\Invoke-SoaStaticChecks.ps1 first. See docs/RELEASING.md.
#>
[CmdletBinding()]
param(
    [string] $Ref = 'HEAD',
    [string] $OutputPath,
    [switch] $SkipCiCheck
)
$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
$root = Split-Path $ScriptRoot -Parent
if (-not $OutputPath) { $OutputPath = Split-Path $root -Parent }
$stage = Join-Path ([IO.Path]::GetTempPath()) ("soa-release-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$top   = Join-Path $stage 'cloudsync-soa-toolkit'
New-Item -Path $top -ItemType Directory -Force | Out-Null

$git = Get-Command git -ErrorAction SilentlyContinue
$inGit = $git -and (Test-Path -LiteralPath (Join-Path $root '.git'))
if ($inGit) {
    Push-Location $root
    try {
        $dirty = @(& git status --porcelain)
        if ($dirty.Count -and $Ref -eq 'HEAD') { Write-Warning "Uncommitted changes are NOT part of the package ($($dirty.Count) path(s)). Commit first or package a tag." }
        $tar = Join-Path $stage 'src.tar'
        & git archive --format=tar --output=$tar $Ref
        if ($LASTEXITCODE) { throw "git archive $Ref failed" }
        & tar -xf $tar -C $top
        if ($LASTEXITCODE) { throw 'tar extraction failed' }
        Remove-Item -LiteralPath $tar -Force
        $commit = (& git rev-parse "$Ref^{commit}").Trim()
        # CI gate (docs/RELEASING.md step 4/6): all workflow runs of this commit must have succeeded
        if (-not $SkipCiCheck) {
            if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'GitHub CLI (gh) not found - install it and run gh auth login, or verify CI manually and use -SkipCiCheck.' }
            $runsJson = & gh run list --commit $commit --workflow ci.yml --json name,status,conclusion --limit 50
            if ($LASTEXITCODE) { throw "gh run list failed for $commit (gh auth login?)" }
            $runs = @($runsJson | ConvertFrom-Json | ForEach-Object { $_ })
            if (-not $runs.Count) { throw "No CI run found for commit $commit - push the commit and wait for CI before building the release." }
            $bad = @($runs | Where-Object { $_.status -ne 'completed' -or $_.conclusion -ne 'success' })
            if ($bad.Count) { throw ("CI is not green for {0}: {1}" -f $commit.Substring(0, 12), (($bad | ForEach-Object { "$($_.name)=$($_.status)/$($_.conclusion)" }) -join ', ')) }
            Write-Host ("CI gate : {0} run(s) successful for {1}" -f $runs.Count, $commit.Substring(0, 12)) -ForegroundColor Green
        } else { Write-Warning 'CI gate skipped (-SkipCiCheck) - make sure both CI jobs are green for this commit.' }
    } finally { Pop-Location }
} else {
    Write-Warning 'Not a git work tree - packaging the folder content (export-ignore emulated).'
    # export-ignore and local files (your configuration, terms, pseudonym maps are never part of a release)
    $exclude = '^(\.git|\.github[\\/]assets|reports|.*\.local\..*|.*\.zip|.*\.sha256|SoaToolkit\.config\.psd1|scripts[\\/]SoaToolkit\.config\.psd1|SoaToolkit\.config\.(?!example\.).+\.psd1|(?!.*\.example\.txt$).*\.terms\.txt|.*forbidden-terms.*\.txt|.*\.map\.csv|.*pseudonyms\.csv)([\\/]|$)'
    foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -Force)) {
        $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/')
        if ($rel -match $exclude) { continue }
        $dest = Join-Path $top $rel
        New-Item -Path (Split-Path $dest -Parent) -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $f.FullName -Destination $dest
    }
    $commit = 'working folder'
}

# Version and date of the packaged content
$psmText = Get-Content -LiteralPath (Join-Path (Join-Path $top 'scripts') 'SoaToolkit.psm1') -Raw
$version = if ($psmText -match "\`$script:SoaVersion\s*=\s*'([^']+)'") { $Matches[1] } else { throw 'version not found in SoaToolkit.psm1' }
$releaseDate = if ($psmText -match "\`$script:SoaReleaseDate\s*=\s*'(\d{4}-\d{2}-\d{2})'") { [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } else { throw 'release date not found in SoaToolkit.psm1' }
$name = "cloudsync-soa-toolkit-$version"

# SHA256SUMS.txt
$sums = foreach ($f in (Get-ChildItem -LiteralPath $top -Recurse -File -Force | Sort-Object FullName)) {
    $rel = $f.FullName.Substring($top.Length).TrimStart('\', '/') -replace '\\', '/'
    '{0}  {1}' -f (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower(), $rel
}
[IO.File]::WriteAllText((Join-Path $top 'SHA256SUMS.txt'), (($sums -join "`n") + "`n"))

# Zip with forward slashes
$zip = Join-Path $OutputPath "$name.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$fs = [IO.File]::Open($zip, [IO.FileMode]::CreateNew)
try {
    $archive = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $top -Recurse -File -Force | Sort-Object FullName)) {
            $entry = 'cloudsync-soa-toolkit/' + ($f.FullName.Substring($top.Length).TrimStart('\', '/') -replace '\\', '/')
            [IO.File]::SetLastWriteTime($f.FullName, $releaseDate)   # entry time = release date 00:00, independent of build time and place
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $f.FullName, $entry, [IO.Compression.CompressionLevel]::Optimal)
        }
    } finally { $archive.Dispose() }
} finally { $fs.Dispose() }
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
$contents = (Get-FileHash -LiteralPath (Join-Path $top 'SHA256SUMS.txt') -Algorithm SHA256).Hash.ToLower()
"$hash  $name.zip" | Set-Content -LiteralPath "$zip.sha256" -Encoding ASCII
Remove-Item -LiteralPath $stage -Recurse -Force

Write-Host "Package : $zip" -ForegroundColor Cyan
Write-Host "Source  : $commit"
Write-Host "Files   : $(@($sums).Count + 1) (incl. SHA256SUMS.txt)"
Write-Host "SHA-256 : $hash" -ForegroundColor Green
Write-Host "Contents: $contents  (SHA-256 of SHA256SUMS.txt - compare this value between builds)" -ForegroundColor Green
