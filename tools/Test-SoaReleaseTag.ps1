#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Checks a release tag before anything is built from it: name, annotated, signature, on main, version, CHANGELOG,
    release notes, no existing release. Used by the release workflow and, before pushing the tag, by the maintainer.

.DESCRIPTION
    Every check must pass; one FAIL stops the release (exit code 1).
      T1  name v<major>.<minor>.<patch>
      T2  annotated tag (git tag -a / -s), not a lightweight tag
      T3  signature (SSH), verified with git verify-tag against .github/allowed_signers taken from -MainRef - not from
          the tagged commit, so a tag cannot bring its own key:
            valid signature                          PASS
            invalid signature                        FAIL, always
            no signature / no allowed_signers on main FAIL; WARN with -AllowUnsigned (transition until signing is set
                                                     up - the release workflow sets it from the repository variable
                                                     SOA_ALLOW_UNSIGNED_TAGS)
      T4  the tagged commit is on -MainRef
      T5  $script:SoaVersion in the tagged commit = the tag
      T6  CHANGELOG.md in the tagged commit has '## <version> – <SoaReleaseDate>'
      T7  .github/release-notes/v<version>.md in the tagged commit: first line '<!-- title: ... -->', no TODO-RELEASE-NOTES
      T8  no GitHub release (also no draft) for the tag yet (gh; -SkipReleaseCheck: not checked)
    Everything is read with git from the tag and from -MainRef; the working tree is not used. Nothing is changed.
    In GitHub Actions the title goes to $env:GITHUB_OUTPUT (title=...) and the results to the job summary.

.PARAMETER Tag
    Tag to check, e.g. v2.0.7. It must exist locally (git fetch origin +refs/tags/<tag>:refs/tags/<tag>).

.PARAMETER MainRef
    Reference of the protected main branch (default origin/main; run git fetch origin first).

.PARAMETER AllowUnsigned
    Accept a tag without signature (WARN instead of FAIL). An invalid signature still fails.

.PARAMETER NotesOut
    Write the release notes without the title line to this file (input for gh release create --notes-file).

.PARAMETER SkipReleaseCheck
    Do not ask GitHub for an existing release (T8), e.g. without the GitHub CLI.

.PARAMETER Root
    Repository root (default: parent of tools\).

.EXAMPLE
    git fetch origin
    .\tools\Test-SoaReleaseTag.ps1 -Tag v2.0.7                    # signed tag
    .\tools\Test-SoaReleaseTag.ps1 -Tag v2.0.7 -AllowUnsigned     # transition: unsigned annotated tag

.NOTES
    Exit code 0 = all checks passed (WARN allowed), 1 = at least one FAIL.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Tag,
    [string] $MainRef = 'origin/main',
    [switch] $AllowUnsigned,
    [string] $NotesOut,
    [switch] $SkipReleaseCheck,
    [string] $Root
)
$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
if (-not $Root) { $Root = Split-Path $ScriptRoot -Parent }

$results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$Id, [string]$Status, [string]$Text) {
    $results.Add([pscustomobject]@{ Id = $Id; Status = $Status; Text = $Text })
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }[$Status]
    Write-Host ("  [{0}] {1}  {2}" -f $Status, $Id, $Text) -ForegroundColor $color
}
function Invoke-Git([string[]]$Arguments) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'   # git writes progress / hints to stderr
    # git writes UTF-8; PowerShell decodes native output with the console code page (Windows: an OEM code page such as
    # 850), which would turn the en dash of '## <version> – <date>' into other characters.
    $prevEncoding = $null
    try { $prevEncoding = [Console]::OutputEncoding; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { $prevEncoding = $null }
    try { $out = & git -C $Root @Arguments 2>&1 } finally {
        $ErrorActionPreference = $prev
        if ($prevEncoding) { try { [Console]::OutputEncoding = $prevEncoding } catch { } }
    }
    [pscustomobject]@{ Code = $LASTEXITCODE; Out = @($out | ForEach-Object { "$_" }); Text = (@($out | ForEach-Object { "$_" }) -join "`n") }
}

Write-Host "Release tag check: $Tag (main = $MainRef)" -ForegroundColor Cyan
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Host '  [FAIL] git not found' -ForegroundColor Red; exit 1 }

# T1 name
$version = $null
if ($Tag -match '^v(\d+\.\d+\.\d+)$') { $version = $Matches[1]; Add-Result 'T1' 'PASS' 'tag name' }
else { Add-Result 'T1' 'FAIL' "tag name '$Tag' is not v<major>.<minor>.<patch>" }

$type = Invoke-Git @('cat-file', '-t', "refs/tags/$Tag")
$commit = $null
if ($type.Code -ne 0) {
    Add-Result 'T2' 'FAIL' "tag $Tag not found locally - git fetch origin +refs/tags/${Tag}:refs/tags/$Tag"
} else {
    # T2 annotated
    if ($type.Text.Trim() -eq 'tag') { Add-Result 'T2' 'PASS' 'annotated tag' }
    else { Add-Result 'T2' 'FAIL' "lightweight tag ($($type.Text.Trim())) - create it with git tag -s (or git tag -a during the transition)" }
    $commit = (Invoke-Git @('rev-parse', "refs/tags/$Tag^{commit}")).Text.Trim()

    # T3 signature
    if ($type.Text.Trim() -eq 'tag') {
        $raw = (Invoke-Git @('cat-file', 'tag', "refs/tags/$Tag")).Text
        $sigType = if ($raw -match '-----BEGIN SSH SIGNATURE-----') { 'SSH' } elseif ($raw -match '-----BEGIN PGP SIGNATURE-----') { 'PGP' } else { $null }
        $signers = Invoke-Git @('show', "${MainRef}:.github/allowed_signers")
        $unsignedStatus = if ($AllowUnsigned) { 'WARN' } else { 'FAIL' }
        if (-not $sigType) {
            Add-Result 'T3' $unsignedStatus ('tag is not signed' + $(if ($AllowUnsigned) { ' - accepted during the transition (SOA_ALLOW_UNSIGNED_TAGS / -AllowUnsigned)' } else { ' - create it with git tag -s' }))
        } elseif ($sigType -eq 'PGP') {
            Add-Result 'T3' $unsignedStatus 'PGP signature - this check verifies SSH signatures only (docs/RELEASING.md: SSH signing key)'
        } elseif ($signers.Code -ne 0 -or -not ($signers.Out | Where-Object { $_ -and $_ -notmatch '^\s*#' })) {
            Add-Result 'T3' $unsignedStatus "SSH signature, but no .github/allowed_signers on $MainRef to verify it against"
        } else {
            $tmp = [IO.Path]::GetTempFileName()
            try {
                [IO.File]::WriteAllText($tmp, (($signers.Out -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
                # ssh-keygen verifies; a configured signing helper (gpg.ssh.program, e.g. of a password manager) may only sign
                $verify = Invoke-Git @('-c', 'gpg.ssh.program=ssh-keygen', '-c', "gpg.ssh.allowedSignersFile=$tmp", 'verify-tag', "refs/tags/$Tag")
                $principal = if ($verify.Text -match 'Good "git" signature for (\S+)') { $Matches[1] } else { 'allowed signer' }
                if ($verify.Code -eq 0) { Add-Result 'T3' 'PASS' "valid SSH signature ($principal, allowed_signers from $MainRef)" }
                else { Add-Result 'T3' 'FAIL' ("SSH signature does NOT verify against allowed_signers from {0}: {1}" -f $MainRef, (($verify.Out | Select-Object -First 2) -join ' ')) }
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }

    # T4 on main
    $anc = Invoke-Git @('merge-base', '--is-ancestor', $commit, $MainRef)
    if ($anc.Code -eq 0) { Add-Result 'T4' 'PASS' ("commit {0} is on {1}" -f $commit.Substring(0, 12), $MainRef) }
    else { Add-Result 'T4' 'FAIL' ("commit {0} is not on {1} (push main first, then git fetch origin)" -f $commit.Substring(0, 12), $MainRef) }

    # T5 version
    $psm = Invoke-Git @('show', "${commit}:scripts/SoaToolkit.psm1")
    $soaVersion = if ($psm.Text -match "\`$script:SoaVersion\s*=\s*'([^']+)'") { $Matches[1] } else { $null }
    $soaDate = if ($psm.Text -match "\`$script:SoaReleaseDate\s*=\s*'([^']+)'") { $Matches[1] } else { $null }
    if ($version -and $soaVersion -eq $version) { Add-Result 'T5' 'PASS' "SoaVersion $soaVersion ($soaDate)" }
    else { Add-Result 'T5' 'FAIL' "SoaVersion in the tagged commit is '$soaVersion', the tag says '$version' (tools\Set-SoaVersion.ps1)" }

    # T6 CHANGELOG
    $cl = Invoke-Git @('show', "${commit}:CHANGELOG.md")
    if ($soaVersion -and $cl.Code -eq 0 -and $cl.Text -match ('(?m)^## ' + [regex]::Escape($soaVersion) + ' – ' + [regex]::Escape("$soaDate") + '\s*$')) { Add-Result 'T6' 'PASS' "CHANGELOG section $soaVersion – $soaDate" }
    else { Add-Result 'T6' 'FAIL' "CHANGELOG.md has no section '## $soaVersion – $soaDate'" }

    # T7 release notes
    $notes = Invoke-Git @('show', "${commit}:.github/release-notes/$Tag.md")
    $title = $null
    if ($notes.Code -ne 0) { Add-Result 'T7' 'FAIL' ".github/release-notes/$Tag.md not found in the tagged commit" }
    else {
        $lines = @($notes.Text -split '\r?\n')
        if ($lines[0] -match '^<!--\s*title:\s*(.+?)\s*-->\s*$') { $title = $Matches[1] }
        if (-not $title) { Add-Result 'T7' 'FAIL' "first line of $Tag.md is not '<!-- title: $Tag – <summary> -->'" }
        elseif ($notes.Text -match 'TODO-RELEASE-NOTES') { Add-Result 'T7' 'FAIL' "$Tag.md still contains TODO-RELEASE-NOTES" }
        else {
            Add-Result 'T7' 'PASS' "release notes, title '$title'"
            if ($NotesOut) {
                $bodyLines = @($lines | Select-Object -Skip 1)
                while ($bodyLines.Count -and -not $bodyLines[0].Trim()) { $bodyLines = @($bodyLines | Select-Object -Skip 1) }
                [IO.File]::WriteAllText($NotesOut, (($bodyLines -join "`n").TrimEnd() + "`n"), (New-Object System.Text.UTF8Encoding($false)))
            }
        }
    }
}

# T8 no release yet
if ($SkipReleaseCheck) { Add-Result 'T8' 'WARN' 'existing releases not checked (-SkipReleaseCheck)' }
elseif (-not (Get-Command gh -ErrorAction SilentlyContinue)) { Add-Result 'T8' 'FAIL' 'GitHub CLI (gh) not found - install it (gh auth login) or use -SkipReleaseCheck' }
else {
    Push-Location $Root
    try {
        $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $relJson = & gh release list --limit 200 --json tagName,isDraft 2>&1; $relCode = $LASTEXITCODE } finally { $ErrorActionPreference = $prev }
    } finally { Pop-Location }
    if ($relCode -ne 0) { Add-Result 'T8' 'FAIL' ("gh release list failed: {0}" -f (@($relJson) -join ' ')) }
    else {
        $hit = @((@($relJson) -join "`n") | ConvertFrom-Json | ForEach-Object { $_ } | Where-Object { $_.tagName -eq $Tag })
        if ($hit.Count) { Add-Result 'T8' 'FAIL' ("a release for {0} exists already ({1}) - delete a failed draft first; a published version is never rebuilt" -f $Tag, $(if ($hit[0].isDraft) { 'draft' } else { 'published' })) }
        else { Add-Result 'T8' 'PASS' 'no release for this tag yet' }
    }
}

$fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
if ($env:GITHUB_OUTPUT -and $title -and -not $fail) { Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "title=$title" -Encoding UTF8 }
if ($env:GITHUB_STEP_SUMMARY) {
    $md = @("### Release tag check $Tag", '', '| Check | Result | Detail |', '|---|---|---|') + @($results | ForEach-Object { '| {0} | {1} | {2} |' -f $_.Id, $_.Status, ($_.Text -replace '\|', '/') })
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $md -Encoding UTF8
}
Write-Host ("Result: {0}" -f $(if ($fail) { "$fail FAIL" } else { 'PASS' })) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
