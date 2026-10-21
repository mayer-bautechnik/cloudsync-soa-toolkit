#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Static checks for two PowerShell scope pitfalls: overwritten script-level values and -WhatIf that does not reach
    the toolkit module.

.DESCRIPTION
    PowerShell variable names are case-insensitive, and switch / foreach / if blocks do not open a new scope. A
    script-level value such as $KnownGuid = Get-SoaConstant 'Guid' is therefore silently replaced by a later
    "$knownguid = ..." or "foreach ($knownGuid in ...)" anywhere in the same scope. (2.0.4: $g = Get-ADGroup ...
    replaced $G = Get-SoaConstant 'Guid' in Install-SoaToolkit.ps1, and $ucc replaced the flag table $Ucc in
    Watch-CloudUserConformance.ps1.)

    Parses every script (no code is executed). A "script-level context value" is an assignment directly in the
    script body whose right-hand side calls Get-Soa* / Import-Soa* / Initialize-Soa* / Select-Soa*. Reported is
    every later assignment or foreach variable with the same name (case-insensitive) in the same scope. Not counted:
    function bodies and script blocks that run in their own scope (Invoke-Command, Start-Job, stored script blocks);
    script blocks of ForEach-Object / Where-Object run in the caller's scope and are counted. A deliberate refresh
    that calls the same command again (e.g. re-reading a group membership) is allowed.

    Second check: preference variables such as $WhatIfPreference do not cross the boundary into a script module.
    A script started with -WhatIf that calls a module function with SupportsShouldProcess (New-SoaGpo, Add-SoaAce ...)
    without passing -WhatIf:$WhatIfPreference makes that function really write. (2.0.4: New-SoaGpo created GPOs during
    Install-SoaToolkit.ps1 -WhatIf.) Reported is every such call in a script that itself supports ShouldProcess.

.PARAMETER Path
    Folders with scripts (default: ..\scripts and ..\tools). Module functions with SupportsShouldProcess are read from
    every *.psm1 in these folders.

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.0.5 (2026-10-21)
    Exit code 0 = clean, 1 = findings.
#>
[CmdletBinding()]
param([string[]] $Path)
$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
if (-not $Path) { $root = Split-Path $ScriptRoot -Parent; $Path = @((Join-Path $root 'scripts'), (Join-Path $root 'tools')) }

function Test-OwnScope($Ast) {
    $p = $Ast.Parent
    while ($p) {
        if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $true }
        if ($p -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
            $cmd = $p.Parent
            $inCaller = ($cmd -is [System.Management.Automation.Language.CommandAst]) -and ($cmd.GetCommandName() -in 'ForEach-Object', 'Where-Object', '%', '?', 'foreach', 'where')
            if (-not $inCaller) { return $true }
        }
        $p = $p.Parent
    }
    $false
}
function Get-SoaCommandNames($Ast) {
    @($Ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } |
        Where-Object { $_ -match '^(Get|Import|Initialize|Select)-Soa' } | Select-Object -Unique)
}

$findings = New-Object System.Collections.Generic.List[object]
$files = @(foreach ($p in $Path) { Get-ChildItem -LiteralPath $p -Filter '*.ps1' -File -ErrorAction SilentlyContinue })
$spFunctions = @(foreach ($p in $Path) {
    foreach ($m in @(Get-ChildItem -LiteralPath $p -Filter '*.psm1' -File -ErrorAction SilentlyContinue)) {
        $mast = [System.Management.Automation.Language.Parser]::ParseFile($m.FullName, [ref]$null, [ref]$null)
        $mast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object {
            $_.Body.ParamBlock -and @($_.Body.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' -and @($_.NamedArguments | ForEach-Object { $_.ArgumentName }) -contains 'SupportsShouldProcess' }).Count
        } | ForEach-Object { $_.Name }
    }
}) | Select-Object -Unique
$whatIfFindings = 0
foreach ($f in $files) {
    $tokens = $null; $errors = $null
    $root = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { $findings.Add([pscustomobject]@{ File = $f.Name; Line = 0; Text = 'parse errors - not checked' }); continue }
    $assign = @($root.FindAll({ param($a) $a -is [System.Management.Automation.Language.AssignmentStatementAst] -and $a.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
        Where-Object { -not (Test-OwnScope $_) })
    $loops = @($root.FindAll({ param($a) $a -is [System.Management.Automation.Language.ForEachStatementAst] }, $true) | Where-Object { -not (Test-OwnScope $_) })

    $ctxValues = @{}
    foreach ($a in $assign) {
        if (-not ($a.Parent -is [System.Management.Automation.Language.NamedBlockAst] -and $a.Parent.Parent -eq $root)) { continue }
        $cmds = Get-SoaCommandNames $a.Right
        $n = $a.Left.VariablePath.UserPath.ToLowerInvariant()
        if ($cmds.Count -and -not $ctxValues.ContainsKey($n)) { $ctxValues[$n] = [pscustomobject]@{ Ast = $a; Commands = $cmds } }
    }
    foreach ($a in $assign) {
        $n = $a.Left.VariablePath.UserPath.ToLowerInvariant()
        if (-not $ctxValues.ContainsKey($n)) { continue }
        $def = $ctxValues[$n]
        if ($a -eq $def.Ast -or $a.Extent.StartOffset -lt $def.Ast.Extent.StartOffset) { continue }
        if (@(Get-SoaCommandNames $a.Right | Where-Object { $def.Commands -contains $_ }).Count) { continue }   # deliberate refresh
        $findings.Add([pscustomobject]@{ File = $f.Name; Line = $a.Extent.StartLineNumber; Text = ('${0} overwrites the script-level value ${1} (line {2})' -f $a.Left.VariablePath.UserPath, $def.Ast.Left.VariablePath.UserPath, $def.Ast.Extent.StartLineNumber) })
    }
    # -WhatIf propagation into module functions
    $scriptSp = $root.ParamBlock -and @($root.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' -and @($_.NamedArguments | ForEach-Object { $_.ArgumentName }) -contains 'SupportsShouldProcess' }).Count
    if ($scriptSp -and $spFunctions.Count) {
        foreach ($c in $root.FindAll({ param($x) $x -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            if ($spFunctions -notcontains $c.GetCommandName()) { continue }
            if (@($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'WhatIf' }).Count) { continue }
            $whatIfFindings++
            $findings.Add([pscustomobject]@{ File = $f.Name; Line = $c.Extent.StartLineNumber; Text = ('{0} is called without -WhatIf:$WhatIfPreference (preference variables do not reach module functions - it would write during -WhatIf)' -f $c.GetCommandName()) })
        }
    }
    foreach ($l in $loops) {
        $n = $l.Variable.VariablePath.UserPath.ToLowerInvariant()
        if ($ctxValues.ContainsKey($n) -and $l.Extent.StartOffset -gt $ctxValues[$n].Ast.Extent.StartOffset) {
            $def = $ctxValues[$n].Ast
            $findings.Add([pscustomobject]@{ File = $f.Name; Line = $l.Extent.StartLineNumber; Text = ('foreach variable ${0} overwrites the script-level value ${1} (line {2})' -f $l.Variable.VariablePath.UserPath, $def.Left.VariablePath.UserPath, $def.Extent.StartLineNumber) })
        }
    }
}

Write-Host ("Script scope - {0} file(s), {1} module function(s) with ShouldProcess" -f $files.Count, $spFunctions.Count) -ForegroundColor Cyan
$overwrite = $findings.Count - $whatIfFindings
Write-Host ("  [{0}] no script-level context value is overwritten" -f $(if ($overwrite) { 'FAIL' } else { 'PASS' })) -ForegroundColor $(if ($overwrite) { 'Red' } else { 'Green' })
Write-Host ("  [{0}] -WhatIf is passed to every module function with ShouldProcess" -f $(if ($whatIfFindings) { 'FAIL' } else { 'PASS' })) -ForegroundColor $(if ($whatIfFindings) { 'Red' } else { 'Green' })
foreach ($x in $findings) { Write-Host ("      {0}:{1} {2}" -f $x.File, $x.Line, $x.Text) -ForegroundColor Red }
exit $(if ($findings.Count) { 1 } else { 0 })
