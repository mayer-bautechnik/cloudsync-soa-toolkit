#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Static checks for three PowerShell scope pitfalls: overwritten script-level values, -WhatIf that does not reach the
    toolkit module, and -WhatIf that suppresses local scratch files and run logs.

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

    Third check, the reverse case: inside the script (and its functions) $WhatIfPreference does reach the built-in
    cmdlets. Local scratch work that the dry run itself needs - staging in %TEMP%, the run log - is then silently skipped,
    and the next step reads files that do not exist. (2.0.5 lab run: DeployTasks -WhatIf staged nothing and Get-FileHash
    failed; the run log had no START line, so Export-SoaReport.ps1 found no dry run for L2.) In a script that supports
    ShouldProcess, reported is every New-Item, Copy-Item, Set-Content, Add-Content, Out-File, Remove-Item ... whose target
    path uses a variable assigned from $env:TEMP / GetTempPath() / GetTempFileName() or a '*.log' name, and that does not
    pass -WhatIf:$false. Also reported is every Start-Process: it honours -WhatIf in PowerShell 7 but has no -WhatIf
    parameter in Windows PowerShell 5.1, so it belongs in a module function (Expand-SoaMsi). Not covered: splatted
    targets (@params) and child scripts called with & (they inherit $WhatIfPreference; Install-SoaToolkit.ps1 runs the
    read-only ones through Invoke-ReadOnlyScript).

.PARAMETER Path
    Folders with scripts (default: ..\scripts and ..\tools). Module functions with SupportsShouldProcess are read from
    every *.psm1 in these folders.

.NOTES
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
# Script block that runs detached from the script's preference variables (Invoke-Command, stored blocks). Unlike
# Test-OwnScope, function bodies of the script count as attached: they see the caller's $WhatIfPreference.
function Test-DetachedBlock($Ast) {
    $p = $Ast.Parent
    while ($p) {
        if ($p -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
            $cmd = $p.Parent
            $inCaller = ($cmd -is [System.Management.Automation.Language.CommandAst]) -and ($cmd.GetCommandName() -in 'ForEach-Object', 'Where-Object', '%', '?', 'foreach', 'where')
            if (-not $inCaller) { return $true }
        }
        $p = $p.Parent
    }
    $false
}
# Target path argument(s) of a built-in file cmdlet: named parameter(s), else the positional argument at $Position.
$scratchTargets = @{
    'New-Item' = @{ Names = 'Path', 'LiteralPath'; Position = 0 };         'Remove-Item' = @{ Names = 'Path', 'LiteralPath'; Position = 0 }
    'Set-Content' = @{ Names = 'Path', 'LiteralPath'; Position = 0 };      'Add-Content' = @{ Names = 'Path', 'LiteralPath'; Position = 0 }
    'Clear-Content' = @{ Names = 'Path', 'LiteralPath'; Position = 0 };    'Rename-Item' = @{ Names = 'Path', 'LiteralPath'; Position = 0 }
    'Export-Csv' = @{ Names = 'Path', 'LiteralPath'; Position = 0 };       'Export-Clixml' = @{ Names = 'Path', 'LiteralPath'; Position = 0 }
    'Out-File' = @{ Names = 'FilePath', 'LiteralPath'; Position = 0 };     'Set-AuthenticodeSignature' = @{ Names = 'FilePath', 'LiteralPath'; Position = 0 }
    'Copy-Item' = @{ Names = @('Destination'); Position = 1 };             'Move-Item' = @{ Names = @('Destination'); Position = 1 }
    'Compress-Archive' = @{ Names = @('DestinationPath'); Position = 1 }; 'Expand-Archive' = @{ Names = @('DestinationPath'); Position = 1 }
}
$switchParams = 'Force', 'Recurse', 'PassThru', 'NoTypeInformation', 'Append', 'NoNewline', 'NoClobber', 'Container', 'Wait', 'WhatIf', 'Confirm',
                'Verbose', 'Debug', 'Update', 'AsByteStream', 'IncludeTypeInformation', 'UseQuotes', 'NoHeader', 'Stream'
function Get-TargetArgument($Command, $Spec) {
    $els = $Command.CommandElements; $named = @(); $positional = @(); $i = 1
    while ($i -lt $els.Count) {
        $e = $els[$i]
        if ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
            if ($e.Argument) { if ($Spec.Names -contains $e.ParameterName) { $named += $e.Argument } }
            elseif ($switchParams -notcontains $e.ParameterName -and ($i + 1) -lt $els.Count) { $i++; if ($Spec.Names -contains $e.ParameterName) { $named += $els[$i] } }
        } else { $positional += $e }
        $i++
    }
    if ($named.Count) { return $named }
    if ($positional.Count -gt $Spec.Position) { return @($positional[$Spec.Position]) }
    @()
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
$scratchFindings = 0
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
    # Local scratch files / run logs must not depend on -WhatIf; Start-Process belongs in the module
    if ($scriptSp) {
        $scratchVars = @($root.FindAll({ param($a) $a -is [System.Management.Automation.Language.AssignmentStatementAst] -and $a.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
            Where-Object { -not (Test-DetachedBlock $_) -and $_.Right.Extent.Text -match '(?i)\$env:TEMP\b|GetTemp(Path|FileName)\s*\(|\.log[''"]' } |
            ForEach-Object { $_.Left.VariablePath.UserPath } | Sort-Object -Unique)
        foreach ($c in $root.FindAll({ param($x) $x -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $name = $c.GetCommandName()
            if (-not $name -or (Test-DetachedBlock $c)) { continue }
            $hasWhatIf = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'WhatIf' }).Count -gt 0
            if ($name -eq 'Start-Process') {
                $scratchFindings++
                $findings.Add([pscustomobject]@{ File = $f.Name; Line = $c.Extent.StartLineNumber; Text = 'Start-Process in a script with -WhatIf: skipped during -WhatIf in PowerShell 7, not in 5.1 (no -WhatIf parameter) - call it from a module function' })
                continue
            }
            if ($hasWhatIf -or -not $scratchTargets.ContainsKey($name) -or -not $scratchVars.Count) { continue }
            $refs = @(foreach ($t in @(Get-TargetArgument $c $scratchTargets[$name])) {
                $t.FindAll({ param($v) $v -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) | ForEach-Object { $_.VariablePath.UserPath } | Where-Object { $scratchVars -contains $_ }
            })
            if (-not $refs.Count) { continue }
            $scratchFindings++
            $findings.Add([pscustomobject]@{ File = $f.Name; Line = $c.Extent.StartLineNumber; Text = ('{0} on the scratch / run-log path ${1} without -WhatIf:$false (skipped during -WhatIf, later steps miss the file)' -f $name, $refs[0]) })
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
$overwrite = $findings.Count - $whatIfFindings - $scratchFindings
Write-Host ("  [{0}] no script-level context value is overwritten" -f $(if ($overwrite) { 'FAIL' } else { 'PASS' })) -ForegroundColor $(if ($overwrite) { 'Red' } else { 'Green' })
Write-Host ("  [{0}] -WhatIf is passed to every module function with ShouldProcess" -f $(if ($whatIfFindings) { 'FAIL' } else { 'PASS' })) -ForegroundColor $(if ($whatIfFindings) { 'Red' } else { 'Green' })
Write-Host ("  [{0}] local scratch files and run logs are written also during -WhatIf (no Start-Process in scripts)" -f $(if ($scratchFindings) { 'FAIL' } else { 'PASS' })) -ForegroundColor $(if ($scratchFindings) { 'Red' } else { 'Green' })
foreach ($x in $findings) { Write-Host ("      {0}:{1} {2}" -f $x.File, $x.Line, $x.Text) -ForegroundColor Red }
exit $(if ($findings.Count) { 1 } else { 0 })
