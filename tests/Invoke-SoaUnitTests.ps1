#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    Unit and integration tests that need no domain (Windows PowerShell 5.1 and PowerShell 7, Windows or Linux).

.DESCRIPTION
    - module functions: configuration, marker, scope, KIR ADMX parsing, event subscription, conformance evaluation,
      manifest, GPO version / CSE merge (mocked AD cmdlets), SACL fingerprint, random secret, JSON array reading,
      run log, anonymizer and leak check
    - tools\Test-SoaSecurityClaims.ps1 against a script with deliberate violations (must fail)
    - tools\Test-SoaScriptScope.ps1 against a script that overwrites script-level values, omits -WhatIf on a module
      function or lets -WhatIf skip scratch / run-log writes (must fail)
    - tools\Set-SoaVersion.ps1 on a fixture (version everywhere, Unreleased -> version section, notes template,
      repeat, refusals) and tools\Test-SoaReleaseTag.ps1 against a local git repository (unsigned, lightweight, not on
      main, SSH-signed with an allowed and with an unknown key)
    - Export-SoaReport.ps1 end to end against a mocked ActiveDirectory module (tests\mocks) and generated fixtures:
      L1-L20 evaluation, anonymization, map outside the folder, leak check, packaging refusal on a leak
    Child processes are used where mocks must not leak into the main test scope.

.NOTES
    Exit code = number of failed assertions (0 = all passed).
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
$repo = Split-Path $ScriptRoot -Parent
$tmp  = Join-Path ([IO.Path]::GetTempPath()) ('soa-tests-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -Path $tmp -ItemType Directory -Force | Out-Null
Import-Module (Join-Path (Join-Path $repo 'scripts') 'SoaToolkit.psm1') -Force -DisableNameChecking
$script:fail = 0
function Assert-Test($Condition, [string]$Message) { if ($Condition) { Write-Host "PASS $Message" -ForegroundColor Green } else { Write-Host "FAIL $Message" -ForegroundColor Red; $script:fail++ } }
$exe = (Get-Process -Id $PID).Path

try {
# Config
$tmpCfg = Join-Path $tmp 'cfg.psd1'
(Get-Content (Join-Path $repo 'SoaToolkit.config.example.psd1') -Raw) -replace 'C:\\SoaToolkitAdmin\\Reports', ((Join-Path $tmp 'reports') -replace "'", "''") | Set-Content $tmpCfg
$cfg = Import-SoaConfig -Path $tmpCfg
Assert-Test ($cfg.Pso.MinPasswordLength -eq 64) 'config PSO min length 64'
Assert-Test ($cfg.Pso.MaxPasswordAgeDays -eq 30) 'config PSO max age 30'
Assert-Test ($cfg.GmsaName -eq 'gmsaSoaToolkit') 'config gMSA'
Assert-Test (@($cfg.AgentHosts).Count -eq 2) 'config agent hosts'

# Legacy key warning / validation
$bad = Join-Path $tmp 'bad.psd1'
"@{ AgentHosts=@('a'); RotationDays = 30; Pso=@{ MaxPasswordAgeDays = 0 } }" | Set-Content $bad
try { Import-SoaConfig -Path $bad 3>$null | Out-Null; Assert-Test $false 'invalid config throws' } catch { Assert-Test ($_.Exception.Message -match 'MaxPasswordAgeDays') 'invalid config throws (MaxPasswordAgeDays)' }

# Marker
$mk = Get-SoaMarker -Config $cfg -Short -Purpose 'Test'
Assert-Test (Test-SoaMarker $mk) 'marker recognized'
Assert-Test ($mk -match 'do not modify manually') 'marker text'
Assert-Test (-not (Test-SoaMarker 'something else')) 'non-marker not recognized'

# Marker without configuration (scripts used on their own)
$mk0 = Get-SoaMarker -Config $null -Purpose 'Standalone'
Assert-Test ((Test-SoaMarker $mk0) -and $mk0 -match 'github\.com/mayer-bautechnik/cloudsync-soa-toolkit') 'marker without configuration uses the default project URL'

# Diagnostics GPP item state (removePolicy, action, marker in desc)
$rx = Join-Path $tmp 'Registry.xml'
Set-Content -LiteralPath $rx -Encoding UTF8 -Value '<?xml version="1.0" encoding="utf-8"?><RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}"><Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="2 Security Events" status="2 Security Events" image="10" changed="2026-10-16 12:00:00" uid="{11111111-2222-3333-4444-555555555555}"><Properties action="U" displayDecimal="1" default="0" hive="HKEY_LOCAL_MACHINE" key="SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" name="2 Security Events" type="REG_DWORD" value="00000001"/></Registry></RegistrySettings>'
$st0 = Get-SoaDiagnosticsItemState -RegistryXmlPath $rx
Assert-Test ($st0.Count -eq 1 -and -not $st0.RemovePolicy -and $st0.Action -eq 'U' -and -not $st0.Marked) 'diagnostics item: 1.x "Update" item without removePolicy detected (not adoptable)'
(Get-Content -LiteralPath $rx -Raw) -replace '<Registry clsid', ('<Registry removePolicy="1" desc="' + (Get-SoaMarker -Config $cfg -Short) + '" clsid') | Set-Content -LiteralPath $rx -Encoding UTF8
$st1 = Get-SoaDiagnosticsItemState -RegistryXmlPath $rx
Assert-Test ($st1.RemovePolicy -and $st1.Marked) 'diagnostics item: removePolicy and marker in desc recognized'
Assert-Test (-not (Get-SoaDiagnosticsItemState -RegistryXmlPath (Join-Path $tmp 'missing.xml')).Readable) 'diagnostics item: missing Registry.xml reported as not readable'

# DN scope
Assert-Test (Test-SoaDnInScope -Dn 'CN=u,OU=A,DC=c,DC=com' -ScopeDns @('DC=c,DC=com')) 'dn in domain scope'
Assert-Test (-not (Test-SoaDnInScope -Dn 'CN=u,OU=A,DC=c,DC=com' -ScopeDns @('OU=B,DC=c,DC=com'))) 'dn not in other OU'
Assert-Test (-not (Test-SoaDnInScope -Dn 'CN=u,OU=AB,DC=c,DC=com' -ScopeDns @('B,DC=c,DC=com'))) 'no partial RDN match'

# KIR parsing
$defs = @(Get-SoaKirDefinition -AdmxPath (Join-Path (Join-Path $ScriptRoot 'fixtures') 'sample-kir.admx'))
Assert-Test ($defs.Count -eq 1) 'one KIR policy found'
Assert-Test ($defs[0].DisplayName -eq 'Feature Preview: AD object enforcement') 'display name from ADML'
Assert-Test (@($defs[0].Items).Count -eq 2) 'two feature IDs'
Assert-Test ((@($defs[0].Items | Where-Object FeatureId -eq '1234567890')[0].Disabled) -eq 0) 'disabled value'

# Event subscription
$sub = Get-SoaEventSubscription -AgentSids @('S-1-5-21-1-2-3-1111','S-1-5-21-1-2-3-2222')
[xml]$x = $sub.UserCreated
Assert-Test ($x.QueryList.Query.Select.Path -eq 'Security') 'subscription xml well-formed'
Assert-Test ($sub.XPathSoaWritten -match "AttributeLDAPDisplayName']='msDS-ObjectSoa'" -and $sub.XPathSoaWritten -match " or ") 'subscription 5136 with two SIDs'
$q = $sub.XPathUserCreated -replace '^\*\[System\[\(EventID=(\d+)\)\]\]', ('*[System[(EventID=$1) and TimeCreated[timediff(@SystemTime) <= ' + 5000 + ']]]')
Assert-Test ($q.StartsWith('*[System[(EventID=4720) and TimeCreated[timediff(@SystemTime) <= 5000]]]')) 'doorbell xpath rewrite'

# Conformance evaluation
function New-U($dn, $uac, $soa) { [pscustomobject]@{ SamAccountName = ($dn -split ',')[0].Substring(3); DistinguishedName = $dn; userAccountControl = $uac; 'msDS-ObjectSoa' = $soa } }
$pso = @{ 'cn=in,ou=c,dc=x' = $true; 'cn=gone,ou=c,dc=x' = $true }
$ex  = @{ 'cn=ex,ou=c,dc=x' = $true }
$u1 = Get-SoaUserConformance -User (New-U 'CN=new,OU=c,DC=x' 512 'Cloud') -Config $cfg -PsoMembers $pso -ExcludeMembers $ex -WriteScope @('DC=x')
Assert-Test ($u1.NeedScril -and $u1.NeedGroupAdd -and -not $u1.NeedPneClear) 'new user needs SCRIL + group'
$u2 = Get-SoaUserConformance -User (New-U 'CN=in,OU=c,DC=x' (512 -bor 0x40000 -bor 0x10000) 'Cloud') -Config $cfg -PsoMembers $pso -ExcludeMembers $ex -WriteScope @('DC=x')
Assert-Test ((-not $u2.NeedScril) -and $u2.NeedPneClear -and -not $u2.NeedGroupAdd) 'PNE must be cleared'
$u3 = Get-SoaUserConformance -User (New-U 'CN=ex,OU=c,DC=x' 512 'Cloud') -Config $cfg -PsoMembers $pso -ExcludeMembers $ex -WriteScope @('DC=x')
Assert-Test ($u3.Excluded -and -not $u3.NeedScril) 'excluded user untouched'
$u4 = Get-SoaUserConformance -User (New-U 'CN=gone,OU=c,DC=x' 512 $null) -Config $cfg -PsoMembers $pso -ExcludeMembers $ex -WriteScope @('DC=x')
Assert-Test ($u4.NeedGroupRemove -and -not $u4.NeedScril) 'unmarked member removed from PSO group, SCRIL not touched'
$u5 = Get-SoaUserConformance -User (New-U 'CN=far,OU=c,DC=y' 512 'Cloud') -Config $cfg -PsoMembers $pso -ExcludeMembers $ex -WriteScope @('DC=x')
Assert-Test (-not $u5.Writable -and $u5.NeedScril) 'outside write scope flagged'
$cfgPilot = $cfg.PSObject.Copy(); $cfgPilot.PilotMode = $true
$u6 = Get-SoaUserConformance -User (New-U 'CN=new,OU=c,DC=x' 512 'Cloud') -Config $cfgPilot -PsoMembers $pso -ExcludeMembers $ex -PilotMembers @{} -WriteScope @('DC=x')
Assert-Test ($u6.PilotOut -and -not $u6.NeedScril) 'pilot mode excludes non-members'

# Manifest
$man = Get-SoaManifest -Config $cfg
Set-SoaManifestEntry -Manifest $man -Kind 'Domain' -Key 'Rolling' -Action Changed -Data @{ Value = $true } -Previous @{ Value = $null }
Set-SoaManifestEntry -Manifest $man -Kind 'Domain' -Key 'Rolling' -Action Changed -Data @{ Value = $true } -Previous @{ Value = $true }
Save-SoaManifest -Config $cfg -Manifest $man
$man2 = Get-SoaManifest -Config $cfg
$e = Get-SoaManifestEntry -Manifest $man2 -Kind 'Domain' -Key 'Rolling'
Assert-Test (@($e).Count -eq 1) 'manifest single entry'
Assert-Test ($null -eq $e[0].Previous.Value) 'manifest keeps FIRST previous value'
Remove-SoaManifestEntry -Manifest $man2 -Kind 'Domain'
Assert-Test (@(Get-SoaManifestEntry -Manifest $man2 -Kind 'Domain').Count -eq 0) 'manifest entry removed'

# CSE merge via mocked AD cmdlets
$global:setCalls = @()
function global:Get-ADObject { param($Identity, $Server, $Properties) [pscustomobject]@{ versionNumber = (3 -shl 16) + 7; gPCMachineExtensionNames = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]' } }
function global:Set-ADObject { param($Identity, $Server, $Replace) $global:setCalls += $Replace }
$ctxFake = [pscustomobject]@{ DomainDN = 'DC=x'; Pdc = 'pdc'; DnsRoot = 'x' }
try { $nv = Update-SoaGpoMachineVersion -Id ([guid]::NewGuid()) -Context $ctxFake -AddCse @('[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]') } catch { "  (GPT.INI write expected to fail without a domain: $($_.Exception.Message.Substring(0,[Math]::Min(80,$_.Exception.Message.Length))))" }
$r = $global:setCalls[0]
Assert-Test ($r.versionNumber -eq ((3 -shl 16) + 8)) 'machine version incremented, user version kept'
Assert-Test ($r.gPCMachineExtensionNames -eq '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]') 'CSE list merged and sorted'

# SACL fingerprint (toolkit entry vs. broad / foreign rules)
$ag = [guid]'cd26b9f3-d415-442a-8f78-7c61523ee95b'
$ok = $true
try { $r0 = New-SoaSaclRule -AttributeGuid $ag } catch { $ok = $false; "  (DirectoryServices not available here: $($_.Exception.GetType().Name) - using stand-in objects)" }
function New-FakeRule($who, $rights, $flags, $ot, $inh, $iot, $isInh = $false) {
    [pscustomobject]@{ IdentityReference = [pscustomobject]@{ Value = $who }; ActiveDirectoryRights = $rights; AuditFlags = $flags; ObjectType = [guid]$ot; InheritanceType = $inh; InheritedObjectType = [guid]$iot; IsInherited = $isInh }
}
$uc = 'bf967aba-0de6-11d0-a285-00aa003049e2'
$tk = if ($ok) { $r0 } else { New-FakeRule 'S-1-1-0' ([DirectoryServices.ActiveDirectoryRights]::WriteProperty) 'Success' $ag 'Descendents' $uc }
Assert-Test (Test-SoaSaclFingerprint -Rule $tk -AttributeGuid $ag) 'toolkit SACL rule matches its fingerprint'
Assert-Test (-not (Test-SoaSaclFingerprint -Rule (New-FakeRule 'S-1-1-0' ([DirectoryServices.ActiveDirectoryRights]::WriteProperty) 'Success, Failure' ([guid]::Empty) 'Descendents' $uc) -AttributeGuid $ag)) 'broad diagnostic rule (all properties, S+F) is not the toolkit rule'
Assert-Test (-not (Test-SoaSaclFingerprint -Rule (New-FakeRule 'S-1-5-11' ([DirectoryServices.ActiveDirectoryRights]::WriteProperty) 'Success' $ag 'Descendents' $uc) -AttributeGuid $ag)) 'other trustee is not the toolkit rule'
Assert-Test (-not (Test-SoaSaclFingerprint -Rule (New-FakeRule 'S-1-1-0' ([DirectoryServices.ActiveDirectoryRights]'WriteProperty, ReadProperty') 'Success' $ag 'Descendents' $uc) -AttributeGuid $ag)) 'extra rights are not the toolkit rule'
Assert-Test (-not (Test-SoaSaclFingerprint -Rule (New-FakeRule 'S-1-1-0' ([DirectoryServices.ActiveDirectoryRights]::WriteProperty) 'Success' $ag 'All' ([guid]::Empty)) -AttributeGuid $ag)) 'other inheritance is not the toolkit rule'

# Random secret
$sec = New-SoaRandomSecret
Assert-Test ($sec.Length -eq 120) 'random secret length 120'


# JSON array reading (Windows PowerShell 5.1 does not enumerate ConvertFrom-Json arrays)
$ja = Join-Path $tmp 'arr.json'
'[{"Test":"A"},{"Test":"B"},{"Test":"C"}]' | Set-Content -LiteralPath $ja
Assert-Test (@(Read-SoaJsonArray -Path $ja).Count -eq 3) 'Read-SoaJsonArray returns the elements, not a nested array'
'{"Test":"single"}' | Set-Content -LiteralPath $ja
Assert-Test (@(Read-SoaJsonArray -Path $ja).Count -eq 1) 'Read-SoaJsonArray handles a single object'
Assert-Test (@(Read-SoaJsonArray -Path (Join-Path $tmp 'missing.json')).Count -eq 0) 'Read-SoaJsonArray handles a missing file'

# Run log (Write-SoaLine copy for Export-SoaReport.ps1)
$rl = Join-Path $tmp 'run.log'
Set-SoaLineLog -Path $rl -Prefix 'RUN abcd1234'
Write-SoaLine ADD 'created something' 6>$null
Set-SoaLineLog
Write-SoaLine ADD 'not logged' 6>$null
$lines = @(Get-Content -LiteralPath $rl)
Assert-Test ($lines.Count -eq 1 -and $lines[0] -match '^\S+ RUN abcd1234 \[ADD\] created something$') 'Write-SoaLine copies to the run log only while it is set'

# Anonymizer
$an = New-SoaAnonymizer
Add-SoaAnonymizerTerm -Anonymizer $an -Kind DOMAIN -Value 'fabrikam.local'
Add-SoaAnonymizerTerm -Anonymizer $an -Kind NETBIOS -Value 'FABRIKAM'
Add-SoaAnonymizerTerm -Anonymizer $an -Kind DC -Value 'srv-dc1.fabrikam.local'
Add-SoaAnonymizerTerm -Anonymizer $an -Kind USER -Value 'jdoe'
Add-SoaAnonymizerTerm -Anonymizer $an -Kind GMSA -Value 'provAgentgMSA$'
Add-SoaAnonymizerTerm -Anonymizer $an -Kind TERM -Value 'Springfield'
$raw = "FABRIKAM\adm-x wrote CN=jdoe,OU=Sales,OU=Springfield,DC=fabrikam,DC=local on srv-dc1.fabrikam.local (SRV-DC1) " +
       "S-1-5-21-111-222-333-1105 3f2504e0-4f89-11d3-9a0c-0305e82c3301 bf967aba-0de6-11d0-a285-00aa003049e2 jdoe@fabrikam.com 10.1.2.3 " +
       "build 10.0.26100.32995 C:\Users\jdoe\x {""RunBy"":""FABRIKAM\\adm-x""} CN=SOA-CloudUsers-PSO,CN=Users"
$out = ConvertTo-SoaAnonymizedText -Anonymizer $an -Text $raw
Assert-Test ($out -notmatch '(?i)fabrikam|srv-dc1|jdoe|Springfield|adm-x|Sales|S-1-5-21-111|3f2504e0|10\.1\.2\.3') 'anonymizer removes domain, host, user, OU, account, SID, GUID, mail, IP'
Assert-Test ($out -match 'bf967aba-0de6-11d0-a285-00aa003049e2' -and $out -match '10\.0\.26100\.32995' -and $out -match 'CN=SOA-CloudUsers-PSO,CN=Users') 'anonymizer keeps schema GUIDs, OS builds and toolkit / well-known names'
Assert-Test ($out -match 'dc01\.corp\.example' -and $out -match 'S-1-5-21-1000000000-0-0-1105') 'pseudonyms are readable and keep the RID'
Assert-Test ((ConvertTo-SoaAnonymizedText -Anonymizer $an -Text 'jdoe') -eq (ConvertTo-SoaAnonymizedText -Anonymizer $an -Text 'JDOE')) 'pseudonyms are stable and case-insensitive'
Assert-Test (@(Find-SoaResidualIdentifier -Anonymizer $an -Text $out).Count -eq 0) 'leak check is clean on anonymized text'
Assert-Test (@(Find-SoaResidualIdentifier -Anonymizer $an -Text "$out srv-dc1").Count -ge 1) 'leak check finds a remaining original value'
Assert-Test (@(Find-SoaResidualIdentifier -Anonymizer $an -Text ('x' + '@' + 'contoso-real.de S-1-5-21-9-9-9')).Count -eq 2) 'leak check finds unknown e-mail addresses and domain SIDs'

# Configuration lookup, path guard, terms file, cumulative pseudonym map
$lay = Join-Path $tmp 'layout'; $laySc = Join-Path $lay 'scripts'; New-Item -Path $laySc -ItemType Directory -Force | Out-Null
Set-Content -LiteralPath (Join-Path $lay 'SoaToolkit.config.example.psd1') -Value '@{}'
$noCfg = $false; try { Resolve-SoaConfigPath -ScriptRoot $laySc | Out-Null } catch { $noCfg = $_.Exception.Message -match 'SoaToolkit\.config\.example\.psd1' }
Assert-Test $noCfg 'no configuration: the message names the template to copy'
Set-Content -LiteralPath (Join-Path $lay 'SoaToolkit.config.psd1') -Value '@{}'
Assert-Test ((Resolve-SoaConfigPath -ScriptRoot $laySc) -eq (Join-Path $lay 'SoaToolkit.config.psd1')) 'configuration found at the top level'
Set-Content -LiteralPath (Join-Path $laySc 'SoaToolkit.config.psd1') -Value '@{}'
$two = $false; try { Resolve-SoaConfigPath -ScriptRoot $laySc | Out-Null } catch { $two = $_.Exception.Message -match 'Two configuration files' }
Assert-Test $two 'two configuration files are refused'
Remove-Item -LiteralPath (Join-Path $lay 'SoaToolkit.config.psd1')
Assert-Test ((Resolve-SoaConfigPath -ScriptRoot $laySc 3>$null) -eq (Join-Path $laySc 'SoaToolkit.config.psd1')) 'configuration next to the script (hosts, layout <= 2.0.3) still works'
Assert-Test ($null -eq (Resolve-SoaConfigPath -ScriptRoot (Join-Path $tmp 'nothing') -Optional)) 'optional lookup returns nothing'
Assert-Test (Test-SoaPathInside -Path 'C:\ProgramData\SoaToolkit\Reports' -Parent 'c:/programdata/soatoolkit/') 'path containment: inside (case and separators ignored)'
Assert-Test (-not (Test-SoaPathInside -Path 'C:\ProgramData\SoaToolkitAdmin\Reports' -Parent 'C:\ProgramData\SoaToolkit')) 'path containment: sibling with common prefix is not inside'
$guardCfg = [pscustomobject]@{ ReportPath = 'C:\ProgramData\SoaToolkit\Reports'; DataPath = 'C:\ProgramData\SoaToolkit'; ScriptInstallPath = 'C:\Program Files\SoaToolkit'; AgentHosts = @('somewhere.contoso.com') }
$w = @(Assert-SoaAdminPaths -Config $guardCfg -ScriptRoot $laySc 3>&1)
Assert-Test ($w.Count -ge 1 -and "$($w[0])" -match 'inside DataPath') 'ReportPath inside DataPath is reported (warning off a toolkit host)'
$guardCfg.AgentHosts = @([Environment]::MachineName)
$blocked = $false; try { Assert-SoaAdminPaths -Config $guardCfg -ScriptRoot $laySc } catch { $blocked = $true }
Assert-Test $blocked 'ReportPath inside DataPath stops the script on a toolkit host'
$tf = Join-Path $tmp 't.txt'; Set-Content -LiteralPath $tf -Value @('# comment', '', '  Springfield  ', 'Contoso Ltd')
Assert-Test ((@(Read-SoaTermsFile -Path $tf) -join '|') -eq 'Springfield|Contoso Ltd') 'terms file: comments and empty lines ignored, trimmed'
$a1 = New-SoaAnonymizer; Add-SoaAnonymizerTerm -Anonymizer $a1 -Kind DC -Value 'srv-a.fabrikam.local'; Add-SoaAnonymizerTerm -Anonymizer $a1 -Kind DC -Value 'srv-b.fabrikam.local'
$a2 = New-SoaAnonymizer; Import-SoaAnonymizerMap -Anonymizer $a2 -Entries @(Get-SoaAnonymizerMap -Anonymizer $a1)
Add-SoaAnonymizerTerm -Anonymizer $a2 -Kind DC -Value 'srv-c.fabrikam.local'; Add-SoaAnonymizerTerm -Anonymizer $a2 -Kind DC -Value 'srv-b.fabrikam.local'
Assert-Test ((ConvertTo-SoaAnonymizedText -Anonymizer $a2 -Text 'srv-b srv-c') -eq 'dc02 dc03') 'imported map keeps pseudonyms and continues the numbering'

# Security claims checker must detect violations
$bad = Join-Path $tmp 'claims'; New-Item -Path $bad -ItemType Directory -Force | Out-Null
Set-Content -LiteralPath (Join-Path $bad 'Bad.ps1') -Value @(
    '$u = Get-ADUser x -Properties ntPwdHistory'
    'Invoke-WebRequest https://example.invalid/x'
    'Set-ADAccountPassword -Identity x -Reset -NewPassword $p'
    '[Convert]::FromBase64String("eA==")'
)
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaSecurityClaims.ps1') -Path $bad *> $null
Assert-Test ($LASTEXITCODE -eq 1) 'Test-SoaSecurityClaims.ps1 fails on a script with violations'
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaSecurityClaims.ps1') *> $null
Assert-Test ($LASTEXITCODE -eq 0) 'Test-SoaSecurityClaims.ps1 passes on the toolkit scripts'

# Script scope checker must detect an overwritten script-level value (the 2.0.4 Install / Watch defect)
$scopeDir = Join-Path $tmp 'scope'; New-Item -Path $scopeDir -ItemType Directory -Force | Out-Null
Set-Content -LiteralPath (Join-Path $scopeDir 'Bad.ps1') -Value @(
    '$G = Get-SoaConstant ''Guid'''
    '$Ucc = Get-SoaConstant ''Ucc'''
    'switch ($x) { ''a'' { $g = Get-ADGroup x } }'
    'foreach ($u in $users) { $ucc = [int]$u.y }'
    '$m = Get-SoaManifest -Config $c'
    'if ($z) { $m = Get-SoaManifest -Config $c }'
    'function Test-Local { $g = 1 }'
    '$sb = { $g = 2 }'
)
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') -Path $scopeDir *> $null
Assert-Test ($LASTEXITCODE -eq 1) 'Test-SoaScriptScope.ps1 fails on a script that overwrites a script-level value'
Set-Content -LiteralPath (Join-Path $scopeDir 'Bad.ps1') -Value @('$G = Get-SoaConstant ''Guid''', 'function Test-Local { $g = 1 }', '$sb = { $g = 2 }', '$m = Get-SoaManifest -Config $c', 'if ($z) { $m = Get-SoaManifest -Config $c }')
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') -Path $scopeDir *> $null
Assert-Test ($LASTEXITCODE -eq 0) 'Test-SoaScriptScope.ps1 accepts function scope, stored script blocks and a deliberate refresh'
Set-Content -LiteralPath (Join-Path $scopeDir 'Mod.psm1') -Value @('function New-Thing { [CmdletBinding(SupportsShouldProcess)] param($Name) if ($PSCmdlet.ShouldProcess($Name)) { } }')
Set-Content -LiteralPath (Join-Path $scopeDir 'Caller.ps1') -Value @('[CmdletBinding(SupportsShouldProcess = $true)] param()', 'New-Thing -Name a')
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') -Path $scopeDir *> $null
Assert-Test ($LASTEXITCODE -eq 1) 'Test-SoaScriptScope.ps1 fails when a ShouldProcess module function is called without -WhatIf'
Set-Content -LiteralPath (Join-Path $scopeDir 'Caller.ps1') -Value @('[CmdletBinding(SupportsShouldProcess = $true)] param()', 'New-Thing -Name a -WhatIf:$WhatIfPreference')
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') -Path $scopeDir *> $null
Assert-Test ($LASTEXITCODE -eq 0) 'Test-SoaScriptScope.ps1 accepts -WhatIf:$WhatIfPreference'
# Scratch files and run logs must be written also during -WhatIf (the 2.0.5 DeployTasks / run-log defect)
Set-Content -LiteralPath (Join-Path $scopeDir 'Scratch.ps1') -Value @(
    '[CmdletBinding(SupportsShouldProcess = $true)] param()'
    '$stage = Join-Path $env:TEMP ''soa_stage_x'''
    'New-Item -Path $stage -ItemType Directory -Force | Out-Null'
    '$runLog = Join-Path $root ''install_x.log'''
    'function Write-RunLog($t) { Add-Content -Path $runLog -Value $t }'
)
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') -Path $scopeDir *> $null
Assert-Test ($LASTEXITCODE -eq 1) 'Test-SoaScriptScope.ps1 fails on scratch / run-log writes that -WhatIf would skip'
Set-Content -LiteralPath (Join-Path $scopeDir 'Scratch.ps1') -Value @(
    '[CmdletBinding(SupportsShouldProcess = $true)] param()'
    '$stage = Join-Path $env:TEMP ''soa_stage_x'''
    'New-Item -Path $stage -ItemType Directory -Force -WhatIf:$false | Out-Null'
    'if ($PSCmdlet.ShouldProcess(''host'')) { Copy-Item -LiteralPath (Join-Path $stage ''a.ps1'') -Destination ''C:\Target\a.ps1'' -Force }'
    '$runLog = Join-Path $root ''install_x.log'''
    'function Write-RunLog($t) { Add-Content -Path $runLog -Value $t -WhatIf:$false }'
    '$sb = { Remove-Item -Path (Join-Path $env:TEMP ''x'') }'
)
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') -Path $scopeDir *> $null
Assert-Test ($LASTEXITCODE -eq 0) 'Test-SoaScriptScope.ps1 accepts -WhatIf:$false on scratch paths and real writes from the scratch folder'
Add-Content -LiteralPath (Join-Path $scopeDir 'Scratch.ps1') -Value '$p = Start-Process -FilePath ''msiexec.exe'' -Wait -PassThru'
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') -Path $scopeDir *> $null
Assert-Test ($LASTEXITCODE -eq 1) 'Test-SoaScriptScope.ps1 fails on Start-Process in a script with -WhatIf'
Remove-Item -LiteralPath (Join-Path $scopeDir 'Scratch.ps1') -Force
# @() around a List[object] throws "Argument types do not match" (2.0.7 lab: Watch-CloudUserConformance.ps1 report output)
Set-Content -LiteralPath (Join-Path $scopeDir 'List.ps1') -Value @('$l = New-Object System.Collections.Generic.List[object]', '$a = @($l)')
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') -Path $scopeDir *> $null
Assert-Test ($LASTEXITCODE -eq 1) 'Test-SoaScriptScope.ps1 fails on @() around a List[object]'
Set-Content -LiteralPath (Join-Path $scopeDir 'List.ps1') -Value @('$l = New-Object System.Collections.Generic.List[object]', '$a = $l.ToArray()', '$b = @($l | Where-Object { $_ })', 'function Get-Other([object[]]$L) { @($L) }', '$rows = foreach ($i in 1..2) { $v = New-Object System.Collections.Generic.List[object]; $i }', '$c = @($rows)')
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') -Path $scopeDir *> $null
Assert-Test ($LASTEXITCODE -eq 0) 'Test-SoaScriptScope.ps1 accepts ToArray(), a pipeline, the same name in another function and loop output'
Remove-Item -LiteralPath (Join-Path $scopeDir 'List.ps1') -Force
# A parameter replaced by a variable of the same name in other case (2.0.8: $p replaced $P in the monitor's host block)
Set-Content -LiteralPath (Join-Path $scopeDir 'Param.ps1') -Value @('$sb = { param($P) $p = Get-Item x; $P.Admin }', 'function Set-X([string]$Mode) { $mode = 1 }')
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') -Path $scopeDir *> $null
Assert-Test ($LASTEXITCODE -eq 1) 'Test-SoaScriptScope.ps1 fails when a variable of the same name in other case replaces a parameter'
Set-Content -LiteralPath (Join-Path $scopeDir 'Param.ps1') -Value @('param([string]$ConfigPath)', '$ConfigPath = Resolve-X $ConfigPath', '$sb = { param($P) $diag = Get-Item x; $P.Admin }', 'function Get-Y { $p = 1 }')
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') -Path $scopeDir *> $null
Assert-Test ($LASTEXITCODE -eq 0) 'Test-SoaScriptScope.ps1 accepts a reassignment in the same spelling and the name in another scope'
Remove-Item -LiteralPath (Join-Path $scopeDir 'Param.ps1') -Force
# Assessment of monitor results (Get-SoaCheckAssessment, docs/CHECKS.md)
$as = Get-SoaCheckAssessment -CheckId 'TASK-MISSING' -Status 'FAIL' -PlannedSteps @('HostGroup', 'DeployTasks')
Assert-Test ($as.Class -eq 'PLANNED' -and $as.Fix -match 'DeployTasks') 'assessment: a check that a step of the dry run creates is PLANNED'
Assert-Test ((Get-SoaCheckAssessment -CheckId 'TASK-MISSING' -Status 'FAIL').Class -eq 'ACTION') 'assessment: the same check without that step is ACTION'
Assert-Test ((Get-SoaCheckAssessment -CheckId 'USR-PSOGROUP' -Status 'FAIL' -PlannedSteps @('DeployTasks')).Class -eq 'FOLLOW-UP') 'assessment: users not yet in the PSO group are FOLLOW-UP (reconcile run)'
Assert-Test ((Get-SoaCheckAssessment -CheckId 'AGENT-SVC' -Status 'FAIL' -PlannedSteps @('DeployTasks')).Class -eq 'BLOCKER') 'assessment: a missing provisioning agent is a BLOCKER'
Assert-Test ((Get-SoaCheckAssessment -CheckId 'DC-LOAD' -Status 'WARN').Class -eq 'FOLLOW-UP' -and (Get-SoaCheckAssessment -CheckId 'DC-LOAD' -Status 'FAIL').Class -eq 'BLOCKER') 'assessment: status-specific class (DC-LOAD WARN / FAIL)'
Assert-Test ((Get-SoaCheckAssessment -CheckId 'DC-KERB-0x17' -Status 'FAIL').Class -eq 'REVIEW') 'assessment: wildcard entry for Kerberos status codes'
Assert-Test ($null -eq (Get-SoaCheckAssessment -CheckId 'TASK-MISSING' -Status 'PASS') -and (Get-SoaCheckAssessment -CheckId 'NO-SUCH-CHECK' -Status 'WARN').Class -eq 'REVIEW') 'assessment: nothing for PASS, REVIEW for an unknown check'
$htmlRows = New-Object System.Collections.Generic.List[object]
$htmlRows.Add([pscustomobject]@{ Status = 'PASS'; Item = 'a' }); $htmlRows.Add([pscustomobject]@{ Status = 'WARN'; Item = 'b<c' })
try { $html = ConvertTo-SoaHtmlTable -Rows $htmlRows -Properties @('Status', 'Item'); Assert-Test (([regex]::Matches($html, '<tr class=')).Count -eq 2 -and $html -match 'b&lt;c') 'ConvertTo-SoaHtmlTable accepts a List[object] (no @() around it)' }
catch { Assert-Test $false "ConvertTo-SoaHtmlTable accepts a List[object] (no @() around it): $($_.Exception.Message)" }

# Release tooling: Set-SoaVersion.ps1 on a fixture (no git, no GitHub, no PDF, no checks)
$en = [char]0x2013
$sv = Join-Path $tmp 'setversion'
foreach ($d in 'scripts', '.github\release-notes') { New-Item -Path (Join-Path $sv $d) -ItemType Directory -Force | Out-Null }
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
function Write-Fixture([string]$Rel, [string[]]$Lines) { [IO.File]::WriteAllText((Join-Path $sv $Rel), (($Lines -join "`n") + "`n"), $utf8NoBom) }
Write-Fixture 'scripts\SoaToolkit.psm1' @("`$script:SoaVersion     = '1.2.3'", "`$script:SoaReleaseDate = '2026-01-01'")
Write-Fixture 'scripts\Tool.ps1' @('<#', '.NOTES', ('    Toolkit: cloudsync-soa' + '-toolkit 1.2.3 (2026-01-01)'), '#>')   # split: H6 must not see a version line in tests\
Write-Fixture 'SoaToolkit.config.example.psd1' @('# SOA Toolkit configuration TEMPLATE (cloudsync-soa-toolkit 1.2.3)', '@{}')
Write-Fixture 'README.md' @('> **Status: 1.2.3 (2026-01-01).** text')
Write-Fixture 'CHANGELOG.md' @('# Changelog', '', '## Unreleased', '', '### Fixed', '', '- fix a', '', "## 1.2.3 $en 2026-01-01", '', '- old')
Write-Fixture '.github\release-notes\v1.2.3.md' @('notes', '---', 'Licensed under MPL-2.0 x [README](https://github.com/x/blob/v1.2.3/README.md)')
$setVersion = Join-Path (Join-Path $repo 'tools') 'Set-SoaVersion.ps1'
$svArgs = @('-Root', $sv, '-SkipRemoteCheck', '-NoStage', '-SkipPdf', '-SkipChecks')
& $exe -NoProfile -NonInteractive -File $setVersion -Version 1.3.0 -Date 2026-02-02 @svArgs *> $null
$clText = [IO.File]::ReadAllText((Join-Path $sv 'CHANGELOG.md'))
Assert-Test ($LASTEXITCODE -eq 0 -and [IO.File]::ReadAllText((Join-Path $sv 'scripts\SoaToolkit.psm1')) -match "SoaVersion\s+= '1\.3\.0'[\s\S]*SoaReleaseDate = '2026-02-02'") 'Set-SoaVersion.ps1 sets version and date in the module'
Assert-Test (([IO.File]::ReadAllText((Join-Path $sv 'scripts\Tool.ps1')) -match 'Toolkit: cloudsync-soa-toolkit 1\.3\.0 \(2026-02-02\)') -and ([IO.File]::ReadAllText((Join-Path $sv 'SoaToolkit.config.example.psd1')) -match 'cloudsync-soa-toolkit 1\.3\.0\)') -and ([IO.File]::ReadAllText((Join-Path $sv 'README.md')) -match 'Status: 1\.3\.0 \(2026-02-02\)')) 'Set-SoaVersion.ps1 sets script help, configuration header and README status'
Assert-Test ($clText -match ("(?s)## Unreleased\n\n## 1\.3\.0 $en 2026-02-02\n\n### Fixed\n\n- fix a\n\n## 1\.2\.3 ")) 'Set-SoaVersion.ps1 turns Unreleased into the version section and leaves an empty Unreleased'
$newNotes = Join-Path $sv '.github\release-notes\v1.3.0.md'
Assert-Test ((Test-Path $newNotes) -and ([IO.File]::ReadAllText($newNotes) -match '^<!-- title: v1\.3\.0') -and ([IO.File]::ReadAllText($newNotes) -match 'TODO-RELEASE-NOTES') -and ([IO.File]::ReadAllText($newNotes) -match 'blob/v1\.3\.0/README')) 'Set-SoaVersion.ps1 creates the release notes template (title line, TODO marker, footer)'
& $exe -NoProfile -NonInteractive -File $setVersion -Version 1.3.0 -Date 2026-02-02 @svArgs *> $null
Assert-Test ($LASTEXITCODE -eq 0 -and [IO.File]::ReadAllText((Join-Path $sv 'CHANGELOG.md')) -ceq $clText) 'Set-SoaVersion.ps1 repeated with the same version changes nothing'
& $exe -NoProfile -NonInteractive -File $setVersion -Version 1.2.9 @svArgs *> $null
Assert-Test ($LASTEXITCODE -eq 1) 'Set-SoaVersion.ps1 refuses a lower version'
& $exe -NoProfile -NonInteractive -File $setVersion -Version 1.4.0 @svArgs *> $null
Assert-Test ($LASTEXITCODE -eq 1) 'Set-SoaVersion.ps1 refuses an empty Unreleased section'

# Release tooling: Test-SoaReleaseTag.ps1 against a local git repository (origin/main simulated with update-ref)
$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) { Write-Host 'SKIP Test-SoaReleaseTag.ps1 tests (git not found)' -ForegroundColor DarkGray } else {
    $rt = Join-Path $tmp 'releasetag'
    New-Item -Path (Join-Path $rt 'scripts') -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $rt '.github\release-notes') -ItemType Directory -Force | Out-Null
    $id = @('-c', 'user.name=Release Test', '-c', 'user.email=release-test@example.invalid', '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false')
    function Invoke-TestGit([string[]]$GitArgs) { $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'; try { & git -C $rt @id @GitArgs 2>&1 | Out-Null } finally { $ErrorActionPreference = $prev } }
    function Write-RtFile([string]$Rel, [string[]]$Lines) { [IO.File]::WriteAllText((Join-Path $rt $Rel), (($Lines -join "`n") + "`n"), $utf8NoBom) }
    Write-RtFile 'scripts\SoaToolkit.psm1' @("`$script:SoaVersion     = '1.3.0'", "`$script:SoaReleaseDate = '2026-02-02'")
    Write-RtFile 'CHANGELOG.md' @('# Changelog', '', '## Unreleased', '', "## 1.3.0 $en 2026-02-02", '', '- fix a')
    Write-RtFile '.github\release-notes\v1.3.0.md' @('<!-- title: v1.3.0 - test release -->', '', 'Notes.')
    Invoke-TestGit @('init', '-q'); Invoke-TestGit @('add', '-A'); Invoke-TestGit @('commit', '-q', '-m', 'release')
    Invoke-TestGit @('update-ref', 'refs/remotes/origin/main', 'HEAD')
    $tagTool = Join-Path (Join-Path $repo 'tools') 'Test-SoaReleaseTag.ps1'
    $notesOut = Join-Path $tmp 'notes-out.md'
    function Invoke-TagCheck([string[]]$Extra) { & $exe -NoProfile -NonInteractive -File $tagTool -Tag v1.3.0 -Root $rt -SkipReleaseCheck @Extra *> $null; $LASTEXITCODE }
    Invoke-TestGit @('tag', '-a', 'v1.3.0', '-m', 'test')
    Assert-Test ((Invoke-TagCheck @()) -eq 1) 'Test-SoaReleaseTag.ps1 fails on an unsigned tag'
    Assert-Test ((Invoke-TagCheck @('-AllowUnsigned', '-NotesOut', $notesOut)) -eq 0 -and ([IO.File]::ReadAllText($notesOut) -match '^Notes\.')) 'Test-SoaReleaseTag.ps1 accepts an unsigned annotated tag with -AllowUnsigned and writes the notes without the title line'
    & $exe -NoProfile -NonInteractive -Command "[Console]::OutputEncoding = [Text.Encoding]::GetEncoding(850); & '$tagTool' -Tag v1.3.0 -Root '$rt' -SkipReleaseCheck -AllowUnsigned; exit `$LASTEXITCODE" *> $null
    Assert-Test ($LASTEXITCODE -eq 0) 'Test-SoaReleaseTag.ps1 reads git output as UTF-8 also with an OEM console code page (850)'
    Invoke-TestGit @('tag', '-d', 'v1.3.0'); Invoke-TestGit @('tag', 'v1.3.0')
    Assert-Test ((Invoke-TagCheck @('-AllowUnsigned')) -eq 1) 'Test-SoaReleaseTag.ps1 fails on a lightweight tag'
    Invoke-TestGit @('tag', '-d', 'v1.3.0')
    Write-RtFile 'other.txt' @('not on main'); Invoke-TestGit @('add', '-A'); Invoke-TestGit @('commit', '-q', '-m', 'side')
    Invoke-TestGit @('tag', '-a', 'v1.3.0', '-m', 'test')
    Assert-Test ((Invoke-TagCheck @('-AllowUnsigned')) -eq 1) 'Test-SoaReleaseTag.ps1 fails when the tagged commit is not on main'
    Invoke-TestGit @('tag', '-d', 'v1.3.0'); Invoke-TestGit @('update-ref', 'refs/remotes/origin/main', 'HEAD')
    # SSH-signed tags (PowerShell 7 only: Windows PowerShell 5.1 drops the empty passphrase argument of ssh-keygen)
    $keygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if (-not $keygen -or $PSVersionTable.PSEdition -eq 'Desktop') { Write-Host 'SKIP signed-tag tests (ssh-keygen not found or Windows PowerShell 5.1)' -ForegroundColor DarkGray } else {
        $k1 = Join-Path $tmp 'sign1'; $k2 = Join-Path $tmp 'sign2'
        foreach ($k in $k1, $k2) { & $keygen.Source -q -t ed25519 -N '' -C release-test -f $k 2>&1 | Out-Null }
        Write-RtFile '.github\allowed_signers' @("release-test@example.invalid namespaces=`"git`" $((Get-Content "$k1.pub" -Raw).Trim())")
        Invoke-TestGit @('add', '-A'); Invoke-TestGit @('commit', '-q', '-m', 'allowed signers'); Invoke-TestGit @('update-ref', 'refs/remotes/origin/main', 'HEAD')
        Invoke-TestGit @('-c', 'gpg.format=ssh', '-c', 'gpg.ssh.program=ssh-keygen', '-c', "user.signingkey=$k1", 'tag', '-s', 'v1.3.0', '-m', 'signed')
        $signed = ((& git -C $rt cat-file tag v1.3.0) -join "`n") -match 'BEGIN SSH SIGNATURE'
        if (-not $signed) { Write-Host 'SKIP signed-tag tests (git could not sign with ssh-keygen here)' -ForegroundColor DarkGray } else {
            Assert-Test ((Invoke-TagCheck @()) -eq 0) 'Test-SoaReleaseTag.ps1 accepts a tag signed with a key from allowed_signers on main'
            Invoke-TestGit @('tag', '-d', 'v1.3.0')
            Invoke-TestGit @('-c', 'gpg.format=ssh', '-c', 'gpg.ssh.program=ssh-keygen', '-c', "user.signingkey=$k2", 'tag', '-s', 'v1.3.0', '-m', 'signed with another key')
            Assert-Test ((Invoke-TagCheck @('-AllowUnsigned')) -eq 1) 'Test-SoaReleaseTag.ps1 fails on a signature by an unknown key, also with -AllowUnsigned'
        }
    }
}
& $exe -NoProfile -NonInteractive -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaScriptScope.ps1') *> $null
Assert-Test ($LASTEXITCODE -eq 0) 'Test-SoaScriptScope.ps1 passes on the toolkit scripts and tools'

# Export-SoaReport.ps1 end to end (mocked ActiveDirectory module, child process)
& $exe -NoProfile -NonInteractive -File (Join-Path $ScriptRoot 'Test-SoaExportReport.ps1') -WorkPath (Join-Path $tmp 'export')
Assert-Test ($LASTEXITCODE -eq 0) 'Export-SoaReport.ps1 end-to-end test (see output above)'
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "FAILURES: $script:fail"
exit $script:fail
