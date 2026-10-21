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
    - Export-SoaReport.ps1 end to end against a mocked ActiveDirectory module (tests\mocks) and generated fixtures:
      L1-L20 evaluation, anonymization, map outside the folder, leak check, packaging refusal on a leak
    Child processes are used where mocks must not leak into the main test scope.

.NOTES
    Toolkit: cloudsync-soa-toolkit 2.0.3 (2026-10-21)
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
(Get-Content (Join-Path (Join-Path $repo 'scripts') 'SoaToolkit.config.psd1') -Raw) -replace 'C:\\ProgramData\\SoaToolkit\\Reports', ((Join-Path $tmp 'reports') -replace "'", "''") | Set-Content $tmpCfg
$cfg = Import-SoaConfig -Path $tmpCfg
Assert-Test ($cfg.Pso.MinPasswordLength -eq 64) 'config PSO min length 64'
Assert-Test ($cfg.Pso.MaxPasswordAgeDays -eq 30) 'config PSO max age 30'
Assert-Test ($cfg.GmsaName -eq 'gmsaSoaToolkit') 'config gMSA'
Assert-Test (@($cfg.AgentHosts).Count -eq 2) 'config agent hosts'

# Legacy key warning / validation
$bad = Join-Path $tmp 'bad.psd1'
"@{ AgentHosts=@('a'); RotationDays = 30; Pso=@{ MaxPasswordAgeDays = 0 } }" | Set-Content $bad
try { Import-SoaConfig -Path $bad 3>$null | Out-Null; Assert $false 'invalid config throws' } catch { Assert-Test ($_.Exception.Message -match 'MaxPasswordAgeDays') 'invalid config throws (MaxPasswordAgeDays)' }

# Marker
$mk = Get-SoaMarker -Config $cfg -Short -Purpose 'Test'
Assert-Test (Test-SoaMarker $mk) 'marker recognized'
Assert-Test ($mk -match 'do not modify manually') 'marker text'
Assert-Test (-not (Test-SoaMarker 'something else')) 'non-marker not recognized'

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

# Security claims checker must detect violations
$bad = Join-Path $tmp 'claims'; New-Item -Path $bad -ItemType Directory -Force | Out-Null
Set-Content -LiteralPath (Join-Path $bad 'Bad.ps1') -Value @(
    '$u = Get-ADUser x -Properties ntPwdHistory'
    'Invoke-WebRequest https://example.invalid/x'
    'Set-ADAccountPassword -Identity x -Reset -NewPassword $p'
    '[Convert]::FromBase64String("eA==")'
)
& $exe -NoProfile -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaSecurityClaims.ps1') -Path $bad *> $null
Assert-Test ($LASTEXITCODE -eq 1) 'Test-SoaSecurityClaims.ps1 fails on a script with violations'
& $exe -NoProfile -File (Join-Path (Join-Path $repo 'tools') 'Test-SoaSecurityClaims.ps1') *> $null
Assert-Test ($LASTEXITCODE -eq 0) 'Test-SoaSecurityClaims.ps1 passes on the toolkit scripts'

# Export-SoaReport.ps1 end to end (mocked ActiveDirectory module, child process)
& $exe -NoProfile -File (Join-Path $ScriptRoot 'Test-SoaExportReport.ps1') -WorkPath (Join-Path $tmp 'export')
Assert-Test ($LASTEXITCODE -eq 0) 'Export-SoaReport.ps1 end-to-end test (see output above)'
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "FAILURES: $script:fail"
exit $script:fail
