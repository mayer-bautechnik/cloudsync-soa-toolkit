#Requires -Version 5.1
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
<#
.SYNOPSIS
    End-to-end test of Export-SoaReport.ps1 against the mocked ActiveDirectory module in tests\mocks (fictitious
    domain fabrikam.local). Called by Invoke-SoaUnitTests.ps1; exit code = number of failed assertions.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $WorkPath)
$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }   # $PSScriptRoot can be empty in Windows PowerShell 5.1 (-File)
$repo = Split-Path $ScriptRoot -Parent
$env:PSModulePath = (Join-Path $ScriptRoot 'mocks') + [IO.Path]::PathSeparator + $env:PSModulePath
$fail = 0
function Assert-Test($Condition, [string]$Message) { if ($Condition) { Write-Host "PASS export: $Message" -ForegroundColor Green } else { Write-Host "FAIL export: $Message" -ForegroundColor Red; $script:fail++ } }

# Fixtures: a lab after installation, a few tests and one event-triggered run per origin
$rp = Join-Path $WorkPath 'rp'; $dp = Join-Path $WorkPath 'data'
foreach ($d in 'Prerequisites\20261101_1000', 'Monitor', 'Tests', 'State', 'Impact\20261102_1000') { New-Item -Path (Join-Path $rp $d) -ItemType Directory -Force | Out-Null }
New-Item -Path (Join-Path $dp 'Journal') -ItemType Directory -Force | Out-Null
Set-Content -LiteralPath (Join-Path $rp 'Prerequisites\20261101_1000\checks.csv') -Value @'
"DC","Check","Status","Detail"
"srv-dc1.fabrikam.local","ntdsai.dll","PASS","10.0.26100.32995"
"srv-dc2.fabrikam.local","KIR override","WARN","not applied yet on SRV-DC2 (restart pending)"
'@
Set-Content -LiteralPath (Join-Path $rp 'State\install_20261101.log') -Value @'
2026-11-01T10:00:00 FABRIKAM\adm-jl RUN aaaa1111 START tool=Install version=2.0.2 steps=HostGroup,Gmsa,BatchLogonGpo,DiagnosticsGpo,AuditConfig,EnableRolling,Policy,Groups,Pso,Delegate,AllowList,DeployTasks,Verify whatif=True
2026-11-01T10:00:01 RUN aaaa1111 [ADD] group SOA-Toolkit-Hosts in OU=Groups,OU=Tier0,DC=fabrikam,DC=local
2026-11-01T10:00:02 RUN aaaa1111 [ADD] SACL on OU=Cloud Users,OU=Fuerth,DC=fabrikam,DC=local
2026-11-01T10:00:09 FABRIKAM\adm-jl RUN aaaa1111 END
2026-11-01T11:00:00 FABRIKAM\adm-jl RUN bbbb2222 START tool=Install version=2.0.2 steps=HostGroup,Gmsa,BatchLogonGpo,DiagnosticsGpo,AuditConfig,EnableRolling,Policy,Groups,Pso,Delegate,AllowList,DeployTasks,Verify whatif=False
2026-11-01T11:00:01 RUN bbbb2222 [ADD] group SOA-Toolkit-Hosts in OU=Groups,OU=Tier0,DC=fabrikam,DC=local
2026-11-01T11:00:02 RUN bbbb2222 [ADD] SACL on OU=Cloud Users,OU=Fuerth,DC=fabrikam,DC=local
2026-11-01T11:00:03 RUN bbbb2222 [SAME] something
2026-11-01T11:00:09 FABRIKAM\adm-jl RUN bbbb2222 END
2026-11-01T13:00:00 FABRIKAM\adm-jl RUN cccc3333 START tool=Install version=2.0.2 steps=HostGroup,Gmsa,BatchLogonGpo,DiagnosticsGpo,AuditConfig,EnableRolling,Policy,Groups,Pso,Delegate,AllowList,DeployTasks,Verify whatif=False
2026-11-01T13:00:01 RUN cccc3333 [SAME] group SOA-Toolkit-Hosts present
2026-11-01T13:00:02 RUN cccc3333 [SAME] SACL on OU=Cloud Users,OU=Fuerth,DC=fabrikam,DC=local: toolkit entry present
2026-11-01T13:00:09 FABRIKAM\adm-jl RUN cccc3333 END
'@
Set-Content -LiteralPath (Join-Path $rp 'Monitor\monitor_20261105_0900.json') -Value @'
{"Time":"2026-11-05T09:00:00","Overall":"WARN","Counts":{"PASS":20,"INFO":3,"WARN":1,"FAIL":0},
 "Results":[{"CheckId":"DC-NTDSAI","Area":"DC srv-dc1","Item":"ntdsai.dll","Status":"PASS","Detail":"ok","Objects":[]},
 {"CheckId":"DC-KIR","Area":"DC srv-dc2","Item":"KIR","Status":"PASS","Detail":"ok","Objects":[]},
 {"CheckId":"DC-LOAD","Area":"DC srv-dc2","Item":"3095","Status":"PASS","Detail":"loaded","Objects":[]},
 {"CheckId":"DC-AUDIT","Area":"DC srv-dc1","Item":"audit","Status":"PASS","Detail":"ok","Objects":[]},
 {"CheckId":"AUD-SACL","Area":"Audit","Item":"SACL OU=Cloud Users,OU=Fuerth,DC=fabrikam,DC=local","Status":"PASS","Detail":"toolkit entry present","Objects":[]},
 {"CheckId":"BATCH","Area":"Host srv-dc1","Item":"batch logon","Status":"PASS","Detail":"gMSA FABRIKAM\\gmsaSoaToolkit$ present","Objects":[]},
 {"CheckId":"GRP-DRIFT","Area":"Toolkit objects","Item":"drift","Status":"WARN","Detail":"1 - mmuster removed next run","Objects":["mmuster"]}],
 "Users":[{"Status":"PASS","User":"jdoe","Origin":"cloud-native","SCRIL":true,"PNE":false,"PsoGroup":true,"Expiry":"2026-12-03 10:00","SecretChanged":"2026-11-03 10:01","LastLogon":"2026-11-04 08:00","Issues":""}]}
'@
Set-Content -LiteralPath (Join-Path $rp 'Tests\test-state.json') -Value @'
[{"Test":"Scril","Time":"2026-11-02T10:00:00","PolicyMode":"Audit","Status":"PASS","Detail":"matrix as K11","RunBy":"FABRIKAM\\adm-jl"},
 {"Test":"Onboarding","Time":"2026-11-02T11:00:00","PolicyMode":"Audit","Status":"PASS","Detail":"restored by reconcile on SRV-DC2","RunBy":"FABRIKAM\\adm-jl"},
 {"Test":"ProbeAllowed","Time":"2026-11-02T12:00:00","PolicyMode":"Audit","Status":"PASS","Detail":"ok","RunBy":"FABRIKAM\\adm-jl"},
 {"Test":"UnauthorizedWrite","Time":"2026-11-02T12:01:00","PolicyMode":"Audit","Status":"INFO","Detail":"audit mode - 3097 logged","RunBy":"FABRIKAM\\adm-jl"}]
'@
Set-Content -LiteralPath (Join-Path $rp 'Impact\20261102_1000\writer-summary.csv') -Value @'
"Verdict","Subject","Count","Events","Targets","LastSeen"
"allowed (agent)","FABRIKAM\provAgentgMSA$","12","5136","7","2026-11-02"
"WOULD BE BLOCKED","FABRIKAM\helpdesk-anna","2","5136","1","2026-11-01"
'@
Set-Content -LiteralPath (Join-Path $dp 'Journal\journal-202611.jsonl') -Value @'
{"Time":"2026-11-03T10:01:10","Host":"SRV-DC2","Server":"srv-dc2.fabrikam.local","Trigger":"Event","RunAs":"FABRIKAM\\gmsaSoaToolkit$","User":"jdoe","Dn":"CN=John Doe,OU=Cloud Users,OU=Fuerth,DC=fabrikam,DC=local","ObjectGuid":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","Before":{"Scril":false,"Pne":false,"InPsoGroup":false},"Actions":["userAccountControl 0x200 -> 0x40200 (Cas)","member of SOA-CloudUsers-PSO"]}
{"Time":"2026-11-04T09:02:00","Host":"SRV-DC1","Server":"srv-dc1.fabrikam.local","Trigger":"Event","RunAs":"FABRIKAM\\gmsaSoaToolkit$","User":"mmuster","Dn":"CN=Max Muster,OU=Staff,OU=Fuerth,DC=fabrikam,DC=local","ObjectGuid":"4f2504e0-4f89-11d3-9a0c-0305e82c3302","Before":{"Scril":false,"Pne":true,"InPsoGroup":false},"Actions":["userAccountControl 0x10200 -> 0x40200 (Cas)"]}
'@
$cfgPath = Join-Path $WorkPath 'cfg.psd1'
@"
@{
    ProjectUrl = 'https://github.com/mayer-bautechnik/cloudsync-soa-toolkit'
    AgentHosts = @('srv-dc1.fabrikam.local', 'srv-dc2.fabrikam.local')
    AgentGmsaNames = @('FABRIKAM\provAgentgMSA$')
    ToolkitGroupOU = 'OU=Groups,OU=Tier0,DC=fabrikam,DC=local'
    ReportPath = '$($rp -replace "'", "''")'
    DataPath = '$($dp -replace "'", "''")'
    TestUser = 'jdoe'
}
"@ | Set-Content -LiteralPath $cfgPath

Set-Content -LiteralPath (Join-Path $WorkPath 'SoaToolkit.terms.txt') -Value @('# test terms', 'Fuerth', 'Max Muster')
Add-Content -LiteralPath (Join-Path $rp 'Prerequisites\20261101_1000\checks.csv') -Value '"srv-dc1.fabrikam.local","note","INFO","mail relay fabrikam-group.com"'
$export = Join-Path (Join-Path $repo 'scripts') 'Export-SoaReport.ps1'
& $export -Record L16 -Result PASS -Note 'department change for jdoe arrived on SRV-DC1' -ConfigPath $cfgPath 6>$null | Out-Null
& $export -NoRemote -Days 400 -ConfigPath $cfgPath 6>$null | Out-Null
$bundle = @(Get-ChildItem -LiteralPath (Join-Path $rp 'Export') -Directory | Where-Object { $_.Name -like 'SoaReport_*' })[0].FullName
$report = Get-Content -LiteralPath (Join-Path $bundle 'report.json') -Raw | ConvertFrom-Json
$st = @{}; foreach ($i in $report.Validation) { $st[$i.Id] = $i.Status }

Assert-Test (Test-Path (Join-Path $bundle 'README-FIRST.md')) 'README-FIRST.md written'
Assert-Test ($st.L1 -eq 'WARN' -and $st.L2 -eq 'REVIEW' -and $st.L3 -eq 'PASS') 'L1 WARN (one WARN check), L2 REVIEW (dry run), L3 PASS (repeat run only SAME)'
Assert-Test ($st.L5 -eq 'PASS' -and $st.L6 -eq 'PASS' -and $st.L7 -eq 'OPEN') 'L5 / L6 PASS from the monitor report, L7 OPEN without remote collection'
Assert-Test ($st.L8 -eq 'PASS' -and $st.L9 -eq 'PASS' -and $st.L11 -eq 'PASS') 'L8 cloud-native, L9 SOA-converted, L11 update method from the journal'
Assert-Test ($st.L14 -eq 'WARN' -and $st.L15 -eq 'OPEN' -and $st.L16 -eq 'PASS') 'L14 WARN (writer would be blocked), L15 OPEN (tests in Audit), L16 manual PASS'
Assert-Test ($report.Anonymized -and $report.Environment.Domain -eq 'corp.example') 'environment anonymized'
$all = (Get-ChildItem -LiteralPath $bundle -Recurse -File | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
Assert-Test ($all -notmatch '(?i)fabrikam|srv-dc|jdoe|mmuster|John Doe|Max Muster|Fuerth|helpdesk-anna|provAgentgMSA|S-1-5-21-111-|3f2504e0') 'no original identifier in any file of the folder (incl. UPN suffix and terms file)'
Assert-Test ((Get-Content -LiteralPath (Join-Path $bundle 'README-FIRST.md') -Raw) -match 'SoaToolkit\.terms\.txt \(2 term') 'terms file next to the configuration loaded automatically'
$map = Get-ChildItem -LiteralPath (Join-Path (Join-Path $rp 'Export') 'private') -Filter '*.map.csv'
Assert-Test (@($map).Count -eq 1 -and -not (Get-ChildItem -LiteralPath $bundle -Recurse -Filter '*.map.csv')) 'pseudonym map written outside the folder only'

# Second report: pseudonyms stay the same (cumulative map)
Start-Sleep -Seconds 1
& $export -NoRemote -Days 400 -ConfigPath $cfgPath 6>$null | Out-Null
$bundles = @(Get-ChildItem -LiteralPath (Join-Path $rp 'Export') -Directory | Where-Object { $_.Name -like 'SoaReport_*' } | Sort-Object Name)
$m1 = @(Import-Csv -LiteralPath (Join-Path (Join-Path (Join-Path $rp 'Export') 'private') "$($bundles[0].Name).map.csv"))
$m2 = @(Import-Csv -LiteralPath (Join-Path (Join-Path (Join-Path $rp 'Export') 'private') "$($bundles[-1].Name).map.csv"))
$p1 = ($m1 | Where-Object { $_.Kind -eq 'DC' -and $_.Original -eq 'srv-dc2' }).Pseudonym; $p2 = ($m2 | Where-Object { $_.Kind -eq 'DC' -and $_.Original -eq 'srv-dc2' }).Pseudonym
Assert-Test ($bundles.Count -eq 2 -and $p1 -and $p1 -eq $p2 -and $m2.Count -ge $m1.Count) 'pseudonyms are stable across reports (private\pseudonyms.csv)'

Add-Content -LiteralPath (Join-Path $bundle 'report.md') -Value 'leak: srv-dc1'
$refused = $false
try { & $export -Package $bundle -ConfigPath $cfgPath -Confirm:$false 6>$null | Out-Null } catch { $refused = $true }
Assert-Test ($refused -and -not (Test-Path "$bundle.zip")) 'packaging refused when the leak check finds an original value'
(Get-Content -LiteralPath (Join-Path $bundle 'report.md')) | Where-Object { $_ -ne 'leak: srv-dc1' } | Set-Content -LiteralPath (Join-Path $bundle 'report.md')
& $export -Package $bundle -ConfigPath $cfgPath -Confirm:$false 6>$null | Out-Null
Assert-Test ((Test-Path "$bundle.zip") -and (Test-Path "$bundle.zip.sha256")) 'package and checksum written after a clean leak check'
exit $fail
