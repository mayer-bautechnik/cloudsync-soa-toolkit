# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
# TEST MOCK - a fake 'ActiveDirectory' module with a fictitious domain (fabrikam.local) for tests\Test-SoaExportReport.ps1.
# Never put this folder into PSModulePath outside the tests.
$dom = [pscustomobject]@{ DNSRoot = 'fabrikam.local'; NetBIOSName = 'FABRIKAM'; DistinguishedName = 'DC=fabrikam,DC=local'; DomainSID = [pscustomobject]@{ Value = 'S-1-5-21-111-222-333' }; PDCEmulator = 'srv-dc1.fabrikam.local'; DomainControllersContainer = 'OU=Domain Controllers,DC=fabrikam,DC=local'; DomainMode = 'Windows2025Domain' }
function Get-ADDomain { $dom }
function Get-ADDomainController { param($Filter, $Server) @([pscustomobject]@{ HostName = 'srv-dc1.fabrikam.local'; Name = 'SRV-DC1'; IsReadOnly = $false; OperatingSystem = 'Windows Server 2025 Datacenter'; OperatingSystemVersion = '10.0 (26100)'; Site = 'Fuerth-HQ' }, [pscustomobject]@{ HostName = 'srv-dc2.fabrikam.local'; Name = 'SRV-DC2'; IsReadOnly = $false; OperatingSystem = 'Windows Server 2025 Datacenter'; OperatingSystemVersion = '10.0 (26100)'; Site = 'Fuerth-HQ' }) }
function Get-ADRootDSE { param($Server) [pscustomobject]@{ configurationNamingContext = 'CN=Configuration,DC=fabrikam,DC=local'; schemaNamingContext = 'CN=Schema,CN=Configuration,DC=fabrikam,DC=local' } }
function Get-ADForest { param($Server) [pscustomobject]@{ RootDomain = 'fabrikam.local'; ForestMode = 'Windows2025Forest'; Domains = @('fabrikam.local'); UPNSuffixes = @('fabrikam-group.com') } }
function Get-ADObject { param($Identity, $Server, $Properties, $LDAPFilter, $SearchBase)
  if ("$Identity" -like 'CN=Cloud,*') { return [pscustomobject]@{ keywords = @('Enforced'); 'msDS-Settings' = @('S-1-5-21-111-222-333-1105', 'S-1-5-21-111-222-333-1110') } }
  [pscustomobject]@{ 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' = $true } }
function Get-ADUser { param($Identity, $Server, $Properties, $LDAPFilter, $ResultPageSize, $Filter)
  $u = @([pscustomobject]@{ SamAccountName = 'jdoe'; Name = 'John Doe'; UserPrincipalName = 'jdoe@fabrikam.com'; DistinguishedName = 'CN=John Doe,OU=Cloud Users,OU=Fuerth,DC=fabrikam,DC=local'; 'msDS-ObjectSoa' = 'Cloud'; userAccountControl = 0x40200; whenCreated = [datetime]'2026-11-03T10:00:00'; ObjectGuid = '3f2504e0-4f89-11d3-9a0c-0305e82c3301' },
         [pscustomobject]@{ SamAccountName = 'mmuster'; Name = 'Max Muster'; UserPrincipalName = 'mmuster@fabrikam.com'; DistinguishedName = 'CN=Max Muster,OU=Staff,OU=Fuerth,DC=fabrikam,DC=local'; 'msDS-ObjectSoa' = 'Cloud'; userAccountControl = 0x40200; whenCreated = [datetime]'2019-01-01T08:00:00'; ObjectGuid = '4f2504e0-4f89-11d3-9a0c-0305e82c3302' })
  if ($Identity) { return ($u | Where-Object { $_.ObjectGuid -eq "$Identity" } | Select-Object -First 1) }
  $u }
function Get-ADServiceAccount { param($Filter, $Server) [pscustomobject]@{ SID = [pscustomobject]@{ Value = 'S-1-5-21-111-222-333-1105' }; DistinguishedName = 'CN=provAgentgMSA,CN=Managed Service Accounts,DC=fabrikam,DC=local' } }
function Get-ADFineGrainedPasswordPolicy { param($Identity, $Server) [pscustomobject]@{ Name = 'PSO-SOA-CloudUsers'; Precedence = 10; MaxPasswordAge = [timespan]::FromDays(30); MinPasswordAge = [timespan]::FromDays(1); MinPasswordLength = 64; ComplexityEnabled = $true; PasswordHistoryCount = 24; LockoutThreshold = 0 } }
function Get-ADReplicationAttributeMetadata { param($Object, $Server)
  if ($Object -like '*John Doe*') { @([pscustomobject]@{ AttributeName = 'msDS-ExternalDirectoryObjectId'; LastOriginatingChangeTime = [datetime]'2026-11-03T10:00:05'; Version = 1 }) }
  else { @([pscustomobject]@{ AttributeName = 'msDS-ExternalDirectoryObjectId'; LastOriginatingChangeTime = [datetime]'2026-11-04T09:00:00'; Version = 1 }) } }
Export-ModuleMember -Function *
