# Setup guide

This guide covers everything from the download to Enforced mode. Read the first section before you start: it shows which parts Microsoft documents, which parts the toolkit takes over unchanged, where it deliberately deviates from Microsoft's documentation and scripts, and where its own functionality begins.

- [1. Microsoft documentation vs. this toolkit](#1-microsoft-documentation-vs-this-toolkit)
- [2. Planning](#2-planning)
- [3. Manual steps after the download](#3-manual-steps-after-the-download)
- [4. Installation](#4-installation)
- [5. Initial conformance and Enforced mode](#5-initial-conformance-and-enforced-mode)
- [6. Monitoring integration](#6-monitoring-integration)
- [7. Optional: code signing](#7-optional-code-signing)
- [8. Migration from toolkit 1.x](#8-migration-from-toolkit-1x)
- [9. Objects created by the toolkit](#9-objects-created-by-the-toolkit)

---

## 1. Microsoft documentation vs. this toolkit

Reference: Microsoft's [Configure AD user and group enforcement in Microsoft Entra Cloud Sync (preview)](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-active-directory-object-enforcement) (ms.date 2026-08-11, re-checked 2026-10-20) and the scripts `Set-CloudSyncSOAPolicy.ps1` / `Check-CloudSyncSOAPolicy.ps1` (versions in the [README](../README.md#upstream-issues-in-microsofts-scripts-and-documentation)).

### 1.1 Same as Microsoft (redundant: the toolkit automates or verifies it)

| Microsoft step | Microsoft documentation | Toolkit | Manual? |
|---|---|---|---|
| 1. Latest cumulative update on every writable DC | install, verify `ntdsai.dll` (WS2022 ≥ 10.0.20348.5257, WS2025 ≥ 10.0.26100.32995) | **verifies** per DC (`Test-SoaPrerequisites.ps1`, monitoring check `DC-NTDSAI`) | **yes** (Windows Update) |
| 2. Restart if prompted | – | **reports** pending reboots | **yes** |
| 3. Feature enablement with the Group Policy package (KIR model) | download the package for WS2022 / WS2025 and deploy it with Group Policy | **automates**: `Install-SoaToolkit.ps1 -Step KirGpo -KirMsi2022/-KirMsi2025` extracts the MSI, copies ADMX/ADML to the central store, creates one GPO per OS with a WMI filter on the build number, links it to the Domain Controllers OU; detects an existing KIR GPO and does not create a second one; verifies the effective override per DC (RSoP + registry) | **download** of the MSI(s) |
| 4. Restart each DC after enablement | restart | **verifies** "last boot after the last KIR GPO change" | **yes** (one DC at a time) |
| 5. Confirm the `SOA-Policies` container | check that it exists | **verifies on every DC**, including the originating DC (engine on the PDCe vs. created by a script) | no |
| Diagnostics logging | "Set the Security Diagnostics value to `1`" | GPO `SOA Toolkit - DC - NTDS Security Diagnostics` sets `NTDS\Diagnostics\2 Security Events = 1` and removes it when disabled (see F5 for the value name) | no |
| 10. / 11. Mark groups / users with `msDS-ObjectSoa` (attribute mapping) | constant / expression in Cloud Sync; default user mapping already marks users | **not touched** (Entra side); the monitoring reports provisioned objects that are not marked | **yes** for groups (Cloud Sync configuration) |
| 12. Verify marking in ADSI Edit | manual | **automated** (`Get-SoaEnforcementImpact.ps1`, monitoring) | no |

### 1.2 Deliberate deviations (Microsoft's documentation or script is wrong or incomplete)

| Topic | Microsoft | Toolkit | Why |
|---|---|---|---|
| Creating the policy `CN=Cloud` (steps 6–9) | Run `Set-CloudSyncSOAPolicy.ps1` on an agent host | `Install-SoaToolkit.ps1 -Step Policy` creates **the same object** (`serviceConnectionPoint`, `serviceBindingInformation = CloudSync`, `keywords`, `msDS-Settings`) | The script creates the missing container itself and hides an inactive engine (**F2**); it adds only the local agent's gMSA (**F6**). An existing policy (for example one created with Microsoft's script) is kept and adopted. |
| Container `CN=SOA-Policies` | created by the PDC emulator, but also by the script if missing | **never created by the toolkit**; a missing container stops the Policy step with an explanation | The container is the proof that the engine on the PDCe is running (**F2**) |
| Changing the mode | "run the script again with the new `-EnforcementMode`" | `-Step SetMode -Mode Audit|Enforced` writes `keywords` directly, with pre-checks and a replication wait | The script does not change an existing policy (**F1**); this would also break an emergency rollback |
| Starting mode | Step 8 shows `-EnforcementMode Enforced` directly (Audit as the "what-if" option) | Always **Audit first**, impact analysis (`Get-SoaEnforcementImpact.ps1`), then Enforced | Best practice; Enforced also blocks Domain Admins |
| Checking the enablement | `Check-CloudSyncSOAPolicy.ps1` "reports whether the policy is enabled on that DC" | Per DC: `ntdsai.dll`, KIR override, RSoP, policy load event 3095, replication | The script reads only domain-wide objects (**F3**) and a hard-coded gMSA DN (**F4**) |
| Allow-list | agent gMSA of the local host | **all** agent gMSAs (one per agent host is possible) + toolkit gMSA, SID validation, 64-SID limit, stale-SID detection | **F6**, and K6 (one stale SID disables the whole policy) |
| Diagnostics value name | "Security Diagnostics" | `2 Security Events` | **F5** |

### 1.3 Additional functionality (not part of Microsoft's documentation)

| Area | What the toolkit adds |
|---|---|
| Passwordless target state | SCRIL on every in-scope cloud user, "password never expires" cleared, PSO with the rolling interval, automatic rolling enabled (domain attribute) |
| Continuous configuration | onboarding task on every writable DC (events 4720 / 5136 by the agent), reconcile task on every agent host |
| Prerequisites for that | gMSA + host group, "Log on as a batch job" GPO(s), audit subcategories (only those missing) and SACL for `msDS-ObjectSoa`, delegation (least privilege) |
| Monitoring | event log `SoaToolkit`, exit codes, per-user checks (SCRIL, PNE, PSO, expired-but-not-rolled, Kerberos failures, AzureADKerberos password replication policy) |
| Tests | SCRIL matrix, rolling with a real passwordless sign-in, onboarding, enforcement, logon |
| Lifecycle | manifest, marker on every object, step-by-step rollback, decommissioning, migration from 1.x |

---

## 2. Planning

1. **Hosts.**
   - Writable DCs are discovered automatically.
   - Put every **agent host** into `AgentHosts`. Agent hosts can be DCs (as in the reference environment) or member servers.
   - Microsoft recommends hardening agent hosts as Tier 0 and running **3 active agents** (R27).
2. **Admin workstation.** A PAW with RSAT (`ActiveDirectory`, `GroupPolicy`) and WinRM to all toolkit hosts.
3. **OU for the toolkit groups** (`ToolkitGroupOU`). It must be outside the Cloud Sync scope and Tier-0 protected.
4. **Scope.**
   - Users are found **domain-wide by attributes**, so no OU list is needed.
   - Optional exclusions: the group `SOA-CloudUsers-Exclude` or `ExcludeOUs`.
   - Optional staged rollout: `PilotMode = $true` plus the group `SOA-CloudUsers-Pilot`.
5. **Write scope.** `WriteScope = 'AgentScope'` (default) gives the toolkit gMSA write permission on `userAccountControl` exactly where the Cloud Sync agent itself holds write permissions.
6. **Test user.** Create a user **in Entra ID**, put it in the Cloud Sync scope, and let it be provisioned. Enter it as `TestUser`.
7. **Communication.** Plan this for SOA-converted users: when SCRIL is set, their known password is replaced, and password-based sign-ins stop working. This affects VPN/RADIUS, Wi-Fi PEAP-MSCHAPv2, LDAP binds by applications, and RDP or `runas` with a password.

### 2.1 Without a separate admin workstation

In a small domain the admin scripts can run directly on a domain controller or an agent host. Remote calls to the local host run locally. A DC is Tier 0, so this stays within the tier model; use the session only for administration (no browsing, no mail).

| Point | What to do |
|---|---|
| Elevation | Start PowerShell with "Run as administrator" (the scripts register tasks, set ACLs and the event log locally) |
| Modules | AD PowerShell and Group Policy Management (DCs normally have both; a member-server agent host needs `Install-WindowsFeature RSAT-AD-PowerShell, GPMC`) |
| WinRM | `Test-SoaPrerequisites.ps1` and `Get-SoaEnforcementImpact.ps1` connect to every DC with WinRM, including the local one (enabled on Windows Server by default) |
| Your copy of the toolkit | Keep it in its own folder, e.g. `C:\SoaToolkitAdmin\cloudsync-soa-toolkit`, **not** in `ScriptInstallPath` (`C:\Program Files\SoaToolkit`): `Uninstall -Step RemoveTasks` deletes the deployed folder |
| `ReportPath` | **Outside** `DataPath` and `ScriptInstallPath` (default `C:\SoaToolkitAdmin\Reports`). Inside `DataPath` the toolkit gMSA would get modify rights on the manifest and the reports, and the rollback would delete them in the middle of the run. The scripts refuse that layout on a toolkit host and create `ReportPath` with access for Administrators and SYSTEM only |

## 3. Manual steps after the download

| # | Step | Details |
|---|---|---|
| 1 | Verify the download | Compare the SHA-256 of the release ZIP with the value on the release page, then `Get-ChildItem -Recurse \| Unblock-File` |
| 2 | Prepare the admin workstation | Windows PowerShell 5.1 (7.x works as well), RSAT AD DS + GPMC, Domain Admin (for the setup only), WinRM to all DCs / agent hosts. No separate admin workstation? See [section 2.1](#21-without-a-separate-admin-workstation) |
| 3 | Microsoft prerequisites | Cloud Sync Entra ID → AD provisioning configured (agents, scope, target container, default user mapping with `msDS-ObjectSoa`); group marking if groups are provisioned; cumulative update on every writable DC; Cloud Kerberos Trust (AzureADKerberos object) |
| 4 | **Download the KIR package(s)** | WS2022: `aka.ms/ADEnforcementGPMSI2022`, WS2025: `aka.ms/ADEnforcementGPMSI2025` - only for OS versions that run as writable DCs. **Do not** copy the ADMX by hand; the toolkit does it (central store if it exists, otherwise the local store of the workstation; it never creates a central store) |
| 5 | KDS root key | `Get-KdsRootKey`; if none: `Add-KdsRootKey` and wait for replication (up to 10 h). Never delete it later. |
| 6 | Member-server agent hosts | `Install-WindowsFeature RSAT-AD-PowerShell` (the tasks need the module; DCs have it) |
| 7 | Configuration | Copy `SoaToolkit.config.example.psd1` to `SoaToolkit.config.psd1` (both at the top level of the toolkit folder) and edit the copy: `AgentHosts`, `ToolkitGroupOU`, `TestUser`, `ReportPath` (outside `DataPath`), optional names, PSO values, `PilotMode`, `ReconcileMinutes`, `EventLogMaxSizeMB`, `EventLogAllowWef`, `ProjectUrl`. The scripts find it automatically; `-ConfigPath` overrides. |
| 7a | Terms for reports | Copy `SoaToolkit.terms.example.txt` to `SoaToolkit.terms.txt` and list company, site, project and other names that the toolkit cannot find in AD ([REPORTING.md](REPORTING.md#anonymization)) |
| 8 | Optional: code-signing certificate | see [section 7](#7-optional-code-signing) |

## 4. Installation

All steps are idempotent and support `-WhatIf`. Run each step with `-WhatIf` first.

```powershell
cd .\scripts
.\Test-SoaPrerequisites.ps1                                    # read-only; fix FAILs first

# One call for the whole base setup (KirGpo only if an MSI is given)
.\Install-SoaToolkit.ps1 -Step All -KirMsi2025 C:\Install\AD-Enforcement-WS2025.msi -WhatIf
.\Install-SoaToolkit.ps1 -Step All -KirMsi2025 C:\Install\AD-Enforcement-WS2025.msi -Refresh
```

`-Step All` runs these steps in order:

| Step | Creates / changes | Notes |
|---|---|---|
| `HostGroup` | group `SOA-Toolkit-Hosts` (Domain Controllers + member-server agent hosts) | |
| `Gmsa` | gMSA `gmsaSoaToolkit`, retrievable by the host group; tested on every host | purges the computer tickets so the new group membership is used |
| `BatchLogonGpo` | GPO `SOA Toolkit - DC - Batch Logon` (+ `… - Agent Hosts - …` if needed), link order 1 | User rights from GPOs are **not merged**. The GPO contains the **current effective** list of every host **plus** the gMSA. Check with `-Refresh` / Verify. |
| `KirGpo` | GPO(s) `SOA Toolkit - DC - KIR AD Object Enforcement (WS20xx)`, WMI filter(s), ADMX/ADML | **Restart the DCs afterwards, one at a time** |
| `DiagnosticsGpo` | GPO `SOA Toolkit - DC - NTDS Security Diagnostics` | renames and adopts the 1.x GPO if present |
| `AuditConfig` | GPO `SOA Toolkit - DC - Audit` **only if** a required subcategory is missing; **always** the toolkit's own narrow SACL entry on every write-scope container (Everyone, Success, Write `msDS-ObjectSoa`, descendant user objects) | never reduces existing auditing; broader SACL rules of others (e.g. a diagnostic "Write all properties") are reported as INFO and **not** relied upon |
| `EnableRolling` | `msDS-ExpirePasswordsOnSmartCardOnlyAccounts = TRUE` if not set | previous value is recorded |
| `Policy` | `CN=Cloud` in mode **Audit** | skipped with a warning until the engine has created the container (after the restart) |
| `Groups` | `SOA-CloudUsers-PSO`, `-Exclude`, `-Pilot` | |
| `Pso` | `PSO-SOA-CloudUsers` → `SOA-CloudUsers-PSO` | warns about PSOs with the same or a lower precedence |
| `Delegate` | ACEs for the gMSA, Event Log Readers membership | |
| `AllowList` | agent gMSAs + toolkit gMSA in `msDS-Settings` | skipped until `CN=Cloud` exists |
| `DeployTasks` | scripts, folders, event log, tasks on every toolkit host | event log `SoaToolkit`: `EventLogMaxSizeMB` (default 64), overwrite as needed; with `EventLogAllowWef` also readable by NETWORK SERVICE for Windows Event Forwarding |
| `Verify` | – | policy replication / load per DC + full monitoring run |

After restarting the DCs, finish the policy-related steps:

```powershell
.\Test-SoaPrerequisites.ps1                                    # engine active on every DC, container written on the PDCe
.\Install-SoaToolkit.ps1 -Step Policy, AllowList, DeployTasks, Verify
```

`DeployTasks` is repeated here because the event triggers and `deployment.json` contain the agent SIDs and the write scope.

## 5. Initial conformance and Enforced mode

```powershell
.\Test-SoaBehavior.ps1 -Suite Inventory, Scril              # behaviour in your domain (TestUser only)
.\Test-SoaBehavior.ps1 -Suite Onboarding                    # toolkit identity + reconcile work
.\Install-SoaToolkit.ps1 -Step Conform -WhatIf              # analysis of all cloud users (report in ReportPath\Conformance)
.\Install-SoaToolkit.ps1 -Step Conform                      # one reconcile run as the gMSA
.\Get-SoaEnforcementImpact.ps1 -Days 14                     # who would be blocked?
# observe 1-2 weeks in Audit mode: events 3097 (monitoring check DC-3097)
.\Install-SoaToolkit.ps1 -Step SetMode -Mode Enforced
.\Test-SoaBehavior.ps1 -Suite Enforcement, Logon
```

Optional, to re-confirm automatic rolling in your environment:

```powershell
.\Test-SoaBehavior.ps1 -Suite RollingPrepare
.\Test-SoaBehavior.ps1 -Suite RollingObserve -WaitForExpiry   # sign in passwordless when prompted
.\Test-SoaBehavior.ps1 -Suite RollingCleanup
```

Emergency rollback of enforcement: `.\Uninstall-SoaToolkit.ps1 -Step SetModeAudit`.

### 5.1 Validate the installation

Work through the checklist [VALIDATION.md](VALIDATION.md) (L1-L20) and record what the toolkit cannot observe with `.\Export-SoaReport.ps1 -Record <Lx> -Result <PASS|FAIL> -Note '...'`. `.\Export-SoaReport.ps1` shows the status of every item and creates an anonymized report.

## 6. Monitoring integration

Connect the event log `SoaToolkit` on every toolkit host to your monitoring system. Details: [OPERATIONS.md](OPERATIONS.md#monitoring).

- Alert on **2002** (failure) and on a **missing heartbeat 2000** for more than 2 × `MonitorMinutes` per host.
- Optional: alert on **1002** (conformance error) and on **2001** (warning).
- Interactive full check: `.\Watch-CloudUserConformance.ps1 -Html`.

## 7. Optional: code signing

**Why.** The tasks run scripts as a privileged gMSA on Tier-0 hosts. Anyone who can change these files runs code with those rights.

**How.**
1. Issue a code-signing certificate from your PKI (EKU *Code Signing*) and keep the key protected.
2. Distribute the issuing chain and the certificate as a **Trusted Publisher** to all toolkit hosts by GPO.
3. Set `SigningCertThumbprint` (and optionally `SigningTimestampUrl`) in the configuration.
4. Run `-Step DeployTasks` again. It signs the scripts and registers the tasks with `-ExecutionPolicy AllSigned`.

**Limits.** The execution policy is not a security boundary. Real enforcement needs WDAC / AppLocker on the hosts.

**Without signing**, the monitoring compares the file hashes of every host with `deployment.json` and reports modified files (check `INTEGRITY`).

## 8. Migration from toolkit 1.x

1. Replace the 1.x configuration with `SoaToolkit.config.psd1`. Use `LegacyJobHost`, `LegacyGmsaName`, `LegacyTargetUserOUs` and `LegacyScriptFolder` for the clean-up.
2. Run `.\Install-SoaToolkit.ps1 -Step All` (plus `KirGpo` if wanted). This renames and adopts the diagnostics GPO.
3. Run `.\Install-SoaToolkit.ps1 -Step RemoveLegacy`. It removes:
   - the tasks on the old job host;
   - the job script and the local batch logon entry on the old job host;
   - the legacy ACEs, including *Reset Password*;
   - the legacy gMSA, after it has been removed from the allow-list.
4. Run `.\Install-SoaToolkit.ps1 -Step Conform -WhatIf`. It reports users with PNE (1.x allowed it), and the subsequent `Conform` clears it.

## 9. Objects created by the toolkit

All of them carry the marker **`[SoaToolkit] Managed by SOA Toolkit - do not modify manually`** with a link to the repository. Change them only through the configuration and `Install-SoaToolkit.ps1`.

| Object | Default name | Where the marker is |
|---|---|---|
| gMSA | `gmsaSoaToolkit` | description, info |
| Groups | `SOA-Toolkit-Hosts`, `SOA-CloudUsers-PSO`, `SOA-CloudUsers-Exclude`, `SOA-CloudUsers-Pilot` | description, info |
| PSO | `PSO-SOA-CloudUsers` | description |
| Enforcement policy (only if created by the toolkit) | `CN=Cloud` | description |
| GPOs | `SOA Toolkit - DC - …`, `SOA Toolkit - Agent Hosts - Batch Logon` | GPO comment |
| WMI filters | `SOA Toolkit - OS build …` | description |
| Tasks | `\SoaToolkit\CloudUserConformance-Event`, `…-Reconcile`, `\SoaToolkit\Monitor` | task description |
| Files | `%ProgramFiles%\SoaToolkit\*`, `%ProgramData%\SoaToolkit\*` | file header |
| Event log | `SoaToolkit` | – |
| Delegation ACEs | trustee = toolkit gMSA (the trustee carries the marker) | recorded in the manifest |
| SACL entry | exact fingerprint (see below) | recorded in the manifest (kind `Sacl`) |

### 9.1 Changes that cannot carry a marker

Active Directory has no description field for access-control entries, audit entries, attribute values or group memberships. The toolkit therefore identifies its own changes like this:

| Change | Identification | Removal |
|---|---|---|
| Delegation ACEs on the write scope | trustee = toolkit gMSA (marked object) | `Uninstall-SoaToolkit.ps1 -Step RemoveDelegation` removes every ACE of that trustee |
| SACL entry for `msDS-ObjectSoa` | **exact fingerprint**: trustee Everyone (`S-1-1-0`), audit *Success* only, right *WriteProperty* only, object type = schemaIDGUID of `msDS-ObjectSoa`, inheritance *Descendents*, inherited object type = `user`, explicit; plus the manifest | `-Step RemoveAudit` removes only entries with exactly this fingerprint, and only on the containers the manifest lists |
| Domain setting `msDS-ExpirePasswordsOnSmartCardOnlyAccounts` | manifest (previous value) | `-Step RestoreRolling` restores the previous value |
| User attributes (SCRIL, PNE) and PSO group membership | target state + manifest of the conformance runs; user objects are deliberately **not** marked (Cloud Sync owns them) | `-Step RevertUsers` (explicit, with warning) |
| ADMX / ADML copied to the central store | Microsoft files, copied unchanged and therefore not marked; path + hash recorded in the manifest (kind `AdmxFiles`) | `-Step RemoveKirGpo -RemoveAdmx`, only if the file is unchanged |

The toolkit **never** relies on audit or access rules it did not create. Broader rules that also produce event 5136 (for example a diagnostic SACL "Everyone, Write all properties, Success + Failure") are reported by `AuditConfig` and by the monitor check `AUD-SACL-OTHER`. If they were only created for a diagnosis, remove them; the toolkit entry stays in place.
