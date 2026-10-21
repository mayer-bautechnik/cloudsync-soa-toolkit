# Changelog

## 2.0.4 – 2026-10-21

Configuration and terms as top-level templates, safe operation without a separate admin workstation, a properly sized event log and central collection, stable pseudonyms in reports.

### Changed

- **Configuration and terms are templates at the top level:**
  - `SoaToolkit.config.example.psd1` (was `scripts\SoaToolkit.config.psd1`) and the new `SoaToolkit.terms.example.txt`.
  - Your copies `SoaToolkit.config.psd1` / `SoaToolkit.terms.txt` live next to them. They are git-ignored and not part of the release zip, so extracting a new release never overwrites them.
  - The scripts look for the configuration at `-ConfigPath`, then next to the script (deployed hosts, old layout, with a hint to move it), then at the top level. Two configurations at once are refused, and a missing one names the template to copy.
- **Default `ReportPath` is now `C:\SoaToolkitAdmin\Reports`** (was `C:\ProgramData\SoaToolkit\Reports`, inside `DataPath`). It is created on first use with access for Administrators and SYSTEM only.
- **Report names contain seconds** (`SoaReport_<purpose>_yyyyMMdd_HHmmss`), so two runs within one minute no longer overwrite each other.

### Fixed

- **Admin scripts on a DC or agent host** (no separate admin workstation):
  - with `ReportPath` inside `DataPath`, `DeployTasks` gave the toolkit gMSA modify rights on the install manifest, and `Uninstall -Step RemoveTasks` deleted manifest and reports in the middle of the rollback;
  - running the admin scripts from the deployed copy (`ScriptInstallPath`) let `RemoveTasks` delete them.
  - Install, Uninstall, Export, Test-SoaBehavior, Get-SoaEnforcementImpact, Test-SoaPrerequisites and `Watch -Scope All` now stop on a toolkit host in both cases, and warn elsewhere (`Assert-SoaAdminPaths`).
- **Event log `SoaToolkit`:** a classic log is created with 512 KB and "overwrite older", so new events (heartbeats, failures) could be dropped when it was full. `DeployTasks` now sets `EventLogMaxSizeMB` (default 64) with "overwrite as needed"; new monitor check `EVENTLOG-SIZE`.

### New

- `EventLogAllowWef`: read access for NETWORK SERVICE on the `SoaToolkit` log only, for Windows Event Forwarding.
- **Central collection** in [docs/OPERATIONS.md](docs/OPERATIONS.md#central-collection):
  - event table with alert recommendations;
  - WEF / WEC (GPO, subscription query, `SOA-Toolkit-Hosts` as subscription ACL);
  - Azure Monitor Agent / DCR (XPath), WEF + AMA on the collector, SCOM;
  - KQL for missing heartbeats and failures, Tier-0 notes on WEC and Azure Arc.
- **Reports:**
  - `SoaToolkit.terms.txt` is loaded automatically;
  - UPN suffixes and further forest domains are pseudonymized automatically;
  - pseudonyms are stable across reports (`private\pseudonyms.csv`, `-ResetPseudonyms` to start anew).
- Repository hygiene (H5) reads the same `SoaToolkit.terms.txt` (the former `tools\forbidden-terms.local.txt` is still read) and scans only the files git would publish.
- [docs/SETUP.md](docs/SETUP.md#21-without-a-separate-admin-workstation): section *Without a separate admin workstation*. [docs/DECISIONS.md](docs/DECISIONS.md): D-21 to D-23.

### Upgrade from 2.0.3

1. Extract the release. Copy your configuration from `scripts\SoaToolkit.config.psd1` to the top level as `SoaToolkit.config.psd1`, and delete the old one. Two configurations are refused.
2. Add the new keys if you want other values than the defaults: `EventLogMaxSizeMB = 64`, `EventLogAllowWef = $false`.
3. If `ReportPath` is inside `DataPath` (the old default), move the folder - it contains `State\manifest.json` - and set `ReportPath`, for example:
   ```powershell
   Move-Item C:\ProgramData\SoaToolkit\Reports C:\SoaToolkitAdmin\Reports
   ```
4. Optional: create `SoaToolkit.terms.txt` from `SoaToolkit.terms.example.txt`.
5. `.\Install-SoaToolkit.ps1 -Step DeployTasks`, which updates the scripts and the event log size on every host.

## 2.0.3 – 2026-10-21

Fix for Windows PowerShell 5.1, a CI gate in the release process, and consistent reporting instructions.

### Fixed

- **Scripts started with `powershell.exe -File` on Windows PowerShell 5.1** (as the scheduled tasks are) could fail before they started. `$PSScriptRoot` was empty in parameter default values, so the default `-ConfigPath` could not be built.
  - All scripts, tools and tests now resolve their folder at the start of the script, with a fallback to `$MyInvocation.MyCommand.Definition`.
  - `-ConfigPath`, `-Path` and `-Root` get their defaults after `param()`.
  - Found by the CI job on Windows PowerShell 5.1 after the 2.0.2 release. The 2.x scripts have not run in a domain yet (lab validation pending), so no deployment was affected.
- Tests and tools build child paths with nested `Join-Path` (no mixed `/` and `\`).

### Changed

- **Release process ([docs/RELEASING.md](docs/RELEASING.md)):**
  - the commit is pushed and both CI jobs must be green **before** the tag is created and the release is published;
  - `tools/Build-SoaRelease.ps1` refuses to build when the CI runs of the commit are not all successful (checked with the GitHub CLI; `-SkipCiCheck` only with a reason);
  - a new section describes what to do when a published, immutable release turns out to be broken: fix forward, never move a published tag.
- `tools/Invoke-SoaStaticChecks.ps1` also runs the tests and the claims check under **Windows PowerShell 5.1** when it is started from PowerShell 7 on Windows.
- **Reporting consistency:**
  - `Test-SoaPrerequisites.ps1`, `Watch-CloudUserConformance.ps1`, `Get-SoaEnforcementImpact.ps1` and `Test-SoaBehavior.ps1` point out that their reports contain identifiers and are shared through `Export-SoaReport.ps1`;
  - CONTRIBUTING, README, OPERATIONS (troubleshooting), REPORTING, AGENTS and the issue forms describe the same process;
  - new issue form *Question or idea*.

## 2.0.2 – 2026-10-21

Maintainability, transparency and verifiability. No change to the target state, the delegated rights or the setup steps.

### New

- **`Export-SoaReport.ps1`**: collects the lab validation status (L1-L20) or the data for a bug report into a local folder with `report.md`, `report.json`, `README-FIRST.md` and anonymized artifacts.
  - **Content:** AD facts, all toolkit reports and run logs, and per toolkit host the OS build / latest updates, agent version, tasks, event counts, journals and script hashes.
  - **Anonymization:** domain, hosts, users, accounts, gMSAs, DN values, SIDs, GUIDs, e-mail and IP addresses are replaced by stable pseudonyms; extra terms via `-AdditionalTerms` / `-TermsFile`. The pseudonym map is stored **outside** the folder.
  - **Leak check** after collection and again before packaging.
  - **Packaging** only as a separate, confirmed step (`-Package`).
  - **Manual results** via `-Record`; the list of checks via `-ListChecks`.
- Install and uninstall write a **run log** (run ID, steps, WhatIf, every ADD / SAME / DEL / FAIL line). It is used to evaluate idempotency (L3), dry runs (L2), mode switches (L17) and rollback (L19).
- **`tools/`**:
  - `Test-SoaSecurityClaims.ps1`: static check of the security claims plus an inventory of all write operations.
  - `Test-SoaRepoHygiene.ps1`: hidden / bidi characters, encodings, license headers, e-mail addresses, local forbidden terms, version consistency.
  - `Build-SoaRelease.ps1`: zip from the signed tag with `SHA256SUMS.txt`.
  - `Invoke-SoaStaticChecks.ps1`: all of the above plus parser, PSScriptAnalyzer and tests.
- **`tests/`**: unit tests and an end-to-end test of `Export-SoaReport.ps1` against a mocked `ActiveDirectory` module.
- **CI** (`.github/workflows/ci.yml`): PowerShell 7 on Linux and Windows PowerShell 5.1.
- Issue forms (*Bug report*, *Lab validation result*). Release notes are now in `.github/release-notes/`.
- PDF source in the repository: `docs/src/build_findings_pdf.py` (version and date read from the module).
- Documentation:
  - [AGENTS.md](AGENTS.md): rules for contributors and coding agents.
  - [docs/DECISIONS.md](docs/DECISIONS.md): design decisions D-01 to D-20.
  - [docs/EVIDENCE.md](docs/EVIDENCE.md): lab evidence behind *Observed*.
  - [docs/VALIDATION.md](docs/VALIDATION.md): checklist L1-L20.
  - [docs/REPORTING.md](docs/REPORTING.md): reports and bug reports.
  - [docs/RELEASING.md](docs/RELEASING.md), [docs/MAINTENANCE.md](docs/MAINTENANCE.md): release process and recurring maintenance.
  - [SECURITY.md](SECURITY.md): security properties S1-S7, how to verify them, a prompt for reviewing with your own AI.
- README:
  - **verification status**, with the open lab validation items L1-L20;
  - a section **How this project was built** (AI assistance, human review, manual lab measurements);
  - a summary of the security properties.

### Fixed

- Windows PowerShell 5.1 does not enumerate arrays returned by `ConvertFrom-Json`. Reading the test results (`test-state.json`) in `Test-SoaBehavior.ps1` and `Watch-CloudUserConformance.ps1` could therefore produce a nested array, so earlier results were lost or not shown. Both now use the new module function `Read-SoaJsonArray`.

### Changed

- The README no longer says the toolkit "never sets" a password without the exception: the acceptance test `RandomReset` sets a random, never-stored secret on the configured TestUser (claim S2).

## 2.0.1 – 2026-10-20

### Changed

- **AuditConfig always sets the toolkit's own SACL entry** for writes to `msDS-ObjectSoa` (Everyone, Success, WriteProperty on that attribute, descendant user objects) on every write-scope container. Before, a broader existing rule (for example a diagnostic "Write all properties" SACL) counted as sufficient; if that rule was removed later, event 5136 - the trigger for SOA-converted users - disappeared silently. Broader rules are now reported as INFO and never relied upon.
- **Uninstall `RemoveAudit`** removes only SACL entries with the toolkit's exact fingerprint (before: every Everyone rule on `msDS-ObjectSoa`).
- `Get-SoaAttributeGuid` reads from the DC the context is bound to (no PDC emulator dependency).

### New

- Monitor checks **`AUD-SACL`** (toolkit SACL entry present on every write-scope container, FAIL if missing) and **`AUD-SACL-OTHER`** (other rules that also audit these writes, INFO). Reading SACLs needs "Manage auditing and security log", so the checks run in `Watch-CloudUserConformance.ps1 -Scope All` and `Install-SoaToolkit.ps1 -Step Verify`; the gMSA monitor reports INFO.
- Module functions `Test-SoaSaclFingerprint`, `New-SoaSaclRule`, `Get-SoaSaclState` (shared by install, monitor and uninstall).
- Documentation: how the toolkit identifies changes that cannot carry a marker (ACEs, SACL entries, domain setting, user attributes) - `docs/SETUP.md` section 9.1.

### Upgrade from 2.0.0

1. Copy the new scripts, then run `Install-SoaToolkit.ps1 -Step AuditConfig` (adds the toolkit SACL entry where only a broader rule existed) and `-Step DeployTasks` (updates the scripts on the hosts).
2. Remove diagnostic SACLs that are no longer needed (`AUD-SACL-OTHER` lists them).
3. `Install-SoaToolkit.ps1 -Step Verify` → `AUD-SACL` must be PASS for every write-scope container.

## 2.0.0 – 2026-10-20

Repository renamed from `cloudsync-ad-enforcement-toolkit` to **`cloudsync-soa-toolkit`**. License: **MPL-2.0**.

### Design changes

- **No password rotation by the toolkit any more.** The domain controllers roll SCRIL secrets themselves (automatic rolling). Measured in a domain with the previews (K10, K11, K16, K17):
  - a WHfB / FIDO2 sign-in via Cloud Kerberos Trust with AVD SSO succeeds after expiry, and the DC rolls the secret during it;
  - "password never expires" disables rolling.
- **No management server.** Onboarding runs event-triggered on **every writable DC**. The reconcile runs on **every agent host**, staggered. Monitoring runs on every toolkit host. Nothing runs only on the PDC emulator (no single point of failure).
- **Scope by attributes, domain-wide** (`User_*` + `msDS-ObjectSoa = Cloud`) instead of OU lists. Exclusions come from a group or `ExcludeOUs`; staged rollout uses `PilotMode` with a pilot group. Write permissions follow the Cloud Sync agent's scope (`WriteScope = AgentScope`).
- **Target state**:
  - SCRIL set, "password never expires" cleared;
  - fine-grained password policy `PSO-SOA-CloudUsers` (30 days = rolling interval, min length 64, lockout 0) on the AD-native global group `SOA-CloudUsers-PSO`;
  - automatic rolling enabled.
- **Lifecycle**: install manifest with previous values, marker `[SoaToolkit] Managed by SOA Toolkit - do not modify manually` on every created object, and a step-by-step rollback (`Uninstall-SoaToolkit.ps1`, presets `Decommission` / `Full`).
- **Policy creation** by the toolkit (same object as `Set-CloudSyncSOAPolicy.ps1`, mode Audit). The container `SOA-Policies` is never created (upstream F2), and all agent gMSAs are allow-listed (F6).

### New

- `SoaToolkit.psm1` (shared functions).
- `Install-SoaToolkit.ps1`, replacing `Initialize-SoaEnforcement.ps1`. New steps: HostGroup, BatchLogonGpo, KirGpo, DiagnosticsGpo, AuditConfig, EnableRolling, Policy, Groups, Pso, DeployTasks, Conform, RemoveLegacy.
  - **KIR GPO from Microsoft's package**: the MSI is extracted, ADMX/ADML are copied to the central store (never created), and one GPO per OS (WS2022 / WS2025) gets a WMI filter on the build number. An existing KIR GPO is detected.
  - **"Log on as a batch job" via GPO** (DC OU; agent-host OUs with a security filter). The GPO contains the current effective list + gMSA, because user rights from GPOs are not merged. This replaces the local `secedit` change of 1.x, which a DC GPO refresh would have overwritten.
  - **Audit**: creates a GPO only for missing subcategories (never reduces auditing), plus a SACL on `msDS-ObjectSoa` writes (event 5136 for SOA-converted users).
- `Uninstall-SoaToolkit.ps1`.
- `Invoke-CloudUserConformance.ps1`, replacing `Invoke-ScrilJob.ps1`:
  - `Analyze` / `Apply` / `Test`; triggers `Event` / `Schedule` / `Manual`;
  - doorbell loop on event runs;
  - atomic compare-and-swap update of `userAccountControl`, so concurrent Cloud Sync changes are never overwritten;
  - journal with previous flags.
- `Watch-CloudUserConformance.ps1`, replacing `Watch-CloudUserPasswordless.ps1 -Mode Monitor`:
  - `-Scope Local` (tasks; event log 2000/2001/2002) / `-Scope All` (interactive);
  - new checks: PSO values / target / precedence, PSO group drift, expired-but-not-rolled, "rolled but pwdLastSet not updated", script integrity / signatures, GPO marker / link / version, write scope.
- `Test-SoaBehavior.ps1`, merging `Test-ScrilBehavior.ps1` and `Watch-CloudUserPasswordless.ps1 -Mode Test`. Suites: Inventory, UiObserve, Scril, Rolling*, Onboarding, Enforcement, Logon. RollingObserve records whether rolling updates `pwdLastSet`.
- `Test-SoaPrerequisites.ps1`, replacing `Test-SoaEnforcementPrereqs.ps1`. It adds the toolkit prerequisites: agent topology, Server Core, RSAT on agent hosts, rolling, KDS root key, OUs, test user, write scope.
- `Set-SoaDiagnosticsGpo.ps1`, replacing `Set-NtdsSecurityDiagnosticsGpo.ps1`: marker, `-Action Remove`, `-WhatIf`.
- Optional code signing of the deployed scripts (`SigningCertThumbprint`, tasks with `-ExecutionPolicy AllSigned`).

### Removed

- Job host, rotation task, `RotationDays` / `RotationTime` / `RotationMethod`, `EnforceDenyChangePassword` (no effect, K18), `Reset Password` right for the toolkit identity (except on the TestUser), password-reset and lockout tests (non-LDAP paths, lockout threshold 0).
- Break-glass account no longer part of the default setup (optional step `BreakGlass`; recovery path is `SetMode Audit`).

### Migration from 1.x

1. Create `SoaToolkit.config.psd1`; 1.x keys are reported as unused.
2. `Install-SoaToolkit.ps1 -Step All` renames and adopts the 1.x diagnostics GPO.
3. `Install-SoaToolkit.ps1 -Step RemoveLegacy` with `LegacyJobHost`, `LegacyGmsaName`, `LegacyTargetUserOUs`, `LegacyScriptFolder`.
4. `Install-SoaToolkit.ps1 -Step Conform` clears PNE where 1.x allowed it.

## 1.0.0 – 2026-10-19

- Consistent terminology (secret / secret rotation / automatic rolling); task `Rotate SCRIL hash` renamed `Rotate SCRIL secret`; `HashAgeWarnDays` renamed `SecretAgeWarnDays`.
- Secret changes verified through `unicodePwd` replication metadata; `RotationMethod` Toggle / RandomReset / Auto.
- `Test-ScrilBehavior.ps1`; monitoring of the rolling window.
- KIR detection supports feature-preview packages with `enabledList`.
- Neutral placeholders (`contoso.com`).
