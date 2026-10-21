# Changelog

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
