# Changelog

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
