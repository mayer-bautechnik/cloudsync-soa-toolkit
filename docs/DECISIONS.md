# Design decisions

Short records of the decisions that shape the toolkit: context, decision, alternatives that were rejected, and the evidence. Change a decision only through a new or updated entry. Do not quietly change the code instead. Finding numbers (K, F) refer to the [README](../README.md#key-findings).

| ID | Decision | Since |
|---|---|---|
| D-01 | No password rotation by the toolkit, the DCs roll the secret | 2.0.0 |
| D-02 | SCRIL on, "password never expires" off, no deny-change ACEs | 2.0.0 |
| D-03 | One PSO on an AD-native global group; 30 days, length 64, lockout 0 | 2.0.0 |
| D-04 | Onboarding on every writable DC, reconcile on every agent host, no management server | 2.0.0 |
| D-05 | Scope by attributes, domain-wide; write permissions follow the agent scope | 2.0.0 |
| D-06 | The toolkit creates and maintains the enforcement policy itself | 2.0.0 |
| D-07 | Least-privilege gMSA without "Manage auditing and security log" | 2.0.0 |
| D-08 | Own narrow SACL entry, never rely on foreign audit rules | 2.0.1 |
| D-09 | Audit GPO only adds missing subcategories; event 4662 is not used | 2.0.0 |
| D-10 | "Log on as a batch job" via GPO with the merged effective list | 2.0.0 |
| D-11 | KIR enablement GPO from Microsoft's package, one per OS with WMI filter | 2.0.0 |
| D-12 | Marker, manifest and fingerprints identify everything the toolkit changed | 2.0.0 |
| D-13 | SCRIL is never removed automatically; `RevertUsers` only explicitly | 2.0.0 |
| D-14 | No break-glass account by default; recovery is `SetMode Audit` | 2.0.0 |
| D-15 | Non-LDAP and DC-internal write paths are out of scope | 2.0.0 |
| D-16 | MPL-2.0, inbound = outbound, DCO sign-off | 2.0.0 |
| D-17 | Naming scheme `Soa*` / `CloudUser*` | 2.0.0 |
| D-18 | Optional code signing, tasks then run with `AllSigned` | 2.0.0 |
| D-19 | Environment data leaves only anonymized, after human review | 2.0.2 |
| D-20 | Security claims are checked by a tool, not only documented | 2.0.2 |
| D-21 | User-edited files are templates at the top level; the copies are never versioned or shipped | 2.0.4 |
| D-22 | Admin data (`ReportPath`) is separated from runtime data (`DataPath`) | 2.0.4 |
| D-23 | The toolkit sizes its own event log; central collection with Microsoft-native means | 2.0.4 |
| D-24 | The release asset contains only what users need; it is verified and unblocked as a whole | 2.1.1 |

---

### D-01 No password rotation by the toolkit, the DCs roll the secret
- **Context:** Provisioned users never know their AD password. An expired AD password blocks the passwordless Kerberos sign-in (K2). Toolkit 1.x rotated the secret itself from a job host.
- **Decision:** Enable automatic rolling (`msDS-ExpirePasswordsOnSmartCardOnlyAccounts`, DFL ≥ 2016). The DC re-randomizes an expired SCRIL secret at the next passwordless sign-in.
- **Rejected:**
  - Rotation by the toolkit. It needs a central job, password-reset rights and a single point of failure, and it is not needed (K10, K16).
  - "Password never expires". It disables rolling and leaves a static secret (K17).
- **Evidence:** K9 (Documented), K10, K16 (Observed), K12 (Observed / Inferred for idle accounts).

### D-02 SCRIL on, "password never expires" off, no deny-change ACEs
- **Context:** Setting SCRIL randomizes the secret (K11). PNE makes the computed expiry "never" (K17).
- **Decision:** The target state is SCRIL set and PNE cleared. "User cannot change password" ACEs are not used.
- **Rejected:** Deny-change ACEs, because they have no effect on the randomization (K18).

### D-03 One PSO on an AD-native global group; 30 days, length 64, lockout 0
- **Context:** Synced groups are universal, and PSOs apply only to users and global groups (K19).
- **Decision:**
  - The toolkit maintains `SOA-CloudUsers-PSO` (global, AD-native) as the only PSO target.
  - PSO values:
    - max age 30 days. This is the rolling interval; DISA STIG requires ≤ 60.
    - min age 1 day, history 24.
    - min length 64.
    - lockout threshold 0. The secret is random and unknown, so a lockout would only enable denial of service.
- **Rejected:** PSO on synced groups (not possible), domain-wide password policy changes (too broad).

### D-04 Onboarding on every writable DC, reconcile on every agent host, no management server
- **Context:** Events 4720 / 5136 exist only on the DC that processed the write (K21), and Microsoft does not document which DC an agent writes to (K20).
- **Decision:**
  - An event-triggered task runs on every writable DC.
  - A staggered reconcile runs on every agent host.
  - A monitor runs on every toolkit host.
  - Nothing runs only on the PDC emulator; runtime reads go to the local / selected DC.
- **Rejected:** A central management server or PDCe-only processing, because both are single points of failure.

### D-05 Scope by attributes, domain-wide; write permissions follow the agent scope
- **Decision:**
  - In scope = anchor `User_*` and `msDS-ObjectSoa = Cloud`, in the whole domain.
  - Exclusions come from a group or `ExcludeOUs`; staged rollout uses `PilotMode`.
  - Write permissions are delegated where the agent gMSA has write permissions (`WriteScope = AgentScope`).
- **Rejected:** OU lists as scope. They drift from the Cloud Sync configuration and miss SOA-converted users outside the lists.

### D-06 The toolkit creates and maintains the enforcement policy itself
- **Context:** Microsoft's `Set-CloudSyncSOAPolicy.ps1` cannot change the mode of an existing policy (F1). It creates the `SOA-Policies` container itself (F2) and adds only the local agent (F6).
- **Decision:**
  - The toolkit creates the same `CN=Cloud` object in mode Audit.
  - It never creates the container.
  - It allow-lists all agent gMSAs and the toolkit gMSA, with SID validation and the 64 limit.
  - It switches modes with its own steps (`SetMode`, `SetModeAudit`).

### D-07 Least-privilege gMSA without "Manage auditing and security log"
- **Decision:** The toolkit gMSA receives only the rights listed in [SECURITY.md](../SECURITY.md#security-properties-claims) (S4). It is not a Domain Admin or local admin. Checks that need more rights, such as reading SACLs or the effective audit policy, run interactively (`Watch -Scope All`, `Install -Step Verify`).

### D-08 Own narrow SACL entry, never rely on foreign audit rules
- **Context:** In 2.0.0 a broad diagnostic SACL counted as sufficient. Removing it would have silently stopped event 5136 for SOA conversions.
- **Decision:** `AuditConfig` always sets the toolkit's own entry (Everyone, Success, WriteProperty on `msDS-ObjectSoa`, descendant users) and identifies it by fingerprint. Foreign rules are reported (`AUD-SACL-OTHER`). The monitor checks the entry (`AUD-SACL`).

### D-09 Audit GPO only adds missing subcategories; event 4662 is not used
- **Decision:** A GPO is created only for missing subcategories: User Account Management success, DS Changes success, Kerberos AS failure. Existing auditing is never reduced.
- **Note:** "Directory Service Access" (event 4662) was used once in the lab, only to diagnose the `userAccountControl` mapping. The toolkit does not need it.

### D-10 "Log on as a batch job" via GPO with the merged effective list
- **Context:** User rights from GPOs replace each other. A local `secedit` change (1.x) is overwritten by the next DC policy refresh.
- **Decision:** The GPO contains the current effective list plus the gMSA. Validation item L4 confirms that nothing is lost.

### D-11 KIR enablement GPO from Microsoft's package, one per OS with WMI filter
- **Decision:**
  - The MSI is extracted and its ADMX/ADML are copied unchanged to the central store; nothing is authored by the toolkit.
  - There is one GPO per OS (WS2022 / WS2025), with a WMI filter on the build.
  - An existing KIR GPO is detected and adopted as pre-existing.

### D-12 Marker, manifest and fingerprints identify everything the toolkit changed
- **Decision:**
  - Every created object carries `[SoaToolkit] Managed by SOA Toolkit - do not modify manually` and the repository link.
  - Every change is recorded in the manifest; the first previous value wins.
  - Changes without a description field are identified by trustee, exact fingerprint or manifest ([SETUP 9.1](SETUP.md#91-changes-that-cannot-carry-a-marker)).

### D-13 SCRIL is never removed automatically; `RevertUsers` only explicitly
- **Decision:**
  - Users leaving the scope keep SCRIL (a warning is logged).
  - `Uninstall-SoaToolkit.ps1 -Step RevertUsers` restores previous flags only when called explicitly, and it warns that users may need a password again.

### D-14 No break-glass account by default; recovery is `SetMode Audit`
- **Decision:** Domain Admins can always change the policy object, so switching to Audit is the recovery path. An optional break-glass step exists.

### D-15 Non-LDAP and DC-internal write paths are out of scope
- **Decision:** The toolkit uses and tests only LDAP writes. Other paths are not used, not tested and not claimed.

### D-16 MPL-2.0, inbound = outbound, DCO sign-off
- **Decision:**
  - Licensors are GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann.
  - Contributions come under the same license.
  - Every commit is signed off; no CLA is required.

### D-17 Naming scheme `Soa*` / `CloudUser*`
- **Decision:** `Soa*` = toolkit, infrastructure and Microsoft's feature. `CloudUser*` = target state of the users. Only approved PowerShell verbs are used.

### D-18 Optional code signing, tasks then run with `AllSigned`
- **Decision:** If `SigningCertThumbprint` is set, `DeployTasks` signs the scripts and the tasks run with `-ExecutionPolicy AllSigned`. Otherwise the integrity check compares file hashes (`INTEGRITY`).

### D-19 Environment data leaves only anonymized, after human review
- **Context:** Lab results and bug reports need data from real environments.
- **Decision:** `Export-SoaReport.ps1` collects into a local folder and replaces identifiers by stable pseudonyms. The map stays outside the folder, a leak check runs, and packaging needs a separate, confirmed step ([REPORTING.md](REPORTING.md)).
- **Rejected:**
  - Automatic upload. The operator must see what leaves.
  - Free-form copy and paste, which is not reproducible and easy to leak.

### D-20 Security claims are checked by a tool, not only documented
- **Decision:** S1-S5 are checked statically by `tools/Test-SoaSecurityClaims.ps1` in CI. The checker also prints an inventory of all write operations for reviewers, human or AI.

### D-21 User-edited files are templates at the top level; the copies are never versioned or shipped
- **Context:** Up to 2.0.3, `scripts\SoaToolkit.config.psd1` was the template and the user's configuration at the same time. An update overwrote it, a maintainer could commit real values, and the integrity check could not tell a template from a configuration.
- **Decision:**
  - `SoaToolkit.config.example.psd1` and `SoaToolkit.terms.example.txt` are at the top level. Users copy them to `SoaToolkit.config.psd1` / `SoaToolkit.terms.txt`; the copies are git-ignored and not in the release zip.
  - The scripts look for the configuration at `-ConfigPath`, then next to the script (deployed hosts, old layout), then at the top level. Two configurations at once are refused.
  - One terms file serves both report pseudonyms and repository hygiene.
- **Rejected:**
  - Configuration in the user profile or registry: not visible, hard to review.
  - Moving `PSScriptAnalyzerSettings.psd1`: the top level is the VS Code / PSScriptAnalyzer default.

### D-22 Admin data (`ReportPath`) is separated from runtime data (`DataPath`)
- **Context:** The default `ReportPath` was inside `DataPath`. On a toolkit host (no separate admin workstation) this had two effects: `DeployTasks` gave the toolkit gMSA modify rights on the manifest that a Domain Admin later executes during uninstall, and `RemoveTasks` deleted manifest and reports during the rollback.
- **Decision:**
  - Default `ReportPath = C:\SoaToolkitAdmin\Reports`, created with access for Administrators and SYSTEM only.
  - The admin scripts refuse to run on a DC / agent host when `ReportPath` is inside `DataPath` or `ScriptInstallPath`, or when they run from the deployed copy (`Assert-SoaAdminPaths`).

### D-23 The toolkit sizes its own event log; central collection with Microsoft-native means
- **Context:** A classic log created by `CreateEventSource` has 512 KB and "overwrite older". When it is full, new events can be dropped, and the local log is also the buffer of Windows Event Forwarding.
- **Decision:**
  - `DeployTasks` sets `EventLogMaxSizeMB` (default 64) with "overwrite as needed"; the monitor checks it (`EVENTLOG-SIZE`).
  - Optional read access for NETWORK SERVICE on this log only (`EventLogAllowWef`).
  - Documented collection paths: WEF/WEC with `SOA-Toolkit-Hosts` as subscription ACL, AMA/DCR, both combined, SCOM.
- **Rejected:** adding NETWORK SERVICE to *Event Log Readers* by the toolkit. That opens the Security log as well; it stays the operator's decision.

### D-24 The release asset contains only what users need; it is verified and unblocked as a whole
- **Context:** Up to 2.1.0 the release zip contained the whole repository except `.github/assets`: tools, tests, CI workflows, editor settings and maintainer documents that users neither need nor should run. The instructions said to unblock every extracted file (`Get-ChildItem -Recurse | Unblock-File`), after the download had been checked by its hash.
- **Decision:**
  - `tools/Build-SoaRelease.ps1` packages an allow-list: `scripts/`, the two templates, `docs/` without the maintainer documents, README, CHANGELOG, SECURITY, LICENSE, plus `SHA256SUMS.txt`. A new top-level file is left out until it is listed. The build fails if a required file is missing or a packaged document links to a file that is not packaged.
  - The full source stays available: repository clone and the source code archives of every tag (generated by `git archive`, so `.gitattributes` is not used to slim the asset).
  - Download path for users: verify the zip (`gh release verify-asset` against the release attestation, or SHA-256), then `Unblock-File` on the zip only, then extract. The extracted files carry no download mark. Works offline with Windows PowerShell 5.1 alone.
- **Rejected:**
  - `export-ignore` for tools and tests: it would also remove them from the source code archives that reviewers use.
  - Unblocking every extracted file: it removes the mark without a link to the verification of the download.
  - For now, a package on the PowerShell Gallery: the toolkit is a folder with scripts, a shared module and a configuration next to them, not an installable module. To be reconsidered if the scripts become a module.
