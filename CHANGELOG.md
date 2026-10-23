# Changelog

## Unreleased

## 2.1.1 – 2026-10-23

A leaner release asset with only the files users need, and a simpler download path: verify the zip, unblock the zip, extract. The scripts are functionally unchanged (only their version lines).

### Changed

- **Release asset for users only** ([D-24](docs/DECISIONS.md)): `cloudsync-soa-toolkit-<version>.zip` contains `scripts/`, the two templates, the documentation for users and reviewers (`docs/` without `RELEASING.md`, `GITHUB-SETTINGS.md` and `docs/src/`), README, CHANGELOG, SECURITY, LICENSE and `SHA256SUMS.txt`. `tools/`, `tests/`, `.github/`, `.vscode/`, `AGENTS.md`, `CONTRIBUTING.md`, `PSScriptAnalyzerSettings.psd1`, `.gitattributes` and `.gitignore` are only in the repository and in the source code archives of the release.
  - `tools/Build-SoaRelease.ps1` packages an allow-list and fails if a required file is missing or a packaged document links to a file that is not packaged. Links to repository-only documents in README, CHANGELOG and SECURITY now use their full GitHub URL.
  - New unit tests build the asset from a copy of the repository and check its content and the link check.
- **Download, verify, unblock** (`docs/SETUP.md`, new section 3.1; release notes template): verify the zip with `gh release verify-asset` (release attestation) or its SHA-256, then `Unblock-File` on the zip itself, then extract - instead of unblocking every extracted file. Separate paths for the GitHub CLI, a browser download, isolated networks and a clone of the repository.

## 2.1.0 – 2026-10-22

Assessment of every FAIL / WARN of the monitor with a result line for the reader (OK, PENDING, ATTENTION, ACTION REQUIRED; in a dry run READY / NOT READY FOR THE REAL RUN), and fixes for defects that the lab dry run of 2.0.8 showed in the monitor and the static check then found.

### Fixed

- **Monitor on domain controllers: audit policy, event window, Kerberos failures and agent service were never read** (affected: 2.0.5-2.0.8 in the code; older versions not checked).
  - Cause: in the host block of `Watch-CloudUserConformance.ps1`, `$p = Get-ItemProperty ...` replaced the parameter `$P` (variable names are case-insensitive). From that line on, on every DC:
    - the effective audit policy was "not readable" (`-Scope All`);
    - the time window for the events 3097 / 3098 was empty, so both were always 0 (PASS) - the counts before switching to Enforced were not reliable;
    - the XPath query for Kerberos failures was invalid ("The specified query is invalid"), so failures of cloud users (0x17, 0x12, 0x18) were never reported;
    - the provisioning agent service was not queried: on a DC that is also an agent host, `AGENT-SVC` was always FAIL ("service not found"), also in the scheduled monitor (event 2002 at every run).
  - Fix: the variable is now `$diag`. Deploy 2.1.0 to the hosts (`-Step DeployTasks`).
- **`Install-SoaToolkit.ps1`: SetMode could ignore `-Mode`** (affected: 2.0.5-2.0.8 in the code; older versions not checked). The Delegate step stored the current policy mode in `$mode`, which replaced the parameter `-Mode`. A run with Delegate and SetMode (for example `-Step Delegate, SetMode -Mode Enforced`) then applied the current mode instead of the requested one: SetMode reported SAME and changed nothing. `-Step SetMode` on its own was not affected.
- **Monitor: WARN "Conformance errors" without text** when the `SoaToolkit` event log did not exist or had no error event (an empty result was counted as one entry).
- **Monitor: the KIR check named the GPO `''`** when the expected feature IDs came from the manifest instead of `deployment.json`.
- **`tools/Test-SoaScriptScope.ps1`, fourth check:** `@($x)` was reported when `$x` held the output of a loop that creates a `List[object]` inside; only a direct assignment (`$x = New-Object ...`) counts now.

### New

- **Assessment of FAIL / WARN** in `Watch-CloudUserConformance.ps1` and the Verify step: every FAIL / WARN gets a class and what to do.
  - BLOCKER (prerequisite outside the toolkit), ACTION (a toolkit step that is not part of this run), REVIEW (operational finding), FOLLOW-UP (reached after the installation, for example by the first reconcile run or a DC restart), PLANNED (a step of this run creates it).
  - Console: a line under each item and a closing section with the counts, the to-do list and the follow-up actions. CSV, JSON and HTML: columns `Class` and `Fix`; JSON: `Assessment`. Status, events and exit code are unchanged.
- **Dry run:** `Install-SoaToolkit.ps1 -WhatIf` passes its steps to the monitor (`-PlannedSteps`). What these steps create is PLANNED, and the result is **READY FOR THE REAL RUN** or **NOT READY FOR THE REAL RUN** (as long as there is a BLOCKER).
- **`docs/CHECKS.md`:** every monitor check, where its target state comes from and what to do. `tools/Export-SoaCheckTable.ps1` generates the table from the check origin table in `SoaToolkit.psm1` (`Get-SoaCheckAssessment`); the new hygiene check **H7** fails if the table differs or the monitor uses an unlisted check. README quick start, SETUP, OPERATIONS and VALIDATION (L2) explain how to read a dry run.
- **`tools/Test-SoaScriptScope.ps1`, fifth check:** a variable that differs from a parameter only in case and so replaces it. Run against 2.0.8, it reports `Watch-CloudUserConformance.ps1` (`$p`), `Install-SoaToolkit.ps1` (`$mode`) and `Invoke-CloudUserConformance.ps1` (`$server`, a deliberate reassignment, now in the same spelling).
- **`tools/Build-SoaRelease.ps1 -Unreleased`:** lab package of a state whose version is not agreed yet, named `cloudsync-soa-toolkit-unreleased-<yyyyMMdd-HHmm>.zip`.

### Changed

- **Monitor console: result instead of "Overall"** (the lab run of 2.1.0 ended with "Overall: FAIL" although everything had run as intended - only the first reconcile run was still pending).
  - The last line `Overall: <status>` is replaced by **`Result:`** for the reader - OK (green), PENDING (cyan, nothing to do now, says what it waits for), ATTENTION (yellow), ACTION REQUIRED (red); in a dry run READY / NOT READY FOR THE REAL RUN - and a dark grey line **`Monitoring status:`** with the worst raw status, the exit code and the note that events and script sensors use it. Status, events and exit code are unchanged.
  - A FAIL / WARN of class FOLLOW-UP is shown as `[PEND]` (cyan), one of class PLANNED as `[PLAN]` (green), also per user in *Provisioned users*. A legend line explains the tags. CSV and JSON keep FAIL / WARN; the HTML report has the column `Shown`, colours its rows the same way and shows the result at the top; JSON: `Assessment.Result`.
  - Class colours: BLOCKER and ACTION red; REVIEW yellow, red if its status is FAIL; FOLLOW-UP cyan; PLANNED green. The section header is "Checks - <domain> - scope <scope>" (it was "Result ... overall FAIL").
  - A FAIL / WARN without a class (checks of kind Info) is listed under *To do* and counts for the result.
  - `TASK-STATE`: a task that has not run yet (0x41303) says "not run yet".
- **Signal words and colours across the toolkit** (`docs/CHECKS.md`, new section): skipped lines of Install / Uninstall show `[SKIP]` instead of `~` (other tools use `~` for "changed in place"); "waiting for replication" and "not expired yet" are cyan (waiting) instead of yellow; the validation status REVIEW of `Export-SoaReport.ps1` is yellow (your confirmation is needed) instead of cyan. L18 also shows the result of the monitor.
- **`docs/SETUP.md`:** without `-WhatIf`, Install asks for confirmation before changes with a high impact; `-Confirm:$false` for an unattended run.
- **Release process** (`docs/RELEASING.md`, `AGENTS.md`, `CONTRIBUTING.md`):
  - the version is set only after the maintainer has agreed on it; until then every state, also a delivery of the AI assistant, keeps the changes under `## Unreleased`;
  - the AI assistant may set the agreed version with `Set-SoaVersion.ps1 -SkipRemoteCheck`; the maintainer repeats the script with the same version and `-Date`, which changes nothing and adds the check against origin and GitHub;
  - test in the lab with the release zip before tagging.

## 2.0.8 – 2026-10-22

Fixes the report output of the monitor, which stopped the Verify step of `Install-SoaToolkit.ps1`, and adds a static check against the cause.

### Fixed

- **`Watch-CloudUserConformance.ps1 -Scope All` stopped with "Argument types do not match"** after the list of provisioned users - also as the last part of `Install-SoaToolkit.ps1 -Step Verify` and `-Step All` (affected: 2.0.5-2.0.7 in the code; older versions not checked).
  - Cause: the array subexpression `@(...)` around a `System.Collections.Generic.List[object]` created with `New-Object` throws this exception in Windows PowerShell 5.1 and PowerShell 7 (reproduced with 7.4), also when the list arrives through a parameter. The monitor used `@($Results)` for its JSON report, and `ConvertTo-SoaHtmlTable` used `@($Rows)` for the HTML report.
  - Effect: the CSV files were written, the JSON and HTML reports were not. `Export-SoaReport.ps1` found no monitor report for L5, L6, L18 and L20.
  - The same expression made the **scheduled monitor** on every host (`-Scope Local`) fail silently when it saved `Status\monitor.json` (the error was caught). Its events (heartbeat, warnings, failures) were written; the status file was missing, so `Export-SoaReport.ps1` showed no scheduled monitor result for L18.
  - Fix: `$Results.ToArray()` and `foreach ($r in $Rows)`. Deploy 2.0.8 to the hosts (`-Step DeployTasks`) so that the scheduled monitor writes its status again.
  - The dry run in the lab first looked like a `-WhatIf` problem; it is not. The read-only scripts stay as in 2.0.6 and 2.0.7.

### New

- **`tools/Test-SoaScriptScope.ps1`, fourth check:** reports every `@($x)` in a script or module whose `$x` is assigned a `List[object]` in the same function or script. Run against 2.0.7, it reports the two lines in `Watch-CloudUserConformance.ps1`. A unit test covers `ConvertTo-SoaHtmlTable` with a `List[object]`.

## 2.0.7 – 2026-10-22

Release process: one script sets the version, a workflow builds the asset from a checked tag and creates a draft release, and every build can be compared by its contents digest. The toolkit scripts are unchanged apart from their version line.

### New

- **`tools/Set-SoaVersion.ps1`** prepares the release commit and is the only supported way to change the version:
  - refuses a version that exists as a tag on origin or as a GitHub release, also a draft (a published version is never changed);
  - sets the version and date in every place that carries them and rebuilds the PDF;
  - turns `## Unreleased` in the CHANGELOG into the version section and leaves an empty `## Unreleased` above it;
  - creates the release notes from a template if they are missing, runs the static checks and stages the files - it never commits, tags or pushes;
  - safe to repeat with the same version.
- **`tools/Test-SoaReleaseTag.ps1`** checks a release tag (T1-T8): name, annotated, SSH signature against `.github/allowed_signers` from `main`, commit on `main`, version, CHANGELOG section, release notes, no existing release. An invalid signature always fails; an unsigned tag fails unless `-AllowUnsigned`.
- **`.github/workflows/release.yml`**: on a pushed tag `v<major>.<minor>.<patch>`, it checks the tag with the checker taken from `main`, builds the asset (CI gate included), checks `SHA256SUMS.txt` and creates a **draft** release with title, notes and asset. Publishing stays manual. Only this job may write. Transition until signing is set up: the repository variable `SOA_ALLOW_UNSIGNED_TAGS` = `true` accepts an unsigned tag with a warning.
- **`docs/GITHUB-SETTINGS.md`**: the GitHub settings the process relies on, step by step - immutable releases, Actions permissions, rulesets for `main` and the release tags, the transition variable, security features, and the switch to signed commits and tags.
- Unit tests for both tools, including tags signed with an allowed and with an unknown SSH key.

### Changed

- **CHANGELOG** has a permanent `## Unreleased` section. New entries go there; the version is decided at release time. H6 requires it as the first section.
- **The version only where it is used:** the module, the help of the scripts in `scripts\` (deployed), the configuration template, the README status line and the PDF. Removed from the help of `tools\` and `tests\` (H6 now reports a version line there), from the issue templates, `docs/VALIDATION.md` and the README verification table.
- **H6** also checks the date of the CHANGELOG section, the release notes of the current version (present, no `TODO-RELEASE-NOTES`) and the version in the PDF keywords.
- **`tools/Build-SoaRelease.ps1`:**
  - version and date are read from the packaged tag, not from the working tree;
  - every zip entry carries the release date as its time;
  - it prints the contents digest (SHA-256 of `SHA256SUMS.txt`) to compare builds of the same tag - the zip digest can differ between machines (deflate implementation of the .NET version);
  - the CI gate counts only the CI workflow, so it also works inside the release workflow.
- **PDF:** reproducible build (no creation time) with version and date in its keywords; rebuilt. The PDF of 2.0.6 still carried the version 2.0.5.
- **CI:** `actions/checkout` v6.0.0 → v6.1.0. Both SHAs were compared with the tags in the `actions/checkout` repository. Since v6.0.2 checkout keeps annotated tags (actions/checkout#882); the release workflow also fetches the tag explicitly.
- **`docs/RELEASING.md`** rewritten for the phases develop, prepare, tag, release workflow, review and publish. `SECURITY.md`, `AGENTS.md` and `CONTRIBUTING.md` describe the new process.

## 2.0.6 – 2026-10-21

Makes the `-WhatIf` dry run of `Install-SoaToolkit.ps1` work end to end (found in the lab dry run of 2.0.5) and adds a static check against this class of defect.

### Fixed

- **`-WhatIf` skipped the toolkit's own scratch files** (affected: 2.0.4 and 2.0.5; older versions not checked). Inside a script, `$WhatIfPreference` does reach the built-in cmdlets, so the dry run also skipped work it needs itself:
  - `DeployTasks` staged no file in `%TEMP%`, and `Get-FileHash` failed with "Cannot find path ...\soa_stage_*\SoaToolkit.psm1"; the file hashes and `deployment.json` of the dry run were empty. With `SigningCertThumbprint` set, the step would have stopped with "Signing ... failed" (no signature object).
  - `KirGpo`: in PowerShell 7, `Start-Process` honours `-WhatIf`, so `msiexec /a` did not run and the step stopped with "msiexec /a failed with exit code". In Windows PowerShell 5.1 (no `-WhatIf` on `Start-Process`) the extraction ran, but its folder `%TEMP%\soa_kir_*` was not removed - in a real run neither, when the package was skipped (pre-existing KIR GPO).
  - Now staging and MSI extraction run in the dry run as well (`-WhatIf:$false` on the scratch paths; msiexec in the new module function `Expand-SoaMsi`), and both scratch folders are removed in a `finally` block. A dry run does not sign the staged scripts (no key use, no timestamp request) and reports SKIP instead.
  - Left-over folders `soa_stage_*` / `soa_kir_*` in `%TEMP%` of the admin account can be deleted.
- **Dry runs had no START line in the run log** (affected: 2.0.2-2.0.5, the versions with run markers). `Write-InstallLog` / `Write-UninstallLog` use `Add-Content`, which `-WhatIf` skipped; only the step lines written by the module reached the log, without their run. `Export-SoaReport.ps1` therefore found no dry run, and L2 stayed OPEN ("no -WhatIf run of Install -Step All found"). The run log is now written in dry runs as well; repeat the dry run with 2.0.6 for L2.
- **Verify and Conform wrote no report in a dry run** (affected: 2.0.4 and 2.0.5; older versions not checked). A script called with `&` inherits `$WhatIfPreference`, so the read-only `Watch-CloudUserConformance.ps1` (Verify) and `Invoke-CloudUserConformance.ps1 -Mode Analyze` (Conform) skipped their report files, and Verify printed the path of a report that did not exist. Both now run through `Invoke-ReadOnlyScript` and write their reports; they change nothing in the domain either way.

### New

- **`tools/Test-SoaScriptScope.ps1`, third check:** in a script that supports `-WhatIf`, writes to scratch and run-log paths (variables from `$env:TEMP`, `GetTempPath()`, `GetTempFileName()` or a `*.log` name) pass `-WhatIf:$false`, and there is no `Start-Process` (it honours `-WhatIf` in PowerShell 7 only; Windows PowerShell 5.1 has no such parameter). Run against 2.0.5, it reports the defects above. Three new unit tests.
- `AGENTS.md` (scope pitfalls) and `docs/VALIDATION.md` (L2: what a dry run writes) describe the rule.

## 2.0.5 – 2026-10-21

Fixes two defects found in the first lab run of `Install-SoaToolkit.ps1 -Step All` and one in the monitor, adds a static check against this class of defect, and tightens the ownership of the diagnostics GPO.

### Fixed

- **`Install-SoaToolkit.ps1 -Step Delegate` stopped with "Cannot convert null to type System.Guid"** (affected: 2.0.0-2.0.4). PowerShell variable names are case-insensitive, and the steps share one scope: `$g = Get-ADGroup ...` in the steps HostGroup and Groups replaced the GUID table `$G`, and `foreach ($s in ...)` in AuditConfig, Policy and AllowList replaced the SID table `$S`. Delegate then passed `$null` as the attribute GUID. Nothing was written with a wrong value: the step failed before its first ACE, and `BreakGlass` (the only other user of `$G`) is not part of `-Step All`. The tables are now `$KnownGuid` / `$KnownSid` in every script. Re-run `-Step All`; it is idempotent.
- **Monitor: locked-out and expired accounts were never reported** (affected: 2.0.0-2.0.4). In `Watch-CloudUserConformance.ps1` the per-user value `$ucc` replaced the flag table `$Ucc`, so the checks `USR-LOCKED` and the expiry checks compared against `$null`. The table is now `$UccFlag`.
- **`-WhatIf` could create GPOs** (affected: 2.0.0-2.0.4). Preference variables do not reach functions of a script module, and `New-SoaGpo` was called without `-WhatIf:$WhatIfPreference` in the steps BatchLogonGpo, KirGpo and AuditConfig. A dry run that reached these steps created the (empty, unlinked) GPOs. Check with `Uninstall-SoaToolkit.ps1 -Step Verify` or GPMC whether such GPOs exist after an earlier dry run; a later real run uses them.
- **`-Step All -WhatIf` on a fresh domain stopped at the Gmsa step** ("Group SOA-Toolkit-Hosts not found"). Steps that need an object an earlier step creates (host group, gMSA) now report `(WhatIf) ... not simulated further` and continue with the next step; a real run still stops.

### Changed

- **Diagnostics GPO ownership and markers** (`Set-SoaDiagnosticsGpo.ps1`, `Install-SoaToolkit.ps1 -Step DiagnosticsGpo`):
  - The marker is set also when the script is used on its own without a configuration (default project URL); a configuration that fails to load is reported instead of silently ignored.
  - The GPP registry item carries a short marker in its description (GPMC tab *Common*). `-Action Enable` adds it to toolkit GPOs created by older versions.
  - `-Action Enable` and `-Action Remove` refuse a GPO of the same name without the marker unless `-Force`; Install no longer enables a pre-existing foreign GPO (WARN instead).
  - The toolkit 1.x GPO is adopted only if its item has "Remove this item when it is no longer applied"; otherwise the step reports FAIL with instructions and changes nothing.
  - `Get-SoaMarker` accepts a missing configuration; new module function `Get-SoaDiagnosticsItemState`.
- Repository: `SHA256SUMS.txt` at the top level is git-ignored (it belongs only to the release zip). `AGENTS.md` / `CONTRIBUTING.md` name the trailer format `Assisted-by: <tool> (<vendor>)`.
- CI: `actions/checkout` v4 (Node.js 20, deprecated on GitHub-hosted runners) replaced by v6.0.0 (Node.js 24), pinned to its commit SHA. New `.github/dependabot.yml` keeps the actions current.
- CI: job and step time limits (a hang fails after minutes instead of the 6-hour default) and `-NonInteractive` for every PowerShell process of the checks and tests, so a prompt fails visibly instead of waiting.

### New

- **`tools/Test-SoaScriptScope.ps1`**, part of `Invoke-SoaStaticChecks.ps1` and the unit tests (so it also runs under Windows PowerShell 5.1 in CI):
  - no script-level context value (assigned from `Get-Soa*` / `Import-Soa*` / `Initialize-Soa*` / `Select-Soa*`) is overwritten later in the same scope, case-insensitive, including `foreach` variables;
  - every call of a module function with `SupportsShouldProcess` from a script that supports `-WhatIf` passes `-WhatIf:$WhatIfPreference`.
  Both checks report the 2.0.4 defects above when run against 2.0.4.

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

- **Release process ([docs/RELEASING.md](https://github.com/mayer-bautechnik/cloudsync-soa-toolkit/blob/main/docs/RELEASING.md)):**
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
  - [AGENTS.md](https://github.com/mayer-bautechnik/cloudsync-soa-toolkit/blob/main/AGENTS.md): rules for contributors and coding agents.
  - [docs/DECISIONS.md](docs/DECISIONS.md): design decisions D-01 to D-20.
  - [docs/EVIDENCE.md](docs/EVIDENCE.md): lab evidence behind *Observed*.
  - [docs/VALIDATION.md](docs/VALIDATION.md): checklist L1-L20.
  - [docs/REPORTING.md](docs/REPORTING.md): reports and bug reports.
  - [docs/RELEASING.md](https://github.com/mayer-bautechnik/cloudsync-soa-toolkit/blob/main/docs/RELEASING.md), [docs/MAINTENANCE.md](docs/MAINTENANCE.md): release process and recurring maintenance.
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
