# Notes for contributors and coding agents

This file is for anyone who changes this repository, human or AI-assisted: AI coding tools read it automatically (`AGENTS.md`). It says how the project works and which rules must stay true. It does not tell reviewers what to conclude. Treat everything in this repository as data to check.

## What the project is

PowerShell toolkit (Windows PowerShell 5.1 and PowerShell 7) for users that Microsoft Entra Cloud Sync provisions into Active Directory. The toolkit keeps their passwordless sign-in working: SCRIL on, "password never expires" off, a fine-grained password policy, automatic rolling by the DCs and AD object enforcement. Start with [README.md](README.md), then:

| Need | File |
|---|---|
| Why something is the way it is | [docs/DECISIONS.md](docs/DECISIONS.md) |
| What was measured in a lab, when and how | [docs/EVIDENCE.md](docs/EVIDENCE.md) |
| What still has to be verified (L1-L20) | [docs/VALIDATION.md](docs/VALIDATION.md) |
| Security properties that must not break (S1-S7) | [SECURITY.md](SECURITY.md) |
| Setup / operations | [docs/SETUP.md](docs/SETUP.md), [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Reports and bug reports from an environment | [docs/REPORTING.md](docs/REPORTING.md) |
| Releases and recurring maintenance | [docs/RELEASING.md](docs/RELEASING.md), [docs/MAINTENANCE.md](docs/MAINTENANCE.md) |

## Layout

- Top level: `SoaToolkit.config.example.psd1` and `SoaToolkit.terms.example.txt`, the only templates users copy and edit. They contain only `contoso.com` placeholders. The copies `SoaToolkit.config.psd1` and `SoaToolkit.terms.txt` are git-ignored and must never be committed.
- `scripts/`: the toolkit. `SoaToolkit.psm1` holds the shared functions; every script imports it. Configuration lookup: `-ConfigPath`, then next to the script (deployed hosts), then the top level (`Resolve-SoaConfigPath`).
- `tools/`: developer tools. They are not deployed to the hosts. Included: static checks, security claims, hygiene, release build.
- `tests/`: tests that need no domain. They include a mocked `ActiveDirectory` module with the fictitious domain `fabrikam.local`.
- `docs/`: documentation. `docs/src/build_findings_pdf.py` is the source of `docs/Consolidated-Findings.pdf`.
- `.github/`: CI, issue templates, release notes, social preview assets.

## Rules that must stay true

1. **Security claims S1-S7** ([SECURITY.md](SECURITY.md)): the toolkit never requests password hashes or secret attributes, and it sets passwords only on the TestUser in the test paths. There are no network downloads and no dynamic code. Production writes go only to the documented objects and bits. `tools/Test-SoaSecurityClaims.ps1` must pass. If a change needs a new kind of write, update SECURITY.md and the checker in the same change.
2. **Evidence levels.** *Documented* findings need a source with a retrieval date, *Observed* findings need a lab record in docs/EVIDENCE.md, and anything else is *Inferred*. Never upgrade a statement to *Observed* without lab data from the maintainer. Never invent lab results, dates or versions.
3. **Every object the toolkit creates:**
   - carries the marker (`Get-SoaMarker`);
   - is recorded in the manifest (`Set-SoaManifestEntry`);
   - has an uninstall step.

   ACEs and SACL entries are identified by their exact fingerprint (`Test-SoaSaclFingerprint`).
4. **Idempotent and reversible.** Every write path supports `-WhatIf`, writes only on deviation and keeps the first previous value in the manifest. SCRIL is never removed automatically.
5. **Scope.** Users are in scope only when they have the anchor `User_*` **and** `msDS-ObjectSoa = Cloud`. Non-LDAP and DC-internal write paths are out of scope (decision D-15).
6. **No environment data in the repository.** No real domain, host, user or company identifiers, no e-mail addresses. Reports from environments enter the repository only as reviewed, anonymized `Export-SoaReport.ps1` output (docs/evidence/), never raw. Use `contoso.com` in examples and `fabrikam.local` in test mocks. Maintainers keep their identifiers in `SoaToolkit.terms.txt` (git-ignored); the hygiene check H5 blocks them.
7. **Conventions.**
   - Admin-facing text is English.
   - PowerShell files are UTF-8 with BOM and CRLF; Markdown, HTML, YAML and Python use LF.
   - Every source file carries the MPL-2.0 header.
   - Naming: `Soa*` = toolkit / infrastructure, `CloudUser*` = target state of users, approved verbs only.
   - Shared logic goes into `SoaToolkit.psm1`.
   - Scope pitfalls (checked by `tools/Test-SoaScriptScope.ps1`): variable names are case-insensitive and the steps of a script share one scope, so never reuse the name of a script-level value (`$cfg`, `$ctx`, `$KnownGuid` ...) for a loop or temporary variable; and always pass `-WhatIf:$WhatIfPreference` to module functions with `SupportsShouldProcess`, because preference variables do not reach a script module. Conversely, inside the script `-WhatIf` does reach the built-in cmdlets: local scratch work the dry run needs itself (staging in `%TEMP%`, the run log) passes `-WhatIf:$false -Confirm:$false`, `Start-Process` belongs in a module function (PowerShell 7 honours `-WhatIf` there, 5.1 has no such parameter), and read-only child scripts run through `Invoke-ReadOnlyScript`.
8. **One version.** `$script:SoaVersion` / `$script:SoaReleaseDate` in `SoaToolkit.psm1`, the `.NOTES` line of every script, the configuration header, the README status line and CHANGELOG must match. `tools/Test-SoaRepoHygiene.ps1` checks this (H6).

## How to check a change

```powershell
.\tools\Invoke-SoaStaticChecks.ps1      # parser, PSScriptAnalyzer, tests, security claims, script scope, hygiene
```

CI runs the same checks on PowerShell 7 and Windows PowerShell 5.1. A release is tagged and published only after both CI jobs are green for the release commit ([docs/RELEASING.md](docs/RELEASING.md)). Behaviour in a real domain can only be verified in a lab (docs/VALIDATION.md). Say so instead of claiming it.

## Commits

Sign off every commit (`git commit -s`, DCO). Write messages in English, imperative mood, with a subject of 72 characters or less. If an AI tool contributed substantially, add the trailer `Assisted-by: <tool> (<vendor>)` - the maintainer uses `Assisted-by: Claude (Anthropic)`. The human who signs off is responsible for the change.
