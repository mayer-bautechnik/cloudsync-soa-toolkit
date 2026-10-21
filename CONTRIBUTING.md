# Contributing

Thank you for helping to improve the SOA Toolkit.

## Authors and contributors

| Role | Name | Organisation |
|---|---|---|
| Licensor, author, maintainer | Johannes Lämmermann | GEBR. MAYER Bautechnik (GEBR. MAYER GmbH + Co. KG) |
| Licensor | GEBR. MAYER GmbH + Co. KG | |
| Contributor | Tom Rückert | teccle group |

## License of contributions (inbound = outbound)

This project is licensed under the [Mozilla Public License 2.0](LICENSE). By submitting a contribution you agree that it is licensed under the MPL-2.0, the same license as the project. No contributor license agreement (CLA) is required.

Please sign off every commit (Developer Certificate of Origin, https://developercertificate.org/):

```
git commit -s -m "Short description"
```

The sign-off line (`Signed-off-by: Name <email>`) confirms that you have the right to submit the change under the project's license.

## Reporting issues, lab results and questions

| What | Where | Attachment |
|---|---|---|
| Bug | issue form *Bug report* | `.\Export-SoaReport.ps1 -Purpose BugReport -Description '...'`, reviewed, then `-Package` |
| Lab validation result (L1-L20) | issue form *Lab validation result* | `.\Export-SoaReport.ps1`, reviewed, then `-Package` |
| Question or idea | issue form *Question or idea* | usually none |
| Security-relevant finding | **private** vulnerability report ([SECURITY.md](SECURITY.md)), never a public issue | anonymized package if needed |

- `Export-SoaReport.ps1` collects every fact a report needs (version, OS builds and updates, agent version, topology, policy mode, script integrity) and replaces identifiers by pseudonyms. You review the folder before packaging. Details: [docs/REPORTING.md](docs/REPORTING.md).
- **Do not attach the raw reports** of `Test-SoaPrerequisites.ps1`, `Watch-CloudUserConformance.ps1`, `Get-SoaEnforcementImpact.ps1` or `Test-SoaBehavior.ps1`, or event logs. They contain names of your environment; the export includes them anonymized.
- **Never post identifying data**: no tenant IDs, domain, host or user names, SIDs or GUIDs of your environment. Never attach the pseudonym map (`private\*.map.csv`).

## Changes

- Read [AGENTS.md](AGENTS.md) (rules that must stay true) and, for design questions, [docs/DECISIONS.md](docs/DECISIONS.md).
- Your `SoaToolkit.config.psd1` and `SoaToolkit.terms.txt` are git-ignored. Change only the templates (`*.example.*`), and keep them free of real values.
- Run `.\tools\Invoke-SoaStaticChecks.ps1` before you open a pull request. It runs the parser, PSScriptAnalyzer, the tests, the security claims, the script-scope check and the hygiene checks. Started from PowerShell 7 on Windows, it also runs the tests under Windows PowerShell 5.1. CI runs the same checks on both versions, and a pull request is merged only when CI is green.
- Target Windows PowerShell 5.1 **and** PowerShell 7.x. Check with PSScriptAnalyzer using `PSScriptAnalyzerSettings.psd1` (the VS Code workspace settings in `.vscode/` use it automatically and enable `git.alwaysSignOff`).
- Follow the naming scheme: `Soa*` = toolkit / infrastructure / Microsoft feature, `CloudUser*` = target state of the users; approved PowerShell verbs.
- Put shared logic into `SoaToolkit.psm1`.
- Every new object the toolkit creates must:
  - carry the marker (`Get-SoaMarker`);
  - be recorded in the manifest (`Set-SoaManifestEntry`);
  - have a matching step in `Uninstall-SoaToolkit.ps1`.
- Every write path supports `-WhatIf` and is idempotent. Never read, log or store secret values.
- Mark statements in the documentation as **Documented**, **Observed** or **Inferred**, and add sources (with retrieval date) to the README references.
- Admin-facing texts (scripts, comments, documentation) are written in English.
- Keep the MPL-2.0 header (copyright line and repository link) in every file you change, and add it to new files.
- A change that needs a new kind of write operation must update the claims in [SECURITY.md](SECURITY.md) and `tools/Test-SoaSecurityClaims.ps1` in the same pull request.

## AI-assisted contributions

AI tools may be used. The person who signs off the commit:
- has read and understood every line;
- has run the checks;
- is responsible for the change (DCO).

Statements labelled *Observed* require real lab data ([docs/EVIDENCE.md](docs/EVIDENCE.md)). AI-generated "results" are not evidence. If an AI tool contributed substantially, say so in the pull request and optionally add the trailer `Assisted-by: <tool> (<vendor>)` to the commit, for example `Assisted-by: Claude (Anthropic)`.
- Social preview and README banner: edit `.github/assets/social-preview.html` and render it at exactly 1280×640 and 1820×640 (PNG; JPEG XL optional). Upload the 1280×640 PNG under *Settings → General → Social preview* (GitHub accepts PNG, JPG or GIF under 1 MB). The folder is excluded from source archives (`export-ignore`).
