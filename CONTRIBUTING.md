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

## Reporting issues

- Describe the toolkit version, OS build of the DCs / agent hosts, the step / suite you ran and the result.
- **Never post identifying data**: no tenant IDs, domain names, user names, SIDs or GUIDs of your environment, and no unredacted reports or event logs. Replace them with `contoso.com`-style placeholders.
- For security-relevant findings see [SECURITY.md](SECURITY.md).

## Changes

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
- Social preview and README banner: edit `.github/assets/social-preview.html` and render it at exactly 1280×640 and 1820×640 (PNG; JPEG XL optional). Upload the 1280×640 PNG under *Settings → General → Social preview* (GitHub accepts PNG, JPG or GIF under 1 MB). The folder is excluded from source archives (`export-ignore`).
