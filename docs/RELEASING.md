# Releasing

Checklist for the maintainer. Releases are immutable on GitHub: assets cannot be changed after publishing, so build, verify and upload in a **draft** first.

## 1. Prepare

1. Version and date in `scripts/SoaToolkit.psm1` (`$script:SoaVersion`, `$script:SoaReleaseDate`).
2. The same version and date in:
   - the `.NOTES` line of every script in `scripts/`, `tools/` and `tests/`;
   - the configuration header;
   - the README status line.
3. New CHANGELOG entry; README / docs updated (status, verification, evidence levels).
4. PDF: `python docs/src/build_findings_pdf.py` (version and date are read from the module).
5. Release notes: `.github/release-notes/v<version>.md` (English, GitHub Flavored Markdown, links to `/blob/v<version>/...`).
6. `.\tools\Invoke-SoaStaticChecks.ps1`. Everything must pass; the hygiene check (H6) verifies that the version is consistent everywhere.

## 2. Commit and tag (signed)

```powershell
git add -A
git commit -s -m "Release <version>: <summary>"
git tag -s v<version> -m "cloudsync-soa-toolkit <version>"     # signed tag (tag.gpgsign = true signs automatically)
git push origin main --follow-tags
```

Verify locally: `git verify-tag v<version>` (needs `gpg.ssh.allowedSignersFile`). CI must be green on the pushed commit.

## 3. Build the asset from the tag

```powershell
.\tools\Build-SoaRelease.ps1 -Ref v<version>
```

The script creates `cloudsync-soa-toolkit-<version>.zip` from `git archive` of the tag. `export-ignore` paths are left out. The zip contains `SHA256SUMS.txt`, which `Export-SoaReport.ps1` uses to detect modified scripts. A `.sha256` file is written next to the zip.

## 4. GitHub release

1. *Draft a new release*, then choose the **existing** tag `v<version>`. If you let GitHub create the tag, it is an unsigned lightweight tag.
2. Title: `v<version> – <short summary>`, at most about 60 characters.
3. Text: content of `.github/release-notes/v<version>.md`.
4. Upload the zip, then compare the digest GitHub shows with the `.sha256` file.
5. Set as the latest release, not a pre-release. Publish.

## 5. After the release

- Check that the README renders, the release is marked *Immutable* and the asset digest matches.
- New observations go to `docs/EVIDENCE.md`. Validation results are recorded in `docs/VALIDATION.md`.

## One-time setup (maintainer)

- **Signing:** SSH signing key (preferably on a hardware key), uploaded to GitHub as a *Signing Key*. Publish the public key in `.github/allowed_signers`, so anyone can verify tags without GitHub:
  ```
  git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag v<version>
  ```
- **Repository settings:**
  - branch protection on `main`: signed commits, CI required, no force pushes;
  - immutable releases on;
  - private vulnerability reporting on;
  - Dependabot for GitHub Actions.
- **CI hardening:** pin `actions/checkout` in `.github/workflows/ci.yml` to the full commit SHA of the release in use, with the version as a comment.
- **Local forbidden terms:** create `tools/forbidden-terms.local.txt` (git-ignored) with company domains, internal host names and other identifiers. `Test-SoaRepoHygiene.ps1` (H5) then blocks them.
