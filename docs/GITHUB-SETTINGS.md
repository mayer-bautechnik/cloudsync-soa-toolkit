# GitHub settings

Step-by-step settings of the GitHub repository that the release process ([RELEASING.md](RELEASING.md)) relies on. They are not stored in the repository, so they are described here. Labels follow the GitHub documentation; the exact wording in the web interface can change slightly.

You need the *Admin* role on the repository. Do the steps in this order: the rulesets need CI runs from the last days to offer the status-check names, and the release workflow needs the variable before the first tag.

| # | Setting | Why |
|---|---|---|
| 1 | Immutable releases | a published release (tag + assets) cannot be changed |
| 2 | Actions: permissions | only GitHub's own actions, pinned to commit SHAs; read-only token by default |
| 3 | Variable `SOA_ALLOW_UNSIGNED_TAGS` | transition: unsigned tags are accepted with a warning until signing is set up |
| 4 | Branch ruleset `main` | no deletion or force push of `main`; changes by others only by pull request with green CI |
| 5 | Tag ruleset `release-tags` | only the maintainer can create, move or delete `v*` tags |
| 6 | Security features | private vulnerability reporting, Dependabot alerts |
| 7 | First release | check that everything works together |
| 8 | Later: signed commits and tags | the target state; until then an open point (tracked in a GitHub issue) |

## 1. Immutable releases

1. Repository page → **Settings** (tab under the repository name).
2. **General** (left sidebar, selected by default) → scroll to **Releases**.
3. Tick **Enable release immutability**. It applies to releases published from now on.

## 2. Actions permissions

1. **Settings** → left sidebar **Actions** → **General**.
2. **Actions permissions**:
   - select **Allow *owner*, and select non-*owner*, actions and reusable workflows**;
   - tick **Allow actions created by GitHub** (the workflows use only `actions/checkout`);
   - leave the field for further allowed actions empty;
   - tick **Require actions to be pinned to a full-length commit SHA** (the workflows already do this);
   - **Save**.
3. **Approval for running fork pull request workflows from contributors**: select **Require approval for all external contributors** → **Save**.
4. **Workflow permissions**:
   - select **Read repository contents and packages permissions** (read-only default for `GITHUB_TOKEN`). The release job asks for `contents: write` itself, only for creating the draft release;
   - leave **Allow GitHub Actions to create and approve pull requests** unticked;
   - **Save**.

If a setting is greyed out, an organization policy overrides it: check the same settings at the organization level (*Organization settings* → *Actions* → *General*).

## 3. Variable for the signing transition

1. **Settings** → **Secrets and variables** → **Actions** → tab **Variables**.
2. **New repository variable**: Name `SOA_ALLOW_UNSIGNED_TAGS`, Value `true` → **Add variable**.

Effect: the release workflow accepts an annotated but unsigned tag and shows a warning (check T3 = WARN). An invalid signature still stops the release. Delete the variable as soon as tags are signed (step 8).

## 4. Branch ruleset `main`

1. **Settings** → left sidebar, section *Code and automation* → **Rules** → **Rulesets**.
2. **New ruleset** → **New branch ruleset**.
3. **Ruleset name**: `main`. **Enforcement status**: **Active**.
4. **Bypass list** → **Add bypass** → select the role **Repository admin** → **Add selected**. Keep the mode **Always allow**.
   - This keeps the current way of working: the maintainer pushes directly to `main`. The rules then bind everyone else; for the maintainer, CI still runs, and the release workflow refuses a commit without green CI.
   - Stricter alternative, later: mode **For pull requests only**. Then the maintainer also works through pull requests.
5. **Target branches** → **Add target** → **Include default branch**.
6. **Rules** - tick:
   - **Restrict deletions** (preselected);
   - **Block force pushes**;
   - **Require a pull request before merging**, with **Required approvals** `0` (a single maintainer cannot approve their own pull request);
   - **Require status checks to pass** → **Add checks** → search for and add both:
     - `PowerShell 7 - all static checks`
     - `Windows PowerShell 5.1 - tests and claims`

     (They appear only if CI ran in the last days. If they are missing, push a commit to `main` first. Optional: **Require branches to be up to date before merging**.)
7. Leave **Require signed commits** unticked for now (step 8).
8. **Create**.

## 5. Tag ruleset `release-tags`

1. **Settings** → **Rules** → **Rulesets** → **New ruleset** → **New tag ruleset**.
2. **Ruleset name**: `release-tags`. **Enforcement status**: **Active**.
3. **Bypass list** → **Add bypass** → **Repository admin** → **Add selected**, mode **Always allow**.
4. **Target tags** → **Add target** → **Include by pattern** → `v*` → **Add inclusion pattern**.
5. **Rules** - tick **Restrict creations**, **Restrict updates**, **Restrict deletions**, **Block force pushes**.
6. **Create**.

Effect: only the maintainer can push, move or delete release tags; nobody else can start the release workflow. Deleting a tag after a failed release run is still possible for the maintainer (allowed while no release uses it). After publishing, immutable releases lock the tag in addition.

## 6. Security features

1. **Settings** → **Advanced Security** (on some accounts **Code security**):
   - **Private vulnerability reporting** → **Enable** ([SECURITY.md](../SECURITY.md) relies on it);
   - **Dependabot alerts** → **Enable**;
   - Dependabot version updates for GitHub Actions need no switch: `.github/dependabot.yml` configures them. Check under **Insights** → **Dependency graph** → **Dependabot** that the update job runs.

## 7. First release with the new process

1. Follow [RELEASING.md](RELEASING.md) phases 2-5. During the transition, tag with `git tag -a` (not `-s`).
2. In the **Actions** tab, open the run of the *release* workflow. The job summary should show T1-T8 PASS except T3 = WARN ("tag is not signed - accepted during the transition"), the asset digest and the contents digest.
3. On the releases page, the run has created a **draft**. Review it, compare the contents digest with the independent build, publish.
4. After publishing, the release shows the *Immutable* label.

## 8. Later: switch to signed commits and tags

This is an open point, tracked in a GitHub issue. Steps:

1. **Create an SSH signing key** on the release workstation, preferably on a hardware key:
   ```powershell
   ssh-keygen -t ed25519-sk -O resident -C "git signing"    # FIDO2 security key (needs OpenSSH 8.2+)
   ssh-keygen -t ed25519 -C "git signing"                   # without a hardware key
   ```
2. **Register it on GitHub as a signing key:** your profile picture → **Settings** → **SSH and GPG keys** → **New SSH key** → **Key type**: **Signing Key** → paste the content of the `.pub` file → **Add SSH key**.
3. **Commit e-mail:** use your GitHub no-reply address (**Settings** → **Emails**, *Keep my email addresses private*; it looks like `<id>+<user>@users.noreply.github.com`). GitHub shows a signature as *Verified* only if the commit e-mail belongs to your account, and the hygiene check H4 accepts only placeholder and no-reply addresses in the repository.
4. **Configure git** on the release workstation:
   ```powershell
   git config --global gpg.format ssh
   git config --global user.signingkey "$HOME/.ssh/id_ed25519_sk.pub"     # your public key file
   git config --global commit.gpgsign true
   git config --global tag.gpgsign true
   git config --global user.email "<id>+<user>@users.noreply.github.com"
   ```
   In VS Code, also set `git.enableCommitSigning` to `true`.
5. **Publish the public key in the repository:** create `.github/allowed_signers` with one line per key - the e-mail, `namespaces="git"`, then key type and key exactly as in your `.pub` file (without its comment):
   ```text
   <id>+<user>@users.noreply.github.com namespaces="git" ssh-ed25519 AAAA...
   ```
   Commit it signed (`git commit -s -S`), push, and check with `git verify-commit HEAD` and on GitHub (*Verified*). From now on the release workflow verifies tags against this file on `main`.
6. **Require signed commits on `main`:** **Settings** → **Rules** → **Rulesets** → `main` → tick **Require signed commits** → **Save changes**. With the bypass mode *Always allow*, this binds everyone except the maintainer; to bind the maintainer as well, change the bypass to *For pull requests only* or remove it.
7. **Delete the variable** `SOA_ALLOW_UNSIGNED_TAGS` (**Settings** → **Secrets and variables** → **Actions** → **Variables** → delete). From now on an unsigned tag stops the release.
8. Optional: **Settings** (profile) → **SSH and GPG keys** → tick **Flag unsigned commits as unverified** (vigilant mode).
9. Next release: tag with `git tag -s`. `Test-SoaReleaseTag.ps1 -Tag v<version>` without `-AllowUnsigned` must pass, and the job summary must show T3 = PASS. Then close the issue.
