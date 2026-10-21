# Maintenance

How the toolkit stays correct over time, while Microsoft's preview features, Windows updates and the provisioning agent change.

## Where which kind of information lives

| Kind | Place | Why there |
|---|---|---|
| Recurring routines (what to check, when, how) | this file | stable; part of every release |
| Dated plans, milestones, follow-ups ("after the first rolling cycle", "report F1 upstream") | **GitHub issues and milestones** | they have owners, dates and a status; documents would go stale |
| Why something is designed as it is | [DECISIONS.md](DECISIONS.md) | prevents accidental reversal |
| What was measured | [EVIDENCE.md](EVIDENCE.md) | source of every *Observed* statement |
| What is still to be verified | [VALIDATION.md](VALIDATION.md) and the README status section | visible to users |
| What changed | [CHANGELOG.md](../CHANGELOG.md), release notes | per version |

## Recurring routines

| When | What | How |
|---|---|---|
| After every Windows cumulative update on the DCs (monthly) | engine still active, nothing regressed | `.\Test-SoaPrerequisites.ps1`, `.\Watch-CloudUserConformance.ps1 -Html` |
| After every provisioning agent update | agent gMSA and writes unchanged, events still trigger onboarding | `Watch -Scope All` (`AGENT-SVC`, `POL-AGENT`); provision one test user (L8) |
| Monthly | upstream watch list (below) | compare versions / hashes, read the change history |
| After changes to OUs, Cloud Sync scoping or audit settings | write scope, SACL, delegation still match | `.\Install-SoaToolkit.ps1 -Step AuditConfig, Delegate, Verify` |
| Every PSO max age (default 30 days) | rolling works for active users | monitor report: secret changes, Kerberos 0x17 (L20) |
| Quarterly | references older than 6 months re-read; signing key, maintainers, branch protection, CI action pins reviewed | README references (retrieval dates), repository settings |
| On every report from users | reproduce with an anonymized report | [REPORTING.md](REPORTING.md) |

## Upstream watch list

| Item | Pinned state (see README) | Check |
|---|---|---|
| Microsoft documentation *Configure AD user and group enforcement (preview)* | docs commit `e12ee338`, `ms.date` 2026-08-11 | `ms.date`, change history; does it fix F1, F2, F3, F5 or change the policy schema? |
| `Set-CloudSyncSOAPolicy.ps1` | commit `3f03ef2d`, SHA-256 `d23e36a8…` | new commits; mode switch (F1), container creation (F2), allow-list (F6) |
| `Check-CloudSyncSOAPolicy.ps1` | commit `0afc4332`, SHA-256 `66a78644…` | new commits; per-DC checks (F3), gMSA lookup (F4) |
| Minimum `ntdsai.dll` versions (WS2022 / WS2025) | `SoaToolkit.psm1` (`$script:SoaMinNtdsai`) | Microsoft documentation, update history |
| KIR package | current MSI per OS | new packages; **general availability** makes the KIR GPO unnecessary → `Uninstall -Step RemoveKirGpo` after GA |
| Event IDs 3095 / 3097 / 3098, `SOA-Policies` container | as documented | renamed or new events at GA |
| Cloud Sync agent | version in the monitor / report | release notes: attribute mapping, gMSA, writes to `msDS-ObjectSoa` |

When something changes, open an issue. Verify the change in the lab, then update the code, the README findings, the pinned state above and the CHANGELOG.

## Planning horizon (create these as GitHub milestones)

| Milestone | Content |
|---|---|
| Next patch release (after the lab validation) | results of L1-L19 in VALIDATION.md, EVIDENCE.md and the README; fixes found in the lab |
| After the first full rolling cycle in production | L20; first operational experience in the docs |
| General availability of AD object enforcement | remove the KIR dependency, re-check events / schema / Microsoft scripts, decide on 3.0 |
