# Lab validation of toolkit 2.x (L1-L20)

The findings K1-K21 describe Microsoft's features and were measured or researched before and during the development of 2.x. This checklist verifies **the toolkit itself** end to end in a lab domain. Until an item is verified, its status below is *open*. The README status section links here.

**Status on 2026-10-21 (release 2.0.3): all items open.** The 2.x scripts have passed parser, PSScriptAnalyzer, unit tests, an end-to-end test against a mocked AD module and the static security-claim checks. They have **not** yet run in a real domain.

## How to run it

1. Do the steps in the order of the table. Use a lab with snapshots of the DCs if possible, and run every write step with `-WhatIf` first.
2. For items the toolkit cannot observe, record the result: `.\Export-SoaReport.ps1 -Record L16 -Result PASS -Note '...'`
3. Collect everything: `.\Export-SoaReport.ps1` (validation is the default purpose). This writes a report folder with `report.md`, `report.json`, `README-FIRST.md` and anonymized artifacts.
4. Review the folder (README-FIRST.md has the checklist), then package it: `.\Export-SoaReport.ps1 -Package <folder>`.
5. Hand the zip to the maintainer or attach it to a *Lab validation result* issue. The pseudonym map stays with you.

`.\Export-SoaReport.ps1 -ListChecks` prints this list with instructions. The report evaluates each item automatically where the toolkit has evidence:

| Status | Meaning |
|---|---|
| PASS / FAIL / WARN | evaluated |
| REVIEW | evidence found; confirm it with `-Record` |
| OPEN | no evidence yet |

## Checklist

| # | Check | How | Expected | Evaluated from | Status |
|---|---|---|---|---|---|
| L1 | Prerequisites | `.\Test-SoaPrerequisites.ps1` | all PASS or explained | latest prerequisites report | open |
| L2 | Installation dry run | `.\Install-SoaToolkit.ps1 -Step All -KirMsi2025 <msi> -WhatIf` | no unexpected planned change | install run log (planned ADD/DEL), then `-Record L2` | open |
| L3 | Installation and idempotency | `-Step All`, restart the writable DCs one at a time, `-Step All` again | second run: only SAME, no ADD / DEL / FAIL | install run logs | open |
| L4 | Batch logon GPO keeps existing rights | before / after on every DC and agent host: `secedit /export /cfg c:\temp\ur.inf /areas USER_RIGHTS`, compare `SeBatchLogonRight` | after = before + toolkit gMSA | monitor `BATCH`, then `-Record L4` | open |
| L5 | KIR GPO, WMI filter, engine per DC | `.\Watch-CloudUserConformance.ps1 -Html` | `DC-NTDSAI`, `DC-KIR`, `DC-LOAD` PASS on every writable DC | monitor report | open |
| L6 | Audit policy and SACL | `-Step AuditConfig`; remove diagnostic SACLs; `-Step Verify` | `DC-AUDIT`, `AUD-SACL` PASS; no `AUD-SACL-OTHER` | monitor report | open |
| L7 | Tasks and event log as gMSA | wait one `MonitorMinutes` interval after `DeployTasks` | heartbeat 2000 on every toolkit host | event log of each host | open |
| L8 | New cloud-only user (4720) | create a user in Entra ID, wait for provisioning | event task on the processing DC; target state within minutes | journals + creation time | open |
| L9 | SOA conversion (5136) | convert the SOA of an existing AD user to the cloud | 5136 on `msDS-ObjectSoa` by the agent gMSA; event task; target state | journals + anchor time + 5136 counts | open |
| L10 | Reconcile repairs drift | `.\Test-SoaBehavior.ps1 -Suite Onboarding` | target state restored | test results | open |
| L11 | `userAccountControl` update method | journal of L8 / L10 | method recorded (compare-and-swap or replace) | journals | open |
| L12 | SCRIL matrix with 2.x code | `-Suite Scril` | results as K11 | test results | open |
| L13 | Rolling updates `pwdLastSet` (V1) | `-Suite RollingPrepare` → passwordless sign-in after expiry → `-Suite RollingObserve` → `-Suite RollingCleanup` | answers V1 | test results | open |
| L14 | Audit phase impact | `.\Get-SoaEnforcementImpact.ps1`, review events 3097 | only known writers | impact report | open |
| L15 | Enforced mode | `-Step SetMode -Mode Enforced`; `-Suite Enforcement` | toolkit write allowed; own write blocked on **every** DC | test results (mode Enforced) | open |
| L16 | Cloud Sync writes under Enforced | change an attribute in Entra ID (e.g. department) | change arrives in AD | `-Record L16` | open |
| L17 | Emergency switch back to Audit | `.\Uninstall-SoaToolkit.ps1 -Step SetModeAudit`, then `-Step SetMode -Mode Enforced` | mode switch effective (counterpart of F1) | run logs | open |
| L18 | Monitoring | `.\Watch-CloudUserConformance.ps1 -Html`; scheduled monitor as gMSA | all PASS or explained | monitor reports | open |
| L19 | Rollback and reinstall | `-Preset Decommission -WhatIf`, then for real, then reinstall | previous values restored, nothing pre-existing deleted | run logs + manifest, then `-Record L19` | open |
| L20 | Long-term rolling | after one PSO max age + 5 days | active users rolled; no Kerberos 0x17 | monitor report | open |

The report contains the facts that every result needs: date, OS build and latest update of every host, provisioning agent version, functional levels, topology, policy mode, PSO values and integrity of the scripts (against `SHA256SUMS.txt` of the release).

## Deliberately left open

| Item | Why |
|---|---|
| Group SIDs in the allow-list | not used by design; only account SIDs are allow-listed |
| DC-internal writes, non-LDAP password paths | out of scope (decision D-15) |
| K12 for idle accounts | remains *Inferred*: an idle account keeps an expired secret that nobody knows |

## Open documentation tasks

- Complete the records of the existing observations in [EVIDENCE.md](EVIDENCE.md): dates, OS builds, agent version, raw data.
- After the validation, update this table, the README status section and the evidence levels, and release the next version.
