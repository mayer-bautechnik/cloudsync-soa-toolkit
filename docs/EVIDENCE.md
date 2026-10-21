# Lab evidence

Every finding labelled **Observed** in the README needs a record here: what was measured, when, in which environment and with which tool, and where the anonymized raw data is. Without such a record, a statement may not be labelled *Observed*. New evidence comes from the validation run ([VALIDATION.md](VALIDATION.md)) and is exported with `Export-SoaReport.ps1` ([REPORTING.md](REPORTING.md)).

## Lab environment

| Item | Value |
|---|---|
| Domain controllers | Windows Server 2025, two writable DCs; both are also Cloud Sync agent hosts |
| Functional level | domain functional level 2025 |
| Automatic rolling | `msDS-ExpirePasswordsOnSmartCardOnlyAccounts = TRUE` (default for a domain installed at DFL ≥ 2016) |
| Sign-in | Windows Hello for Business and FIDO2 via Cloud Kerberos Trust, Azure Virtual Desktop SSO, AD file share |
| Features | Entra ID → AD provisioning and AD object enforcement (preview, KIR enablement) |
| OS build / CU, agent version | *to be added from the next export (report.md, section Environment)* |

## Records of the existing observations

These observations were measured manually by the maintainer in October 2026, before toolkit 2.x existed or alongside its development. The exact dates, builds and raw data are not yet in the repository. Completing them is an open task ([VALIDATION.md](VALIDATION.md#open-documentation-tasks)).

| Finding | What was observed | Date | Method / tool | Raw data |
|---|---|---|---|---|
| K7 | A direct `userAccountControl` mapping is not applied by the agent; `accountDisabled` toggles only bit 0x2 | 2026-10 (to add) | manual, Cloud Sync attribute mapping + diagnosis with event 4662 | to add |
| K10 | WHfB / FIDO2 sign-in via Cloud Kerberos Trust, AVD SSO and file share succeed after expiry; the DC rolls the secret during the sign-in | 2026-10 (to add) | manual sign-in, replication metadata of `unicodePwd` before / after | to add |
| K11 | SCRIL off → on re-randomizes the secret without updating `pwdLastSet`; rewrite / clear does not | 2026-10 (to add) | SCRIL matrix (manual / toolkit test suite) | to add |
| K13 | Rolling attribute `TRUE` in the test domain | 2026-10 (to add) | attribute read | to add |
| K14 | The KIR "Feature Preview" package switches several feature IDs (`enabledList`) | 2026-10 (to add) | ADMX inspection, registry overrides | to add |
| K16 | With rolling enabled, SCRIL secrets expire on schedule (`msDS-UserPasswordExpiryTimeComputed`, PE flag) | 2026-10 (to add) | attribute reads on a test user with a short PSO | to add |
| K17 | PNE makes the computed expiry "never" and therefore disables rolling | 2026-10 (to add) | attribute reads | to add |
| K18 | Deny-change ACEs do not change the randomization when SCRIL is set | 2026-10 (to add) | SCRIL matrix with deny ACEs | to add |

## How to add a record

1. Run the validation step or test and export: `.\Export-SoaReport.ps1` (anonymized; review, then `-Package`).
2. Put the reviewed, anonymized `report.md` (and, if useful, single artifacts) into `docs/evidence/<yyyy-mm-dd>/`.
3. Add or update the row: finding, what was observed, date, method / tool **with toolkit version**, link to the folder.
4. Only then label the statement *Observed* in the README.

Never commit the pseudonym map, unreviewed exports or raw event logs.
