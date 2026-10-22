# Monitor checks and how to read them

`Watch-CloudUserConformance.ps1` (and the Verify step of `Install-SoaToolkit.ps1`, which runs it) reports every check as PASS, INFO, WARN or FAIL. A FAIL does not always mean that something is broken: in a dry run, most of the objects the installation creates do not exist yet. Therefore every FAIL and WARN also gets a **class** and a **what to do**. The status, the events and the exit code stay as they are; the class is an additional column (console, CSV, JSON, HTML).

| Class | Meaning | What to do |
|---|---|---|
| **BLOCKER** | prerequisite outside the toolkit | fix it before the real run |
| **ACTION** | a toolkit step that is not part of this run creates it | run that step |
| **REVIEW** | operational finding | read the detail; it does not block the installation |
| **FOLLOW-UP** | reached after the installation without a further step | wait for it or trigger it (reconcile run, replication, DC restart) - then run `-Step Verify` again |
| **PLANNED** | a step of this run creates it (dry run only) | nothing - the real run creates it |

## Result and monitoring status

The console ends with two lines:

- **Result** - for you. It is derived from the classes:

  | Result | Colour | Meaning |
  |---|---|---|
  | **OK** | green | every check passed |
  | **PENDING** | cyan | nothing to do now: only FOLLOW-UP items are left (for example the first reconcile run). The line says what you are waiting for; check again after it. |
  | **ATTENTION** | yellow | at least one item to look at: REVIEW with status WARN, or a WARN without a class - see *To do* |
  | **ACTION REQUIRED** | red | at least one item to fix: BLOCKER, ACTION, REVIEW with status FAIL, or a FAIL without a class - see *To do* |
  | **READY FOR THE REAL RUN** (dry run) | green | no BLOCKER. Items under *To do* can still be worth a look. |
  | **NOT READY FOR THE REAL RUN** (dry run) | red | at least one BLOCKER - fix it first |

- **Monitoring status** (dark grey) - for machines: the worst raw status of all checks (PASS, INFO, WARN, FAIL). It sets the exit code (0 / 1 / 2) and the events, and it is what script sensors read. It does **not** follow the classes: a user who is not in the PSO group yet is a FAIL for a sensor until the reconcile task has put it there, even if the result says PENDING. So a result PENDING next to a monitoring status FAIL is normal right after the installation.

The JSON report carries both (`Assessment.Result`, `Overall`); the HTML report shows the result at the top.

## Reading a dry run

`.\Install-SoaToolkit.ps1 -Step All -KirMsi2025 <msi> -WhatIf` passes its steps to the monitor. The console then ends with the section **Assessment of the dry run**:

- the number of items per class;
- **To do:** every BLOCKER, ACTION and REVIEW with what to do;
- **After the real run (nothing to do now):** the follow-up actions (for example the first reconcile run that puts the users into the PSO group, or the DC restart after the KIR GPO);
- **Result: READY FOR THE REAL RUN** or **NOT READY FOR THE REAL RUN** - not ready as long as there is at least one BLOCKER.

A first dry run in a domain where nothing has been deployed yet typically shows the scheduled tasks, the event log and the scripts on every host as `[PLAN]` (PLANNED, step DeployTasks), and the users that are not yet in the PSO group as `[PEND]` (FOLLOW-UP). That is the expected picture.

## Reading the run after the installation

After the real run, call `-Step Verify` (or `Watch-CloudUserConformance.ps1 -Html`) again. Until the reconcile task has run and the DCs have been restarted, the FOLLOW-UP items stay `[PEND]` and the result is **PENDING** - or **ATTENTION** / **ACTION REQUIRED** if there are items under *To do* as well. Once the follow-ups are reached, the result is **OK** or names what is left.

## Signal words and colours

The colours follow the usual convention of command-line tools: **red** - act now, **yellow** - look at it, **green** - fine or created, **cyan** - waiting, next step or heading, **grey** - background information.

**Items of the monitor** (also the Verify step):

| Tag | Colour | Meaning |
|---|---|---|
| `[PASS]` | green | as expected |
| `[INFO]` | grey | note without a target state |
| `[WARN]` | yellow | deviation to look at (red if its class is BLOCKER or ACTION) |
| `[FAIL]` | red | deviation to fix |
| `[PEND]` | cyan | a FAIL / WARN of class FOLLOW-UP: it is reached without a further step - nothing to do now |
| `[PLAN]` | green | a FAIL / WARN of class PLANNED (dry run): a step of this run creates it |

`[PEND]` and `[PLAN]` exist on the console and in the HTML report only (column `Shown`). The status in CSV, JSON, the events and the exit code stays FAIL / WARN, so that monitoring systems see the real state.

**Classes:** BLOCKER and ACTION red; REVIEW yellow, red if the status is FAIL; FOLLOW-UP cyan; PLANNED green.

**Changes** of `Install-SoaToolkit.ps1` and `Uninstall-SoaToolkit.ps1` (with `-WhatIf`: what would change):

| Marker | Colour | Meaning |
|---|---|---|
| `  +` | green | added or set |
| `  =` | dark grey | unchanged (already in the target state) |
| `  -` | magenta | removed - an intended change, not an error (therefore not red as in a diff) |
| `[SKIP]` | dark grey | skipped - the line says why |

**Validation items** of `Export-SoaReport.ps1`: PASS green, WARN yellow, FAIL red, REVIEW yellow (your confirmation is needed: `-Record`), OPEN grey.

## All checks

The table is generated from the check origin table in `scripts/SoaToolkit.psm1` (`.\tools\Export-SoaCheckTable.ps1 -Update`); the hygiene check H7 fails if it differs or if the monitor uses a check that is not in the table. `*` stands for the Kerberos status code (for example `0x17`).

<!-- checks:begin -->
| Check | Area | Target state from | FAIL / WARN is assessed as | What to do |
|---|---|---|---|---|
| `HOST-REACH` | Host | outside the toolkit | BLOCKER | WinRM from this computer to the host (Test-WSMan with its name), name resolution, firewall |
| `HOST-READ` | Host | - | - (PASS / INFO only) | data that could not be read on the host - the detail names it |
| `TASK-READ` | Host | - | - (PASS / INFO only) | task list not readable with this identity |
| `TASK-MISSING` | Host | install step `DeployTasks` | PLANNED if the step is part of the dry run, else ACTION |  |
| `TASK-STATE` | Host | install step `DeployTasks` | PLANNED if the step is part of the dry run, else ACTION; WARN: REVIEW | WARN: last result not OK - SoaToolkit event log and Status\\*.json on the host; FAIL: task disabled - enable it or deploy again |
| `RECON-STATUS` | Host | after the installation | FOLLOW-UP; FAIL: REVIEW | WARN: first run of the reconcile task after DeployTasks (every ReconcileMinutes) or -Step Conform; FAIL: last reconcile run failed or is too old - Status\\conformance.json and the SoaToolkit event log on the host |
| `CONF-ERRORS` | Host | operation | REVIEW | conformance errors in the SoaToolkit event log (event 1002) - the detail shows the first ones |
| `EVENTLOG` | Host | install step `DeployTasks` | PLANNED if the step is part of the dry run, else ACTION |  |
| `EVENTLOG-SIZE` | Host | install step `DeployTasks` | PLANNED if the step is part of the dry run, else ACTION |  |
| `INTEGRITY` | Host | install step `DeployTasks` | PLANNED if the step is part of the dry run, else ACTION | scripts missing or changed on the host - deploy again |
| `SIGNATURE` | Host | install step `DeployTasks` | PLANNED if the step is part of the dry run, else ACTION | signing certificate trusted on the host (Trusted Publishers + root CA)? |
| `BATCH` | Host | install step `BatchLogonGpo`, then: gpupdate /target:computer /force on the host (or -Refresh) | PLANNED if the step is part of the dry run, else ACTION |  |
| `DC-NTDSAI` | Host (DC) | outside the toolkit | BLOCKER | install the Windows update with AD object enforcement (minimum ntdsai.dll per build: Test-SoaPrerequisites.ps1) |
| `DC-KIR` | Host (DC) | install step `KirGpo`, then: SYSVOL replication, gpupdate and a restart of the DC (one DC at a time) | PLANNED if the step is part of the dry run, else ACTION |  |
| `DC-DIAG` | Host (DC) | install step `DiagnosticsGpo`, then: gpupdate /target:computer /force on the DC | PLANNED if the step is part of the dry run, else ACTION |  |
| `DC-LOAD` | Host (DC) | after the installation | FOLLOW-UP; FAIL: BLOCKER | WARN: no event 3095 yet - it appears after a policy change or a DC restart with diagnostics level 1; FAIL: the DC fails to load CN=Cloud - read event 3095; do not switch to Enforced |
| `DC-3097` | Host (DC) | operation | REVIEW | changes the Enforced mode would block - review them before -Step SetMode -Mode Enforced (Get-SoaEnforcementImpact.ps1) |
| `DC-3098` | Host (DC) | operation | REVIEW | writes blocked by the Enforced mode - the detail shows samples |
| `DC-AUDIT` | Host (DC) | install step `AuditConfig`, then: gpupdate /target:computer /force on the DC | PLANNED if the step is part of the dry run, else ACTION |  |
| `DC-KERB-*` | Host (DC) | operation | REVIEW | Kerberos failures of cloud users on this DC - see the users |
| `AGENT-SVC` | Host (agent) | outside the toolkit | BLOCKER | provisioning agent service AADConnectProvisioningAgent not installed or not running on a host listed in AgentHosts |
| `POL-EXISTS` | Enforcement | install step `Policy` | PLANNED if the step is part of the dry run, else ACTION |  |
| `POL-MODE` | Enforcement | operation | REVIEW | keywords are neither Audit nor Enforced - -Step SetMode |
| `POL-SIDS` | Enforcement | install step `AllowList` | PLANNED if the step is part of the dry run, else ACTION | stale SID in the allow-list - the policy fails to load |
| `POL-AGENT` | Enforcement | install step `AllowList` | PLANNED if the step is part of the dry run, else ACTION |  |
| `POL-TOOLKIT` | Enforcement | install step `AllowList` | PLANNED if the step is part of the dry run, else ACTION |  |
| `POL-REPL` | Enforcement | after the installation | FOLLOW-UP | AD replication of CN=Cloud - wait, then -Step Verify again |
| `ROLL` | Password policy | install step `EnableRolling` | PLANNED if the step is part of the dry run, else ACTION | needs domain functional level 2016 or higher |
| `PSO-EXISTS` | Password policy | install step `Pso` | PLANNED if the step is part of the dry run, else ACTION |  |
| `PSO-VALUES` | Password policy | install step `Pso` | PLANNED if the step is part of the dry run, else ACTION |  |
| `PSO-MARKER` | Password policy | - | - (PASS / INFO only) |  |
| `PSO-TARGET` | Password policy | install step `Pso` | PLANNED if the step is part of the dry run, else ACTION |  |
| `PSO-PREC` | Password policy | operation | REVIEW | another PSO with the same or a lower precedence wins for the users it applies to |
| `OBJ-GMSA` | Toolkit objects | install step `Gmsa` | PLANNED if the step is part of the dry run, else ACTION |  |
| `OBJ-HOSTGROUP` | Toolkit objects | install step `HostGroup` | PLANNED if the step is part of the dry run, else ACTION |  |
| `OBJ-GROUPS` | Toolkit objects | install step `Groups` | PLANNED if the step is part of the dry run, else ACTION |  |
| `OBJ-GPO` | Toolkit objects | install step `BatchLogonGpo` / `KirGpo` / `DiagnosticsGpo` / `AuditConfig` | PLANNED if the step is part of the dry run, else ACTION |  |
| `GRP-DRIFT` | Toolkit objects | after the installation | FOLLOW-UP | members out of scope are removed by the first run of the reconcile task after DeployTasks (every ReconcileMinutes) or -Step Conform |
| `CKT-OBJECT` | Cloud Kerberos Trust | outside the toolkit | BLOCKER | Cloud Kerberos Trust: create the AzureADKerberos object (Set-AzureADKerberosServer) |
| `CKT-KEYAGE` | Cloud Kerberos Trust | operation | REVIEW | rotate the krbtgt_AzureAD key (Set-AzureADKerberosServer -RotateServerKey) |
| `PRV-UNMARKED` | Provisioning | operation | REVIEW | provisioned objects without msDS-ObjectSoa - out of scope; check the Cloud Sync configuration |
| `USR-SUMMARY` | Users | summary of the user checks | - |  |
| `USR-UNMARKED` | Users | operation | REVIEW | provisioned but not marked (msDS-ObjectSoa) - out of scope, not protected |
| `USR-EXCLUDED` | Users | - | - (PASS / INFO only) |  |
| `USR-PILOT` | Users | - | - (PASS / INFO only) |  |
| `USR-SCRIL` | Users | after the installation | FOLLOW-UP | first run of the reconcile task after DeployTasks (every ReconcileMinutes) or -Step Conform |
| `USR-PNE` | Users | after the installation | FOLLOW-UP | first run of the reconcile task after DeployTasks (every ReconcileMinutes) or -Step Conform |
| `USR-PSOGROUP` | Users | after the installation | FOLLOW-UP | first run of the reconcile task after DeployTasks (every ReconcileMinutes) or -Step Conform |
| `USR-EXPIRED-NOSCRIL` | Users | after the installation | FOLLOW-UP | first run of the reconcile task after DeployTasks (every ReconcileMinutes) or -Step Conform |
| `USR-RPSO` | Users | operation | REVIEW | another PSO applies to the user (precedence) |
| `USR-WRITE` | Users | outside the toolkit | BLOCKER | user outside the write scope (WriteScope in the configuration) - the toolkit cannot correct it |
| `USR-LOCKED` | Users | operation | REVIEW | account locked out - Kerberos sign-in blocked |
| `USR-NOROLL` | Users | operation | REVIEW | sign-in while expired without rolling - check the DC (diagnostics, ntdsai.dll) and the user |
| `USR-ROLLPLS` | Users | - | - (PASS / INFO only) |  |
| `USR-EXPIRED` | Users | - | - (PASS / INFO only) |  |
| `USR-NEVERREVEAL` | Users | outside the toolkit | BLOCKER | remove the group from the denied list of the AzureADKerberos password replication policy |
| `USR-KERB-*` | Users | operation | REVIEW | Kerberos failures of this user - see docs/OPERATIONS.md |
| `AUD-SACL` | Audit | install step `AuditConfig` | PLANNED if the step is part of the dry run, else ACTION |  |
| `AUD-SACL-OTHER` | Audit | - | - (PASS / INFO only) |  |
| `TEST` | Validation tests | operation | REVIEW | results of Test-SoaBehavior.ps1 - repeat the test |
<!-- checks:end -->
