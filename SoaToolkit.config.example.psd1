# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
@{
    # =====================================================================================================
    # SOA Toolkit configuration TEMPLATE (cloudsync-soa-toolkit 2.1.1)
    # Copy this file to 'SoaToolkit.config.psd1' in the same folder (top level of the toolkit folder) and adjust
    # the copy. The copy is git-ignored and not part of the release zip, so updates never overwrite it.
    # All values below are PLACEHOLDERS (contoso.com). Keys that are omitted fall back to the defaults in
    # scripts\SoaToolkit.psm1 ($script:SoaConfigDefaults). DeployTasks copies your configuration to every host.
    # =====================================================================================================

    # Link written into the marker of every object the toolkit creates ("managed by SOA Toolkit ...")
    ProjectUrl              = 'https://github.com/mayer-bautechnik/cloudsync-soa-toolkit'

    # --- Topology ----------------------------------------------------------------------------------------
    # Every host that runs the Microsoft Entra provisioning agent (service 'AADConnectProvisioningAgent').
    # Can be domain controllers or member servers. Writable DCs are discovered automatically.
    #   Writable DC  -> event-triggered onboarding task + DC-local monitoring
    #   Agent host   -> reconcile task + agent / domain-wide monitoring
    AgentHosts              = @('dc01.contoso.com', 'dc02.contoso.com')

    # Optional: gMSA sAMAccountNames of the agents (e.g. 'provAgentgMSA$'). Empty = read from the agent service.
    AgentGmsaNames          = @()

    # --- Scope -------------------------------------------------------------------------------------------
    # Users in scope are identified by attributes, domain-wide: anchor msDS-ExternalDirectoryObjectId=User_* AND
    # msDS-ObjectSoa=Cloud. WriteScope only defines where the toolkit identity gets write permissions:
    #   'AgentScope' = same containers in which the Cloud Sync agent gMSA holds write permissions (default)
    #   'Domain'     = domain root
    #   @('OU=...')  = explicit list
    WriteScope              = 'AgentScope'
    ExcludeOUs              = @()                     # optional: users below these OUs are left untouched
    PilotMode               = $false                  # $true = apply only to members of PilotGroupName

    # --- Objects created by the toolkit (all carry the marker "[SoaToolkit] Managed by SOA Toolkit ...") -----
    ToolkitGroupOU          = 'OU=Groups,OU=Tier0,DC=contoso,DC=com'   # outside the Cloud Sync scope
    GmsaName                = 'gmsaSoaToolkit'       # sAMAccountName WITHOUT trailing $ (max. 15 characters)
    HostGroupName           = 'SOA-Toolkit-Hosts'    # Domain Controllers + agent hosts; may retrieve the gMSA password
    PsoGroupName            = 'SOA-CloudUsers-PSO'   # global group the PSO applies to (maintained by the toolkit)
    ExcludeGroupName        = 'SOA-CloudUsers-Exclude'
    PilotGroupName          = 'SOA-CloudUsers-Pilot'
    PsoName                 = 'PSO-SOA-CloudUsers'

    # Fine-grained password policy for cloud users (automatic rolling of SCRIL secrets by the DCs)
    Pso = @{
        Precedence                      = 10
        MaxPasswordAgeDays              = 30         # = rolling interval; DISA STIG V-243476: <= 60
        MinPasswordAgeDays              = 1
        MinPasswordLength               = 64
        ComplexityEnabled               = $true
        PasswordHistoryCount            = 24
        ReversibleEncryptionEnabled     = $false
        LockoutThreshold                = 0          # secret is random and unknown; lockout would only allow DoS
        LockoutDurationMinutes          = 15
        LockoutObservationWindowMinutes = 15
    }

    KirGpoNamePrefix        = 'SOA Toolkit - DC - KIR AD Object Enforcement'   # suffix ' (WS2022)' / ' (WS2025)'
    DiagnosticsGpoName      = 'SOA Toolkit - DC - NTDS Security Diagnostics'
    AuditGpoName            = 'SOA Toolkit - DC - Audit'
    BatchLogonGpoNameDc     = 'SOA Toolkit - DC - Batch Logon'
    BatchLogonGpoNameAgent  = 'SOA Toolkit - Agent Hosts - Batch Logon'        # only if agent hosts are member servers

    # --- Runtime on the toolkit hosts ---------------------------------------------------------------------
    TaskFolder              = '\SoaToolkit\'
    EventLogName            = 'SoaToolkit'
    EventLogMaxSizeMB       = 64                      # size of the 'SoaToolkit' log on every host; overwrite as needed (also the WEF buffer)
    EventLogAllowWef        = $false                  # $true = NETWORK SERVICE may read the log (Windows Event Forwarding, docs/OPERATIONS.md)
    ScriptInstallPath       = 'C:\Program Files\SoaToolkit'
    DataPath                = 'C:\ProgramData\SoaToolkit'
    ReconcileMinutes        = 60                      # 0 = reconcile task registered but disabled
    MonitorMinutes          = 60
    EventTriggerDelaySeconds = 30                     # lets Cloud Sync finish its writes before the run starts

    # Optional: thumbprint of a code-signing certificate (CurrentUser\My or LocalMachine\My on the admin host).
    # If set, DeployTasks signs the scripts and the tasks run with -ExecutionPolicy AllSigned.
    SigningCertThumbprint   = ''
    SigningTimestampUrl     = ''                      # optional RFC 3161 timestamp server (keeps signatures valid after expiry)

    # --- Optional break-glass account (not created by default; recovery path is SetMode Audit) ------------
    BreakGlassName          = ''
    BreakGlassOU            = ''

    # --- Validation / reporting (admin workstation) -------------------------------------------------------
    TestUser                = 'soa-test01'            # dedicated test user CREATED IN ENTRA ID and provisioned by Cloud Sync
    # Reports, test results and the install manifest. Must NOT be inside DataPath or ScriptInstallPath (the scripts
    # refuse that on a DC / agent host). Created on first use with access for Administrators and SYSTEM only.
    ReportPath              = 'C:\SoaToolkitAdmin\Reports'
    KrbtgtAzureAdWarnDays   = 180
    NewUserGraceMinutes     = 120                     # monitoring tolerance for users that were just created
    RollingTestMinutes      = 15
    RollingTestPsoName      = 'PSO-SOA-RollingTest'

    # --- Migration from toolkit 1.x (only used by Install-SoaToolkit.ps1 -Step RemoveLegacy) --------------
    LegacyJobHost           = ''                      # e.g. 'mgmt01.contoso.com'
    LegacyGmsaName          = ''                      # e.g. 'gmsaSoaJob'
    LegacyTargetUserOUs     = @()
    LegacyScriptFolder      = 'C:\Scripts\SoaEnforcement'
    LegacyDiagnosticsGpoName = 'DC - NTDS Diagnostics - Security Events'
}
