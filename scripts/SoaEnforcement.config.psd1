@{
    # =====================================================================================
    # Shared configuration (cloudsync-ad-enforcement-toolkit 1.0.0)
    # Used by: Initialize-SoaEnforcement.ps1, Invoke-ScrilJob.ps1,
    #          Watch-CloudUserPasswordless.ps1, Test-ScrilBehavior.ps1
    # All values below are PLACEHOLDERS (contoso.com) - adjust before first use.
    # =====================================================================================

    # --- Scope ---------------------------------------------------------------------------
    # OUs into which Entra Cloud Sync (Entra ID -> AD) provisions users and groups
    TargetUserOUs             = @('OU=Users,OU=Cloud,DC=contoso,DC=com')
    TargetGroupOUs            = @('OU=Groups,OU=Cloud,DC=contoso,DC=com')

    # --- Cloud Sync provisioning agents (service 'AADConnectProvisioningAgent') ------------
    AgentHosts                = @('dc01.contoso.com', 'dc02.contoso.com')

    # --- SCRIL job -----------------------------------------------------------------------
    JobGmsaName               = 'gmsaSoaJob'                  # sAMAccountName WITHOUT trailing $
    JobHost                   = 'mgmt01.contoso.com'          # member server running the job (needs RSAT-AD-PowerShell)
    JobScriptPath             = 'C:\Scripts\SoaEnforcement\Invoke-ScrilJob.ps1'
    JobDataPath               = 'C:\ProgramData\SoaEnforcement'
    JobIntervalMinutes        = 10                             # interval of the 'Enforce SCRIL' task
    RotationDays              = 30                             # rotate the secret of SCRIL users after n days
                                                               # keep RotationDays < effective maxPwdAge (see Test-ScrilBehavior.ps1)
    RotationTime              = '03:15'                        # daily start time of the 'Rotate SCRIL secret' task
    RotationMethod            = 'Auto'                         # Toggle | RandomReset | Auto (= Toggle, fallback RandomReset)
    EnforceDenyChangePassword = $false                         # optional: explicit deny ACEs "User cannot change password"
    ScrilExclude              = @()                            # sAMAccountNames that must NOT get SCRIL

    # --- Break-glass account -------------------------------------------------------------
    BreakGlassName            = 'bg-soa-recovery'
    BreakGlassOU              = 'OU=Tier0,DC=contoso,DC=com'

    # --- Validation / monitoring ---------------------------------------------------------
    TestUser                  = 'soa-test01'   # dedicated test user CREATED IN ENTRA ID and provisioned by Cloud Sync
    ReportPath                = 'C:\ProgramData\SoaEnforcement\Reports'
    SecretAgeWarnDays         = 45             # warn if the secret of a SCRIL user is older (rotation not working)
    KrbtgtAzureAdWarnDays     = 180            # warn if the Entra Kerberos server key was not rotated

    # --- SCRIL behavior tests (Test-ScrilBehavior.ps1) -------------------------------------
    ScrilTestPsoName          = 'PSO-ScrilRollingTest'   # temporary fine-grained password policy, applied to TestUser only
    RollingTestMinutes        = 15                       # max password age of that PSO during the rolling observation
}
