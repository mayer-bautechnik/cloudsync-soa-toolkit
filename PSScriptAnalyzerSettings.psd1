# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
# PSScriptAnalyzer settings used for the toolkit (VS Code PowerShell extension and Invoke-ScriptAnalyzer -Settings).
@{
    Rules = @{
        PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.4') }
    }
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'                        # interactive admin scripts with colored console output
        'PSUseShouldProcessForStateChangingFunctions'  # ShouldProcess is implemented at script level
        'PSUseSingularNouns'
        'PSAvoidUsingPositionalParameters'
        'PSReviewUnusedParameter'
        'PSAvoidUsingEmptyCatchBlock'                  # best-effort reads / logging by design
    )
}
