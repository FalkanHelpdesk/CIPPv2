function Get-CIPPAlertBlockedValidPassword {
    <#
    .FUNCTIONALITY
        Entrypoint

    .SYNOPSIS
        Detects sign-ins where Microsoft Entra confirmed the correct password,
        but a later security control prevented token issuance.

    .DESCRIPTION
        Queries recent Microsoft Entra sign-in events and raises a high-confidence
        alert when:

        - The authentication details explicitly record a successful password step.
        - The password result is "Correct password".
        - The final sign-in was blocked by Conditional Access or a disabled app.
        - The event has not already been returned during the overlapping query window.

        Alert results are written through CIPP's native Write-AlertTrace mechanism
        using the standard UTC yyyyMMdd AlertLastRun partition.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,

        $TenantFilter
    )

    try {
        $LookbackMinutes = 35
        $CandidateErrorCodes = @(53003, 7000112)

        $UtcNow = (Get-Date).ToUniversalTime()
        $CurrentPartition = $UtcNow.ToString('yyyyMMdd')
        $PreviousPartition = $UtcNow.AddDays(-1).ToString('yyyyMMdd')
        $StartTime = $UtcNow.AddMinutes(-$LookbackMinutes).ToString('yyyy-MM-ddTHH:mm:ssZ')

        $Uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $StartTime&`$orderby=createdDateTime desc&`$top=500"

        $SignIns = New-GraphGetRequest `
            -uri $Uri `
            -tenantid $TenantFilter

        $PreviousSignInIds = @()

        try {
            $AlertTable = Get-CIPPTable -TableName 'AlertLastRun'
            $CmdletName = $MyInvocation.MyCommand.ToString()
            $RowKey = "$TenantFilter-$CmdletName"
            $SafeRowKey = ConvertTo-CIPPODataFilterValue -Value $RowKey -Type String

            $PreviousRows = Get-CIPPAzDataTableEntity `
                @AlertTable `
                -Filter "RowKey eq '$SafeRowKey'"

            $RelevantRows = @(
                $PreviousRows | Where-Object {
                    [string]$_.PartitionKey -in @(
                        $CurrentPartition,
                        $PreviousPartition
                    )
                }
            )

            foreach ($PreviousRow in $RelevantRows) {
                if ([System.String]::IsNullOrWhiteSpace([string]$PreviousRow.LogData)) {
                    continue
                }

                try {
                    $PreviousData = $PreviousRow.LogData |
                        ConvertFrom-Json -ErrorAction Stop

                    $PreviousSignInIds += @(
                        $PreviousData |
                            ForEach-Object {
                                $_.SignInId
                            } |
                            Where-Object {
                                -not [System.String]::IsNullOrWhiteSpace([string]$_)
                            }
                    )
                } catch {
                    Write-Information "Could not parse previous blocked-password alert data for partition $($PreviousRow.PartitionKey): $($_.Exception.Message)"
                }
            }

            $PreviousSignInIds = @(
                $PreviousSignInIds |
                    Sort-Object -Unique
            )
        } catch {
            Write-Information "No previous blocked-password alert data was found for $TenantFilter."
        }

        $AlertData = @(
            foreach ($SignIn in @($SignIns)) {
                $ErrorCode = [int64]$SignIn.status.errorCode

                if ($ErrorCode -notin $CandidateErrorCodes) {
                    continue
                }

                if ([System.String]::IsNullOrWhiteSpace([string]$SignIn.id)) {
                    continue
                }

                if ($SignIn.id -in $PreviousSignInIds) {
                    continue
                }

                $SuccessfulPasswordSteps = @(
                    $SignIn.authenticationDetails | Where-Object {
                        $_.authenticationMethod -eq 'Password' -and
                        $_.succeeded -eq $true -and
                        $_.authenticationStepResultDetail -eq 'Correct password'
                    }
                )

                if ($SuccessfulPasswordSteps.Count -eq 0) {
                    continue
                }

                $FailedPolicies = @(
                    $SignIn.appliedConditionalAccessPolicies |
                        Where-Object {
                            $_.result -eq 'failure'
                        } |
                        ForEach-Object {
                            '{0}: {1} ({2})' -f `
                                $_.displayName,
                                $_.result,
                                ($_.enforcedGrantControls -join ', ')
                        }
                )

                $ReportOnlyFailures = @(
                    $SignIn.appliedConditionalAccessPolicies |
                        Where-Object {
                            $_.result -eq 'reportOnlyFailure'
                        } |
                        ForEach-Object {
                            '{0}: {1} ({2})' -f `
                                $_.displayName,
                                $_.result,
                                ($_.enforcedGrantControls -join ', ')
                        }
                )

                [PSCustomObject]@{
                    AlertType                       = 'CorrectPasswordBlocked'
                    AlertID                         = $SignIn.id
                    Confidence                      = 'High'
                    DetectionReason                 = 'Correct password confirmed; access was prevented by a later security control.'
                    CreatedDateTime                 = $SignIn.createdDateTime
                    UserDisplayName                 = $SignIn.userDisplayName
                    UserPrincipalName               = $SignIn.userPrincipalName
                    UserId                          = $SignIn.userId
                    AppDisplayName                  = $SignIn.appDisplayName
                    AppId                           = $SignIn.appId
                    ResourceDisplayName             = $SignIn.resourceDisplayName
                    ResourceId                      = $SignIn.resourceId
                    ErrorCode                       = $ErrorCode
                    FailureReason                   = $SignIn.status.failureReason
                    ConditionalAccessStatus         = $SignIn.conditionalAccessStatus
                    PasswordSucceeded               = $true
                    PasswordDetail                  = ($SuccessfulPasswordSteps.authenticationMethodDetail -join ', ')
                    AuthenticationFlow              = $SignIn.originalTransferMethod
                    IsInteractive                   = $SignIn.isInteractive
                    IPAddress                       = $SignIn.ipAddress
                    City                            = $SignIn.location.city
                    State                           = $SignIn.location.state
                    Country                         = $SignIn.location.countryOrRegion
                    OperatingSystem                 = $SignIn.deviceDetail.operatingSystem
                    Browser                         = $SignIn.deviceDetail.browser
                    IsManaged                       = $SignIn.deviceDetail.isManaged
                    IsCompliant                     = $SignIn.deviceDetail.isCompliant
                    FailedConditionalAccessPolicies = ($FailedPolicies -join '; ')
                    ReportOnlyPolicyMatches         = ($ReportOnlyFailures -join '; ')
                    CorrelationId                   = $SignIn.correlationId
                    SignInId                        = $SignIn.id
                    Tenant                          = $TenantFilter
                }
            }
        )

        if ($AlertData.Count -gt 0) {
            Write-AlertTrace `
                -cmdletName $MyInvocation.MyCommand `
                -tenantFilter $TenantFilter `
                -data $AlertData
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_

        Write-LogMessage `
            -API 'Alerts' `
            -tenant $TenantFilter `
            -message "Could not check blocked correct-password sign-ins for $($TenantFilter): $($ErrorMessage.NormalizedError)" `
            -sev Error `
            -LogData $ErrorMessage
    }
}
