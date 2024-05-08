param
(
    [bool]$DryRun = $true,

    # UA or SA, User-Assigned or System Assigned
    [string]$ManagedIdentityMethod = "SA"
)

$TenantId = Get-AutomationVariable -Name 'TenantId'
$Subscription = Get-AutomationVariable -Name 'Subscription'
$ResourceGroup = Get-AutomationVariable -Name 'ResourceGroup'
$StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'

[int]$ExpirationDays = Get-AutomationVariable -Name 'ExpirationDays'
$NotificationEmailSendAs = Get-AutomationVariable -Name 'NotificationEmailSendAs'
$NotificationEmailBody = Get-AutomationVariable -Name 'NotificationEmailBody'
$NotificationEmailSubject = Get-AutomationVariable -Name 'NotificationEmailSubject'
[bool]$NotificationEmailUseDefault = Get-AutomationVariable -Name 'NotificationEmailUseDefault'
$NotificationEmailDefaultAddress = Get-AutomationVariable -Name 'NotificationEmailDefaultAddress'

if ($NotificationEmailUseDefault) {
    Write-Warning "The account $($NotificationEmailDefaultAddress) will receive notification of apps without owners"
}

$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
Import-Module Az.Resources
Import-Module Az.Storage
Import-Module Az.Accounts
Import-Module AzTable
$VerbosePreference = $PreviousVerbosePreference

function Get-DateString {
    param(
        $Date
    )
    if ($Date.GetType() -ne [DateTime]) {
        $Date = Get-Date $Date
    }
    $culture = [cultureinfo]::CreateSpecificCulture('es-US')
    return $Date.ToString('F', $culture)
}

# $VerbosePreference = 'Continue'
# $ErrorActionPreference = 'Stop'

function Start-Work {
    # Main orchestration function
    param()

    $azureContext = Connect-ManagedIdentity

    $applicationsTable = Get-CloudTable -AzureContext $azureContext -TableName 'Applications'
    $servicePrincipalsTable = Get-CloudTable -AzureContext $azureContext -TableName 'ServicePrincipals'
    $notificationsTable = Get-CloudTable -AzureContext $azureContext -TableName 'ExpirationNotifications'

    $notifications = Get-SentNotifications -Table $notificationsTable
    Write-Verbose "Got $($notifications.Count) rows from notifications"

    # Get expiring credentials for App Registrations (secrets + certs)
    # Then find the service principal for the credential to find the owner
    [array]$appCredentials = Find-ExpiringCredentials -Table $applicationsTable
    Write-Warning "Found $($appCredentials.Count) expiring credentials (applications)"
    if ($appCredentials.Count -gt 0) {
        $servicePrincipals = Get-ServicePrincipalsForCredentials -Table $servicePrincipalsTable -SecretsOrCertificates $appCredentials
        Write-Verbose "Got $($ServicePrincipals.Count) rows from service applications"
        $appCredentials | Send-ExpiringCredentialNotification -NotificationsTable $notificationsTable -SentNotifications $notifications -ServicePrincipals $servicePrincipals
    }

    # Get expiring credentials for Enterprise applications (certs)
    [array]$servicePrincipalCredentials = Find-ExpiringCredentials -Table $servicePrincipalsTable
    Write-Warning "Found $($servicePrincipalCredentials.Count) expiring credentials (service principals)"
    if ($servicePrincipalCredentials.Count -gt 0) {
        $servicePrincipals = Get-ServicePrincipalsForCredentials -Table $servicePrincipalsTable -SecretsOrCertificates $servicePrincipalCredentials
        Write-Verbose "Got $($ServicePrincipals.Count) rows for service applications"
        $servicePrincipalCredentials | Send-ExpiringCredentialNotification -NotificationsTable $notificationsTable -SentNotifications $notifications -ServicePrincipals $servicePrincipals
    }

    Write-Verbose 'Finished'
}

function Send-ExpiringCredentialNotification {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True, ValuefromPipeline = $True)]
        $ExpriringObject,
        $NotificationsTable,
        $SentNotifications,
        $ServicePrincipals
    )
    process {
        $appId = $ExpriringObject.PartitionKey

        # Find notification users
        $sp = $ServicePrincipals | Where-Object { $_.PartitionKey -eq $appId -and $_.RowKey -match 'ServicePrincipal' }
        if ($null -eq $sp) {
            Write-Warning "No enterprise application found with AppId=$($appId). KeyId=$($ExpriringObject.KeyId)"
            return
        }
        
        $remaining = ((Get-Date $ExpriringObject.EndDateTime) - (Get-Date)).TotalDays
        Write-Verbose "Credential=$($ExpriringObject.Name) (KeyId=$($ExpriringObject.KeyId)) App=$($sp.DisplayName) (AppId=$($appId)) Expires: $(Get-DateString $ExpriringObject.EndDateTime) ($($remaining.ToString('N1')) days)"
        $emailImportance = 'normal'
        # Write-Verbose "$($remaining.ToString('N1')) days until expiration"
        # Check if notified
        $alreadyNotified = $SentNotifications | Where-Object { $_.PartitionKey -eq $appId -and $_.RowKey -eq $ExpriringObject.KeyId }
        if (($alreadyNotified | Measure-Object).Count -eq 1) {
            # Write-Verbose "Notifications already sent on $(Get-DateString $alreadyNotified.Notification30)"
            # Write-Verbose "$($alreadyNotified|ConvertTo-Json)"
            if (-not [string]::IsNullOrWhiteSpace($alreadyNotified.Notification15)) {
                Write-Verbose 'Already notified twice'
                return
            } elseif ($remaining -lt 15) {
                Write-Verbose 'Sending second notification'
                $emailImportance = 'high'
            } else {
                Write-Verbose 'Not sending another notification just yet'
                return
            }
        }

        # Find recipients to send the notification
        [array]$recipients = @()
        $recipientCount = 0
        if (-not [string]::IsNullOrWhiteSpace($sp.NotifyUsers)) {
            [array]$recipients = $sp.NotifyUsers.Trim().Split(',', [StringSplitOptions]::RemoveEmptyEntries)
            $recipientCount = ($recipients | Measure-Object).Count
        }

        if ($recipientCount -eq 0) {
            Write-Warning "Did not find users to notify (appId=$($appId))"
            if (-not $NotificationEmailUseDefault) {
                return
            }
            [array]$recipients = , $NotificationEmailDefaultAddress
        }
        
        # Create draft email
        $body = Get-EmailBody -SecretOrCertificate $ExpriringObject -Application $sp
        # $recipients | Select-Object -ExpandProperty Mail | ForEach-Object {
        $recipients | ForEach-Object {
            Write-Verbose "$($sp.DisplayName) ($($appId)) Recipient $($_) "
            # Send email
            New-Email -Subject $NotificationEmailSubject -Body $body -Recipient $_ -Importance $emailImportance
        }
        # Update notification sent
        if ($DryRun) {
            Write-Warning "DRY-RUN: Would upsert a row in the notifications table ($appId)"
        } else {
            if ($null -eq $alreadyNotified) {
                # Write-Verbose 'Storing new notification'
                $properties = @{
                    Notification30 = (Get-Date).ToString('o')
                    Notification15 = ''
                }
                Add-AzTableRow -Table $NotificationsTable -PartitionKey $appId -RowKey $ExpriringObject.KeyId -Property $properties | Out-Null
            } else {
                # Write-Verbose 'Updating notification'
                $alreadyNotified.Notification15 = (Get-Date).ToString('o')
                $alreadyNotified | Update-AzTableRow -Table $NotificationsTable | Out-Null
            }
        }
    }
}

function Get-SentNotifications {
    param(
        $Table
    )

    $notifications = Get-AzTableRow -Table $Table
    if (-not $notifications) {
        return @()
    }
    return $notifications
}

<#
.SYNOPSIS
Find service principals that match the provided credentials.

.PARAMETER Table
Service Principals table

.PARAMETER SecretsOrCertificates
List of credentials to find their service principals

.NOTES
This will query the table in batches of 14 apps.
#>
function Get-ServicePrincipalsForCredentials {
    param(
        $Table,
        $SecretsOrCertificates
    )
    $maxConditionNumber = 14
    $applications = @()
    $sb = New-Object System.Text.StringBuilder
    for ($i = 1; $i -le $SecretsOrCertificates.Count ; $i++) {
        $pk = $SecretsOrCertificates[$i - 1].PartitionKey
        # Write-Verbose "New PK $($pk)"
        $sb.Append("PartitionKey eq '$($pk)'")

        if ($i % $maxConditionNumber -eq 0) {
            # 15 conditions in the filter, make the query
            $filter = $sb.ToString()
            $sb.Clear()
            # Write-Verbose "Using filter (b): $($filter)"
            $newApps = Get-AzTableRow -Table $Table -CustomFilter $filter
            if ($newApps) {
                # Write-Verbose "New apps (b): $($newApps.gettype())"
                $applications += $newApps
            }
        } elseif ($i -lt $SecretsOrCertificates.Count) {
            # Keep adding conditions if needed
            $sb.Append(' or ')
        }
    }
    # Make the last query
    $filter = $sb.ToString()
    # Write-Verbose "Using filter (a): $($filter)"
    $newApps = Get-AzTableRow -Table $Table -CustomFilter $filter
    if ($newApps) {
        # Write-Verbose "New apps (a): $($newApps.gettype())"
        $applications += $newApps
    }
    return $applications
}

function Find-ExpiringCredentials {
    param(
        $Table
    )
    $now = (Get-Date).Date.ToUniversalTime()
    $limit = $now.AddDays($ExpirationDays + 1).Date.ToString('o')
    $now = $now.ToString('o')
    Write-Verbose "Finding credentials expiring between $($now) and $($limit)"

    $credentialsFilter = "KeyId ne 'null' and EndDateTime ge datetime'$($now)' and EndDateTime lt datetime'$($limit)'"
    $credentials = Get-AzTableRow -Table $Table -CustomFilter $credentialsFilter
    return $credentials
}

$entityCharacters = 'áéíóúÁÉÍÓÚñÑüÜçÇ'.ToCharArray()

function Get-EmailBody {
    param(
        $SecretOrCertificate,
        $Application
    )
    $body = $NotificationEmailBody
    $body = $body.Replace('{appId}', $Application.ApplicationId)
    $body = $body.Replace('{appName}', $Application.DisplayName)
    $body = $body.Replace('{keyId}', $SecretOrCertificate.KeyId)
    $body = $body.Replace('{keyName}', $SecretOrCertificate.Name)
    $body = $body.Replace('{expirationTime}', (Get-DateString $SecretOrCertificate.EndDateTime))
    # $body = [System.Web.HttpUtility]::HtmlEncode($body)
    # $body = $body.Replace('`r`n', '<br/>')
    $sb = New-Object System.Text.StringBuilder
    $body.ToCharArray() | ForEach-Object {
        if ($_ -in $entityCharacters) { $sb.Append("&#{0};" -f [Convert]::ToInt32($_)) | Out-Null }
        else { $sb.Append($_) | Out-Null }
    }
    $bodyEntities = $sb.ToString()
    return $bodyEntities
}

function New-Email {
    param (
        $Subject,
        $Body,
        $Recipient,
        $Importance
    )
    $email = @{
        "saveToSentItems" = "true"
        "message"         = @{
            "subject"      = $Subject
            "importance"   = $Importance
            "body"         = @{
                "contentType" = "HTML"
                "content"     = $Body
            }
            "toRecipients" = @(
                @{
                    "emailAddress" = @{
                        "address" = $Recipient
                    }
                }   
            )
        }
    }
    $emailJson = $email | ConvertTo-Json -Depth 10
    # Write-Verbose $emailJson
    $path = "/users/$($NotificationEmailSendAs)/sendMail"
    if ($DryRun) {
        Write-Warning "DRY-RUN: Would send email to $Recipient"
    } else {
        Invoke-Graph -Path $path -Method 'Post' -Body $emailJson | Out-Null
        Write-Verbose 'Email sent successfully'
    }
}

# -------------------
# ----- Helpers -----
# -------------------

function Get-CloudTable {
    param (
        $AzureContext,
        [string]$TableName
    )
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName -DefaultProfile $AzureContext
    if ($null -eq $storageAccount) {
        Write-Error "No storage account found"
        exit
    }
    $storageContext = $storageAccount.Context
    $table = Get-AzStorageTable -Name $TableName -Context $storageContext -ErrorAction Ignore
    if ($null -eq $table) {
        Write-Warning "Table $TableName does not exist. Creating it..."
        $table = New-AzStorageTable -Name $TableName -Context $storageContext
    }
    Write-Verbose "Retrieved table: $($table.Uri)"
    return $table.CloudTable
}

function Connect-ManagedIdentity {
    param()
    $azureContext = $null
    switch ($ManagedIdentityMethod) {
        "SA" { 
            Write-Verbose "Using system-assigned managed identity"
            try {
                $azureContext = (Connect-AzAccount -Identity).Context
                $azureContext = Set-AzContext -SubscriptionName $Subscription -DefaultProfile $azureContext
            } catch {
                Write-Error "Error using system-assigned identity: $($_)"
                exit
            }
        }
        "UA" {
            Write-Verbose "Using user-assigned managed identity"
            try {
                $UserAssignedManagedIdentityAppId = Get-AutomationVariable -Name 'UserAssignedManagedIdentityAppId'
                $azureContext = (Connect-AzAccount -Identity -AccountId $UserAssignedManagedIdentityAppId).Context
                $azureContext = Set-AzContext -SubscriptionName $Subscription -DefaultProfile $azureContext
            } catch {
                Write-Error "Error using user assigned identity: $($_)"
                exit
            }
        }
        Default {
            Write-Error "Invalid method. Choose UA or SA."
            exit
        }
    }
    return $azureContext
}

function Get-GraphToken {
    param()
    # Connect using AppReg credentials from Azure Automation
    if ($env:GraphAccessToken) {
        Write-Verbose 'Returning cached access token'
    } else {
        Write-Verbose "Getting new access token"
        $creds = Get-AutomationPSCredential -Name 'AppReg'
        $context = (Connect-AzAccount -Tenant $TenantId -Credential $creds -ServicePrincipal -Environment AzureCloud).Context
        $token = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -DefaultProfile $context
        $env:GraphAccessToken = $token.Token
    }
    # Write-Verbose $env:GraphAccessToken
    return $env:GraphAccessToken
}

function Invoke-GraphInternal {
    param (
        $Path,
        $Body,
        $Method
    )
    if ($Path.StartsWith('https://')) {
        $url = $Path
    } else {
        $url = "https://graph.microsoft.com/v1.0$Path"
    }
    $headers = @{
        "Authorization" = "Bearer $(Get-GraphToken)"
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json;odata.metadata=none'
        # 'ConsistencyLevel' = 'eventual'
    }
    $ProgressPreference = 'silentlyContinue'
    $VerbosePreference = 'silentlyContinue'
    $response = Invoke-WebRequest -Uri $url -Headers $headers -Method $Method -Body $Body -UseBasicParsing
    $converted = $response | ConvertFrom-Json
    return $converted
}

function Invoke-Graph {
    param (
        $Path,
        $Body = $null,
        $Method = 'Get'
    )
    # Write-Verbose "New request: $Path"
    try {
        $response = Invoke-GraphInternal -Path $Path -Body $Body -Method $Method
    } catch {
        $response = $_.Exception.Response
        if ($response.StatusCode -eq 429) {
            # https://docs.microsoft.com/en-us/graph/throttling
            # Request type	Per app across all tenants
            # Any	        2000 requests per second
            $seconds = [int]$response.Headers["Retry-After"]
            if ($seconds -eq 0) {
                $seconds = 60
            }
            Write-Warning "Throttling error. Retry-After= $($seconds) s"
            Start-Sleep ($seconds + 5)
            $response = Invoke-GraphInternal -Path $Path
        } else {
            Write-Error "Error invoking Graph ($_): $($response.StatusCode)"
            throw
        }
    }
    return $response
}

function Invoke-PaginatedGraphList {
    param(
        $Path, 
        $Method = 'Get'
    )

    $fullReponse = @()
    $nextLink = $Path
    do {
        $response = Invoke-Graph -Path $nextLink -Method $Method
        if ($response.value) {
            # Write-Verbose "Graph returned a list of $($response.value.Count) items"
            $fullReponse += $response.value
        }
        $nextLink = $response.'@odata.nextLink'
        # Write-Verbose "next link: $nextLink"
    } while ($nextLink)
    return $fullReponse
}

# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process | Out-Null
if ($DryRun) {
    Write-Verbose '* DRY RUN *'
}
Start-Work
Disconnect-AzAccount | Out-Null
