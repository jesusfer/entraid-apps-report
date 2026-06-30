#Requires -Module Az.Resources,Az.Storage,Az.Accounts,AzTable
param
(
    # UA or SA, User-Assigned or System Assigned
    [string]$ManagedIdentityMethod = "SA",
    [int]$NotifyUsersResolveBatchSize = 15,
    # When enabled, re-resolve all grant principals from Graph instead of reusing
    # the ones already stored, and clear the Principals table before saving.
    [bool]$ForceUpdateAllUsers = $false
)

$TenantId = Get-AutomationVariable -Name 'TenantId'
$Subscription = Get-AutomationVariable -Name 'Subscription'
$ResourceGroup = Get-AutomationVariable -Name 'ResourceGroup'
$StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'

$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
Import-Module Az.Resources
Import-Module Az.Storage
Import-Module Az.Accounts
Import-Module AzTable
Update-AzConfig -DisplaySecretsWarning $false | Out-Null
# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process | Out-Null
$VerbosePreference = $PreviousVerbosePreference

# $VerbosePreference = 'Continue'
# $ErrorActionPreference = 'Stop'

$ownerRE = '(owner|propietario)=(([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,},?)+)'

# Main orchestration function
function Start-Work {
    param()
    # Store data in Azure Storage Account
    $azureContext = Connect-ManagedIdentity

    #####################
    # App Registrations #
    #####################

    $table = Get-StorageTable -AzureContext $azureContext -TableName "Applications"
    $apps = Get-AppRegistrations
    Write-Output "Found $($apps.Count) Applications"    
    Write-Warning "Mem checkpoint: $((Get-MemoryUsageMB).WorkingSetMB) MB"
    Clear-Table $table
    Write-Output "Saving Applications"
    Save-Applications -Applications $apps -StorageTable $table

    ######################
    # Service Principals #
    ######################

    # List of service principals
    # One paginated Graph request to get everything
    $servicePrincipals = Get-ServicePrincipals
    Write-Output "Found $($servicePrincipals.Count) Service Principals"
    Write-Warning "Mem checkpoint: $((Get-MemoryUsageMB).WorkingSetMB) MB"

    $spTable = Get-StorageTable -AzureContext $azureContext -TableName "ServicePrincipals"
    Clear-Table $spTable

    Write-Output "Saving ServicePrincipals"
    $params = @{
        ServicePrincipals = $servicePrincipals
        StorageTable      = $spTable
    }
    $notifyUsersToResolve = Save-ServicePrincipals @params

    # Map each service principal object id to its appId, used as the storage partition key
    $appIdById = @{}
    foreach ($servicePrincipal in $servicePrincipals) {
        $appIdById[$servicePrincipal.id] = $servicePrincipal.appId
    }

    # List of service principals IDs with their appRoleAssignments
    # One paginated Graph request to get everything
    $servicePrincipalsAppRoleAssignments = Get-SPAppRolesAssignments
    Write-Output "Found $($servicePrincipalsAppRoleAssignments.Count) Service Principal App Role Assignments"
    Write-Warning "Mem checkpoint: $((Get-MemoryUsageMB).WorkingSetMB) MB"

    # Store the app role assignments consumed by all service principals
    Write-Output "Saving SPAppRoleAssignments"
    $params = @{
        AppIdById          = $appIdById
        AppRoleAssignments = $servicePrincipalsAppRoleAssignments
        StorageTable       = $spTable
    }
    Save-SPAppRoleAssignments @params

    # Hashtable with key=servicePrincipalId, value=grants
    # One request per service principal
    # User reference using the principalId
    $servicePrincipalsGrants = Get-SPOAuth2Grants -ServicePrincipals $servicePrincipals
    Write-Output "Found $($servicePrincipalsGrants.Count) Service Principal Grants"
    Write-Warning "Mem checkpoint: $((Get-MemoryUsageMB).WorkingSetMB) MB"

    # Store the oauth2 permission grants of all service principals
    Write-Output "Saving SPGrants"
    $params = @{
        AppIdById    = $appIdById
        AllGrants    = $servicePrincipalsGrants
        StorageTable = $spTable
    }
    Save-SPGrants @params

    $principalsTable = Get-StorageTable -AzureContext $azureContext -TableName "Principals"

    # Store the notification users, searching for their details in Graph
    # Number of Graph requests is roughly the number of notification users / batchSize
    Write-Output "Saving SPNotificationUsers"
    $params = @{
        NotifyUsers     = $notifyUsersToResolve
        PrincipalsTable = $principalsTable
        BatchSize       = $NotifyUsersResolveBatchSize
    }
    Save-SPNotificationUsers @params
    # Hashtable with key=principalId, value=principal
    # Resolve the unique principals referenced in the grants
    # One Graph request per unique principal
    # Potentially the largest amount of requests
    $params = @{
        Grants          = $servicePrincipalsGrants
        PrincipalsTable = $principalsTable
    }
    $grantsPrincipals = Get-SPGrantPrincipals @params
    Write-Output "Found $($grantsPrincipals.Count) new SP Grant Principals"
    Write-Warning "Mem checkpoint: $((Get-MemoryUsageMB).WorkingSetMB) MB"

    if ($ForceUpdateAllUsers) {
        Clear-Table $principalsTable
    }

    # Store the unique principals referenced by the grants
    Write-Output "Saving SPGrantsPrincipals"
    $params = @{
        GrantsPrincipals = $grantsPrincipals
        PrincipalsTable  = $principalsTable
    }
    Save-SPGrantPrincipals @params

}

# Helper functions

function Get-MemoryUsageMB {
    $proc = [System.Diagnostics.Process]::GetCurrentProcess()
    $proc.Refresh()
    [PSCustomObject]@{
        WorkingSetMB  = [math]::Round($proc.WorkingSet64 / 1MB, 1)
        PrivateMB     = [math]::Round($proc.PrivateMemorySize64 / 1MB, 1)
        GCHeapMB      = [math]::Round([GC]::GetTotalMemory($false) / 1MB, 1)
    }
}

function IfNull {
    [CmdletBinding()]
    param(
        $Value, $DefaultValue = ''
    )
    process {
        if ($null -eq $Value) {
            return $DefaultValue
        }
        return $Value
    }
}

function Add-TableRow {
    param(
        $Table,
        $PartitionKey,
        $RowKey,
        $Property
    )
    try {
        Add-AzTableRow -Table $Table -PartitionKey $PartitionKey -RowKey $RowKey -Property $Property | Out-Null
    }
    catch {
        $messages = @()
        $ex = $_.Exception
        while ($null -ne $ex) {
            $messages += $ex.Message
            $ex = $ex.InnerException
        }
        Write-Error "Failed to add row with PartitionKey '$PartitionKey' and RowKey '$RowKey': $([String]::Join(' --> ', $messages))"
    }
}

# https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal
function Save-ServicePrincipals {
    param(
        $ServicePrincipals,
        $StorageTable
    )
    $table = $StorageTable.CloudTable

    Write-Verbose "Saving the service principals in storage"
    $notifyUsersToResolve = @()
    foreach ($servicePrincipal in $ServicePrincipals) {
        Write-Verbose "ServiceApplication $($servicePrincipal.appId)"
        $pk = $servicePrincipal.AppId

        # Process notification users
        $notifyUsers = ''
        if ($servicePrincipal.notes) {
            $notifyUsersList = @()
            # Write-Verbose $servicePrincipal.notes
            $servicePrincipal.notes.Split("`n") | ForEach-Object {
                if ($_ -match $ownerRE) {
                    # $Matches[2] is the list of emails separated by comma in the RE
                    Write-Verbose "Found match: $($Matches[2])"
                    foreach ($email in $Matches[2].Split(',')) {
                        $trimmedEmail = $email.Trim()
                        if ($trimmedEmail -ne '') {
                            $notifyUsersList += $trimmedEmail
                        }
                    }
                }
            }
            if ($notifyUsersList.Count -gt 0) {
                $notifyUsers = [String]::Join(',', $notifyUsersList)
                $notifyUsersToResolve += $notifyUsersList
            }
        }

        $replyUrls = ''
        if ($servicePrincipal.ReplyUrls.Count -gt 0) {
            $replyUrls = [String]::Join(',', $servicePrincipal.ReplyUrls)
        }

        $servicePrincipalNames = ''
        if ($servicePrincipal.ServicePrincipalNames.Count -gt 0) {
            $servicePrincipalNames = [String]::Join(',', $servicePrincipal.servicePrincipalNames)
        }

        $rk = "ServicePrincipal"
        $properties = @{
            AccountEnabled            = $servicePrincipal.accountEnabled
            ApplicationId             = $servicePrincipal.appId
            AppRoleAssignmentCount    = $servicePrincipal.appRoleAssignedTo.Count
            AppRoleAssignmentRequired = IfNull $servicePrincipal.appRoleAssignmentRequired $false
            DisplayName               = $servicePrincipal.displayName
            ObjectId                  = $servicePrincipal.id
            NotifyUsers               = $notifyUsers
            PreferredSingleSignOnMode = IfNull $servicePrincipal.preferredSingleSignOnMode
            ReplyUrls                 = $replyUrls
            ServicePrincipalNames     = $servicePrincipalNames
            ServicePrincipalType      = $servicePrincipal.servicePrincipalType
            SignInAudience            = IfNull $servicePrincipal.signInAudience
        }
        $params = @{
            Table        = $table
            PartitionKey = $pk
            RowKey       = $rk
            Property     = $properties
        }
        Add-TableRow @params

        Write-Verbose "ServiceApplication $($servicePrincipal.appId) scopes"
        foreach ($scope in $servicePrincipal.oauth2PermissionScopes) {
            $rk = "Scope-$($scope.id)"
            # Write-Verbose $rk
            $properties = @{
                ApplicationId = $servicePrincipal.appId
                DisplayName   = $scope.adminConsentDisplayName
                Id            = $scope.id
                Value         = $scope.value
                Type          = 'Delegated'
            }
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }

        Write-Verbose "ServiceApplication $($servicePrincipal.appId) roles"
        foreach ($role in $servicePrincipal.appRoles) {
            $rk = "Role-$($role.id)"
            # Write-Verbose $rk
            $properties = @{
                ApplicationId = $servicePrincipal.appId
                DisplayName   = $role.displayName
                Id            = $role.id
                Value         = IfNull $role.value $role.displayName
                Type          = 'Application'
            }
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }

        Write-Verbose "ServiceApplication $($servicePrincipal.appId) keyCredentials"
        foreach ($key in $servicePrincipal.keyCredentials) {
            $rk = "Certificate-$($key.keyId)"
            $properties = @{
                ApplicationId    = $servicePrincipal.appId
                KeyId            = $key.keyId
                Name             = IfNull $key.displayName
                EndDateTime      = IfNull $key.endDateTime (Get-Date "2099-12-31")
                ServicePrincipal = $true
                Usage            = IfNull $key.usage 'Unknown'
                Type             = IfNull $key.type 'Unknown'
                Thumbprint       = IfNull $key.customKeyIdentifier 'Unknown'
            }
            # Write-Verbose ($servicePrincipal | ConvertTo-Json -Depth 5)
            # Write-Verbose ($properties | ConvertTo-Json -Depth 5)
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }

        Write-Verbose "ServiceApplication $($servicePrincipal.AppId) passwordCredentials"
        foreach ($password in $servicePrincipal.passwordCredentials) {
            $rk = "Secret-$($password.keyId)"
            $properties = @{
                ObjectId      = $servicePrincipal.id
                ApplicationId = $servicePrincipal.appId
                KeyId         = $password.keyId
                Name          = IfNull $password.displayName "Unnamed secret"
                EndDateTime   = $password.endDateTime
            }
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }

        <#
        Nota: Usuarios con default access previos a la creación de AppRoles
        no aparecen en esta lista (no son válidos por tener un role no válido)
        #>
        <# Este service principal crea roles y esta lista son los SP que usan estos roles
        #>
        Write-Verbose "ServiceApplication $($servicePrincipal.appId) appRoleAssignedTo"
        foreach ($assignment in $servicePrincipal.appRoleAssignedTo) {
            $rk = "AppRolesAssignedTo-$($assignment.id)"
            $properties = @{
                ApplicationId        = $servicePrincipal.appId
                AssignmentId         = $assignment.id
                AppRoleId            = $assignment.appRoleId
                CreatedDateTime      = IfNull $assignment.createdDateTime
                PrincipalType        = $assignment.principalType
                PrincipalDisplayName = $assignment.principalDisplayName
                # Object Id of the service principal, user, group or service principal that consumes the role
                PrincipalId          = $assignment.principalId
            }
            # Write-Verbose ($servicePrincipal | ConvertTo-Json -Depth 5)
            # Write-Verbose ($properties | ConvertTo-Json -Depth 5)
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }
    }

    return $notifyUsersToResolve
}

function Save-SPGrantPrincipals {
    param(
        $GrantsPrincipals,
        $PrincipalsTable
    )
    $pTable = $PrincipalsTable.CloudTable

    # Store the unique principals referenced by the grants
    Write-Verbose "Saving the grant principals in storage"
    foreach ($principalId in $GrantsPrincipals.Keys) {
        $principal = $GrantsPrincipals[$principalId]
        Write-Verbose "Storing principal $principalId"
        $properties = @{
            UPN         = $principal.userPrincipalName
            DisplayName = IfNull $principal.displayName $principal.userPrincipalName
            Mail        = IfNull $principal.mail
            State       = IfNull $principal.state
        }
        $params = @{
            Table        = $pTable
            PartitionKey = "Users"
            RowKey       = $principalId
            Property     = $properties
        }
        Add-TableRow @params
    }
}

function Save-SPGrants {
    param(
        $AppIdById,
        $AllGrants,
        $StorageTable
    )
    $table = $StorageTable.CloudTable

    Write-Verbose "Saving the service principals oauth2 permission grants in storage"
    foreach ($servicePrincipalId in $AllGrants.Keys) {
        # Listado de permisos delegados que este service principal tiene concedidos por admin consent
        $appId = $appIdById[$servicePrincipalId]
        Write-Verbose "ServiceApplication $appId oauth2PermissionGrants"
        foreach ($grant in $AllGrants[$servicePrincipalId]) {
            $rk = "OAuth2PermissionGrants-$($grant.id)"
            $properties = @{
                ConsentType = $grant.consentType
                ConsentId   = $grant.id
                PrincipalId = IfNull $grant.principalId
                ResourceId  = $grant.resourceId
                Scopes      = $grant.scope
            }
            $params = @{
                Table        = $table
                PartitionKey = $appId
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }
    }
}

function Save-SPAppRoleAssignments {
    param(
        $AppIdById,
        $AppRoleAssignments,
        $StorageTable
    )
    $table = $StorageTable.CloudTable

    Write-Verbose "Saving the service principals app role assignments in storage"
    foreach ($servicePrincipalAssignments in $AppRoleAssignments) {
        # Roles that this service principal consumes from other SPs and for which it has admin grant
        $appId = $appIdById[$servicePrincipalAssignments.id]
        Write-Verbose "ServiceApplication $appId appRoleAssignments"
        foreach ($assignment in $servicePrincipalAssignments.appRoleAssignments) {
            $rk = "AppRolesAssignment-$($assignment.id)"
            $properties = @{
                ApplicationId       = $appId
                AssignmentId        = $assignment.id
                AppRoleId           = $assignment.appRoleId
                CreatedDateTime     = IfNull $assignment.createdDateTime
                ResourceDisplayName = $assignment.resourceDisplayName
                # Object Id of the service principal that exposes the role
                ResourceId          = $assignment.resourceId
            }
            $params = @{
                Table        = $table
                PartitionKey = $appId
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }
    }
}

function Save-SPNotificationUsers {
    param(
        $NotifyUsers,
        $PrincipalsTable,
        [int]$BatchSize = 15
    )

    if (-not $NotifyUsers -or $NotifyUsers.Count -eq 0) {
        Write-Output "No notify users to resolve"
        return
    }

    $pTable = $PrincipalsTable.CloudTable

    $uniqueNotifyUsers = @{}
    foreach ($user in $NotifyUsers) {
        if ($null -eq $user) {
            continue
        }
        $trimmedUser = $user.Trim()
        if ($trimmedUser -eq '') {
            continue
        }
        $normalizedUser = $trimmedUser.ToLowerInvariant()
        if (-not $uniqueNotifyUsers.ContainsKey($normalizedUser)) {
            $uniqueNotifyUsers[$normalizedUser] = $trimmedUser
        }
    }

    if ($uniqueNotifyUsers.Count -eq 0) {
        Write-Warning "No valid notify users to resolve"
        return
    }

    # Only resolve notify users that aren't already present in the Principals table.
    # Notify users are stored under partition key "NotifyUsers" with the raw
    # email/UPN as the row key.
    $usersToResolve = @{}
    foreach ($userKey in $uniqueNotifyUsers.Keys) {
        $rawUser = $uniqueNotifyUsers[$userKey]
        $existing = Get-AzTableRow -Table $pTable -PartitionKey "NotifyUsers" -RowKey $rawUser -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Warning "Notify user $rawUser already exists in storage, skipping"
            continue
        }
        $usersToResolve[$userKey] = $rawUser
    }

    if ($usersToResolve.Count -eq 0) {
        Write-Warning "All notify users already exist in storage"
        return
    }

    Write-Verbose "Resolving $($usersToResolve.Count) notify users in batches of $BatchSize"
    $resolvedUsers = Get-UsersWithEmailOrUPN -EmailOrUPNList $usersToResolve.Keys -BatchSize $BatchSize

    $resolvedUsersByKey = @{}
    foreach ($userDetails in $resolvedUsers) {
        if ($userDetails.mail) {
            $resolvedUsersByKey[$userDetails.mail.ToLowerInvariant()] = $userDetails
        }
        if ($userDetails.userPrincipalName) {
            $resolvedUsersByKey[$userDetails.userPrincipalName.ToLowerInvariant()] = $userDetails
        }
    }

    foreach ($userKey in $usersToResolve.Keys) {
        $rawUser = $usersToResolve[$userKey]
        if ($resolvedUsersByKey.ContainsKey($userKey)) {
            $userDetails = $resolvedUsersByKey[$userKey]
            Write-Verbose "Storing principal $($userDetails.userPrincipalName)"
            $properties = @{
                UPN         = $userDetails.userPrincipalName
                DisplayName = IfNull $userDetails.displayName $userDetails.userPrincipalName
                Mail        = IfNull $userDetails.mail
                State       = IfNull $userDetails.state
            }
            $rk = $rawUser
            $params = @{
                Table        = $pTable
                PartitionKey = "NotifyUsers"
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }
        else {
            Write-Warning "User not found in Entra with email or UPN: $rawUser"
        }
    }
}

# https://learn.microsoft.com/en-us/graph/api/resources/application
function Save-Applications {
    param(
        $Applications,
        $StorageTable
    )
    $table = $StorageTable.CloudTable

    Write-Verbose "Saving the applications in storage"
    foreach ($application in $Applications) {
        Write-Verbose "Application $($application.AppId) application"
        $pk = $application.AppId

        $rk = 'Application'
        $identifierUris = ''
        if ($application.IdentifierUris.Count -gt 0) {
            $identifierUris = [String]::Join(',', $application.IdentifierUris)
        }
        $properties = @{
            ApplicationId             = $application.appId
            CreatedDate               = $application.createdDateTime
            DisplayName               = $application.displayName
            ObjectId                  = $application.id
            IdentifierUris            = $identifierUris
            IsDeviceOnlyAuthSupported = IfNull $application.isDeviceOnlyAuthSupported $false
            IsFallbackPublicClient    = IfNull $application.isFallbackPublicClient $false
            SamlMetadataUrl           = IfNull $application.samlMetadataUrl
            SignInAudience            = $application.signInAudience
        }
        $params = @{
            Table        = $table
            PartitionKey = $pk
            RowKey       = $rk
            Property     = $properties
        }
        Add-TableRow @params

        # keyCredentials
        Write-Verbose "Application $($application.AppId) keyCredentials"
        foreach ($key in $application.keyCredentials) {
            $rk = "Certificate-$($key.keyId)"
            $properties = @{
                ObjectId         = $application.id
                ApplicationId    = $application.appId
                KeyId            = $key.keyId
                Name             = IfNull $key.displayName "Unnamed certificate"
                EndDateTime      = IfNull $key.endDateTime (Get-Date "2099-12-31")
                ServicePrincipal = $false
            }
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }

        # passwordCredentials
        Write-Verbose "Application $($application.AppId) passwordCredentials"
        foreach ($password in $application.passwordCredentials) {
            $rk = "Secret-$($password.keyId)"
            $properties = @{
                ObjectId      = $application.id
                ApplicationId = $application.appId
                KeyId         = $password.keyId
                Name          = IfNull $password.displayName "Unnamed secret"
                EndDateTime   = $password.endDateTime
            }
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }

        Write-Verbose "Application $($application.appId) roles"
        foreach ($role in $application.appRoles) {
            $rk = "Role-$($role.id)"
            # Write-Verbose $rk
            $properties = @{
                ApplicationId = $application.appId
                DisplayName   = $role.displayName
                Id            = $role.id
                Value         = IfNull $role.value $role.displayName
                Type          = 'Application'
            }
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }

        Write-Verbose "Application $($application.AppId) owners"
        foreach ($owner in $application.owners) {
            if ($null -eq $owner.userPrincipalName) { continue }
            $upn = $owner.userPrincipalName.Replace("#", '-')
            $rk = "Owners-$($upn)"
            $properties = @{
                ObjectId      = $application.id
                ApplicationId = $application.appId
                UPN           = $upn
                Mail          = IfNull $owner.mail
                State         = IfNull $owner.state
            }
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-TableRow @params
        }

        # requiredResourceAccess
        Write-Verbose "Application $($application.AppId) requiredResourceAccess"
        foreach ($resource in $application.requiredResourceAccess) {
            foreach ($access in $resource.resourceAccess) {
                $rk = "Permissions-$($resource.resourceAppId)-$($access.id)-$($access.type)"
                $properties = @{
                    ObjectId           = $application.id
                    ApplicationId      = $application.appId
                    ResourceAppId      = $resource.resourceAppId
                    ResourceAccessId   = $access.id
                    ResourceAccessType = $access.type
                }
                $params = @{
                    Table        = $table
                    PartitionKey = $pk
                    RowKey       = $rk
                    Property     = $properties
                }
                Add-TableRow @params
            }
        }

        # api
        # Write-Verbose "Application $($application.AppId) api"
        <#
        foreach ($scope in $application.api.oauth2PermissionScopes) {
            $rk = "CustomApi-$($scope.id)"
            $properties = @{
                ObjectId           = $application.id
                AppId              = $application.appId
                ConsentDisplayName = $scope.adminConsentDisplayName
                AccessId           = $scope.id
                IsEnabled          = $scope.isEnabled
                Type               = $scope.type
                Value              = $scope.value
            }
            Add-AzTableRow -Table $StorageTable.CloudTable -PartitionKey $pk -RowKey $rk -Property $properties | Out-Null
        }
        #>
    }
}

# Storage functions

function Get-StorageTable {
    param (
        $AzureContext,
        $TableName
    )
    Write-Verbose "Checking storage account"
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName -DefaultProfile $AzureContext
    if ($null -eq $storageAccount) {
        Write-Error "No storage account found"
        exit
    }
    Write-Verbose "Checking if table exists"
    $storageContext = $storageAccount.Context
    $table = Get-AzStorageTable -Name $TableName -Context $storageContext -ErrorAction Ignore
    if ($null -eq $table) {
        Write-Warning "Table does not exist. Creating it..."
        $table = New-AzStorageTable -Name $TableName -Context $storageContext
    }
    Write-Verbose "Retrieved table: $($table.Uri)"
    return $table
}

function Clear-Table {
    param (
        $table
    )
    Write-Verbose "Cleaning the table: $($table.CloudTable)"
    Get-AzTableRow -Table $table.CloudTable | Remove-AzTableRow -Table $table.CloudTable | Out-Null
}

# Authentication functions

function Connect-ManagedIdentity {
    param()
    Write-Verbose "Auth method: $($ManagedIdentityMethod)"
    switch ($ManagedIdentityMethod) {
        "SA" {
            Write-Verbose "Using system-assigned managed identity in subscription $Subscription"
            try {
                $azureContext = (Connect-AzAccount -Identity).Context
                $azureContext = Set-AzContext -SubscriptionName $Subscription -DefaultProfile $azureContext
                Write-Verbose "Logged in with managed identity"
                return $azureContext
            }
            catch {
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
                Write-Verbose "Logged in with user assigned identity"
                return $azureContext
            }
            catch {
                Write-Error "Error using user assigned identity: $($_)"
                exit
            }
        }
        Default {
            Write-Error "Invalid method. Choose UA or SA."
            exit
        }
    }
}

# Graph retrieval functions

function Get-AppRegistrations {
    param()
    $props = @(
        # Specifies settings for an application that implements a web API
        # App registration -> Expose an API
        # api.oauth2PermissionScopes[] -> Declared scopes
        # api.preAuthorizedApplications[] -> Pre-authorized applications
        "api",
        # The unique identifier for the application that is assigned to an application by Microsoft Entra ID
        "appId",
        # The collection of roles defined for the application. With app role assignments, these roles can be assigned to users, groups, or service principals associated with other applications
        # App registration -> App roles
        "appRoles",
        # The date and time the application was registered
        "createdDateTime",
        # The display name for the application
        "displayName",
        # Unique identifier for the application object. This property is referred to as Object ID in the Microsoft Entra admin center
        "id",
        # Also known as App ID URI, this value is set when an application is used as a resource app
        # App registration -> Expose an API -> Application ID URI
        "identifierUris",
        # Specifies whether this application supports device authentication without a user
        "isDeviceOnlyAuthSupported",
        # Specifies the fallback application type as public client, such as an installed application running on a mobile device
        "isFallbackPublicClient",
        # The collection of key (certificates) credentials associated with the application
        # App registration -> Certificates & secrets -> Certificates
        "keyCredentials",
        # The collection of password (secrets) credentials associated with the application
        # App registration -> Certificates & secrets -> Client secrets
        "passwordCredentials",
        # Specifies settings for installed clients such as desktop or mobile devices
        "publicClient",
        # Specifies the resources that the application needs to access. This property also specifies the set of delegated permissions and application roles that it needs for each of those resources. This configuration of access to the required resources drives the consent experience
        # App registration -> API permissions -> Configured permissions
        "requiredResourceAccess",
        # The URL where the service exposes SAML metadata for federation
        "samlMetadataUrl",
        # Specifies the Microsoft accounts that are supported for the current application. The possible values are: AzureADMyOrg (default), AzureADMultipleOrgs, AzureADandPersonalMicrosoftAccount, and PersonalMicrosoftAccount
        "signInAudience",
        # Specifies settings for a single-page application, including sign out URLs and redirect URIs for authorization codes and access tokens
        "spa",
        # Custom strings that can be used to categorize and identify the application
        "tags",
        # Specifies settings for a web application
        "web"
    ) -join ','
    # owners
    # Directory objects that are owners of this application
    $path = "/applications?`$select=$props&`$expand=owners(`$select=id,displayName,userPrincipalName,mail,state)"
    $applications = Invoke-PaginatedGraphList -Path $path
    return $applications
}

function Get-ServicePrincipals {
    param()
    $props = @(
        # true if the service principal account is enabled; otherwise, false. 
        "accountEnabled",
        # The unique identifier for the associated application (its appId property).
        "appId",
        # Specifies whether users or other service principals need to be granted an app role assignment for this service principal before users can sign in or apps can get tokens.
        "appRoleAssignmentRequired",
        # The roles exposed by the application that's linked to this service principal.
        "appRoles",
        # The display name of the service principal.
        "displayName",
        # The unique identifier for the service principal.
        "id",
        # The collection of key credentials associated with the service principal.
        "keyCredentials",
        # Notes associated with the service principal.
        "notes",
        # The delegated permissions exposed by the application.
        "oauth2PermissionScopes",
        # The collection of password credentials associated with the application.
        "passwordCredentials",
        # Specifies the single sign-on mode configured for this application.
        "preferredSingleSignOnMode",
        # The URLs that user tokens are sent to for sign in with the associated application, or the redirect URIs that OAuth 2.0 authorization codes and access tokens are sent to for the associated application
        "replyUrls",
        # The resource-specific application permissions exposed by this application.
        "resourceSpecificApplicationPermissions",
        # The collection for settings related to saml single sign-on.
        "samlSingleSignOnSettings",
        # Contains the list of identifiersUris, copied over from the associated application
        "servicePrincipalNames",
        <# Identifies whether the service principal represents an application, a managed identity, or a legacy application. This property is set by Microsoft Entra ID internally. The servicePrincipalType property can be set to three different values:
        * Application - A service principal that represents an application or service
        * ManagedIdentity - A service principal that represents a managed identity
        * Legacy - A service principal that represents an app created before app registrations, or through legacy experiences
        * ServiceIdentity - A service principal that represents an agent identity
        * SocialIdp - For internal use
        #>
        # Identifies whether the service principal represents an application, a managed identity, or a legacy application
        "servicePrincipalType",
        <# Specifies the Microsoft accounts that are supported for the current application. Supported values are:
        * AzureADMyOrg: Users with a Microsoft work or school account in my organization's Microsoft Entra tenant (single-tenant).
        * AzureADMultipleOrgs: Users with a Microsoft work or school account in any organization's Microsoft Entra tenant (multitenant).
        * AzureADandPersonalMicrosoftAccount: Users with a personal Microsoft account, or a work or school account in any organization's Microsoft Entra tenant.
        * PersonalMicrosoftAccount: Users with a personal Microsoft account only.
        #>
        "signInAudience"
    ) -join ','
    # Gets all service principals and their appRoleAssignedTo
    # App role assignments for this app or service, granted to users, groups, and other service principals.
    # -> Users and groups
    $path = "/servicePrincipals?`$select=$props&`$expand=appRoleAssignedTo"
    $servicePrincipals = Invoke-PaginatedGraphList -Path $path
    return $servicePrincipals
}

function Get-SPOAuth2Grants {
    param($ServicePrincipals)
    # oauth2PermissionGrants
    # Delegated permission grants authorizing this service principal to access an API on behalf of a signed-in user
    # -> Permissions
    # Admin -> consentType=AllPrincipals
    # User -> consentType=Principal
    $results = @{}
    foreach ($servicePrincipal in $ServicePrincipals) {
        $path = "/servicePrincipals/$($servicePrincipal.id)/oauth2PermissionGrants"
        $grants = Invoke-Graph -Path $path
        if ($grants.value) {
            $results[$servicePrincipal.id] = $grants.value
        }
    }
    return $results
}

function Get-SPGrantPrincipals {
    param(
        $Grants,
        $PrincipalsTable
    )
    $pTable = $PrincipalsTable.CloudTable

    # Extract the unique, non-null principalIds referenced by the grants.
    # Unless ForceUpdateAllUsers is set, resolve a principal via Graph only when
    # it isn't already present in the Principals storage table. Principals found
    # in storage are recorded in an ignore list so the table isn't queried again
    # for the same principalId.
    $principals = @{}
    $ignoredPrincipals = @{}
    foreach ($servicePrincipalId in $Grants.Keys) {
        foreach ($grant in $Grants[$servicePrincipalId]) {
            $principalId = $grant.principalId
            if (-not $principalId) {
                continue
            }
            # Already resolved or already known to exist in storage
            if ($principals.ContainsKey($principalId) -or $ignoredPrincipals.ContainsKey($principalId)) {
                Write-Warning "Principal $principalId already resolved or ignored, skipping"
                continue
            }
            if (-not $ForceUpdateAllUsers) {
                # Check the storage table once for this principal
                $existing = Get-AzTableRow -Table $pTable -PartitionKey "Users" -RowKey $principalId -ErrorAction SilentlyContinue
                if ($existing) {
                    $ignoredPrincipals[$principalId] = $true
                    Write-warning "Principal $principalId already exists in storage, skipping"
                    continue
                }
            }
            # Resolve from Graph
            $userDetails = Get-UserDetails -UserId $principalId
            $principalDict = @{}
            foreach ($prop in $userDetails.PSObject.Properties) {
                $principalDict[$prop.Name] = $prop.Value
            }
            $principals[$principalId] = $principalDict
        }
    }
    return $principals
}

function Get-SPAppRolesAssignments {
    param()
    # appRoleAssignments
    # App role assignment for another app or service, granted to this service principal
    # App registration -> API Permissions -> Configured Permissions (Type Application)
    $path = "/servicePrincipals?`$select=id&`$expand=appRoleAssignments"
    $appRoleAssignments = Invoke-PaginatedGraphList -Path $path
    return $appRoleAssignments
}

function Get-UserDetails {
    param($UserId)
    $path = "/users/$($UserId)?`$select=displayName,userPrincipalName,mail,state"
    $details = Invoke-Graph -Path $path
    return $details
}

function Get-UsersWithEmailOrUPN {
    param(
        [string[]]$EmailOrUPNList,
        [int]$BatchSize = 15
    )

    # Find users by email or UPN with batched filter queries to keep request size bounded
    $props = @(
        "displayName",
        "userPrincipalName",
        "mail",
        "state"
    ) -join ','

    if (-not $EmailOrUPNList -or $EmailOrUPNList.Count -eq 0) {
        return @()
    }

    if ($BatchSize -lt 1) {
        $BatchSize = 1
    }

    $normalizedIdentifiers = @{}
    foreach ($identifier in $EmailOrUPNList) {
        if ($null -eq $identifier) {
            continue
        }
        $trimmedIdentifier = $identifier.Trim()
        if ($trimmedIdentifier -eq '') {
            continue
        }
        $normalizedIdentifier = $trimmedIdentifier.ToLowerInvariant()
        if (-not $normalizedIdentifiers.ContainsKey($normalizedIdentifier)) {
            $normalizedIdentifiers[$normalizedIdentifier] = $trimmedIdentifier
        }
    }

    $identifiers = @($normalizedIdentifiers.Values)
    if ($identifiers.Count -eq 0) {
        return @()
    }

    $resolvedUsers = @()
    for ($index = 0; $index -lt $identifiers.Count; $index += $BatchSize) {
        $endIndex = [Math]::Min($index + $BatchSize - 1, $identifiers.Count - 1)
        $batch = @($identifiers[$index..$endIndex])

        $filters = @()
        foreach ($identifier in $batch) {
            $escapedIdentifier = $identifier.Replace("'", "''")
            $filters += "mail eq '$escapedIdentifier'"
            $filters += "userPrincipalName eq '$escapedIdentifier'"
        }

        $filterClause = [String]::Join(' or ', $filters)
        $path = "/users?`$filter=$filterClause&`$select=$props"
        $response = Invoke-Graph -Path $path
        if ($response.value) {
            $resolvedUsers += $response.value
        }
    }

    return $resolvedUsers
}

# Graph functions

$script:CachedToken = $null
$script:TokenExpiry = [datetime]::MinValue

function Get-GraphToken {
    param()

    if ($script:CachedToken -and [datetime]::UtcNow -lt $script:TokenExpiry.AddMinutes(-5)) {
        return $script:CachedToken
    }
    # Connect using AppReg credentials from Azure Automation
    Write-Verbose "Getting new access token"

    $creds = Get-AutomationPSCredential -Name 'AppReg'
    $params = @{
        TenantId         = $TenantId
        Credential       = $creds
        ServicePrincipal = $true
        Environment      = 'AzureCloud'
    }
    $context = (Connect-AzAccount @params).Context
    $token = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -DefaultProfile $context -AsSecureString
    $plainToken = ConvertFrom-SecureString -SecureString $token.Token -AsPlainText
    $script:CachedToken = $plainToken
    $script:TokenExpiry = $token.ExpiresOn.DateTime
    return $script:CachedToken
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
            Write-Verbose "Graph returned a list of $($response.value.Count) items"
            $fullReponse += $response.value
        }
        $nextLink = $response.'@odata.nextLink'
    } while ($nextLink)
    return $fullReponse
}

function Invoke-GraphInternal {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        $Body = $null,

        [Parameter(Mandatory = $false)]
        [string]$Method = 'Get',

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = 'v1.0'
    )

    if ($Path.StartsWith('https://')) {
        $url = $Path
    }
    else {
        if (-not $Path.StartsWith('/')) {
            $Path = '/' + $Path
        }
        $url = "https://graph.microsoft.com/$($ApiVersion)$($Path)"
    }

    $headers = @{
        "Authorization"    = "Bearer $(Get-GraphToken)"
        'Content-Type'     = 'application/json;odata.metadata=none'
        'Accept'           = 'application/json;odata.metadata=none'
        'ConsistencyLevel' = 'eventual'
    }
    $ProgressPreference = 'silentlyContinue'
    $VerbosePreference = 'silentlyContinue'
    $params = @{
        Uri     = $url
        Body    = $Body
        Headers = $headers
        Method  = $Method
    }
    $response = Invoke-RestMethod @params
    return $response
}

function Invoke-Graph {
    <#
    .SYNOPSIS
    Call the Microsoft Graph API with the specified path, body, and method.
    Handles authentication and throttling retries.
    Returns a PSObject from ConvertFrom-Json
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        $Body = $null,

        [Parameter(Mandatory = $false)]
        [string]$Method = 'Get'
    )

    $attempts = 0
    $maxAttempts = 3

    do {
        try {
            return Invoke-GraphInternal -Path $Path -Body $Body -Method $Method
        }
        catch {
            if ($_.Exception.Response.StatusCode -in 429, 503) {
                # https://docs.microsoft.com/en-us/graph/throttling
                # Request type	Per app across all tenants
                # Any	        2000 requests per second
                $seconds = [int]$_.Exception.Response.Headers["Retry-After"]
                if (-not $seconds) {
                    $seconds = 60
                }
                $seconds = $seconds + [Math]::Pow(2, $attempts)  # Exponential backoff
                Write-Warning "GraphHelper: Throttling error. Retrying in $($seconds)s"
                Start-Sleep ($seconds)
            }
            else {
                $msg = $_.Exception.Message
                try {
                    $json = $_.ToString() | ConvertFrom-Json
                    $code = $json.error.code
                    $msg = $json.error.message
                    $rid = $json.error.innerError."request-id"
                }
                catch {}
                throw "Error invoking Graph ($($_.Exception.Response.StatusCode)-$code) ($rid): $msg"
            }
        }
    } while ($attempts++ -lt $maxAttempts)
    throw "Failed to invoke Graph after $maxAttempts attempts."
}

Start-Work
Disconnect-AzAccount | Out-Null
