#Requires -Module Az.Resources,Az.Storage,Az.Accounts,AzTable
param
(
    # UA or SA, User-Assigned or System Assigned
    [string]$ManagedIdentityMethod = "SA"
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

$ownerRE = '(owner|propietario)[=:]([\w@.-_]+)'



# Main orchestration function
function Start-Work {
    param()
    # Store data in Azure Storage Account
    $azureContext = Connect-ManagedIdentity

    # App Registrations
    $table = Get-StorageTable -AzureContext $azureContext -TableName "Applications"
    Clear-Table $table
    # Get data from Graph
    $apps = Get-AADApps
    Set-ApplicationsInStorage -Applications $apps -StorageTable $table

    # Service Principals
    $table = Get-StorageTable -AzureContext $azureContext -TableName "ServicePrincipals"
    Clear-Table $table
    $servicePrincipals = Get-AADServicePrincipals
    Set-ServicePrincipalsInStorage -ServicePrincipals $servicePrincipals -StorageTable $table
}

# Helper functions

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

# https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal
function Set-ServicePrincipalsInStorage {
    param(
        $ServicePrincipals,
        $StorageTable
    )
    $table = $StorageTable.CloudTable

    Write-Verbose "Saving the service principals in storage"
    foreach ($servicePrincipal in $ServicePrincipals) {
        Write-Verbose "ServiceApplication $($servicePrincipal.appId)"
        $pk = $servicePrincipal.AppId

        $notifyUsers = ''
        if ($servicePrincipal.notes) {
            $notifyUsersList = @()
            Write-Verbose $servicePrincipal.notes
            $servicePrincipal.notes.Split("`n") | ForEach-Object {
                if ($_ -match $ownerRE) {
                    Write-Verbose "Found match: $($Matches[2])"
                    $notifyUsersList += $Matches[2]
                }
            }
            if ($notifyUsersList.Count -gt 0) {
                $notifyUsers = [String]::Join(',', $notifyUsersList)
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
        Add-AzTableRow @params | Out-Null

        Write-Verbose "ServiceApplication $($servicePrincipal.appId) scopes"
        foreach ($scope in $servicePrincipal.oauth2PermissionScopes) {
            $rk = "Scope-$($scope.id)"
            Write-Verbose $rk
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
            Add-AzTableRow @params | Out-Null
        }

        Write-Verbose "ServiceApplication $($servicePrincipal.appId) roles"
        foreach ($role in $servicePrincipal.appRoles) {
            $rk = "Role-$($role.id)"
            Write-Verbose $rk
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
            Add-AzTableRow @params | Out-Null
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
            Write-Verbose ($servicePrincipal|ConvertTo-Json)
            Write-Verbose ($properties|ConvertTo-Json)
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-AzTableRow @params | Out-Null
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
            Add-AzTableRow @params | Out-Null
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
                PrincipalId          = $assignment.principalId
            }
            Write-Verbose ($servicePrincipal|ConvertTo-Json)
            Write-Verbose ($properties|ConvertTo-Json)
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-AzTableRow @params | Out-Null
        }
    }
}

# https://learn.microsoft.com/en-us/graph/api/resources/application
function Set-ApplicationsInStorage {
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
        Add-AzTableRow @params | Out-Null

        # keyCredentials
        Write-Verbose "Application $($application.AppId) keyCredentials"
        foreach ($key in $application.keyCredentials) {
            $rk = "Certificate-$($key.keyId)"
            $properties = @{
                ObjectId         = $application.id
                ApplicationId    = $application.appId
                KeyId            = $key.keyId
                Name             = IfNull $key.displayName
                EndDateTime      = IfNull $key.endDateTime (Get-Date "2099-12-31")
                ServicePrincipal = $false
            }
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-AzTableRow @params | Out-Null
        }

        # passwordCredentials
        Write-Verbose "Application $($application.AppId) passwordCredentials"
        foreach ($password in $application.passwordCredentials) {
            $rk = "Secret-$($password.keyId)"
            $properties = @{
                ObjectId      = $application.id
                ApplicationId = $application.appId
                KeyId         = $password.keyId
                Name          = IfNull $password.displayName"Unnamed secret"
                EndDateTime   = $password.endDateTime
            }
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-AzTableRow @params | Out-Null
        }

        Write-Verbose "Application $($servicePrincipal.appId) roles"
        foreach ($role in $application.appRoles) {
            $rk = "Role-$($role.id)"
            Write-Verbose $rk
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
            Add-AzTableRow @params | Out-Null
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
            }
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-AzTableRow @params | Out-Null
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
                Add-AzTableRow @params | Out-Null
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
                Write-Verbose "Logged in with user assigned identity"
                return $azureContext
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
}

function Get-AADApps {
    param()
    $path = '/applications?$select=api,appId,appRoles,createdDateTime,displayName,id,identifierUris,isDeviceOnlyAuthSupported,isFallbackPublicClient,keyCredentials,passwordCredentials,publicClient,requiredResourceAccess,samlMetadataUrl,signInAudience,spa,tags,web&$expand=owners($levels=max;$select=id,displayName,userPrincipalName,mail)'
    $applications = Invoke-PaginatedGraphList -Path $path
    Write-Verbose "Got $($applications.Count) apps"
    return $applications
}

function Get-AADServicePrincipals {
    param()
    $path = '/servicePrincipals?$select=accountEnabled,appId,appRoleAssignmentRequired,appRoles,displayName,id,keyCredentials,notes,oauth2PermissionScopes,passwordCredentials,preferredSingleSignOnMode,replyUrls,resourceSpecificApplicationPermissions,samlSingleSignOnSettings,servicePrincipalNames,servicePrincipalType,signInAudience&$expand=appRoleAssignedTo'
    $servicePrincipals = Invoke-PaginatedGraphList -Path $path
    Write-Verbose "Got $($servicePrincipals.Count) service principals"
    return $servicePrincipals
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
        Write-Verbose "Returned token: $($token.Token)"
        $env:GraphAccessToken = $token.Token
    }
    Write-Verbose $env:GraphAccessToken
    return $env:GraphAccessToken
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
        Write-Verbose "next link: $nextLink"
    } while ($nextLink)
    return $fullReponse
}

function Invoke-GraphInternal {
    param (
        $Path,
        $Body,
        $Method
    )
    $url = "https://graph.microsoft.com/v1.0$Path"
    if ($Path.StartsWith('https://')) {
        $url = $Path
    }
    $headers = @{
        "Authorization"    = "Bearer $(Get-GraphToken)"
        'Content-Type'     = 'application/json;odata.metadata=none'
        'Accept'           = 'application/json;odata.metadata=none'
        'ConsistencyLevel' = 'eventual'
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
    Write-Verbose "New request: $Path"
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
            $response = Invoke-GraphInternal -Path $Path -Body $Body -Method $Method
        }
        Write-Error "Error invoking Graph ($_): $($response.StatusCode)"
        exit
    }
    return $response
}

Start-Work
Disconnect-AzAccount | Out-Null
