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
    $apps = Get-AppRegistrations
    Set-ApplicationsInStorage -Applications $apps -StorageTable $table

    $table = Get-StorageTable -AzureContext $azureContext -TableName "Applications"
    Clear-Table $table

    # Service Principals
    $servicePrincipals = Get-ServicePrincipals
    $servicePrincipalsGrants = Get-ServicePrincipalsGrants -ServicePrincipals $servicePrincipals
    $servicePrincipalsAppRoleAssignments = Get-ServicePrincipalsAppRolesAssignments

    $table = Get-StorageTable -AzureContext $azureContext -TableName "ServicePrincipals"
    Clear-Table $table
    $params = @{
        ServicePrincipals  = $servicePrincipals
        AppRoleAssignments = $servicePrincipalsAppRoleAssignments
        AllGrants          = $servicePrincipalsGrants
        StorageTable       = $table
    }
    Set-ServicePrincipalsInStorage @params
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
        $AppRoleAssignments,
        $AllGrants,
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
            Add-AzTableRow @params | Out-Null
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
            # Write-Verbose ($servicePrincipal | ConvertTo-Json -Depth 5)
            # Write-Verbose ($properties | ConvertTo-Json -Depth 5)
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
            Add-AzTableRow @params | Out-Null
        }

        # Este listado son los roles que este service principal consume de otros SPs y para los que tiene admin grant
        Write-Verbose "ServiceApplication $($servicePrincipal.appId) appRoleAssignments"
        $roleAssignments = $AppRoleAssignments | Where-Object { $_.id -eq $servicePrincipal.id } | Select-Object -ExpandProperty appRoleAssignments
        foreach ($assignment in $roleAssignments) {
            $rk = "AppRolesAssignment-$($assignment.id)"
            $properties = @{
                ApplicationId       = $servicePrincipal.appId
                AssignmentId        = $assignment.id
                AppRoleId           = $assignment.appRoleId
                CreatedDateTime     = IfNull $assignment.createdDateTime
                ResourceDisplayName = $assignment.resourceDisplayName
                # Object Id of the service principal that exposes the role
                ResourceId          = $assignment.resourceId
            }
            $params = @{
                Table        = $table
                PartitionKey = $pk
                RowKey       = $rk
                Property     = $properties
            }
            Add-AzTableRow @params | Out-Null
        }

        # Listado de permisos delegados que este service principal tiene concedidos por admin consent
        Write-Verbose "ServiceApplication $($servicePrincipal.appId) oauth2PermissionGrants"
        $grants = $AllGrants | Where-Object { $_.id -eq $servicePrincipal.id } | Select-Object -ExpandProperty oauth2PermissionGrants
        foreach ($grant in $grants) {
            $rk = "OAuth2PermissionGrants-$($grant.id)"
            $properties = @{
                ConsentType = $grant.consentType
                ConsentId   = $grant.id
                PrincipalId = IfNull $grant.principalId
                ResourceId  = $grant.resourceId
                Scopes      = $grant.scope
                GrantedBy   = If ($grant.consentType -eq 'AllPrincipals') { 'Admin' } else { 'User' }
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
    $path = "/applications?`$select=$props&`$expand=owners(`$select=id,displayName,userPrincipalName,mail)"
    $applications = Invoke-PaginatedGraphList -Path $path
    Write-Verbose "Got $($applications.Count) apps"
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
    # appRoleAssignedTo
    # App role assignments for this app or service, granted to users, groups, and other service principals.
    # -> Users and groups
    $path = "/servicePrincipals?`$select=$props&`$expand=appRoleAssignedTo"
    $servicePrincipals = Invoke-PaginatedGraphList -Path $path
    Write-Verbose "Got $($servicePrincipals.Count) service principals"
    return $servicePrincipals
}

function Get-ServicePrincipalsGrants {
    param($ServicePrincipals)

    $results = @()
    foreach ($servicePrincipal in $ServicePrincipals) {
        # oauth2PermissionGrants
        # Delegated permission grants authorizing this service principal to access an API on behalf of a signed-in user
        # -> Permissions
        # Admin -> consentType=AllPrincipals
        # User -> consentType=Principal
        $path = "/servicePrincipals/$($servicePrincipal.id)/oauth2PermissionGrants"
        $grants = Invoke-Graph -Path $path
        if ($grants.value) {
            $results += @{
                id                     = $servicePrincipal.id
                oauth2PermissionGrants = $grants.value
            }
        }
    }
    Write-Verbose "Got $($results.Count) service principals oauth2 permission grants"
    return $results
}

function Get-ServicePrincipalsAppRolesAssignments {
    param()
    # appRoleAssignments
    # App role assignment for another app or service, granted to this service principal
    # App registration -> API Permissions -> Configured Permissions (Type Application)
    $path = "/servicePrincipals?`$select=id&`$expand=appRoleAssignments"
    $appRoleAssignments = Invoke-PaginatedGraphList -Path $path
    Write-Verbose "Got $($appRoleAssignments.Count) service principals app role assignments"
    return $appRoleAssignments
}

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
    } else {
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
    Call the Microsoft Graph API with the specified path, body, and method. Handles authentication and throttling retries.
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
        } catch {
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
            } else {
                $msg = $_.Exception.Message
                try {
                    $json = $_.ToString() | ConvertFrom-Json
                    $code = $json.error.code
                    $msg = $json.error.message
                    $rid = $json.error.innerError."request-id"
                } catch {}
                throw "Error invoking Graph ($($_.Exception.Response.StatusCode)-$code) ($rid): $msg"
            }
        }
    } while ($attempts++ -lt $maxAttempts)
    throw "Failed to invoke Graph after $maxAttempts attempts."
}

Start-Work
Disconnect-AzAccount | Out-Null
