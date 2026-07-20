#Requires -Module ExchangeOnlineManagement
param
(
    # UA or SA, User-Assigned or System Assigned
    [string]$ManagedIdentityMethod = "SA"
)

$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
Import-Module Az.Resources
Import-Module Az.Storage
Import-Module Az.Accounts
Import-Module AzTable
Import-Module ExchangeOnlineManagement
Update-AzConfig -DisplaySecretsWarning $false | Out-Null
$VerbosePreference = $PreviousVerbosePreference

$ErrorActionPreference = 'Stop'

$Subscription = Get-AutomationVariable -Name 'Subscription'
$ResourceGroup = Get-AutomationVariable -Name 'ResourceGroup'
$StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
# Must end with .onmicrosoft.com
$Organization = Get-AutomationVariable -Name 'Organization'

# Main orchestration function
function Start-Work () {
    # https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2
    $AppReg = Get-AutomationPSCredential -Name 'AppReg'
    $cert = Get-AutomationCertificate -Name 'EXOCertificate'
    $params = @{
        ShowBanner            = $false 
        AppId                 = $AppReg.Username 
        CertificateThumbprint = $cert.Thumbprint 
        Organization          = $Organization
    }
    Connect-ExchangeOnline @params
    Write-Output "EXO connected"

    # Store data in Azure Storage Account
    $azureContext = Connect-ManagedIdentity
    # $azureContext = $azureContext | Where-Object { $_.Account -eq $UserAssignedManagedIdentityAppId -and $_.Subscription -eq $Subscription } | Select-Object -First 1

    $table = Get-StorageTable -AzureContext $azureContext -TableName "ApplicationPolicies"
    Clear-Table $table

    # Store EXO application access policies
    Save-ApplicationAccessPolicy -Table $table

    # Store EXO management role assignments granted to service principals
    Save-RoleAssignments -Table $table
}

<#
.SYNOPSIS
Stores the EXO application access policies.

.DESCRIPTION
Enumerates the application access policies configured in Exchange Online and
stores each one in the shared Azure Storage table, keyed by the AppId and the
scope name.
#>
function Save-ApplicationAccessPolicy {
    param (
        $Table
    )
    <#
        Get-ManagementRole -Cmdlet Get-ApplicationAccessPolicy

        Name                       RoleType
        ----                       --------
        Organization Configuration OrganizationConfiguration
        View-Only Configuration    ViewOnlyConfiguration

        The only one needed for read-only: ViewOnlyConfiguration
    #>
    $policies = Get-ApplicationAccessPolicy
    foreach ($policy in $policies) {
        $groupId = $policy.ScopeIdentityRaw.split(";")[1]
        $pk = "AppAccessPolicy"
        # $rk = $policy.Identity.Replace("\", "_").Replace(";", "_").Replace(":", "_")
        $rk = "$($policy.AppId)_$($policy.ScopeName)".Replace("\", "_").Replace("/", "_").Replace(";", "_").Replace(":", "_")
        $properties = @{
            ApplicationId = $policy.AppId
            Name          = $policy.ScopeName
            Identity      = $policy.Identity
            ScopeIdentity = $policy.ScopeIdentity
            Description   = $policy.Description
            GroupId       = $groupId
            AccessRight   = $policy.AccessRight
            ShardType     = $policy.ShardType
            IsValid       = $policy.IsValid
        }
        try {
            Add-AzTableRow -Table $Table.CloudTable -PartitionKey $pk -RowKey $rk -Property $properties | Out-Null
        }
        catch {
            $messages = @()
            $ex = $_.Exception
            while ($null -ne $ex) {
                $messages += $ex.Message
                $ex = $ex.InnerException
            }
            Write-Error "Failed to add row with PartitionKey '$pk' and RowKey '$rk': $([String]::Join(' --> ', $messages))" -ErrorAction Continue
            Write-Error $properties
        }
    }
    $policiesCount = 0
    if ($null -ne $policies) {
        if ($null -ne $policies.Count) {
            $policiesCount = $policies.Count
        }
        else {
            $policiesCount = 1
        }
    }
    Write-Output "Stored $($policiesCount) application access policies"
}

<#
.SYNOPSIS
Stores the EXO management role assignments granted to service principals.

.DESCRIPTION
Enumerates the service principals registered in Exchange Online and, for each
one, the management role assignments granted to it. Assignments can be granted
directly to the service principal or indirectly through a role group; both are
tracked and the RoleAssigneeType property distinguishes between them.

Each role is categorized as either an app-only role (the "Application
<permission>" roles used by the RBAC for Applications model) or "Other".
#>
function Save-RoleAssignments {
    param (
        $Table
    )
    # Get-ServicePrincipal lists the service principals registered in EXO,
    # which are the only ones that can hold management role assignments.
    $servicePrincipals = Get-ServicePrincipal
    Write-Output "Got $($servicePrincipals.Count) EXO SP"
    $stored = 0
    foreach ($sp in $servicePrincipals) {
        # Get-ManagementRoleAssignment -RoleAssignee returns both the
        # assignments granted directly to the service principal and the ones
        # granted indirectly through a role group the service principal belongs
        # to. RoleAssigneeType tells direct (ServicePrincipal) from indirect
        # (RoleGroup) assignments.
        $assignments = Get-ManagementRoleAssignment -RoleAssignee $sp.Identity -ErrorAction SilentlyContinue
        foreach ($assignment in $assignments) {
            $isRoleGroup = $assignment.RoleAssigneeType -eq 'RoleGroup'
            $pk = "RoleAssignment"
            $rk = "$($sp.ObjectId)_$($assignment.Guid)"
            Write-output  $rk
            $properties = @{
                ServicePrincipalObjectId  = $sp.ObjectId
                Enabled                   = $assignment.Enabled
                AssignmentName            = $assignment.Name
                Role                      = "$($assignment.Role)"
                RoleCategory              = Get-RoleCategory -Role "$($assignment.Role)"
                AssignmentMethod          = "$($assignment.AssignmentMethod)"
                RoleGroup                 = if ($isRoleGroup) { $assignment.RoleAssigneeName } else { '' }
                RecipientReadScope        = "$($assignment.RecipientReadScope)"
                RecipientWriteScope       = "$($assignment.RecipientWriteScope)"
                ConfigReadScope           = "$($assignment.ConfigReadScope)"
                ConfigWriteScope          = "$($assignment.ConfigWriteScope)"
                CustomRecipientWriteScope = "$($assignment.CustomRecipientWriteScope)"
                CustomResourceScope       = "$($assignment.CustomResourceScope)"
                CustomConfigWriteScope    = "$($assignment.CustomConfigWriteScope)"
            }
            Add-AzTableRow -Table $Table.CloudTable -PartitionKey $pk -RowKey $rk -Property $properties | Out-Null
            $stored++
        }
    }
    Write-Output "Stored $stored SP role assignments"
}

<#
.SYNOPSIS
Categorizes an EXO management role as an app-only role or other.

.DESCRIPTION
The RBAC for Applications model in Exchange Online exposes app-only roles named
"Application <Graph permission>" (for example "Application Mail.Read"). Any role
matching that naming is categorized as "AppOnly"; every other role is "Other".

.PARAMETER Role
The name of the management role.
#>
function Get-RoleCategory {
    param (
        [string]$Role
    )
    if ($Role -like 'Application *') {
        return 'AppOnly'
    }
    return 'Other'
}

function Get-StorageTable {
    param (
        $AzureContext,
        $TableName
    )
    # Write-Verbose "Checking storage account"
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName -DefaultProfile $AzureContext
    if ($null -eq $storageAccount) {
        Write-Error "No storage account found"
        exit
    }
    # Write-Verbose "Checking if table exists"
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
            Write-Verbose "Using system-assigned managed identity"
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

Start-Work