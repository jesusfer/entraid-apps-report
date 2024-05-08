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
$VerbosePreference = $PreviousVerbosePreference

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
    Write-Verbose "EXO connected"

    $ErrorActionPreference = 'Stop'

    # Store data in Azure Storage Account
    $azureContext = Connect-ManagedIdentity
    # $azureContext = $azureContext | Where-Object { $_.Account -eq $UserAssignedManagedIdentityAppId -and $_.Subscription -eq $Subscription } | Select-Object -First 1

    $table = Get-StorageTable -AzureContext $azureContext -TableName "ApplicationPolicies"
    Clear-Table $table

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
        $pk = $policy.AppId
        $rk = "Policy"
        $properties = @{
            ApplicationId = $policy.AppId
            Name          = $policy.ScopeName
            Identity      = $policy.ScopeIdentity
            Description   = $policy.Description
            GroupId       = $groupId
            AccessRight   = $policy.AccessRight
            ShardType     = $policy.ShardType
            IsValid       = $policy.IsValid
        }
        Add-AzTableRow -Table $table.CloudTable -PartitionKey $pk -RowKey $rk -Property $properties | Out-Null
    }
    $policiesCount = 0
    if ($null -ne $policies) {
        if ($null -ne $policies.Count) {
            $policiesCount = $policies.Count
        } else {
            $policiesCount = 1
        }
    }
    Write-Output "Stored $($policiesCount) policies"
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

Start-Work
