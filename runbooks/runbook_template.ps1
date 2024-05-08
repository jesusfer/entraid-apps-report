Param(
    [string]$resourceGroup,
    [string]$VMName,
    [string]$method,
    [string]$UAMI 
)

$automationAccount = "xAutomationAccount"

# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process | Out-Null

# Connect using a Managed Service Identity
try {
    Connect-AzAccount -Identity -ErrorAction stop -WarningAction SilentlyContinue | Out-Null
}
catch {
    Write-Output "There is no system-assigned user identity. Aborting."; 
    exit
}

# set and store context
$subID = (Get-AzContext).Subscription.Id
$AzureContext = Set-AzContext -SubscriptionId $subID

if ($method -eq "SA") {
    Write-Output "Using system-assigned managed identity"
}
elseif ($method -eq "UA") {
    Write-Output "Using user-assigned managed identity"

    # Connects using the Managed Service Identity of the named user-assigned managed identity
    $identity = Get-AzUserAssignedIdentity -ResourceGroupName $resourceGroup -Name $UAMI -DefaultProfile $AzureContext

    # validates assignment only, not perms
    if ((Get-AzAutomationAccount -ResourceGroupName $resourceGroup -Name $automationAccount -DefaultProfile $AzureContext).Identity.UserAssignedIdentities.Values.PrincipalId.Contains($identity.PrincipalId)) {
        Connect-AzAccount -Identity -AccountId $identity.ClientId | Out-Null

        # set and store context
        $AzureContext = Set-AzContext -SubscriptionId ($identity.id -split "/")[2]
    }
    else {
        Write-Output "Invalid or unassigned user-assigned managed identity"
        exit
    }
}
else {
    Write-Output "Invalid method. Choose UA or SA."
    exit
}