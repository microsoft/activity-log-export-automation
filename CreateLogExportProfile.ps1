#settings
    $AzureSub="MSInternal"
    $LogRetentionDays = 3
    $ServiceBusRuleId = "/subscriptions/aed7eb10-0c55-4e2f-9789-56a40fe42f16/resourceGroups/CorpLogging/providers/Microsoft.EventHub/namespaces/CorpLoggingHub/AuthorizationRules/RootManageSharedAccessKey"

Write-Host "Authenticating..."
    $ctx=Get-AzureRmContext
    if ($ctx.Account -eq $null) {
        Login-AzureRmAccount
    }
    if ($ctx.SubscriptionName -ne $AzureSubscriptionName) {
        Set-AzureRmContext -SubscriptionName $AzureSubscriptionName
    }

    #get list of locations available to this subscription
    $locations = (Get-AzureRMLocation).DisplayName
    $locations = $locations += "Global"

    $profile = Get-AzureRmLogProfile -Name default -ErrorAction SilentlyContinue
    if ($profile -ne $null) {
        #clear any previous profile entry
        Remove-AzureRmLogProfile -Name default
    }

Write-Host "Configuring profile..."
    $profile = Add-AzureRmLogProfile `
        -Location $locations `
        -Name default `
        -ServiceBusRuleId $ServiceBusRuleId `
        -RetentionInDays $LogRetentionDays `
        -Category "Write","Delete","Action"
Write-Host "Profile configured."
$profile
