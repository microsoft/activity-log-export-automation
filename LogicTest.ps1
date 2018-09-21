#settings
$AzureSub="MSInternal"
$RGName = "CorpLogging"
$Location = "West US 2"
$ResourceTags = @{"Owner" = "Corp"}
$splunkConnectorName = "AzureActivityLogs"
#Update the following two variables to use an existing Key Vault, must be in same region and subscription.
#Leave set to $null to create a new Key Vault 
$KVRGName = "Hit1"
$KVName = "Hit2"

#variables
$namespace = "$($RGName)Hub"
$AppDisplayName = "$($RGName)App"
$secretName = "EHLoggingCredentials"


if((!$KVRGName) -and (!$KVName)){
    $vaultName = "$($RGName)Vault"
    $KVRGName = $RGName
}elseif(($KVRGName -and ($KVName))) {
    $vaultName = $KVName
}else{
    Write-Host -ForegroundColor Red "Please check the values for KVRGName and KVName, must be both populated or left empty"
}

Write-Host "Vault RG = "$KVRGName
Write-Host "Vault Name "$vaultName