#settings
$AzureSub="MSInternal"
$RGName = "CorpLogging"
$Location = "West US 2"
$ResourceTags = @{"Owner" = "Corp"}
$splunkConnectorName = "AzureActivityLogs"

#variables
$namespace = "$($RGName)Hub"
$AppDisplayName = "$($RGName)App"
$vaultName = "$($RGName)Vault"
$secretName = "EHLoggingCredentials"

Write-Host "Authenticating..."
    $ctx=Get-AzureRmContext
    if ($ctx.Account -eq $null) {
        Login-AzureRmAccount
    }
    if ($ctx.SubscriptionName -ne $AzureSub) {
        Set-AzureRmContext -SubscriptionName $AzureSub
    }
    $ctx=Get-AzureRmContext  -ErrorAction Stop

    #force context to grab a token for graph
    Get-AzureRmADUser -UserPrincipalName $ctx.Account.Id -ErrorAction Stop

    $cache = $ctx.TokenCache
    $cacheItems = $cache.ReadItems()
    $token = ($cacheItems | where { $_.Resource -eq "https://graph.windows.net/" })
    if ($token.ExpiresOn -le [System.DateTime]::UtcNow) {
        $ac = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new("$($ctx.Environment.ActiveDirectoryAuthority)$($ctx.Tenant.Id)",$token)
        #appId is well-known id of Powershell; reusing token cache from AzureRM login
        $token = $ac.AcquireTokenByRefreshToken($token.RefreshToken, "1950a258-227b-4e31-a9cf-717495945fc2", "https://graph.windows.net")
    }
    $aad = Connect-AzureAD -AadAccessToken $token.AccessToken -AccountId $ctx.Account.Id -TenantId $ctx.Tenant.Id -ErrorAction Stop
    $SubscriptionId = $ctx.Subscription.Id
    $tenantid = $ctx.Tenant.Id

Write-Host "Setting up Resource Group..."
    #create Resource Group for Event Hub
    $rg = Get-AzureRmResourceGroup -Name $RGName -ErrorAction SilentlyContinue

    if ($rg -eq $null) {
        $rg = New-AzureRmResourceGroup `
            -Name $RGName `
            -Location $Location `
            -Tag $ResourceTags `
            -ErrorAction Stop
    }

Write-Host "Setting up Event Hub..."
    $ehn = Get-AzureRmEventHubNamespace -ResourceGroupName $RGName -Name $Namespace -ErrorAction SilentlyContinue

    if ($ehn -eq $null) {
        #test if event hub namespace exists
        $ehntest = Test-AzureRmEventHubName -Namespace $namespace
        if ($ehntest.NameAvailable -eq $true) { 
            #create event hub namespace
            $ehn = New-AzureRmEventHubNamespace `
                -ResourceGroupName $RGName `
                -Name $Namespace `
                -Location $Location `
                -SkuName Standard `
                -SkuCapacity 1 `
                -EnableAutoInflate $true `
                -Tag $ResourceTags `
                -ErrorVariable NSError
        } elseif ($ehntest.NameAvailable -eq $false) {
            Write-Host -ForegroundColor Red $ehntest.Message
			Return
        }
	}

    $ehkey = Get-AzureRmEventHubKey `
        -ResourceGroupName $RGName `
        -Namespace $Namespace `
        -Name "RootManageSharedAccessKey" `
        -ErrorAction Stop

    #get new namespace authorization rule
    $rule = Get-AzureRmEventHubAuthorizationRule -ResourceGroupName $RGName -Namespace $Namespace -ErrorAction Stop

Write-Host "Setting up Key vault..."
    $kv = Get-AzureRmKeyVault -VaultName $vaultName -ResourceGroupName $RGName
    if ($kv -eq $null) {
        #Create Azure Key vault
        $kv = New-AzureRmKeyVault `
            -VaultName $vaultName `
            -ResourceGroupName $RGName `
            -Location $Location `
            -ErrorAction Stop
    }

Write-Host "Setting up Service Principal..."
    $uri = "http://$($AppDisplayName).$((Get-AzureRmSubscription -SubscriptionName $AzureSub).TenantId[0])"
    
    #setup access rules for new app
    $appResources = [System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.RequiredResourceAccess]]::New()
 
    # get AAD SPN/perms
    $aadapp = Get-AzureADServicePrincipal -Filter "DisplayName eq 'Windows Azure Active Directory'"  -ErrorAction Stop
    if ($aadapp -eq $null) {
        throw [System.Exception] "Azure AD Service Principal not found, please check the name"
        exit 1
    }
    $aadSignInPerm = $aadapp | select -expand Oauth2Permissions | ? {$_.value -eq "User.Read"}
 
    try {
        # create perm object
        $readAndSignInPerm = [Microsoft.Open.AzureAD.Model.ResourceAccess]::New()
        $readAndSignInPerm.Id = $aadSignInPerm.Id
        $readAndSignInPerm.Type = "Scope"
 
        # Read/Sign-In Perms to AAD
        $appAccess = [Microsoft.Open.AzureAD.Model.RequiredResourceAccess]::New()
        $appAccess.ResourceAppId = $aadapp.AppId
        $appAccess.ResourceAccess = $readAndSignInPerm
 
        $appResources.Add($appAccess)
    }
    catch {
        throw [System.Exception] "Error creating permissions objects. Please ensure you have installed the Microsoft ADAL library from NuGet or https://github.com/AzureAD/microsoft-authentication-library-for-dotnet"
        exit 1
    }

    #hack to work around odata filter using variable
    $execstr = "AzureAD\Get-AzureADApplication -Filter `"identifierUris/any(uri:uri eq '$uri')`""
    $app = Invoke-Expression $execstr

    if ($app -ne $null) {
        #start over
        AzureAD\Remove-AzureADApplication -ObjectId $app.ObjectId -ErrorAction Stop
        Start-Sleep 3
    }

    #Create AzureAD Application
    $app = AzureAD\New-AzureADApplication `
        -DisplayName $AppDisplayName `
        -IdentifierUris $uri `
        -RequiredResourceAccess $appResources `
        -ErrorAction Stop

    #create Service Principal
    $sp = AzureAD\New-AzureADServicePrincipal `
        -AppId $app.AppId `
        -DisplayName $AppDisplayName `
        -Tags {WindowsAzureActiveDirectoryIntegratedApp} `
        -ErrorAction Stop

    # Generate a client secret
    $now = Get-Date
    $addYear = $now.AddYears(1)
    $cred = New-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId -StartDate $now -EndDate $addYear -CustomKeyIdentifier "Key1"

Write-Host "Pausing 60 seconds to let our new service principal propagate..."
    #give AAD 60 seconds to propagate the new SP over to the directory for RBAC assignment
    Start-Sleep 60

Write-Host "Adding RBAC role assignment..."
    #assign role
    New-AzureRmRoleAssignment `
        -ObjectId $sp.ObjectId `
        -RoleDefinitionName "Reader" `
        -Scope "/subscriptions/$($SubscriptionId)" `
        -ErrorAction Stop

Write-Host "Adding access to key vault..."
    #grant "Get Secrets" access to Key Vault
    Set-AzureRmKeyVaultAccessPolicy `
        -VaultName $vaultName `
        -ObjectId $sp.ObjectId `
        -PermissionsToSecrets get `
        -ResourceGroupName $RGName `
        -ErrorAction Stop

Write-Host "Adding secrets to Key vault..."
    #get and store key
    $ss = ConvertTo-SecureString -String $ehkey.PrimaryKey -AsPlainText -Force

    $secret = Set-AzureKeyVaultSecret `
        -VaultName $kv.VaultName `
        -Name $secretName `
        -SecretValue $ss `
        -ContentType "RootManageSharedAccessKey" `
        -ErrorAction Stop

$output = @{
     "Name" = $splunkConnectorName;
     "SPNTenantID" = $ctx.Tenant.Id;
     "SPNApplicationID" = $sp.AppId;
     "SPNApplicationKey" = $cred.Value;
     "eventHubNamespace" = $ehn.Name;
     "vaultName" = $kv.VaultName;
     "secretName" = $secret.Name;
     "secretVersion" = $secret.Version;
     "ruleid" = $rule.id;
 }

Write-Host ""
Write-Host "---"
Write-Host "Configuration complete"
Write-Host ""

Write-Host ""
Write-Host "****************************"
Write-Host "*** RuleID for Profiles ***"
Write-Host "****************************"
Write-Host ""
Write-Host $output.ruleid

Write-Host ""
Write-Host "****************************"
Write-Host "*** SPLUNK CONFIGURATION ***"
Write-Host "****************************"
Write-Host ""
Write-Host "Data Input Settings for configuration as explained at https://github.com/Microsoft/AzureMonitorAddonForSplunk/wiki/Configuration-of-Splunk"
Write-Host ""
Write-Host "  AZURE MONITOR ACTIVITY LOG"
Write-Host "  ----------------------------"
Write-Host "  Name:              " $output.Name
Write-Host "  SPNTenantID:       " $output.SPNTenantID
Write-Host "  SPNApplicationId:  " $output.SPNApplicationID
Write-Host "  SPNApplicationKey: " $output.SPNApplicationKey
Write-Host "  eventHubNamespace: " $output.eventHubNamespace
Write-Host "  vaultName:         " $output.vaultName
Write-Host "  secretName:        " $output.secretName
Write-Host "  secretVersion:     " $output.secretVersion

