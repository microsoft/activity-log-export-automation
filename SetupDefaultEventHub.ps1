#settings
$AzureSub="MSInternal"
$RGName = "CorpLogging"
$EventHubLocation = "West US 2"
$tags = @{"Owner" = "Corp"}

function Authenticate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $AzureSubscriptionName
    )
    Write-Host "Authenticating..."

    $ctx=Get-AzureRmContext
    if ($ctx.Account -eq $null) {
        Login-AzureRmAccount
    }
    if ($ctx.SubscriptionName -ne $AzureSubscriptionName) {
        Set-AzureRmContext -SubscriptionName $AzureSubscriptionName
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
    return @{
        "subid" = $ctx.Subscription.Id;
        "tenantid" = $ctx.Tenant.Id
    }
} 

function CreateEventHub {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $RGName, 
        [Parameter(Mandatory=$true)]
        $Location,
        [Parameter(Mandatory=$true)]
        $ResourceTags
    )

    Write-Host "Setting up Event Hub..."
    $namespace = "$($RGName)Hub"

    #create Resource Group for Event Hub
    $rg = Get-AzureRmResourceGroup -Name $RGName -ErrorAction SilentlyContinue

    if ($rg -eq $null) {
        $rg = New-AzureRmResourceGroup `
            -Name $RGName `
            -Location $Location `
            -Tag $ResourceTags `
            -ErrorAction Stop
    }

    $ehn = Get-AzureRmEventHubNamespace -ResourceGroupName $RGName -Name $namespace -ErrorAction SilentlyContinue

    if ($ehn -eq $null) {
        #create event hub namespace
        $ehn = New-AzureRmEventHubNamespace `
            -ResourceGroupName $RGName `
            -Name $namespace `
            -Location $Location `
            -SkuName Standard `
            -SkuCapacity 1 `
            -EnableAutoInflate $true `
            -Tag $ResourceTags `
            -ErrorAction Stop
    }

    #get new namespace authorization rule
    $rule = Get-AzureRmEventHubAuthorizationRule -ResourceGroupName $RGName -Namespace $namespace -ErrorAction Stop
    return $rule
}

function SecurityConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $AppDisplayName, 
        [Parameter(Mandatory=$true)]
        $SubscriptionId,
        [Parameter(Mandatory=$true)]
        $AzureSubscriptionName
    )

    Write-Host "Setting up Service Principal..."

    $uri = "http://$($AppDisplayName).$($AzureSubscriptionName)"

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
    $cred = New-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId -StartDate $now -EndDate $addYear

    #loop to ensure SP creation is complete
    $newsp=$null
    while ($newsp -eq $null) {
        $newsp = Get-AzureADServicePrincipal -ObjectId $sp.ObjectId
    }
    Write-Host "Waiting a few seconds to let our new service principal propagate..."
    #give AAD 10 seconds to propagate the new SP over to the directory for RBAC assignment
    Start-Sleep 10

    Write-Host "Adding RBAC role assignment..."
    #assign role
    New-AzureRmRoleAssignment `
        -ObjectId $sp.ObjectId `
        -RoleDefinitionName "Reader" `
        -Scope "/subscriptions/$($SubscriptionId)" `
        -ErrorAction Stop

    return @{
        "Application" = $app;
        "ServicePrincipal" = $sp;
        "SPSecret" = $cred.Value;
    }
}

function AddSecretsToVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $RGName, 
        [Parameter(Mandatory=$true)]
        $Location,
        [Parameter(Mandatory=$true)]
        $EventHubNamespaceName,
        [Parameter(Mandatory=$true)]
        $AppId
    )

    Write-Host "Adding secrets to Key vault..."
    $secretName = "EHLoggingCredentials"
    $vaultName = "$($RGName)Vault"

    $kv = Get-AzureRmKeyVault -VaultName $vaultName -ResourceGroupName $RGName
    if ($kv -eq $null) {
        #Create Azure Key vault
        #get and store key
        $ehkey = Get-AzureRmEventHubKey `
            -ResourceGroupName $RGName `
            -Namespace $EventHubNamespaceName `
            -Name "RootManageSharedAccessKey" `
            -ErrorAction Stop

        $kv = New-AzureRmKeyVault `
            -VaultName $vaultName `
            -ResourceGroupName $RGName `
            -Location $Location `
            -ErrorAction Stop
    }

    #grant "Get Secrets" access to Key Vault
    Set-AzureRmKeyVaultAccessPolicy `
        -VaultName $vaultName `
        -ServicePrincipalName $AppId `
        -PermissionsToSecrets get `
        -ResourceGroupName $RGName `
        -ErrorAction Stop


    $ss = ConvertTo-SecureString -String $ehkey.PrimaryKey -AsPlainText -Force

    $secret = Set-AzureKeyVaultSecret `
        -VaultName $kv.VaultName `
        -Name $secretName `
        -SecretValue $ss `
        -ContentType "RootManageSharedAccessKey" `
        -ErrorAction Stop

    return @{
        "KeyVault" = $kv;
        "SecretName" = $secretName;
        "EHSecretVersion" = $secret.Version
    }
}

function Main {
    $ctx = Authenticate `
        -AzureSubscriptionName $AzureSub `
        -ErrorAction Stop

        $subid = $ctx.subid
        $tenantid = $ctx.tenantid

    $eventHub = CreateEventHub `
        -RGName $RgName `
        -Location $EventHubLocation `
        -ResourceTags $tags `
        -ErrorAction Stop

    $security = SecurityConfig `
        -AppDisplayName "$($RGName)App" `
        -SubscriptionId $subid `
        -AzureSubscriptionName $AzureSub `
        -ErrorAction Stop

    $vault = AddSecretsToVault `
        -RGName $RGName `
        -Location $EventHubLocation `
        -EventHubNamespaceName "$($RGName)Hub" `
        -AppId $security.ServicePrincipal.AppId `
        -ErrorAction Stop

    $output = @{
        "Name" = "AzureActivityLogs";
        "SPNTenantID" = $tenantid;
        "SPNApplicationID" = $Security.ServicePrincipal.AppId;
        "SPNApplicationKey" = $Security.SPSecret;
        "eventHubNamespace" = $EventHub.Name;
        "vaultName" = $vault.KeyVault.VaultName;
        "secretName" = "EHLoggingCredentials";
        "secretVersion" = $vault.EHSecretVersion;
        "ruleid" = $eventHub.id;
    }
    return $output
}

$res = Main

Write-Host "Auth Rule ID: "
Write-Host $res.ruleid
