# Activity Log Export to Splunk - Automation
## Connect Splunk to Azure Activity Log automatically

### Details
These two scripts are designed to automate the deployment of Azure components for configuration of Splunk logging from the Azure Activity Log. It uses the "Azure Monitor Add-on for Splunk":

https://splunkbase.splunk.com/app/3534/

The wiki for that add-on describes the steps necessary to configure Splunk Logging from Azure:

https://github.com/Microsoft/AzureMonitorAddonForSplunk/wiki

There are 2 main scripts in the repo:
 * SetupDefaultEventHub.ps1
   * Deploys the following infrastructure:
     * Azure Event Hub
     * Azure Key Vault
     * Azure AD Application/Service Principal
       * Grants Sign-in and Read directory role
       * Grants RBAC "Reader" to the subscription
       * Grants permission to get secrets from Key Vault
   * Stores Event Hub Primary Key in Key Vault
   * Returns the following output:
       ```powershell
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
        ```
    * All of the above (except "ruleid") is used to connect Splunk to the connector:
        ![alt text][App1]

 * CreateLogExportProfile.ps1
   * Configures the Activity Log to export activity to Event Hub
   * Uses the "ruleid" value exported from the first script
   * Can be run on multiple subscriptions, as long as all subscriptions are in the same tenant
   * For each iteration, the following settings are required:
   ```powershell
    #settings
    $AzureSub="[Subscription name being connected to Splunk]"
    $LogRetentionDays = [int, days to retain data in Event Hub]
    $ServiceBusRuleId = "[ruleid string from SetupDefaultEventHub output]"
   ```
    * (LogRetentionDays gives you a "backup" in case your Splunk instance goes offline for a period of time)

## Notes
The Monitor Add-on provides the capability for Splunk to capture Metrics, Diagnostic Logs and the Activity Log. The approach outlined here is primarily designed for capturing Activity Log data from multiple subscriptions into one Splunk instance, using a single Event Hub. Per the add-on documentation, capturing Metrics and/or Diagnostic Logs requires additional consideration regarding the number of Event Hubs to use, and where they are deployed.

[App1]: ./Images/SplunkDataInput2.png "Splunk Configuration"

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
