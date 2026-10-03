// Model 1 - Wipro-hosted, multi-tenant service in Wipro's Azure subscription (SDD 18.1). Prod shape; copy to
// test / preprod and change environmentName and sizes. Every [to confirm] value needs sign-off (docs/infra.md).
using '../main.bicep'

param environmentName = 'prod'
param location = 'uksouth'
param deploymentModel = 'wipro-hosted'
// Synthetic example tenant codes. Each gets its own Key Vault and raw / evidence / context containers.
param tenants = ['contoso', 'fabrikam']

param owner = 'secagent-platform'
param costCenter = 'to-confirm'
param dataClassification = 'confidential'

param sqlEntraAdmin = {
  login: readEnvironmentVariable('SECAGENT_SQL_ADMIN_LOGIN', 'sg-secagent-sql-admins')
  objectId: readEnvironmentVariable('SECAGENT_SQL_ADMIN_OBJECT_ID', '00000000-0000-0000-0000-000000000000')
  principalType: 'Group'
}
// Operators who set Key Vault secret values after deployment (Key Vault Secrets Officer). Empty = grant separately.
param keyVaultOperatorsGroupId = readEnvironmentVariable('SECAGENT_KV_OPERATORS_GROUP_ID', '')

// Network: VNet, private endpoints, public access off on data services. Address space from the network team.
param enablePrivateNetworking = true
param vnetAddressPrefix = '10.40.0.0/16'
param containerAppsSubnetPrefix = '10.40.0.0/23'
param privateEndpointSubnetPrefix = '10.40.2.0/24'
param internalEnvironment = false // intake must be reachable by GitHub; set true when a front door / WAF is in front
param zoneRedundant = true // [to confirm, NFR-08]

param serviceBusSku = 'Premium'
param serviceBusMessagingUnits = 1
param maxDeliveryCount = 3 // [to agree]
param messageTimeToLive = 'P1D' // [to agree]

param sqlDatabaseSku = { name: 'GP_Gen5', tier: 'GeneralPurpose', family: 'Gen5', capacity: 2 } // [to size]
param sqlZoneRedundant = true // [to confirm]
param sqlBackupRedundancy = 'Zone'
param storageSku = 'Standard_ZRS'
param evidenceRetentionDays = 365 // [to agree with IG / AppSec]
param blobSoftDeleteDays = 30
param keyVaultPurgeProtection = true
param keyVaultSoftDeleteDays = 90
param logRetentionDays = 90
param logDailyQuotaGb = -1
param alertEmailReceivers = [] // team DL [to confirm]

// Azure OpenAI in UK South. Model names, versions and capacity (thousands of tokens per minute) depend on what
// the subscription has quota for in UK South [to confirm with the Azure team]. "Standard" keeps processing in region.
param deployOpenAi = true
param openAiDeployments = [
  { name: 'small', model: 'gpt-4.1-mini', version: '2025-04-14', skuName: 'Standard', capacity: 10 }
  { name: 'strong', model: 'gpt-4.1', version: '2025-04-14', skuName: 'Standard', capacity: 10 }
]

param createContainerRegistry = true
param containerRegistrySku = 'Premium' // private endpoint
param usePlaceholderImages = true // set false once CI pushes images; pin digests with agentOverrides.<agent>.image
// Per-agent settings for this environment (agents themselves come from infra/agents.bicep).
param agentOverrides = {
  intake: {
    allowedSourceRanges: [] // GitHub "hooks" CIDRs from https://api.github.com/meta [to confirm]
    // keyVaultReferences: [ { envName: 'SECAGENT_WEBHOOK_SECRET', secretName: 'github-webhook-secret' } ]
  }
  orchestrator: {
    // keyVaultReferences: [ { envName: 'SECAGENT_HMAC_KEY', secretName: 'secagent-hmac-key' } ]
  }
}
param alwaysOnMinReplicas = 1
param workerMaxReplicas = 10
