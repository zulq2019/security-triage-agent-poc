// Model 2 - customer-hosted, single tenant in the CUSTOMER's subscription (SDD 18.2). No Wipro dependency at run
// time. The customer's admin deploys this; tenants are ignored. Every [to confirm] value is the customer's choice.
using '../main.bicep'

param environmentName = 'prod'
param location = 'uksouth'
param deploymentModel = 'customer-hosted'

param owner = 'customer-appsec'
param costCenter = 'to-confirm'
param dataClassification = 'confidential'
param extraTags = { customer: 'to-confirm' }

param sqlEntraAdmin = {
  login: readEnvironmentVariable('SECAGENT_SQL_ADMIN_LOGIN', 'sg-secagent-sql-admins')
  objectId: readEnvironmentVariable('SECAGENT_SQL_ADMIN_OBJECT_ID', '00000000-0000-0000-0000-000000000000')
  principalType: 'Group'
}
// Operators who set Key Vault secret values after deployment (Key Vault Secrets Officer). Empty = grant separately.
param keyVaultOperatorsGroupId = readEnvironmentVariable('SECAGENT_KV_OPERATORS_GROUP_ID', '')

param enablePrivateNetworking = true
param vnetAddressPrefix = '10.50.0.0/16' // from the customer's IP plan [to confirm]
param containerAppsSubnetPrefix = '10.50.0.0/23'
param privateEndpointSubnetPrefix = '10.50.2.0/24'
param dnsServers = [] // customer hub DNS resolver, if private DNS is centralised [to confirm]
param internalEnvironment = false
param zoneRedundant = true

param serviceBusSku = 'Premium'
param sqlDatabaseSku = { name: 'GP_Gen5', tier: 'GeneralPurpose', family: 'Gen5', capacity: 2 }
param sqlZoneRedundant = true
param sqlBackupRedundancy = 'Zone'
param storageSku = 'Standard_ZRS'
param evidenceRetentionDays = 365
param blobSoftDeleteDays = 30
param keyVaultPurgeProtection = true
param keyVaultSoftDeleteDays = 90
param logRetentionDays = 90

// Models: the customer's own Azure OpenAI in their subscription (default here), OR set deployOpenAi = false and
// point existingModelBaseUrl / existingModelNames at an existing endpoint (their APIM gateway, Azure OpenAI).
param deployOpenAi = true
param openAiDeployments = [
  { name: 'small', model: 'gpt-4.1-mini', version: '2025-04-14', skuName: 'Standard', capacity: 10 }
  { name: 'strong', model: 'gpt-4.1', version: '2025-04-14', skuName: 'Standard', capacity: 10 }
]

// Images: built from the customer's own copy of the repo into their registry.
param createContainerRegistry = true
param containerRegistrySku = 'Premium'
param usePlaceholderImages = true
param agentOverrides = {
  intake: {
    allowedSourceRanges: [] // the customer's GitHub / CI egress ranges [to confirm]
    // Add once the secrets exist in the vault (second deployment):
    // keyVaultReferences: [
    //   { envName: 'SECAGENT_INTAKE_HMAC_SECRET', secretName: 'intake-hmac-secret' }
    //   { envName: 'SECAGENT_INTAKE_ADMIN_TOKEN', secretName: 'intake-admin-token' }
    // ]
  }
}

// Customer extensions (SDD 20): extra agents, for example an in-house fixer on its own queue. Because the
// orchestrator is a dispatcher, it is granted Send on the new queue automatically. Example:
// param additionalAgents = [
//   { name: 'fixer-iac', description: 'Terraform / Bicep fixer', size: 'heavy', consumes: ['fix-iac'],
//     sends: ['results'], blobRead: ['raw'], blobWrite: ['context'], model: true, sql: 'inserter' }
// ]
param alwaysOnMinReplicas = 1
param workerMaxReplicas = 5
