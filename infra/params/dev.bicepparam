// dev: cheapest useful shape. Public endpoints (Entra ID auth only, no keys), Standard Service Bus, serverless SQL
// that auto-pauses, no Azure OpenAI (point SECAGENT_MODEL_BASE_URL at something else, or set deployOpenAi = true),
// placeholder images until the CI pushes real ones. Synthetic data only.
using '../main.bicep'

param environmentName = 'dev'
param location = 'uksouth'
param deploymentModel = 'wipro-hosted'
param tenants = ['demo'] // one synthetic tenant so the per-tenant Key Vault / containers path is exercised

param owner = 'secagent-poc'
param costCenter = 'to-confirm'
param dataClassification = 'synthetic'

// Microsoft Entra admin group for Azure SQL. Set the env vars before deploying (deploy.sh refuses the all-zero id).
param sqlEntraAdmin = {
  login: readEnvironmentVariable('SECAGENT_SQL_ADMIN_LOGIN', 'sg-secagent-sql-admins')
  objectId: readEnvironmentVariable('SECAGENT_SQL_ADMIN_OBJECT_ID', '00000000-0000-0000-0000-000000000000')
  principalType: 'Group'
}
// Operators who set Key Vault secret values after deployment (Key Vault Secrets Officer). Empty = grant separately.
param keyVaultOperatorsGroupId = readEnvironmentVariable('SECAGENT_KV_OPERATORS_GROUP_ID', '')

param enablePrivateNetworking = false
param serviceBusSku = 'Standard'
param sqlDatabaseSku = { name: 'GP_S_Gen5', tier: 'GeneralPurpose', family: 'Gen5', capacity: 2 }
param sqlAutoPauseDelayMinutes = 60
param sqlBackupRedundancy = 'Local'
param storageSku = 'Standard_LRS'
param evidenceRetentionDays = 1 // short in dev so test evidence can be cleaned up
param keyVaultPurgeProtection = false
param logRetentionDays = 30
param logDailyQuotaGb = 1 // cost guard for dev

param deployOpenAi = false
param existingModelBaseUrl = ''

param createContainerRegistry = true
param containerRegistrySku = 'Basic'
param usePlaceholderImages = true
// The POC dashboard has no login, so keep it internal. To reach it from a laptop in dev, switch to 'external' AND set
// agentApiAllowedSourceRanges to your office / VPN egress CIDR(s).
param agentApiIngress = 'internal'
param agentApiAllowedSourceRanges = []
param alwaysOnMinReplicas = 0
param workerMaxReplicas = 3
