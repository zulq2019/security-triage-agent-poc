// keyvault.bicep - Key Vaults with RBAC authorisation (no access policies), soft delete, optional purge protection
// and audit logs to Log Analytics. One call creates the platform vault and, in multi-tenant deployments, one vault
// per tenant (SDD 18.1). No secrets are created: secret VALUES are set by an operator after deployment
// (docs/infra.md "After the first deployment"). Access is granted by role-assignments.bicep.
import { vaultInfo, vaultSpec } from '../types.bicep'

@description('Azure region.')
param location string

@description('Vaults to create (names are globally unique, 3-24 chars).')
param vaults vaultSpec[]

@description('Turn purge protection on. It cannot be turned off again; leave off in throw-away dev environments.')
param enablePurgeProtection bool

@description('Soft-delete retention in days.')
@minValue(7)
@maxValue(90)
param softDeleteRetentionInDays int

@description('Disable public network access (use with private endpoints).')
param disablePublicNetworkAccess bool

@description('Log Analytics workspace for audit logs.')
param logAnalyticsId string

resource kv 'Microsoft.KeyVault/vaults@2024-11-01' = [
  for v in vaults: {
    name: v.name
    location: location
    tags: v.tags
    properties: {
      tenantId: subscription().tenantId
      sku: { family: 'A', name: 'standard' }
      enableRbacAuthorization: true
      enableSoftDelete: true
      softDeleteRetentionInDays: softDeleteRetentionInDays
      // Purge protection is a one-way switch: the property must be omitted (not false) to leave it off.
      enablePurgeProtection: enablePurgeProtection ? true : null
      publicNetworkAccess: disablePublicNetworkAccess ? 'Disabled' : 'Enabled'
      networkAcls: {
        bypass: 'AzureServices'
        defaultAction: disablePublicNetworkAccess ? 'Deny' : 'Allow'
      }
    }
  }
]

// 2021-05-01-preview is the newest version with categoryGroup support (2016-09-01 lacks it).
#disable-next-line use-recent-api-versions
resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = [
  for (v, i) in vaults: {
    name: 'to-log-analytics'
    scope: kv[i]
    properties: {
      workspaceId: logAnalyticsId
      logs: [{ categoryGroup: 'audit', enabled: true }]
      metrics: [{ category: 'AllMetrics', enabled: true }]
    }
  }
]

@description('One entry per vault, in input order.')
output vaults vaultInfo[] = [
  for (v, i) in vaults: {
    name: kv[i].name
    id: kv[i].id
    uri: kv[i].properties.vaultUri
  }
]
