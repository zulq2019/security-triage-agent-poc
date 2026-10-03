// keyvault.bicep - Key Vault with RBAC authorisation (no access policies), soft delete, optional purge protection,
// audit logs to Log Analytics. No secrets are created here: secret VALUES are set by an operator after deployment
// (see docs/infra.md "After the first deployment"). Apps read them with their managed identity.

@description('Azure region.')
param location string

@description('Key Vault name (3-24 chars, globally unique).')
@minLength(3)
@maxLength(24)
param name string

@description('Turn purge protection on. It cannot be turned off again; leave off in throw-away dev environments.')
param enablePurgeProtection bool

@description('Soft-delete retention in days.')
@minValue(7)
@maxValue(90)
param softDeleteRetentionInDays int

@description('Disable public network access (use with a private endpoint).')
param disablePublicNetworkAccess bool

@description('Object id of the operator GROUP that sets secret values after deployment (Key Vault Secrets Officer). Empty = none; grant it outside the template.')
param vaultOperatorsGroupId string

@description('Log Analytics workspace for audit logs.')
param logAnalyticsId string

@description('Tags.')
param tags object

resource kv 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: name
  location: location
  tags: tags
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

// 2021-05-01-preview is the newest version with categoryGroup support (2016-09-01 lacks it).
#disable-next-line use-recent-api-versions
resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-log-analytics'
  scope: kv
  properties: {
    workspaceId: logAnalyticsId
    logs: [{ categoryGroup: 'audit', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

resource officer 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(vaultOperatorsGroupId)) {
  name: guid(kv.id, vaultOperatorsGroupId, 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
  scope: kv
  properties: {
    principalId: vaultOperatorsGroupId
    principalType: 'Group'
    // Key Vault Secrets Officer
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
    )
  }
}

output id string = kv.id
output name string = kv.name
output uri string = kv.properties.vaultUri
