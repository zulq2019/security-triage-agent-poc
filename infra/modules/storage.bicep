// storage.bicep - Blob storage for raw scanner output / SARIF (raw), write-once evidence (evidence), context packs
// (context) and exports. Entra ID only (shared keys off), no public blobs, time-based immutability on evidence
// containers (SDD 11.4, 13.3). Which containers exist (per tenant or not) is decided by the caller.
import { containerSpec } from '../types.bicep'

@description('Azure region.')
param location string

@description('Storage account name (3-24 lowercase letters and digits, globally unique).')
@minLength(3)
@maxLength(24)
param name string

@description('Redundancy SKU, for example Standard_LRS (dev) or Standard_ZRS.')
param skuName string

@description('Containers to create; immutable ones get a time-based WORM policy.')
param containers containerSpec[]

@description('Retention in days for the evidence immutability policy [to agree]. The policy is created UNLOCKED; locking it is a separate, irreversible operator step.')
@minValue(1)
param evidenceRetentionDays int

@description('Soft-delete retention for blobs and containers, in days.')
@minValue(1)
@maxValue(365)
param softDeleteDays int

@description('Disable public network access (use with a private endpoint).')
param disablePublicNetworkAccess bool

@description('Log Analytics workspace for blob diagnostic logs.')
param logAnalyticsId string

@description('Tags.')
param tags object

resource st 'Microsoft.Storage/storageAccounts@2025-06-01' = {
  name: name
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: skuName }
  properties: {
    accessTier: 'Hot'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false // Entra ID only: no account keys or SAS in use
    defaultToOAuthAuthentication: true
    allowCrossTenantReplication: false
    publicNetworkAccess: disablePublicNetworkAccess ? 'Disabled' : 'Enabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: disablePublicNetworkAccess ? 'Deny' : 'Allow'
    }
    encryption: {
      keySource: 'Microsoft.Storage'
      requireInfrastructureEncryption: true
      services: {
        blob: { enabled: true, keyType: 'Account' }
      }
    }
  }
}

resource blob 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' = {
  parent: st
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: softDeleteDays }
    containerDeleteRetentionPolicy: { enabled: true, days: softDeleteDays }
  }
}

resource blobContainers 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' = [
  for c in containers: {
    parent: blob
    name: c.name
    properties: { publicAccess: 'None' }
  }
]

resource worm 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2025-06-01' = [
  for (c, i) in containers: if (c.immutable) {
    parent: blobContainers[i]
    name: 'default'
    properties: {
      immutabilityPeriodSinceCreationInDays: evidenceRetentionDays
      allowProtectedAppendWrites: false
    }
  }
]

// 2021-05-01-preview is the newest version with categoryGroup support (2016-09-01 lacks it).
#disable-next-line use-recent-api-versions
resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-log-analytics'
  scope: blob
  properties: {
    workspaceId: logAnalyticsId
    logs: [{ categoryGroup: 'audit', enabled: true }]
    metrics: [{ category: 'Transaction', enabled: true }]
  }
}

output id string = st.id
output name string = st.name
output blobEndpoint string = st.properties.primaryEndpoints.blob
@description('Container resource ids by container name.')
output containerIds object = toObject(
  range(0, length(containers)),
  i => containers[i].name,
  i => resourceId('Microsoft.Storage/storageAccounts/blobServices/containers', st.name, blob.name, containers[i].name)
)
