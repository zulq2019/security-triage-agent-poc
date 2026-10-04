// openai.bicep - OPTIONAL Azure OpenAI account and model deployments (SDD 12). Local auth (API keys) is disabled:
// apps call it with their managed identity ("Cognitive Services OpenAI User"). In the target, calls go through the
// APIM AI gateway (not part of this POC infra; see docs/infra.md open items).
import { modelDeployment } from '../types.bicep'

@description('Region for the Azure OpenAI account. Defaults to the main region (UK South); model availability and quota differ per region [ask the Azure team].')
param location string

@description('Account name; also used as the custom sub-domain (globally unique).')
param name string

@description('Model deployments: [ { name, model, version, skuName, capacity } ]. skuName Standard keeps processing in the region; GlobalStandard / DataZoneStandard may process elsewhere. capacity is in thousands of tokens per minute and must fit the subscription quota.')
param deployments modelDeployment[]

@description('Disable public network access (use with a private endpoint).')
param disablePublicNetworkAccess bool

@description('Log Analytics workspace for diagnostic logs.')
param logAnalyticsId string

@description('Tags.')
param tags object

resource account 'Microsoft.CognitiveServices/accounts@2025-06-01' = {
  name: name
  location: location
  tags: tags
  kind: 'OpenAI'
  sku: { name: 'S0' }
  properties: {
    customSubDomainName: name
    disableLocalAuth: true
    publicNetworkAccess: disablePublicNetworkAccess ? 'Disabled' : 'Enabled'
    networkAcls: {
      defaultAction: disablePublicNetworkAccess ? 'Deny' : 'Allow'
    }
  }
}

// Deployments on one account must be created one at a time.
@batchSize(1)
resource modelDeployments 'Microsoft.CognitiveServices/accounts/deployments@2025-06-01' = [
  for d in deployments: {
    parent: account
    name: d.name
    sku: {
      name: d.skuName
      capacity: d.capacity
    }
    properties: {
      model: {
        format: 'OpenAI'
        name: d.model
        version: d.version
      }
      versionUpgradeOption: 'NoAutoUpgrade'
    }
  }
]

// 2021-05-01-preview is the newest version with categoryGroup support (2016-09-01 lacks it).
#disable-next-line use-recent-api-versions
resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-log-analytics'
  scope: account
  properties: {
    workspaceId: logAnalyticsId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

output id string = account.id
output name string = account.name
@description('Base URL for the OpenAI v1 API, as used by the POC azureopenai provider.')
output v1BaseUrl string = '${account.properties.endpoint}openai/v1/'
output deploymentNames array = [for (d, i) in deployments: modelDeployments[i].name]
