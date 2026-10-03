// role-assignments.bicep - REUSABLE: assigns built-in roles to principals on individual resources, given only
// resource ids (no names are hard-coded or looked up from other modules). One call can carry every assignment of
// a deployment; least privilege comes from the caller choosing the narrowest scope (queue, subscription,
// container, vault) for each one.
//
// Supported scope types (resource ids in the deployment's resource group):
//   Microsoft.ServiceBus/namespaces/queues | /topics | /topics/subscriptions
//   Microsoft.Storage/storageAccounts/blobServices/containers
//   Microsoft.KeyVault/vaults
//   Microsoft.CognitiveServices/accounts
//   Microsoft.ContainerRegistry/registries
// Any other scope type is returned in the unsupportedScopeIds output (and not assigned).
import { roleAssignmentSpec } from '../types.bicep'

@description('Role assignments to create.')
param assignments roleAssignmentSpec[]

// Resource type of an id, lower case. An id splits on '/' into
//   ['', subscriptions, <sub>, resourceGroups, <rg>, providers, <provider>, <type>, <name>, <childType>, <childName>, ...]
// so the type segments are index 6 (provider), 7, and every odd index after that.
func scopeType(id string) string =>
  toLower(join(
    filter(
      map(range(0, length(split(id, '/'))), i => (i == 6 || (i >= 7 && i % 2 == 1)) ? split(id, '/')[i] : ''),
      s => !empty(s)
    ),
    '/'
  ))

func segment(id string, index int) string => split(id, '/')[index]

var queueRas = filter(assignments, a => scopeType(a.scopeId) == 'microsoft.servicebus/namespaces/queues')
var topicRas = filter(assignments, a => scopeType(a.scopeId) == 'microsoft.servicebus/namespaces/topics')
var subRas = filter(assignments, a => scopeType(a.scopeId) == 'microsoft.servicebus/namespaces/topics/subscriptions')
var containerRas = filter(
  assignments,
  a => scopeType(a.scopeId) == 'microsoft.storage/storageaccounts/blobservices/containers'
)
var vaultRas = filter(assignments, a => scopeType(a.scopeId) == 'microsoft.keyvault/vaults')
var cogRas = filter(assignments, a => scopeType(a.scopeId) == 'microsoft.cognitiveservices/accounts')
var acrRas = filter(assignments, a => scopeType(a.scopeId) == 'microsoft.containerregistry/registries')
var supportedTypes = [
  'microsoft.servicebus/namespaces/queues'
  'microsoft.servicebus/namespaces/topics'
  'microsoft.servicebus/namespaces/topics/subscriptions'
  'microsoft.storage/storageaccounts/blobservices/containers'
  'microsoft.keyvault/vaults'
  'microsoft.cognitiveservices/accounts'
  'microsoft.containerregistry/registries'
]

// --- Service Bus queues ---------------------------------------------------------------------------------------
resource queues 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' existing = [
  for a in queueRas: {
    name: '${segment(a.scopeId, 8)}/${segment(a.scopeId, 10)}'
  }
]

resource queueRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (a, i) in queueRas: {
    name: guid(a.scopeId, a.principalId, a.roleDefinitionId)
    scope: queues[i]
    properties: {
      principalId: a.principalId
      principalType: a.principalType
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', a.roleDefinitionId)
    }
  }
]

// --- Service Bus topics ---------------------------------------------------------------------------------------
resource topics 'Microsoft.ServiceBus/namespaces/topics@2026-01-01' existing = [
  for a in topicRas: {
    name: '${segment(a.scopeId, 8)}/${segment(a.scopeId, 10)}'
  }
]

resource topicRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (a, i) in topicRas: {
    name: guid(a.scopeId, a.principalId, a.roleDefinitionId)
    scope: topics[i]
    properties: {
      principalId: a.principalId
      principalType: a.principalType
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', a.roleDefinitionId)
    }
  }
]

// --- Service Bus topic subscriptions --------------------------------------------------------------------------
resource subs 'Microsoft.ServiceBus/namespaces/topics/subscriptions@2026-01-01' existing = [
  for a in subRas: {
    name: '${segment(a.scopeId, 8)}/${segment(a.scopeId, 10)}/${segment(a.scopeId, 12)}'
  }
]

resource subRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (a, i) in subRas: {
    name: guid(a.scopeId, a.principalId, a.roleDefinitionId)
    scope: subs[i]
    properties: {
      principalId: a.principalId
      principalType: a.principalType
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', a.roleDefinitionId)
    }
  }
]

// --- Blob containers ------------------------------------------------------------------------------------------
resource containers 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' existing = [
  for a in containerRas: {
    name: '${segment(a.scopeId, 8)}/${segment(a.scopeId, 10)}/${segment(a.scopeId, 12)}'
  }
]

resource containerRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (a, i) in containerRas: {
    name: guid(a.scopeId, a.principalId, a.roleDefinitionId)
    scope: containers[i]
    properties: {
      principalId: a.principalId
      principalType: a.principalType
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', a.roleDefinitionId)
    }
  }
]

// --- Key Vaults -----------------------------------------------------------------------------------------------
resource vaults 'Microsoft.KeyVault/vaults@2024-11-01' existing = [
  for a in vaultRas: {
    name: segment(a.scopeId, 8)
  }
]

resource vaultRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (a, i) in vaultRas: {
    name: guid(a.scopeId, a.principalId, a.roleDefinitionId)
    scope: vaults[i]
    properties: {
      principalId: a.principalId
      principalType: a.principalType
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', a.roleDefinitionId)
    }
  }
]

// --- Azure OpenAI / Cognitive Services accounts ---------------------------------------------------------------
resource accounts 'Microsoft.CognitiveServices/accounts@2025-06-01' existing = [
  for a in cogRas: {
    name: segment(a.scopeId, 8)
  }
]

resource cogRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (a, i) in cogRas: {
    name: guid(a.scopeId, a.principalId, a.roleDefinitionId)
    scope: accounts[i]
    properties: {
      principalId: a.principalId
      principalType: a.principalType
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', a.roleDefinitionId)
    }
  }
]

// --- Container registries -------------------------------------------------------------------------------------
resource registries 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = [
  for a in acrRas: {
    name: segment(a.scopeId, 8)
  }
]

resource acrRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (a, i) in acrRas: {
    name: guid(a.scopeId, a.principalId, a.roleDefinitionId)
    scope: registries[i]
    properties: {
      principalId: a.principalId
      principalType: a.principalType
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', a.roleDefinitionId)
    }
  }
]

@description('Number of role assignments created.')
output count int = length(queueRas) + length(topicRas) + length(subRas) + length(containerRas) + length(vaultRas) + length(cogRas) + length(acrRas)

@description('Scope ids of a type this module does not support (nothing was assigned for them).')
output unsupportedScopeIds array = map(
  filter(assignments, a => !contains(supportedTypes, scopeType(a.scopeId))),
  a => a.scopeId
)
