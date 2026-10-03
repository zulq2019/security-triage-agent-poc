// rbac.bicep - least-privilege role assignments for ONE app identity (SDD 13.1 identity table).
// Service Bus roles are scoped to the individual queue / topic / subscription, Blob roles to individual containers,
// Key Vault "Secrets User" to the vaults the app needs, Azure OpenAI "OpenAI User" to the account.
// Azure SQL permissions are database users, not Azure RBAC: see infra/sql/grant-managed-identities.sql.

@description('Principal (object) id of the managed identity.')
param principalId string

@description('Service Bus namespace name.')
param serviceBusName string

@description('Queues the app sends to.')
param sendQueues string[]

@description('Queues the app receives from (also lets the KEDA scaler read the queue).')
param receiveQueues string[]

@description('Topic name (run-events).')
param topicName string

@description('Send (publish) to the topic.')
param sendTopic bool

@description('Topic subscriptions the app receives from.')
param receiveSubscriptions string[]

@description('Storage account name.')
param storageAccountName string

@description('Blob containers with read access.')
param blobReadContainers string[]

@description('Blob containers with read / write access (evidence containers stay write-once through the immutability policy).')
param blobWriteContainers string[]

@description('Key Vault names where the app may read secrets.')
param keyVaultNames string[]

@description('Azure OpenAI account name. Empty = no model access.')
param openAiAccountName string

@description('Container registry name for AcrPull. Empty = none (external registry: grant pull outside this template).')
param containerRegistryName string

// Built-in role definition ids (stable across tenants).
var roles = {
  sbSender: '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39' // Azure Service Bus Data Sender
  sbReceiver: '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0' // Azure Service Bus Data Receiver
  blobReader: '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1' // Storage Blob Data Reader
  blobContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' // Storage Blob Data Contributor
  kvUser: '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User
  openAiUser: '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd' // Cognitive Services OpenAI User
  acrPull: '7f951dda-4ed3-4680-a7ca-43fe172d538d' // AcrPull
}

resource sb 'Microsoft.ServiceBus/namespaces@2026-01-01' existing = {
  name: serviceBusName
}

resource sendQ 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' existing = [
  for q in sendQueues: {
    parent: sb
    name: q
  }
]

resource recvQ 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' existing = [
  for q in receiveQueues: {
    parent: sb
    name: q
  }
]

resource topic 'Microsoft.ServiceBus/namespaces/topics@2026-01-01' existing = {
  parent: sb
  name: topicName
}

resource recvSub 'Microsoft.ServiceBus/namespaces/topics/subscriptions@2026-01-01' existing = [
  for s in receiveSubscriptions: {
    parent: topic
    name: s
  }
]

resource st 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

resource blobSvc 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' existing = {
  parent: st
  name: 'default'
}

resource readC 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' existing = [
  for c in blobReadContainers: {
    parent: blobSvc
    name: c
  }
]

resource writeC 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' existing = [
  for c in blobWriteContainers: {
    parent: blobSvc
    name: c
  }
]

resource vaults 'Microsoft.KeyVault/vaults@2024-11-01' existing = [
  for v in keyVaultNames: {
    name: v
  }
]

resource sendQRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (q, i) in sendQueues: {
    name: guid(sendQ[i].id, principalId, roles.sbSender)
    scope: sendQ[i]
    properties: {
      principalId: principalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.sbSender)
    }
  }
]

resource recvQRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (q, i) in receiveQueues: {
    name: guid(recvQ[i].id, principalId, roles.sbReceiver)
    scope: recvQ[i]
    properties: {
      principalId: principalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.sbReceiver)
    }
  }
]

resource topicRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (sendTopic) {
  name: guid(topic.id, principalId, roles.sbSender)
  scope: topic
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.sbSender)
  }
}

resource recvSubRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (s, i) in receiveSubscriptions: {
    name: guid(recvSub[i].id, principalId, roles.sbReceiver)
    scope: recvSub[i]
    properties: {
      principalId: principalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.sbReceiver)
    }
  }
]

resource readCRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (c, i) in blobReadContainers: {
    name: guid(readC[i].id, principalId, roles.blobReader)
    scope: readC[i]
    properties: {
      principalId: principalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.blobReader)
    }
  }
]

resource writeCRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (c, i) in blobWriteContainers: {
    name: guid(writeC[i].id, principalId, roles.blobContributor)
    scope: writeC[i]
    properties: {
      principalId: principalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.blobContributor)
    }
  }
]

resource kvRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (v, i) in keyVaultNames: {
    name: guid(vaults[i].id, principalId, roles.kvUser)
    scope: vaults[i]
    properties: {
      principalId: principalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.kvUser)
    }
  }
]

resource oai 'Microsoft.CognitiveServices/accounts@2025-06-01' existing = if (!empty(openAiAccountName)) {
  name: empty(openAiAccountName) ? 'none' : openAiAccountName
}

resource oaiRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(openAiAccountName)) {
  name: guid(oai.id, principalId, roles.openAiUser)
  scope: oai
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.openAiUser)
  }
}

resource acr 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = if (!empty(containerRegistryName)) {
  name: empty(containerRegistryName) ? 'none' : containerRegistryName
}

resource acrRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(containerRegistryName)) {
  name: guid(acr.id, principalId, roles.acrPull)
  scope: acr
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.acrPull)
  }
}
