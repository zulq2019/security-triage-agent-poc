// containerapp.bicep - REUSABLE: one Container App for one agent (SDD 4.2 "one container app per agent type").
// Knows nothing about specific agents: main.bicep calls it once per entry of the typed agent list.
// - Runs as the user-assigned managed identity it is given (AZURE_CLIENT_ID is set for DefaultAzureCredential).
// - Scales with KEDA's azure-servicebus scaler on each queue / subscription in scaleRules, authenticated with the
//   same identity (no connection strings). Workers scale to zero when their queues are empty.
// - Optional HTTP ingress (internal or external) with an IP allow-list and an HTTP concurrency rule.
// - Optional Key Vault secret references (secret values never appear in the template or the app definition).
import {
  containerResources
  envVar
  ingressSpec
  keyVaultSecretRef
  scaleSpec
  serviceBusScaleRule
} from '../types.bicep'

@description('Container App name (2-32 lowercase letters, digits and hyphens).')
@maxLength(32)
param name string

@description('Azure region.')
param location string

@description('Container Apps environment id.')
param environmentId string

@description('User-assigned managed identity (resource id) the app runs as.')
param identityId string

@description('Client id of that identity (exported as AZURE_CLIENT_ID).')
param identityClientId string

@description('Container image.')
param image string

@description('Registry login server to pull from with the managed identity. Empty for public images.')
param registryServer string

@description('Ingress settings; mode none = queue worker.')
param ingress ingressSpec

@description('CPU / memory.')
param resources containerResources

@description('Replica bounds and scale targets.')
param scale scaleSpec

@description('Service Bus namespace NAME used by the KEDA scaler (from the servicebus module output).')
param serviceBusNamespace string

@description('KEDA azure-servicebus rules, one per entity the app consumes.')
param scaleRules serviceBusScaleRule[]

@description('Plain environment variables. Never secret values.')
param env envVar[]

@description('Key Vault references exposed as env vars. Each secret must exist before the app is deployed.')
param keyVaultSecrets keyVaultSecretRef[]

@description('Tags.')
param tags object

var sbRules = [
  for r in scaleRules: {
    name: toLower(empty(r.?queueName ?? '') ? 'sb-${r.?topicName}-${r.?subscriptionName}' : 'sb-${r.?queueName}')
    custom: {
      type: 'azure-servicebus'
      identity: identityId
      metadata: union(
        { namespace: serviceBusNamespace, messageCount: string(scale.messagesPerReplica) },
        empty(r.?queueName ?? '')
          ? { topicName: r.?topicName, subscriptionName: r.?subscriptionName }
          : { queueName: r.?queueName }
      )
    }
  }
]

var hasIngress = ingress.mode != 'none'

var httpRules = hasIngress
  ? [
      {
        name: 'http'
        http: { metadata: { concurrentRequests: string(scale.httpConcurrentRequests) } }
      }
    ]
  : []

var ipRestrictions = [
  for (cidr, i) in ingress.allowedSourceRanges: {
    name: 'allow-${i}'
    action: 'Allow'
    ipAddressRange: cidr
  }
]

var baseEnv = [
  { name: 'AZURE_CLIENT_ID', value: identityClientId }
  { name: 'OTEL_SERVICE_NAME', value: name }
]

resource app 'Microsoft.App/containerApps@2025-01-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identityId}': {} }
  }
  properties: {
    environmentId: environmentId
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: hasIngress
        ? {
            external: ingress.mode == 'external'
            targetPort: ingress.targetPort
            transport: 'auto'
            allowInsecure: false
            ipSecurityRestrictions: ipRestrictions
          }
        : null
      registries: empty(registryServer) ? [] : [{ server: registryServer, identity: identityId }]
      secrets: [
        for s in keyVaultSecrets: {
          name: s.secretName
          keyVaultUrl: s.keyVaultSecretUri
          identity: identityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'main'
          image: image
          resources: {
            cpu: json(resources.cpu)
            memory: resources.memory
          }
          env: concat(baseEnv, env, map(keyVaultSecrets, s => { name: s.envName, secretRef: s.secretName }))
        }
      ]
      scale: {
        minReplicas: scale.minReplicas
        maxReplicas: scale.maxReplicas
        rules: concat(sbRules, httpRules)
      }
    }
  }
}

output id string = app.id
output name string = app.name
@description('Ingress FQDN; empty for queue workers.')
output fqdn string = hasIngress ? app.properties.configuration.ingress.fqdn : ''
