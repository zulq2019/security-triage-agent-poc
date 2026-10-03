// containerapp.bicep - REUSABLE: one Container App for one agent / step (SDD 4.2 "one container app per agent type").
// - Runs as its own user-assigned managed identity (AZURE_CLIENT_ID is set so DefaultAzureCredential picks it).
// - Scales with KEDA's azure-servicebus scaler on the queue(s) / topic subscription(s) it consumes, authenticated
//   with the same managed identity (no connection strings). Workers scale to zero when their queue is empty.
// - Optional HTTP ingress (internal or external) with an HTTP concurrency scale rule.
// - Optional Key Vault secret references (secret values never appear in the template or the app definition).

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

@description('Container image, for example <acr>.azurecr.io/secagent-triage:<tag>.')
param image string

@description('Registry login server to pull from with the managed identity. Empty for public images.')
param registryServer string

@description('none = no ingress (queue worker); internal = reachable inside the environment / VNet only; external = public endpoint.')
@allowed(['none', 'internal', 'external'])
param ingress string

@description('Port the container listens on (ignored when ingress = none).')
param targetPort int

@description('Ingress allow-list (CIDR ranges), for example GitHub webhook ranges for the intake app. Empty = no restriction.')
param allowedSourceIpRanges string[]

@description('vCPU as a string, for example "0.5". Must be a valid Consumption pairing with memory.')
param cpu string

@description('Memory, for example "1Gi" (2 x cpu).')
param memory string

@description('Minimum replicas. 0 = scale to zero when idle.')
@minValue(0)
param minReplicas int

@description('Maximum replicas.')
@minValue(1)
param maxReplicas int

@description('Service Bus namespace NAME (not FQDN) used by the KEDA scaler.')
param serviceBusNamespace string

@description('KEDA azure-servicebus rules: [ { queueName } ] or [ { topicName, subscriptionName } ]. One rule per entity the app consumes.')
param serviceBusScaleRules serviceBusScaleRule[]

@description('Target active messages per replica for the KEDA rule(s).')
@minValue(1)
param messageCountPerReplica int

@description('Target concurrent HTTP requests per replica (apps with ingress).')
@minValue(1)
param httpConcurrentRequests int

@description('Plain environment variables: [ { name, value } ]. Never put secret values here.')
param env object[]

@description('Key Vault references: [ { envName, secretName, keyVaultSecretUri } ]. The secret must exist before the app is deployed.')
param keyVaultSecrets keyVaultSecretRef[]

@description('Tags.')
param tags object

@export()
@description('One KEDA azure-servicebus rule: set queueName, or topicName + subscriptionName.')
type serviceBusScaleRule = {
  queueName: string?
  topicName: string?
  subscriptionName: string?
}

@export()
@description('A Container Apps secret backed by a Key Vault secret, exposed to the container as an env var.')
type keyVaultSecretRef = {
  @description('Environment variable name inside the container.')
  envName: string
  @description('Container Apps secret name (lowercase letters, digits, hyphens).')
  secretName: string
  @description('Key Vault secret URI without version (https://<vault>.vault.azure.net/secrets/<name>), so rotation is picked up.')
  keyVaultSecretUri: string
}

var sbRules = [
  for r in serviceBusScaleRules: {
    name: toLower(empty(r.?queueName ?? '') ? 'sb-${r.?topicName}-${r.?subscriptionName}' : 'sb-${r.?queueName}')
    custom: {
      type: 'azure-servicebus'
      identity: identityId
      metadata: union(
        { namespace: serviceBusNamespace, messageCount: string(messageCountPerReplica) },
        empty(r.?queueName ?? '')
          ? { topicName: r.?topicName, subscriptionName: r.?subscriptionName }
          : { queueName: r.?queueName }
      )
    }
  }
]

var httpRules = ingress == 'none'
  ? []
  : [
      {
        name: 'http'
        http: { metadata: { concurrentRequests: string(httpConcurrentRequests) } }
      }
    ]

var ipRestrictions = [
  for (cidr, i) in allowedSourceIpRanges: {
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
      ingress: ingress == 'none'
        ? null
        : {
            external: ingress == 'external'
            targetPort: targetPort
            transport: 'auto'
            allowInsecure: false
            ipSecurityRestrictions: ipRestrictions
          }
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
            cpu: json(cpu)
            memory: memory
          }
          env: concat(baseEnv, env, map(keyVaultSecrets, s => { name: s.envName, secretRef: s.secretName }))
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: concat(sbRules, httpRules)
      }
    }
  }
}

output id string = app.id
output name string = app.name
@description('Ingress FQDN; empty for queue workers.')
output fqdn string = ingress == 'none' ? '' : app.properties.configuration.ingress.fqdn
