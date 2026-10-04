// main.bicep - Security Triage & Fix Agent: one environment in one resource group.
//
// Composition root only: it owns the naming convention and wires module OUTPUTS (ids, names, endpoints) into
// other modules. Modules never look each other up by name. Everything that differs between environments or
// between the two deployment models (SDD 18) is a parameter, set in params/*.bicepparam:
//   - wipro-hosted    : multi-tenant service in Wipro's subscription (params/wipro-hosted.bicepparam)
//   - customer-hosted : single tenant in the customer's own subscription (params/customer-hosted.bicepparam)
// Agents come from the typed catalogue in agents.bicep (+ additionalAgents). Queues, subscriptions, identities,
// KEDA rules, role assignments and Container Apps are all derived from that list, so a new agent needs no module
// change. No secrets: service-to-service auth is Microsoft Entra ID with one managed identity per agent.
targetScope = 'resourceGroup'

import {
  agentOverrideMap
  agentSpec
  builtInRoles
  containerSpec
  modelDeployment
  modelTierNames
  roleAssignmentSpec
  sizingMap
  sqlEntraAdmin as sqlEntraAdminType
  sqlSku
} from 'types.bicep'
import { blobLayout, defaultAgents, runEventsTopic, runQueue } from 'agents.bicep'

// ---------------------------------------------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------------------------------------------
@description('Azure region for all resources. UK South by default.')
param location string = 'uksouth'

@description('Environment.')
@allowed(['dev', 'test', 'preprod', 'prod'])
param environmentName string

@description('Workload short name used in resource names (lowercase letters and digits, max 8).')
@minLength(2)
@maxLength(8)
param workload string = 'secagent'

@description('Deployment model label: tags + SECAGENT_PROFILE for the apps. Behaviour is driven by the other parameters (for example tenants), not by this label.')
@allowed(['wipro-hosted', 'customer-hosted'])
param deploymentModel string

@description('Tenant codes for a multi-tenant (Wipro-hosted) deployment. Each gets its own Key Vault and per-tenant Blob containers. Empty = single tenant.')
param tenants tenantCode[] = []

@minLength(2)
@maxLength(10)
@description('Tenant code: lowercase letters and digits, 2-10 chars (used in Key Vault and container names).')
type tenantCode = string

@description('Owner tag (team or DL, not a person where possible).')
param owner string

@description('Cost centre tag.')
param costCenter string

@description('Data classification tag.')
param dataClassification string = 'confidential'

@description('Extra tags merged into the standard tags (for example customer, project code).')
param extraTags object = {}

// ---------------------------------------------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------------------------------------------
@description('Extra agents for this environment / customer (same shape as agents.bicep), for example a customer-specific fixer.')
param additionalAgents agentSpec[] = []

@description('Per-agent environment settings keyed by agent name: ingress, allowedSourceRanges, minReplicas, maxReplicas, image, keyVaultReferences.')
param agentOverrides agentOverrideMap = {}

@description('CPU / memory per sizing class used by agentSpec.size.')
param appSizing sizingMap = {
  light: { cpu: '0.5', memory: '1Gi' }
  heavy: { cpu: '2.0', memory: '4Gi' }
}

@description('Min replicas for always-on agents (0 in dev to save cost; 1 in prod, SDD 4.2).')
param alwaysOnMinReplicas int = 0

@description('Max replicas for always-on agents.')
param alwaysOnMaxReplicas int = 3

@description('Max replicas per queue worker.')
param workerMaxReplicas int = 5

@description('Active messages per replica for the KEDA scalers.')
param messagesPerReplica int = 5

@description('Concurrent HTTP requests per replica for agents with ingress.')
param httpConcurrentRequests int = 20

@description('Create an Azure Container Registry. False = use externalRegistryServer (grant AcrPull there).')
param createContainerRegistry bool = true

@description('ACR SKU (Premium for private endpoint).')
@allowed(['Basic', 'Standard', 'Premium'])
param containerRegistrySku string = 'Basic'

@description('External registry login server when createContainerRegistry = false.')
param externalRegistryServer string = ''

@description('Deploy every agent with a public placeholder image (first deployment, before images exist). It listens on port 80.')
param usePlaceholderImages bool = true

@description('Image tag for <registry>/<workload>-<agent>:<tag> (per-agent digests go in agentOverrides.<agent>.image).')
param imageTag string = 'latest'

// ---------------------------------------------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------------------------------------------
@description('VNet + private endpoints + private DNS, public network access off on the data services. Off = public endpoints protected by Entra ID only (dev).')
param enablePrivateNetworking bool = false

@description('VNet address space.')
param vnetAddressPrefix string = '10.40.0.0/16'

@description('Container Apps infrastructure subnet.')
param containerAppsSubnetPrefix string = '10.40.0.0/23'

@description('Private endpoint subnet.')
param privateEndpointSubnetPrefix string = '10.40.2.0/24'

@description('Custom DNS servers for the VNet (hub resolver). Empty = Azure DNS.')
param dnsServers string[] = []

@description('Internal-only Container Apps environment (needs private networking). External agents then need Front Door / Application Gateway in front.')
param internalEnvironment bool = false

@description('Zone-redundant Container Apps environment (needs private networking) [to confirm, NFR-08].')
param zoneRedundant bool = false

// ---------------------------------------------------------------------------------------------------------------
// Monitoring
// ---------------------------------------------------------------------------------------------------------------
@description('Log retention in days.')
param logRetentionDays int = 30

@description('Log Analytics daily cap in GB (-1 = none).')
param logDailyQuotaGb int = -1

@description('Alert e-mail recipients (team DL). Empty = no action group and no alerts.')
param alertEmailReceivers string[] = []

// ---------------------------------------------------------------------------------------------------------------
// Service Bus
// ---------------------------------------------------------------------------------------------------------------
@description('Standard (dev) or Premium (private endpoints, isolation) [to confirm].')
@allowed(['Standard', 'Premium'])
param serviceBusSku string = 'Standard'

@description('Premium messaging units.')
@allowed([1, 2, 4, 8, 16])
param serviceBusMessagingUnits int = 1

@description('Queues created WITHOUT sessions (decision OD-03, for example [ triage ]). All others use SessionId = run id. The run queue (runs) always keeps sessions: the intake relies on per-PR ordering.')
param sessionlessQueues string[] = []

@description('Extra run-events subscriptions nobody in the agent list consumes yet (for example notifier).')
param extraTopicSubscriptions string[] = []

@description('MaxDeliveryCount before dead-lettering [to agree] (POC: 3).')
param maxDeliveryCount int = 3

@description('Peek-lock duration (max PT5M).')
param lockDuration string = 'PT5M'

@description('Duplicate detection window (POC: 10 minutes).')
param duplicateDetectionWindow string = 'PT10M'

@description('Message TTL [to agree].')
param messageTimeToLive string = 'P1D'

// ---------------------------------------------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------------------------------------------
@description('Microsoft Entra admin for Azure SQL. Use a group. Comes from an environment variable in the .bicepparam files.')
param sqlEntraAdmin sqlEntraAdminType

@description('Azure SQL database SKU.')
param sqlDatabaseSku sqlSku = { name: 'GP_S_Gen5', tier: 'GeneralPurpose', family: 'Gen5', capacity: 2 }

@description('Serverless auto-pause delay in minutes (-1 = never).')
param sqlAutoPauseDelayMinutes int = 60

@description('Zone-redundant database.')
param sqlZoneRedundant bool = false

@description('SQL backup storage redundancy.')
@allowed(['Local', 'Zone', 'Geo'])
param sqlBackupRedundancy string = 'Local'

@description('Storage redundancy SKU.')
param storageSku string = 'Standard_LRS'

@description('Evidence WORM retention in days [to agree]. Policy is created unlocked.')
param evidenceRetentionDays int = 7

@description('Blob / container soft-delete days.')
param blobSoftDeleteDays int = 7

@description('Key Vault purge protection (irreversible once on).')
param keyVaultPurgeProtection bool = false

@description('Key Vault soft-delete retention days.')
param keyVaultSoftDeleteDays int = 7

@description('Object id of the Entra GROUP of operators who set secret values (Key Vault Secrets Officer on every vault). Empty = grant outside the template.')
param keyVaultOperatorsGroupId string = ''

// ---------------------------------------------------------------------------------------------------------------
// Models (optional)
// ---------------------------------------------------------------------------------------------------------------
@description('Deploy an Azure OpenAI account and model deployments (modules/openai.bicep).')
param deployOpenAi bool = false

@description('Azure OpenAI region (UK South by default) [quota to confirm].')
param openAiLocation string = location

@description('Model deployments. First = small tier, second = strong tier.')
param openAiDeployments modelDeployment[] = []

@description('Use an existing OpenAI-compatible v1 endpoint instead (customer-owned Azure OpenAI or APIM gateway URL). Ignored when deployOpenAi = true.')
param existingModelBaseUrl string = ''

@description('Deployment / model names for the small and strong tiers when using existingModelBaseUrl.')
param existingModelNames modelTierNames = { small: '', strong: '' }

// ===============================================================================================================
// Naming convention: <type>-<workload>-<env>-<region>[-<unique>], with <unique> only where the name is global.
// Per-agent resources: ca-<agent>-<env>, id-<agent>-<env>. Storage / ACR: no hyphens.
// ===============================================================================================================
var envCode = { dev: 'dev', test: 'tst', preprod: 'ppd', prod: 'prd' }[environmentName]
var regionCode = {
  uksouth: 'uks'
  ukwest: 'ukw'
  westeurope: 'weu'
  northeurope: 'neu'
}[?location] ?? location
var unique = take(uniqueString(subscription().id, resourceGroup().id, workload, environmentName), 5)
var base = '${workload}-${envCode}-${regionCode}'
var workloadAlnum = toLower(replace(workload, '-', ''))
var names = {
  vnet: 'vnet-${base}'
  logAnalytics: 'log-${base}'
  appInsights: 'appi-${base}'
  actionGroup: 'ag-${base}'
  containerAppsEnv: 'cae-${base}'
  serviceBus: 'sb-${base}-${unique}'
  keyVault: 'kv-${workload}-${envCode}-${unique}'
  storage: 'st${workloadAlnum}${envCode}${unique}'
  sqlServer: 'sql-${base}-${unique}'
  sqlDatabase: 'sqldb-${workload}'
  openAi: 'oai-${base}-${unique}'
  registry: 'cr${workloadAlnum}${envCode}${unique}'
}

var tags = union(
  {
    workload: workload
    environment: environmentName
    deploymentModel: deploymentModel
    owner: owner
    costCenter: costCenter
    dataClassification: dataClassification
    managedBy: 'bicep'
    designRef: 'SDD-v0.3'
  },
  extraTags
)

// ---------------------------------------------------------------------------------------------------------------
// Agents: catalogue + environment overrides, normalised so every optional field has a value.
// ---------------------------------------------------------------------------------------------------------------
var agents = map(concat(defaultAgents, additionalAgents), a => {
  name: a.name
  ingress: agentOverrides[?a.name].?ingress ?? a.?ingress ?? 'none'
  targetPort: a.?targetPort ?? 8080
  allowedSourceRanges: agentOverrides[?a.name].?allowedSourceRanges ?? []
  alwaysOn: a.?alwaysOn ?? false
  size: a.?size ?? 'light'
  consumes: a.?consumes ?? []
  subscribes: a.?subscribes ?? []
  sends: a.?sends ?? []
  publishesEvents: a.?publishesEvents ?? false
  dispatchesWork: a.?dispatchesWork ?? false
  blobRead: a.?blobRead ?? []
  blobWrite: a.?blobWrite ?? []
  keyVault: a.?keyVault ?? false
  model: a.?model ?? false
  sql: a.?sql ?? 'none'
  hostsIntake: a.?hostsIntake ?? false
  minReplicas: agentOverrides[?a.name].?minReplicas ?? ((a.?alwaysOn ?? false) ? alwaysOnMinReplicas : 0)
  maxReplicas: agentOverrides[?a.name].?maxReplicas ?? ((a.?alwaysOn ?? false) ? alwaysOnMaxReplicas : workerMaxReplicas)
  image: agentOverrides[?a.name].?image ?? ''
  keyVaultReferences: agentOverrides[?a.name].?keyVaultReferences ?? []
})

// Service Bus entities are derived from the agents (SDD 7.2). A dispatcher may send to every queue that a
// non-dispatcher consumes, so adding a worker agent with a new queue needs no other change.
var dispatchQueues = flatten(map(filter(agents, a => !a.dispatchesWork), a => a.consumes))
var agentSends = map(agents, a => union(a.sends, a.dispatchesWork ? dispatchQueues : []))
var queueNames = union(flatten(map(agents, a => a.consumes)), flatten(agentSends))
var queues = map(queueNames, q => { name: q, requiresSession: q == runQueue || !contains(sessionlessQueues, q) })
var topicSubscriptions = union(flatten(map(agents, a => a.subscribes)), extraTopicSubscriptions)

// Tenancy: per-tenant vaults and containers when tenants are listed.
var tenantSuffixes = empty(tenants) ? [''] : map(tenants, t => '-${t}')
var containers containerSpec[] = flatten(map(
  blobLayout,
  l =>
    l.perTenant
      ? map(tenantSuffixes, s => { name: '${l.purpose}${s}', purpose: l.purpose, immutable: l.immutable })
      : [{ name: l.purpose, purpose: l.purpose, immutable: l.immutable }]
))
var vaultSpecs = concat(
  [{ name: names.keyVault, tags: tags }],
  map(tenants, t => { name: 'kv-${t}-${envCode}-${unique}', tags: union(tags, { tenant: t }) })
)

var identityNames = map(agents, a => 'id-${a.name}-${envCode}')
var placeholderImage = 'mcr.microsoft.com/k8se/quickstart:latest'

// ===============================================================================================================
// Platform modules
// ===============================================================================================================
module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  params: {
    location: location
    logAnalyticsName: names.logAnalytics
    appInsightsName: names.appInsights
    actionGroupName: names.actionGroup
    retentionInDays: logRetentionDays
    dailyQuotaGb: logDailyQuotaGb
    alertEmailReceivers: alertEmailReceivers
    tags: tags
  }
}

module network 'modules/network.bicep' = if (enablePrivateNetworking) {
  name: 'network'
  params: {
    location: location
    vnetName: names.vnet
    addressPrefix: vnetAddressPrefix
    containerAppsSubnetPrefix: containerAppsSubnetPrefix
    privateEndpointSubnetPrefix: privateEndpointSubnetPrefix
    includeOpenAiZone: deployOpenAi
    includeAcrZone: createContainerRegistry && containerRegistrySku == 'Premium'
    dnsServers: dnsServers
    tags: tags
  }
}

module identity 'modules/identity.bicep' = {
  name: 'identity'
  params: {
    location: location
    identityNames: identityNames
    tags: tags
  }
}

module keyVaults 'modules/keyvault.bicep' = {
  name: 'keyvaults'
  params: {
    location: location
    vaults: vaultSpecs
    enablePurgeProtection: keyVaultPurgeProtection
    softDeleteRetentionInDays: keyVaultSoftDeleteDays
    disablePublicNetworkAccess: enablePrivateNetworking
    logAnalyticsId: monitoring.outputs.logAnalyticsId
  }
}

module serviceBus 'modules/servicebus.bicep' = {
  name: 'servicebus'
  params: {
    location: location
    name: names.serviceBus
    sku: serviceBusSku
    premiumMessagingUnits: serviceBusMessagingUnits
    queues: queues
    topicName: runEventsTopic
    topicSubscriptions: topicSubscriptions
    maxDeliveryCount: maxDeliveryCount
    lockDuration: lockDuration
    duplicateDetectionWindow: duplicateDetectionWindow
    messageTimeToLive: messageTimeToLive
    disablePublicNetworkAccess: enablePrivateNetworking
    logAnalyticsId: monitoring.outputs.logAnalyticsId
    actionGroupId: monitoring.outputs.actionGroupId
    tags: tags
  }
}

module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    location: location
    name: names.storage
    skuName: storageSku
    containers: containers
    evidenceRetentionDays: evidenceRetentionDays
    softDeleteDays: blobSoftDeleteDays
    disablePublicNetworkAccess: enablePrivateNetworking
    logAnalyticsId: monitoring.outputs.logAnalyticsId
    tags: tags
  }
}

module sql 'modules/sql.bicep' = {
  name: 'sql'
  params: {
    location: location
    serverName: names.sqlServer
    databaseName: names.sqlDatabase
    entraAdmin: sqlEntraAdmin
    databaseSku: sqlDatabaseSku
    autoPauseDelayMinutes: sqlAutoPauseDelayMinutes
    zoneRedundant: sqlZoneRedundant
    backupStorageRedundancy: sqlBackupRedundancy
    disablePublicNetworkAccess: enablePrivateNetworking
    allowAzureServices: !enablePrivateNetworking
    logAnalyticsId: monitoring.outputs.logAnalyticsId
    tags: tags
  }
}

module openAi 'modules/openai.bicep' = if (deployOpenAi) {
  name: 'openai'
  params: {
    location: openAiLocation
    name: names.openAi
    deployments: openAiDeployments
    disablePublicNetworkAccess: enablePrivateNetworking
    logAnalyticsId: monitoring.outputs.logAnalyticsId
    tags: tags
  }
}

module acr 'modules/acr.bicep' = if (createContainerRegistry) {
  name: 'acr'
  params: {
    location: location
    name: names.registry
    sku: containerRegistrySku
    disablePublicNetworkAccess: enablePrivateNetworking
    tags: tags
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Private endpoints: one reusable module, one entry per target (only with private networking).
// ---------------------------------------------------------------------------------------------------------------
var privateEndpoints = !enablePrivateNetworking
  ? []
  : concat(
      [
        { name: 'pe-${names.storage}-blob', target: 'blob', groupId: 'blob', zone: 'blob', vault: -1 }
        { name: 'pe-${names.sqlServer}', target: 'sql', groupId: 'sqlServer', zone: 'sql', vault: -1 }
      ],
      map(range(0, length(vaultSpecs)), i => {
        name: 'pe-${vaultSpecs[i].name}'
        target: 'vault'
        groupId: 'vault'
        zone: 'vault'
        vault: i
      }),
      serviceBusSku == 'Premium'
        ? [
            {
              name: 'pe-${names.serviceBus}'
              target: 'servicebus'
              groupId: 'namespace'
              zone: 'servicebus'
              vault: -1
            }
          ]
        : [],
      deployOpenAi
        ? [{ name: 'pe-${names.openAi}', target: 'openai', groupId: 'account', zone: 'openai', vault: -1 }]
        : [],
      (createContainerRegistry && containerRegistrySku == 'Premium')
        ? [{ name: 'pe-${names.registry}', target: 'acr', groupId: 'registry', zone: 'acr', vault: -1 }]
        : []
    )

module privateEndpointModules 'modules/privateendpoint.bicep' = [
  for pe in privateEndpoints: {
    name: pe.name
    params: {
      location: location
      name: pe.name
      subnetId: network!.outputs.privateEndpointSubnetId
      targetResourceId: pe.target == 'vault'
        ? keyVaults.outputs.vaults[pe.vault].id
        : {
            blob: storage.outputs.id
            sql: sql.outputs.serverId
            servicebus: serviceBus.outputs.id
            openai: deployOpenAi ? openAi!.outputs.id : ''
            acr: createContainerRegistry ? acr!.outputs.id : ''
          }[pe.target]
      groupId: pe.groupId
      privateDnsZoneId: network!.outputs.dnsZoneIds[pe.zone]
      tags: tags
    }
  }
]

// ---------------------------------------------------------------------------------------------------------------
// Least-privilege RBAC: derived from the agent list, assigned by the reusable role-assignments module.
// ---------------------------------------------------------------------------------------------------------------
func assignment(principalId string, role string, scopeId string) roleAssignmentSpec => {
  principalId: principalId
  roleDefinitionId: role
  scopeId: scopeId
  principalType: 'ServicePrincipal'
}

var vaultIds = map(keyVaults.outputs.vaults, v => v.id)

var agentAssignments = flatten(map(
  range(0, length(agents)),
  i =>
    concat(
      map(
        agentSends[i],
        q =>
          assignment(
            identity.outputs.identities[i].principalId,
            builtInRoles.serviceBusDataSender,
            serviceBus.outputs.queueIds[q]
          )
      ),
      map(
        agents[i].consumes,
        q =>
          assignment(
            identity.outputs.identities[i].principalId,
            builtInRoles.serviceBusDataReceiver,
            serviceBus.outputs.queueIds[q]
          )
      ),
      agents[i].publishesEvents
        ? [
            assignment(
              identity.outputs.identities[i].principalId,
              builtInRoles.serviceBusDataSender,
              serviceBus.outputs.topicId
            )
          ]
        : [],
      map(
        agents[i].subscribes,
        s =>
          assignment(
            identity.outputs.identities[i].principalId,
            builtInRoles.serviceBusDataReceiver,
            serviceBus.outputs.subscriptionIds[s]
          )
      ),
      map(
        filter(containers, c => contains(agents[i].blobRead, c.purpose)),
        c =>
          assignment(
            identity.outputs.identities[i].principalId,
            builtInRoles.storageBlobDataReader,
            storage.outputs.containerIds[c.name]
          )
      ),
      map(
        filter(containers, c => contains(agents[i].blobWrite, c.purpose)),
        c =>
          assignment(
            identity.outputs.identities[i].principalId,
            builtInRoles.storageBlobDataContributor,
            storage.outputs.containerIds[c.name]
          )
      ),
      agents[i].keyVault
        ? map(vaultIds, v => assignment(identity.outputs.identities[i].principalId, builtInRoles.vaultUser, v))
        : [],
      (agents[i].model && deployOpenAi)
        ? [assignment(identity.outputs.identities[i].principalId, builtInRoles.openAiUser, openAi!.outputs.id)]
        : [],
      createContainerRegistry
        ? [assignment(identity.outputs.identities[i].principalId, builtInRoles.acrPull, acr!.outputs.id)]
        : []
    )
))

var operatorAssignments = empty(keyVaultOperatorsGroupId)
  ? []
  : map(vaultIds, v => {
      principalId: keyVaultOperatorsGroupId
      roleDefinitionId: builtInRoles.vaultOfficer
      scopeId: v
      principalType: 'Group'
    })

module rbac 'modules/role-assignments.bicep' = {
  name: 'role-assignments'
  params: {
    assignments: concat(agentAssignments, operatorAssignments)
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Container Apps environment + one generic Container App per agent
// ---------------------------------------------------------------------------------------------------------------
module containerAppsEnv 'modules/containerapps-env.bicep' = {
  name: 'containerapps-env'
  params: {
    location: location
    name: names.containerAppsEnv
    infrastructureSubnetId: enablePrivateNetworking ? network!.outputs.containerAppsSubnetId : ''
    internal: enablePrivateNetworking && internalEnvironment
    zoneRedundant: enablePrivateNetworking && zoneRedundant
    logAnalyticsId: monitoring.outputs.logAnalyticsId
    tags: tags
  }
}

var registryServer = usePlaceholderImages
  ? ''
  : (createContainerRegistry ? acr!.outputs.loginServer : externalRegistryServer)
var modelBaseUrl = deployOpenAi ? openAi!.outputs.v1BaseUrl : existingModelBaseUrl
var smallModel = deployOpenAi
  ? (length(openAiDeployments) > 0 ? openAiDeployments[0].name : '')
  : existingModelNames.small
var strongModel = deployOpenAi
  ? (length(openAiDeployments) > 1 ? openAiDeployments[1].name : smallModel)
  : existingModelNames.strong
var platformVault = keyVaults.outputs.vaults[0]
// Settings read by SecAgent.Intake (IntakeOptions "Intake" / AzureIntakeOptions "Intake:Azure") in the apps that host it. The run queue
// always goes to Service Bus. Raw payloads go to the Blob container 'raw' in a single-tenant deployment; the POC intake writes one
// container and is not tenant-aware yet, so a multi-tenant deployment (raw-<tenant> containers only) keeps its local raw store for now.
var intakeEnv = concat(
  [
    { name: 'Intake__Adapters__RunQueue', value: 'azure-servicebus' }
    { name: 'Intake__Azure__ServiceBusNamespace', value: serviceBus.outputs.fullyQualifiedNamespace }
    { name: 'Intake__Azure__RunQueueName', value: runQueue }
  ],
  empty(tenants)
    ? [
        { name: 'Intake__Adapters__RawStore', value: 'azure-blob' }
        { name: 'Intake__Adapters__BlobReader', value: 'azure-blob' }
        { name: 'Intake__Azure__BlobServiceUri', value: storage.outputs.blobEndpoint }
        { name: 'Intake__Azure__RawContainer', value: 'raw' }
      ]
    : []
)
// Tenant code -> vault URI (vaultSpecs puts the platform vault first, then one vault per tenant in parameter order).
// Exposed to the apps that read Key Vault, so per-tenant connector secrets stay in the tenant's vault.
var tenantVaultUris = toObject(range(0, length(tenants)), i => tenants[i], i => keyVaults.outputs.vaults[i + 1].uri)

module containerApps 'modules/containerapp.bicep' = [
  for (a, i) in agents: {
    name: 'ca-${a.name}'
    params: {
      name: 'ca-${a.name}-${envCode}'
      location: location
      environmentId: containerAppsEnv.outputs.id
      identityId: identity.outputs.identities[i].id
      identityClientId: identity.outputs.identities[i].clientId
      image: usePlaceholderImages
        ? placeholderImage
        : (empty(a.image) ? '${registryServer}/${workload}-${a.name}:${imageTag}' : a.image)
      registryServer: registryServer
      ingress: {
        mode: a.ingress
        targetPort: usePlaceholderImages ? 80 : a.targetPort
        allowedSourceRanges: a.allowedSourceRanges
      }
      resources: appSizing[a.size]
      scale: {
        minReplicas: a.minReplicas
        maxReplicas: a.maxReplicas
        messagesPerReplica: messagesPerReplica
        httpConcurrentRequests: httpConcurrentRequests
      }
      serviceBusNamespace: serviceBus.outputs.name
      scaleRules: concat(
        map(a.consumes, q => { queueName: q }),
        map(a.subscribes, s => { topicName: serviceBus.outputs.topicName, subscriptionName: s })
      )
      env: concat(
        [
          { name: 'SECAGENT_PROFILE', value: deploymentModel }
          { name: 'SECAGENT_ENVIRONMENT', value: environmentName }
          { name: 'SECAGENT_AGENT', value: a.name }
          { name: 'SECAGENT_QUEUE', value: 'servicebus' }
          { name: 'SECAGENT_SERVICEBUS_NAMESPACE', value: serviceBus.outputs.fullyQualifiedNamespace }
          { name: 'SECAGENT_RUN_EVENTS_TOPIC', value: serviceBus.outputs.topicName }
          { name: 'SECAGENT_BLOB_ENDPOINT', value: storage.outputs.blobEndpoint }
          { name: 'SECAGENT_KEYVAULT_URI', value: platformVault.uri }
          { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: monitoring.outputs.appInsightsConnectionString }
        ],
        (a.keyVault && !empty(tenants))
          ? [{ name: 'SECAGENT_TENANT_KEYVAULT_URIS', value: string(tenantVaultUris) }]
          : [],
        a.sql == 'none'
          ? []
          : [
              {
                // No password: Entra ID token for the agent's own managed identity.
                name: 'SECAGENT_SQL'
                value: 'Server=tcp:${sql.outputs.serverFqdn},1433;Database=${sql.outputs.databaseName};Authentication=Active Directory Managed Identity;User Id=${identity.outputs.identities[i].clientId};Encrypt=True;TrustServerCertificate=False'
              }
            ],
        (a.model && !empty(modelBaseUrl))
          ? [
              { name: 'SECAGENT_MODEL_PROVIDER', value: 'azureopenai' }
              { name: 'SECAGENT_MODEL_BASE_URL', value: modelBaseUrl }
              { name: 'SECAGENT_SMALL_MODEL', value: smallModel }
              { name: 'SECAGENT_STRONG_MODEL', value: strongModel }
            ]
          : [],
        a.hostsIntake ? intakeEnv : []
      )
      keyVaultSecrets: map(a.keyVaultReferences, s => {
        envName: s.envName
        secretName: toLower(s.secretName)
        // A tenant that is not in the tenants parameter fails the deployment (missing key) instead of silently using the platform vault.
        keyVaultSecretUri: '${empty(s.?tenant ?? '') ? platformVault.uri : tenantVaultUris[s.tenant!]}secrets/${s.secretName}'
      })
      tags: union(tags, { app: a.name })
    }
    dependsOn: [rbac, privateEndpointModules]
  }
]

// ===============================================================================================================
// Outputs (no secrets)
// ===============================================================================================================
output resourceNames object = names
output agents array = map(agents, a => a.name)
output keyVaults array = keyVaults.outputs.vaults
output serviceBusNamespace string = serviceBus.outputs.fullyQualifiedNamespace
output queues array = queueNames
output topic object = { name: serviceBus.outputs.topicName, subscriptions: topicSubscriptions }
output blobContainers array = map(containers, c => c.name)
output keyVaultUri string = platformVault.uri
output tenantKeyVaultUris object = tenantVaultUris
output sqlServerFqdn string = sql.outputs.serverFqdn
output sqlDatabase string = sql.outputs.databaseName
output modelBaseUrl string = modelBaseUrl
output registryLoginServer string = createContainerRegistry ? acr!.outputs.loginServer : externalRegistryServer
output containerAppsEnvironment string = containerAppsEnv.outputs.name
output roleAssignmentCount int = rbac.outputs.count
output unsupportedRoleScopes array = rbac.outputs.unsupportedScopeIds

@description('Ingress URLs by agent (agents with ingress only).')
output agentUrls array = [
  for (a, i) in agents: a.ingress == 'none'
    ? { agent: a.name, url: '' }
    : { agent: a.name, url: 'https://${containerApps[i].outputs.fqdn}' }
]

@description('Per-agent identity details: needed for the SQL grant script and for granting pull on an external registry.')
output agentIdentities array = [
  for (a, i) in agents: {
    agent: a.name
    containerApp: containerApps[i].outputs.name
    identityName: identity.outputs.identities[i].name
    clientId: identity.outputs.identities[i].clientId
    principalId: identity.outputs.identities[i].principalId
    sqlRole: a.sql
  }
]

// T-SQL to run once as the Entra admin (sqlcmd -G). Creates contained users for the managed identities WITHOUT a
// directory lookup (SID from the client id) and adds them to three coarse roles. Narrow to table-level grants later.
var sqlRolesScript = '''
DECLARE @sid NVARCHAR(100), @sql NVARCHAR(400);
IF DATABASE_PRINCIPAL_ID('secagent_reader') IS NULL CREATE ROLE secagent_reader;
IF DATABASE_PRINCIPAL_ID('secagent_inserter') IS NULL CREATE ROLE secagent_inserter;
IF DATABASE_PRINCIPAL_ID('secagent_writer') IS NULL CREATE ROLE secagent_writer;
GRANT SELECT ON SCHEMA::dbo TO secagent_reader;
GRANT SELECT, INSERT ON SCHEMA::dbo TO secagent_inserter;
GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::dbo TO secagent_writer;
'''
func sqlUserStatement(identityName string, clientId string, role string) string =>
  'SET @sid = CONVERT(NVARCHAR(100), CONVERT(VARBINARY(16), CONVERT(UNIQUEIDENTIFIER, \'${clientId}\')), 1);\nIF DATABASE_PRINCIPAL_ID(N\'${identityName}\') IS NULL BEGIN SET @sql = N\'CREATE USER [${identityName}] WITH SID = \' + @sid + N\', TYPE = E;\'; EXEC (@sql); END\nALTER ROLE secagent_${role} ADD MEMBER [${identityName}];\n'

var sqlAgents = filter(range(0, length(agents)), i => agents[i].sql != 'none')

output sqlGrantScript string = '${sqlRolesScript}${join(map(sqlAgents, i => sqlUserStatement(identity.outputs.identities[i].name, identity.outputs.identities[i].clientId, agents[i].sql)), '')}'
