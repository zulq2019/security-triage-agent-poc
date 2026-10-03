// main.bicep - Security Triage & Fix Agent: one environment in one resource group.
// Composes the modules in ./modules. Same template for both deployment models (SDD 18):
//   - wipro-hosted    : multi-tenant service in Wipro's subscription (params/wipro-hosted.bicepparam)
//   - customer-hosted : single tenant in the customer's own subscription (params/customer-hosted.bicepparam)
// Nothing secret is in this file or the parameter files: all service-to-service auth is Microsoft Entra ID with
// user-assigned managed identities. Secret VALUES (HMAC key, GitHub App key, connector tokens) are put in Key Vault
// by an operator after deployment. See docs/infra.md.
targetScope = 'resourceGroup'

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

@description('wipro-hosted = multi-tenant service (per-tenant Key Vault and Blob containers); customer-hosted = single tenant in the customer subscription.')
@allowed(['wipro-hosted', 'customer-hosted'])
param deploymentModel string

@description('Wipro-hosted only: tenant codes (lowercase letters and digits, max 10), for example [ contoso, fabrikam ]. Each gets its own Key Vault and raw / evidence / context containers. Ignored for customer-hosted.')
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

@description('Internal-only Container Apps environment (needs private networking). The intake webhook then needs Front Door / Application Gateway in front of it.')
param internalEnvironment bool = false

@description('Zone-redundant Container Apps environment (needs private networking) [to confirm, NFR-08].')
param zoneRedundant bool = false

@description('CIDR allow-list on the public intake endpoint, for example the GitHub "hooks" ranges from https://api.github.com/meta. Empty = open (signature check still applies).')
param intakeAllowedSourceRanges string[] = []

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

@description('Fixer types. One queue fix-<type> and one Container App fixer-<type> each (SDD 4.2: library, secret, code, binary).')
param fixerTypes fixerType[] = ['library', 'secret', 'code', 'binary']

@minLength(2)
@maxLength(12)
@description('Fixer type: lowercase letters, digits and hyphens. Becomes queue fix-<type> and app ca-fixer-<type>-<env> (max 32 chars).')
type fixerType = string

@description('Queues created WITHOUT sessions (decision OD-03, for example [ triage ]). All others use SessionId = run id.')
param sessionlessQueues string[] = []

@description('Extra run-events subscriptions beyond dashboard and audit (for example notifier, a2a-status).')
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
@description('Microsoft Entra admin for Azure SQL: { login, objectId, principalType }. Use a group. Comes from an environment variable in the .bicepparam files.')
param sqlEntraAdmin object

@description('Azure SQL database SKU.')
param sqlDatabaseSku object = { name: 'GP_S_Gen5', tier: 'GeneralPurpose', family: 'Gen5', capacity: 2 }

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

@description('Model deployments: [ { name, model, version, skuName, capacity } ]. First = small tier, second = strong tier.')
param openAiDeployments object[] = []

@description('Use an existing OpenAI-compatible v1 endpoint instead (customer-owned Azure OpenAI or APIM gateway URL). Ignored when deployOpenAi = true.')
param existingModelBaseUrl string = ''

@description('Deployment / model names for the small and strong tiers when using existingModelBaseUrl.')
param existingModelNames object = { small: '', strong: '' }

// ---------------------------------------------------------------------------------------------------------------
// Container Apps
// ---------------------------------------------------------------------------------------------------------------
@description('Create an Azure Container Registry. False = use externalRegistryServer (grant AcrPull to the app identities there).')
param createContainerRegistry bool = true

@description('ACR SKU (Premium for private endpoint).')
@allowed(['Basic', 'Standard', 'Premium'])
param containerRegistrySku string = 'Basic'

@description('External registry login server when createContainerRegistry = false.')
param externalRegistryServer string = ''

@description('Deploy every app with a public placeholder image (first deployment, before images are pushed). Placeholder listens on port 80.')
param usePlaceholderImages bool = true

@description('Image tag (or use digests through imageOverrides).')
param imageTag string = 'latest'

@description('Per-app full image references, for example { triage: "<acr>/secagent-triage@sha256:..." }. Default: <registry>/secagent-<app>:<imageTag>.')
param imageOverrides object = {}

@description('Intake container port (SARIF / GitHub webhook endpoint).')
param intakeTargetPort int = 8080

@description('Agent API / dashboard container port (POC: secagent serve --port 8795).')
param agentApiTargetPort int = 8795

@description('Agent API / dashboard ingress. external needs agentApiAllowedSourceRanges and an auth layer in front (the POC dashboard has no login).')
@allowed(['none', 'internal', 'external'])
param agentApiIngress string = 'internal'

@description('CIDR allow-list for the agent API / dashboard when its ingress is external (office / VPN egress ranges).')
param agentApiAllowedSourceRanges string[] = []

@description('Min replicas for always-on apps (intake, agent-api, orchestrator). 0 in dev to save cost; 1 in prod (SDD 4.2).')
param alwaysOnMinReplicas int = 0

@description('Max replicas per queue worker.')
param workerMaxReplicas int = 5

@description('Active messages per replica for the KEDA scalers.')
param messagesPerReplica int = 5

@description('CPU / memory per app class: { light: { cpu, memory }, heavy: { cpu, memory } }.')
param appSizing object = {
  light: { cpu: '0.5', memory: '1Gi' }
  heavy: { cpu: '2.0', memory: '4Gi' }
}

@description('Key Vault references per app: { <app>: [ { envName, secretName } ] } (platform vault). The secret must exist before you set this.')
param appKeyVaultReferences object = {}

// ===============================================================================================================
// Naming convention: <type>-<workload>-<env>-<region>[-<unique>], with <unique> only where the name is global.
// Per-app resources: ca-<app>-<env>, id-<app>-<env>. Storage / ACR: no hyphens.
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

var isMultiTenant = deploymentModel == 'wipro-hosted' && !empty(tenants)
var tenantList = isMultiTenant ? tenants : []
var tenantKeyVaultNames = [for t in tenantList: 'kv-${t}-${envCode}-${unique}']

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

// Blob containers (SDD 11.4): raw scanner output and SARIF, write-once evidence, context packs, exports.
var containerSuffixes = isMultiTenant ? map(tenantList, t => '-${t}') : ['']
var rawContainers = map(containerSuffixes, s => 'raw${s}')
var evidenceContainers = map(containerSuffixes, s => 'evidence${s}')
var contextContainers = map(containerSuffixes, s => 'context${s}')
var allContainers = concat(rawContainers, evidenceContainers, contextContainers, ['exports'])

// Service Bus (SDD 7.2). Queue names use '-' (fix-library); the SDD draws them as fix.library.
var fixQueues = map(fixerTypes, t => 'fix-${t}')
var workQueueNames = concat(['runs', 'scan', 'triage'], fixQueues, ['verify', 'results'])
var queues = map(workQueueNames, q => { name: q, requiresSession: !contains(sessionlessQueues, q) })
var topicName = 'run-events'
var topicSubscriptions = union(['dashboard', 'audit'], extraTopicSubscriptions)

// One entry per Container App = one agent / step (SDD 4.2) with its own identity and least-privilege access (SDD 13.1).
// sqlRole: none | reader | inserter | writer (database roles created by the generated SQL grant script).
var noAccess = {
  ingress: 'none'
  send: []
  receive: []
  sendTopic: false
  receiveSubs: []
  blobRead: []
  blobWrite: []
  keyVault: false
  model: false
  sqlRole: 'none'
  size: 'light'
  alwaysOn: false
}
var fixerApps = [
  for t in fixerTypes: union(noAccess, {
    key: 'fixer-${t}'
    receive: ['fix-${t}']
    send: ['results']
    blobRead: rawContainers
    blobWrite: contextContainers
    model: true
    sqlRole: 'inserter'
    size: 'heavy'
  })
]
var apps = concat(
  [
    union(noAccess, {
      key: 'intake'
      ingress: 'external'
      send: ['runs']
      blobWrite: rawContainers
      keyVault: true
      alwaysOn: true
    })
    union(noAccess, {
      key: 'agent-api'
      ingress: agentApiIngress
      send: ['runs']
      receiveSubs: ['dashboard']
      blobRead: concat(rawContainers, evidenceContainers, contextContainers)
      blobWrite: ['exports']
      sqlRole: 'inserter'
      alwaysOn: true
    })
    union(noAccess, {
      key: 'orchestrator'
      send: concat(['scan', 'triage'], fixQueues, ['verify'])
      receive: ['runs', 'results']
      sendTopic: true
      blobRead: concat(rawContainers, evidenceContainers, contextContainers)
      keyVault: true
      sqlRole: 'writer'
      alwaysOn: true
    })
    union(noAccess, {
      key: 'scanner'
      receive: ['scan']
      send: ['results']
      blobWrite: rawContainers
      keyVault: true
      size: 'heavy'
    })
    union(noAccess, {
      key: 'triage'
      receive: ['triage']
      send: ['results']
      blobRead: rawContainers
      blobWrite: contextContainers
      model: true
      sqlRole: 'inserter'
    })
  ],
  fixerApps,
  [
    union(noAccess, {
      key: 'verifier'
      receive: ['verify']
      send: ['results']
      blobRead: rawContainers
      blobWrite: evidenceContainers
      model: true
      sqlRole: 'inserter'
      size: 'heavy'
    })
    union(noAccess, {
      key: 'audit-writer'
      receiveSubs: ['audit']
      blobWrite: evidenceContainers
      sqlRole: 'inserter'
    })
  ]
)
var appKeys = map(apps, a => a.key)

var useVnet = enablePrivateNetworking
var placeholderImage = 'mcr.microsoft.com/k8se/quickstart:latest'
var registryServer = usePlaceholderImages
  ? ''
  : (createContainerRegistry ? acr!.outputs.loginServer : externalRegistryServer)

// ===============================================================================================================
// Platform
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

module network 'modules/network.bicep' = if (useVnet) {
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
    appKeys: appKeys
    environmentName: envCode
    tags: tags
  }
}

module keyVault 'modules/keyvault.bicep' = {
  name: 'keyvault-platform'
  params: {
    location: location
    name: names.keyVault
    enablePurgeProtection: keyVaultPurgeProtection
    softDeleteRetentionInDays: keyVaultSoftDeleteDays
    vaultOperatorsGroupId: keyVaultOperatorsGroupId
    disablePublicNetworkAccess: enablePrivateNetworking
    logAnalyticsId: monitoring.outputs.logAnalyticsId
    tags: tags
  }
}

module tenantKeyVaults 'modules/keyvault.bicep' = [
  for (t, i) in tenantList: {
    name: 'keyvault-tenant-${t}'
    params: {
      location: location
      name: tenantKeyVaultNames[i]
      enablePurgeProtection: keyVaultPurgeProtection
      softDeleteRetentionInDays: keyVaultSoftDeleteDays
      vaultOperatorsGroupId: keyVaultOperatorsGroupId
      disablePublicNetworkAccess: enablePrivateNetworking
      logAnalyticsId: monitoring.outputs.logAnalyticsId
      tags: union(tags, { tenant: t })
    }
  }
]

module serviceBus 'modules/servicebus.bicep' = {
  name: 'servicebus'
  params: {
    location: location
    name: names.serviceBus
    sku: serviceBusSku
    premiumMessagingUnits: serviceBusMessagingUnits
    queues: queues
    topicName: topicName
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
    containerNames: allContainers
    immutableContainerNames: evidenceContainers
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
    allowAzureServices: !useVnet
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
// Private endpoints (only with private networking)
// ---------------------------------------------------------------------------------------------------------------
module peBlob 'modules/privateendpoint.bicep' = if (useVnet) {
  name: 'pe-blob'
  params: {
    location: location
    name: 'pe-${names.storage}-blob'
    subnetId: network!.outputs.privateEndpointSubnetId
    targetResourceId: storage.outputs.id
    groupId: 'blob'
    privateDnsZoneId: network!.outputs.dnsZoneIds.blob
    tags: tags
  }
}

module peKeyVault 'modules/privateendpoint.bicep' = if (useVnet) {
  name: 'pe-kv-platform'
  params: {
    location: location
    name: 'pe-${names.keyVault}'
    subnetId: network!.outputs.privateEndpointSubnetId
    targetResourceId: keyVault.outputs.id
    groupId: 'vault'
    privateDnsZoneId: network!.outputs.dnsZoneIds.vault
    tags: tags
  }
}

module peTenantKeyVaults 'modules/privateendpoint.bicep' = [
  for (t, i) in tenantList: if (useVnet) {
    name: 'pe-kv-tenant-${t}'
    params: {
      location: location
      name: 'pe-${tenantKeyVaultNames[i]}'
      subnetId: network!.outputs.privateEndpointSubnetId
      targetResourceId: tenantKeyVaults[i].outputs.id
      groupId: 'vault'
      privateDnsZoneId: network!.outputs.dnsZoneIds.vault
      tags: union(tags, { tenant: t })
    }
  }
]

module peSql 'modules/privateendpoint.bicep' = if (useVnet) {
  name: 'pe-sql'
  params: {
    location: location
    name: 'pe-${names.sqlServer}'
    subnetId: network!.outputs.privateEndpointSubnetId
    targetResourceId: sql.outputs.serverId
    groupId: 'sqlServer'
    privateDnsZoneId: network!.outputs.dnsZoneIds.sql
    tags: tags
  }
}

module peServiceBus 'modules/privateendpoint.bicep' = if (useVnet && serviceBusSku == 'Premium') {
  name: 'pe-servicebus'
  params: {
    location: location
    name: 'pe-${names.serviceBus}'
    subnetId: network!.outputs.privateEndpointSubnetId
    targetResourceId: serviceBus.outputs.id
    groupId: 'namespace'
    privateDnsZoneId: network!.outputs.dnsZoneIds.servicebus
    tags: tags
  }
}

module peOpenAi 'modules/privateendpoint.bicep' = if (useVnet && deployOpenAi) {
  name: 'pe-openai'
  params: {
    location: location
    name: 'pe-${names.openAi}'
    subnetId: network!.outputs.privateEndpointSubnetId
    targetResourceId: openAi!.outputs.id
    groupId: 'account'
    privateDnsZoneId: network!.outputs.dnsZoneIds.openai
    tags: tags
  }
}

module peAcr 'modules/privateendpoint.bicep' = if (useVnet && createContainerRegistry && containerRegistrySku == 'Premium') {
  name: 'pe-acr'
  params: {
    location: location
    name: 'pe-${names.registry}'
    subnetId: network!.outputs.privateEndpointSubnetId
    targetResourceId: acr!.outputs.id
    groupId: 'registry'
    privateDnsZoneId: network!.outputs.dnsZoneIds.acr
    tags: tags
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Least-privilege RBAC, one module per app identity
// ---------------------------------------------------------------------------------------------------------------
module rbac 'modules/rbac.bicep' = [
  for (a, i) in apps: {
    name: 'rbac-${a.key}'
    params: {
      principalId: identity.outputs.identities[i].principalId
      serviceBusName: serviceBus.outputs.name
      sendQueues: a.send
      receiveQueues: a.receive
      topicName: topicName
      sendTopic: a.sendTopic
      receiveSubscriptions: a.receiveSubs
      storageAccountName: storage.outputs.name
      blobReadContainers: a.blobRead
      blobWriteContainers: a.blobWrite
      keyVaultNames: a.keyVault ? concat([keyVault.outputs.name], tenantKeyVaultNames) : []
      openAiAccountName: (a.model && deployOpenAi) ? openAi!.outputs.name : ''
      containerRegistryName: createContainerRegistry ? acr!.outputs.name : ''
    }
    dependsOn: [tenantKeyVaults]
  }
]

// ---------------------------------------------------------------------------------------------------------------
// Container Apps environment + one app per agent / step
// ---------------------------------------------------------------------------------------------------------------
module containerAppsEnv 'modules/containerapps-env.bicep' = {
  name: 'containerapps-env'
  params: {
    location: location
    name: names.containerAppsEnv
    infrastructureSubnetId: useVnet ? network!.outputs.containerAppsSubnetId : ''
    internal: useVnet && internalEnvironment
    zoneRedundant: useVnet && zoneRedundant
    logAnalyticsId: monitoring.outputs.logAnalyticsId
    tags: tags
  }
}

var modelBaseUrl = deployOpenAi ? openAi!.outputs.v1BaseUrl : existingModelBaseUrl
var smallModel = deployOpenAi
  ? (length(openAiDeployments) > 0 ? openAiDeployments[0].name : '')
  : existingModelNames.small
var strongModel = deployOpenAi
  ? (length(openAiDeployments) > 1 ? openAiDeployments[1].name : smallModel)
  : existingModelNames.strong

module containerApps 'modules/containerapp.bicep' = [
  for (a, i) in apps: {
    name: 'ca-${a.key}'
    params: {
      name: 'ca-${a.key}-${envCode}'
      location: location
      environmentId: containerAppsEnv.outputs.id
      identityId: identity.outputs.identities[i].id
      identityClientId: identity.outputs.identities[i].clientId
      image: usePlaceholderImages
        ? placeholderImage
        : (imageOverrides[?a.key] ?? '${registryServer}/${workload}-${a.key}:${imageTag}')
      registryServer: registryServer
      ingress: a.ingress
      targetPort: usePlaceholderImages ? 80 : (a.key == 'intake' ? intakeTargetPort : agentApiTargetPort)
      allowedSourceIpRanges: a.key == 'intake'
        ? intakeAllowedSourceRanges
        : (a.key == 'agent-api' ? agentApiAllowedSourceRanges : [])
      cpu: appSizing[a.size].cpu
      memory: appSizing[a.size].memory
      minReplicas: a.alwaysOn ? alwaysOnMinReplicas : 0
      maxReplicas: a.alwaysOn ? max(alwaysOnMinReplicas, 3) : workerMaxReplicas
      serviceBusNamespace: serviceBus.outputs.name
      serviceBusScaleRules: concat(
        map(a.receive, q => { queueName: q }),
        map(a.receiveSubs, s => { topicName: topicName, subscriptionName: s })
      )
      messageCountPerReplica: messagesPerReplica
      httpConcurrentRequests: 20
      env: concat(
        [
          { name: 'SECAGENT_PROFILE', value: deploymentModel }
          { name: 'SECAGENT_ENVIRONMENT', value: environmentName }
          { name: 'SECAGENT_AGENT', value: a.key }
          { name: 'SECAGENT_QUEUE', value: 'servicebus' }
          { name: 'SECAGENT_SERVICEBUS_NAMESPACE', value: serviceBus.outputs.fullyQualifiedNamespace }
          { name: 'SECAGENT_RUN_EVENTS_TOPIC', value: topicName }
          { name: 'SECAGENT_BLOB_ENDPOINT', value: storage.outputs.blobEndpoint }
          { name: 'SECAGENT_KEYVAULT_URI', value: keyVault.outputs.uri }
          { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: monitoring.outputs.appInsightsConnectionString }
        ],
        a.sqlRole == 'none'
          ? []
          : [
              {
                // No password: Entra ID token for the app's own managed identity.
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
          : []
      )
      keyVaultSecrets: map(appKeyVaultReferences[?a.key] ?? [], s => {
        envName: s.envName
        secretName: toLower(s.secretName)
        keyVaultSecretUri: '${keyVault.outputs.uri}secrets/${s.secretName}'
      })
      tags: union(tags, { app: a.key })
    }
    dependsOn: [rbac]
  }
]

// ===============================================================================================================
// Outputs (no secrets)
// ===============================================================================================================
output resourceNames object = names
output tenantKeyVaults array = tenantKeyVaultNames
output serviceBusNamespace string = serviceBus.outputs.fullyQualifiedNamespace
output queues array = workQueueNames
output topic object = { name: topicName, subscriptions: topicSubscriptions }
output blobContainers array = allContainers
output keyVaultUri string = keyVault.outputs.uri
output sqlServerFqdn string = sql.outputs.serverFqdn
output sqlDatabase string = sql.outputs.databaseName
output modelBaseUrl string = modelBaseUrl
output registryLoginServer string = createContainerRegistry ? acr!.outputs.loginServer : externalRegistryServer
output containerAppsEnvironment string = containerAppsEnv.outputs.name

@description('Public (or VNet) URL for the SARIF / GitHub webhook intake.')
output intakeUrl string = 'https://${containerApps[0].outputs.fqdn}'

@description('Per-app identity details: needed for the SQL grant script and for granting pull on an external registry.')
output appIdentities array = [
  for (a, i) in apps: {
    app: a.key
    containerApp: containerApps[i].outputs.name
    identityName: identity.outputs.identities[i].name
    clientId: identity.outputs.identities[i].clientId
    principalId: identity.outputs.identities[i].principalId
    sqlRole: a.sqlRole
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

var sqlApps = filter(range(0, length(apps)), i => apps[i].sqlRole != 'none')

output sqlGrantScript string = '${sqlRolesScript}${join(map(sqlApps, i => sqlUserStatement(identity.outputs.identities[i].name, identity.outputs.identities[i].clientId, apps[i].sqlRole)), '')}'
