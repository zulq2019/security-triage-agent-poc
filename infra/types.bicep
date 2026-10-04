// types.bicep - shared, exported user-defined types and constants. No resources.
// Modules and main.bicep import what they need:  import { agentSpec } from 'types.bicep'

// ---------------------------------------------------------------------------------------------------------------
// Agents (one Container App + one managed identity each)
// ---------------------------------------------------------------------------------------------------------------
@export()
@description('Blob container purpose. raw = scanner output / SARIF, evidence = write-once (WORM), context = context packs, exports = reports.')
type blobPurpose = 'raw' | 'evidence' | 'context' | 'exports'

@export()
@description('Database role granted by the generated SQL grant script.')
type sqlRole = 'none' | 'reader' | 'inserter' | 'writer'

@export()
@description('Ingress mode. none = queue worker; internal = environment / VNet only; external = public endpoint.')
type ingressMode = 'none' | 'internal' | 'external'

@export()
@description('One agent / step. Everything about its wiring is data: adding an agent means adding one of these (agents.bicep or the additionalAgents parameter), never editing a module.')
type agentSpec = {
  @description('Short name, lowercase letters, digits and hyphens. Becomes ca-<name>-<env> and id-<name>-<env>.')
  @minLength(2)
  @maxLength(20)
  name: string

  @description('What the agent does (documentation only).')
  description: string?

  @description('Default ingress (environments can override it with agentOverrides).')
  ingress: ingressMode?

  @description('Container port when the agent has ingress.')
  targetPort: int?

  @description('Always-on (uses alwaysOnMinReplicas) instead of scale-to-zero.')
  alwaysOn: bool?

  @description('Sizing class, a key of the appSizing parameter (for example light, heavy).')
  size: string?

  @description('Queues the agent consumes. Each one is created, gets a KEDA scale rule and a Receiver role.')
  consumes: string[]?

  @description('run-events subscriptions the agent consumes. Each one is created, gets a KEDA rule and a Receiver role.')
  subscribes: string[]?

  @description('Queues the agent sends to (Sender role).')
  sends: string[]?

  @description('Publishes to the run-events topic.')
  publishesEvents: bool?

  @description('Dispatcher (the orchestrator): may send to every queue consumed by a non-dispatcher agent, so new workers need no change here.')
  dispatchesWork: bool?

  @description('Blob purposes it may read.')
  blobRead: blobPurpose[]?

  @description('Blob purposes it may write.')
  blobWrite: blobPurpose[]?

  @description('Reads secrets from Key Vault (platform vault and, in multi-tenant mode, every tenant vault).')
  keyVault: bool?

  @description('Calls the model endpoint (gets Cognitive Services OpenAI User when Azure OpenAI is deployed, and the model env vars).')
  model: bool?

  @description('Azure SQL database role.')
  sql: sqlRole?
}

@export()
@description('Environment-specific settings for one agent, keyed by agent name in the agentOverrides parameter.')
type agentOverride = {
  ingress: ingressMode?
  @description('CIDR allow-list on the ingress.')
  allowedSourceRanges: string[]?
  minReplicas: int?
  maxReplicas: int?
  @description('Full image reference (prefer a digest).')
  image: string?
  @description('Key Vault references exposed as env vars. The secret must exist in the target vault (platform, or the tenant\'s) first.')
  keyVaultReferences: keyVaultReference[]?
}

@export()
@description('Container Apps resources for a sizing class.')
type containerResources = {
  @description('vCPU as a string, for example "0.5".')
  cpu: string
  @description('Memory, for example "1Gi".')
  memory: string
}

@export()
@description('A Key Vault secret exposed to the container as an env var: from the platform vault, or from one tenant\'s vault.')
type keyVaultReference = {
  envName: string
  @description('Key Vault secret name (lowercase letters, digits and hyphens).')
  secretName: string
  @description('Tenant code (one of the tenants parameter) whose vault holds the secret. Omit for the platform vault.')
  tenant: string?
}

@export()
@description('A resolved Key Vault reference for the containerapp module.')
type keyVaultSecretRef = {
  envName: string
  @description('Container Apps secret name.')
  secretName: string
  @description('Versionless secret URI, so rotation is picked up.')
  keyVaultSecretUri: string
}

@export()
@description('Plain environment variable. Never a secret value.')
type envVar = {
  name: string
  value: string
}

@export()
@description('One KEDA azure-servicebus rule: queueName, or topicName + subscriptionName.')
type serviceBusScaleRule = {
  queueName: string?
  topicName: string?
  subscriptionName: string?
}

@export()
@description('Ingress settings for the containerapp module.')
type ingressSpec = {
  mode: ingressMode
  targetPort: int
  allowedSourceRanges: string[]
}

@export()
@description('Replica bounds and scale targets for the containerapp module.')
type scaleSpec = {
  @minValue(0)
  minReplicas: int
  @minValue(1)
  maxReplicas: int
  @description('Active messages per replica for the KEDA rules.')
  @minValue(1)
  messagesPerReplica: int
  @description('Concurrent HTTP requests per replica (apps with ingress).')
  @minValue(1)
  httpConcurrentRequests: int
}

// ---------------------------------------------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------------------------------------------
@export()
@description('Service Bus queue definition.')
type queueSpec = {
  name: string
  requiresSession: bool
}

@export()
@description('Blob container definition.')
type containerSpec = {
  name: string
  purpose: blobPurpose
  @description('Gets a time-based immutability (WORM) policy.')
  immutable: bool
}

@export()
@description('Microsoft Entra admin of the Azure SQL server. Use a group.')
type sqlEntraAdmin = {
  @description('Display name of the group / principal.')
  login: string
  @description('Object id.')
  objectId: string
  principalType: 'Group' | 'User' | 'Application'
}

@export()
@description('Azure SQL database SKU, for example { name: GP_S_Gen5, tier: GeneralPurpose, family: Gen5, capacity: 2 }.')
type sqlSku = {
  name: string
  tier: string
  family: string?
  capacity: int
}

@export()
@description('Azure OpenAI model deployment. skuName Standard keeps processing in region; capacity = thousands of tokens per minute.')
type modelDeployment = {
  name: string
  model: string
  version: string
  skuName: 'Standard' | 'DataZoneStandard' | 'GlobalStandard' | 'ProvisionedManaged'
  capacity: int
}

@export()
@description('One role assignment for the role-assignments module: who, which built-in role, on which resource id.')
type roleAssignmentSpec = {
  principalId: string
  @description('Role definition GUID (see builtInRoles).')
  roleDefinitionId: string
  @description('Full resource id of the scope (queue, topic, subscription, blob container, vault, OpenAI account, registry).')
  scopeId: string
  principalType: 'ServicePrincipal' | 'Group' | 'User'
}

@export()
@description('Identity details returned by the identity module.')
type identityInfo = {
  name: string
  id: string
  principalId: string
  clientId: string
}

@export()
@description('Built-in Azure role definition ids used by this template (stable across tenants).')
var builtInRoles = {
  serviceBusDataSender: '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'
  serviceBusDataReceiver: '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0'
  storageBlobDataReader: '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
  storageBlobDataContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  vaultUser: '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User
  vaultOfficer: 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' // Key Vault Secrets Officer
  openAiUser: '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd' // Cognitive Services OpenAI User
  acrPull: '7f951dda-4ed3-4680-a7ca-43fe172d538d'
}

@export()
@description('Per-environment agent settings keyed by agent name, for example { "agent-api": { ingress: "external" } }.')
type agentOverrideMap = {
  *: agentOverride
}

@export()
@description('Sizing classes keyed by name, for example { light: { cpu: "0.5", memory: "1Gi" } }.')
type sizingMap = {
  *: containerResources
}

@export()
@description('Key Vault to create.')
type vaultSpec = {
  @minLength(3)
  @maxLength(24)
  name: string
  tags: object
}

@export()
@description('Key Vault returned by the keyvault module.')
type vaultInfo = {
  name: string
  id: string
  uri: string
}

@export()
@description('Model names for the small and strong tiers.')
type modelTierNames = {
  small: string
  strong: string
}
