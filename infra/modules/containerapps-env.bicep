// containerapps-env.bicep - Container Apps environment (workload profiles, Consumption profile) with logs to
// Log Analytics through Azure Monitor diagnostic settings (no workspace shared key in the template).
// Optional VNet integration; optional internal-only mode (no public load balancer).

@description('Azure region.')
param location string

@description('Environment name.')
param name string

@description('Infrastructure subnet (delegated to Microsoft.App/environments). Empty = no VNet integration.')
param infrastructureSubnetId string

@description('Internal-only environment: apps get no public endpoint (needs a VNet; the intake webhook then needs a front door / app gateway in front).')
param internal bool

@description('Zone redundancy (needs a VNet) [to confirm, NFR-08].')
param zoneRedundant bool

@description('Log Analytics workspace for console and system logs.')
param logAnalyticsId string

@description('Tags.')
param tags object

var useVnet = !empty(infrastructureSubnetId)

resource env 'Microsoft.App/managedEnvironments@2025-01-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: { destination: 'azure-monitor' }
    workloadProfiles: [{ name: 'Consumption', workloadProfileType: 'Consumption' }]
    vnetConfiguration: useVnet
      ? {
          infrastructureSubnetId: infrastructureSubnetId
          internal: internal
        }
      : null
    zoneRedundant: useVnet ? zoneRedundant : false
    peerTrafficConfiguration: { encryption: { enabled: true } }
  }
}

// 2021-05-01-preview is the newest version with categoryGroup support (2016-09-01 lacks it).
#disable-next-line use-recent-api-versions
resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-log-analytics'
  scope: env
  properties: {
    workspaceId: logAnalyticsId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
  }
}

output id string = env.id
output name string = env.name
output defaultDomain string = env.properties.defaultDomain
output staticIp string = env.properties.staticIp
