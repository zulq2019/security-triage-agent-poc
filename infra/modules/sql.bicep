// sql.bicep - Azure SQL logical server with Microsoft Entra-only authentication (no SQL logins, no passwords),
// one database, auditing to Log Analytics (SDD 9, 13).
// Database users for the app identities cannot be created by ARM: run infra/sql/grant-managed-identities.sql
// as the Entra admin after deployment (deploy.sh prints the command).
import { sqlEntraAdmin, sqlSku } from '../types.bicep'

@description('Azure region.')
param location string

@description('Logical server name (globally unique).')
param serverName string

@description('Database name.')
param databaseName string

@description('Microsoft Entra admin of the server: a GROUP is recommended. { login: display name, objectId, principalType: Group | User | Application }.')
param entraAdmin sqlEntraAdmin

@description('Database SKU, for example { name: GP_S_Gen5, tier: GeneralPurpose, family: Gen5, capacity: 2 } (serverless) or { name: GP_Gen5, tier: GeneralPurpose, family: Gen5, capacity: 2 }.')
param databaseSku sqlSku

@description('Serverless only: minutes of inactivity before auto-pause (-1 = never). Ignored for provisioned SKUs.')
param autoPauseDelayMinutes int

@description('Zone-redundant database (supported SKUs and regions only) [to confirm, NFR-08].')
param zoneRedundant bool

@description('Backup storage redundancy: Local, Zone or Geo.')
@allowed(['Local', 'Zone', 'Geo'])
param backupStorageRedundancy string

@description('Disable public network access (use with a private endpoint).')
param disablePublicNetworkAccess bool

@description('When public access is on: add the "Allow Azure services" firewall rule. Needed when the Container Apps environment has no VNet (its outbound IPs are not fixed).')
param allowAzureServices bool

@description('Log Analytics workspace for audit and diagnostic logs.')
param logAnalyticsId string

@description('Tags.')
param tags object

var isServerless = contains(databaseSku.name, '_S_')

resource server 'Microsoft.Sql/servers@2025-01-01' = {
  name: serverName
  location: location
  tags: tags
  properties: {
    minimalTlsVersion: '1.2'
    publicNetworkAccess: disablePublicNetworkAccess ? 'Disabled' : 'Enabled'
    administrators: {
      administratorType: 'ActiveDirectory'
      azureADOnlyAuthentication: true
      login: entraAdmin.login
      sid: entraAdmin.objectId
      principalType: entraAdmin.principalType
      tenantId: subscription().tenantId
    }
  }
}

resource allowAzure 'Microsoft.Sql/servers/firewallRules@2025-01-01' = if (!disablePublicNetworkAccess && allowAzureServices) {
  parent: server
  name: 'AllowAllWindowsAzureIps'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

resource db 'Microsoft.Sql/servers/databases@2025-01-01' = {
  parent: server
  name: databaseName
  location: location
  tags: tags
  sku: databaseSku
  properties: union(
    {
      zoneRedundant: zoneRedundant
      requestedBackupStorageRedundancy: backupStorageRedundancy
    },
    isServerless ? { autoPauseDelay: autoPauseDelayMinutes, minCapacity: json('0.5') } : {}
  )
}

// Server auditing to Azure Monitor (Log Analytics). The diagnostic setting has to sit on the master database.
resource auditing 'Microsoft.Sql/servers/auditingSettings@2025-01-01' = {
  parent: server
  name: 'default'
  properties: {
    state: 'Enabled'
    isAzureMonitorTargetEnabled: true
  }
}

resource master 'Microsoft.Sql/servers/databases@2025-01-01' existing = {
  parent: server
  name: 'master'
}

// 2021-05-01-preview is the newest version with categoryGroup support (2016-09-01 lacks it).
#disable-next-line use-recent-api-versions
resource auditDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'audit-to-log-analytics'
  scope: master
  properties: {
    workspaceId: logAnalyticsId
    logs: [{ category: 'SQLSecurityAuditEvents', enabled: true }]
  }
}

// 2021-05-01-preview is the newest version with categoryGroup support (2016-09-01 lacks it).
#disable-next-line use-recent-api-versions
resource dbDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-log-analytics'
  scope: db
  properties: {
    workspaceId: logAnalyticsId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'Basic', enabled: true }]
  }
}

output serverId string = server.id
output serverName string = server.name
output serverFqdn string = server.properties.fullyQualifiedDomainName
output databaseName string = db.name
