// monitoring.bicep - Log Analytics workspace, workspace-based Application Insights (OpenTelemetry target),
// and an optional action group for alerts (SDD 15).

@description('Azure region.')
param location string

@description('Log Analytics workspace name.')
param logAnalyticsName string

@description('Application Insights component name.')
param appInsightsName string

@description('Action group name (only created when alertEmailReceivers is not empty).')
param actionGroupName string

@description('Log retention in days (Log Analytics and Application Insights).')
@minValue(30)
@maxValue(730)
param retentionInDays int

@description('Daily ingestion cap in GB. -1 = no cap. A cap is a cost guard: data above it is dropped for the rest of the day.')
param dailyQuotaGb int

@description('E-mail addresses for alerts. Empty = no action group.')
param alertEmailReceivers string[]

@description('Tags.')
param tags object

resource law 'Microsoft.OperationalInsights/workspaces@2025-02-01' = {
  name: logAnalyticsName
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: retentionInDays
    workspaceCapping: { dailyQuotaGb: dailyQuotaGb }
    features: { enableLogAccessUsingOnlyResourcePermissions: true }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'other'
    WorkspaceResourceId: law.id
    IngestionMode: 'LogAnalytics'
    RetentionInDays: retentionInDays
  }
}

resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = if (!empty(alertEmailReceivers)) {
  name: actionGroupName
  location: 'global'
  tags: tags
  properties: {
    groupShortName: 'secagent'
    enabled: true
    emailReceivers: [
      for (email, i) in alertEmailReceivers: {
        name: 'email-${i}'
        emailAddress: email
        useCommonAlertSchema: true
      }
    ]
  }
}

output logAnalyticsId string = law.id
output logAnalyticsName string = law.name
output appInsightsId string = appInsights.id
output appInsightsName string = appInsights.name
@description('Not a secret (Microsoft guidance), but kept out of source: passed to apps as APPLICATIONINSIGHTS_CONNECTION_STRING.')
output appInsightsConnectionString string = appInsights.properties.ConnectionString
@description('Empty when no action group is created.')
output actionGroupId string = empty(alertEmailReceivers) ? '' : actionGroup.id
