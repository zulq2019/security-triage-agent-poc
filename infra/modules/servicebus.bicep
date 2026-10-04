// servicebus.bicep - Service Bus namespace (Entra ID only, no SAS), one work queue per kind of work, the run-events
// topic and its subscriptions (SDD 7). Queue settings follow SDD 7.4; values marked [to agree] there are parameters.
import { queueSpec } from '../types.bicep'

@description('Azure region.')
param location string

@description('Namespace name (6-50 chars, globally unique).')
param name string

@description('Standard or Premium. Private endpoints and VNet isolation need Premium; sessions and topics work on both.')
@allowed(['Standard', 'Premium'])
param sku string

@description('Premium messaging units (1, 2, 4, 8 or 16). Ignored for Standard.')
@allowed([1, 2, 4, 8, 16])
param premiumMessagingUnits int

@description('Work queues to create.')
param queues queueSpec[]

@description('Topic for run progress events (published once, fanned out to subscriptions).')
param topicName string

@description('Subscriptions on the topic, for example [ dashboard, audit ].')
param topicSubscriptions string[]

@description('Deliveries before a message is dead-lettered (POC InProcessQueue: 3).')
@minValue(1)
param maxDeliveryCount int

@description('Peek-lock duration (ISO 8601, max PT5M). Workers auto-renew for long steps.')
param lockDuration string

@description('Duplicate detection window (ISO 8601). MessageId = idempotency key (POC: 10 minutes).')
param duplicateDetectionWindow string

@description('Default message time to live (ISO 8601). Stale work is dead-lettered after this.')
param messageTimeToLive string

@description('Disable public network access (Premium + private endpoint only).')
param disablePublicNetworkAccess bool

@description('Log Analytics workspace for diagnostic logs.')
param logAnalyticsId string

@description('Action group for the dead-letter alert. Empty = no alert.')
param actionGroupId string

@description('Tags.')
param tags object

var isPremium = sku == 'Premium'

resource sb 'Microsoft.ServiceBus/namespaces@2026-01-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: sku
    tier: sku
    capacity: isPremium ? premiumMessagingUnits : null
  }
  properties: {
    disableLocalAuth: true // Entra ID (managed identity) only: no SAS keys or connection strings anywhere
    minimumTlsVersion: '1.2'
    publicNetworkAccess: (isPremium && disablePublicNetworkAccess) ? 'Disabled' : 'Enabled'
    zoneRedundant: isPremium ? true : null
  }
}

resource sbQueues 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' = [
  for q in queues: {
    parent: sb
    name: q.name
    properties: {
      requiresSession: q.requiresSession
      requiresDuplicateDetection: true
      duplicateDetectionHistoryTimeWindow: duplicateDetectionWindow
      maxDeliveryCount: maxDeliveryCount
      lockDuration: lockDuration
      defaultMessageTimeToLive: messageTimeToLive
      deadLetteringOnMessageExpiration: true
      enablePartitioning: false
    }
  }
]

resource topic 'Microsoft.ServiceBus/namespaces/topics@2026-01-01' = {
  parent: sb
  name: topicName
  properties: {
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: duplicateDetectionWindow
    defaultMessageTimeToLive: messageTimeToLive
    enablePartitioning: false
  }
}

resource subs 'Microsoft.ServiceBus/namespaces/topics/subscriptions@2026-01-01' = [
  for s in topicSubscriptions: {
    parent: topic
    name: s
    properties: {
      maxDeliveryCount: maxDeliveryCount
      lockDuration: lockDuration
      defaultMessageTimeToLive: messageTimeToLive
      deadLetteringOnMessageExpiration: true
      deadLetteringOnFilterEvaluationExceptions: true
    }
  }
]

// 2021-05-01-preview is the newest version with categoryGroup support (2016-09-01 lacks it).
#disable-next-line use-recent-api-versions
resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-log-analytics'
  scope: sb
  properties: {
    workspaceId: logAnalyticsId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

// SDD 7.4: a dead letter means a human task; alert as soon as any entity has one.
resource dlqAlert 'Microsoft.Insights/metricAlerts@2026-01-01' = if (!empty(actionGroupId)) {
  name: 'alert-${name}-deadletter'
  location: 'global'
  tags: tags
  properties: {
    description: 'Dead-lettered messages on any Service Bus queue or subscription.'
    severity: 2
    enabled: true
    scopes: [sb.id]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'deadletter'
          criterionType: 'StaticThresholdCriterion'
          metricNamespace: 'Microsoft.ServiceBus/namespaces'
          metricName: 'DeadletteredMessages'
          dimensions: [{ name: 'EntityName', operator: 'Include', values: ['*'] }]
          operator: 'GreaterThan'
          threshold: 0
          timeAggregation: 'Maximum'
        }
      ]
    }
    actions: [{ actionGroupId: actionGroupId }]
  }
}

output id string = sb.id
output name string = sb.name
@description('Fully qualified namespace for the SDK (ServiceBusClient with DefaultAzureCredential).')
output fullyQualifiedNamespace string = split(replace(sb.properties.serviceBusEndpoint, 'https://', ''), ':')[0]
@description('Queue resource ids by queue name.')
output queueIds object = toObject(
  range(0, length(queues)),
  i => queues[i].name,
  i => resourceId('Microsoft.ServiceBus/namespaces/queues', sb.name, queues[i].name)
)
output topicName string = topic.name
output topicId string = topic.id
@description('Subscription resource ids by subscription name.')
output subscriptionIds object = toObject(
  range(0, length(topicSubscriptions)),
  i => topicSubscriptions[i],
  i => resourceId('Microsoft.ServiceBus/namespaces/topics/subscriptions', sb.name, topic.name, topicSubscriptions[i])
)
