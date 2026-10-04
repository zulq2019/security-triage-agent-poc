// agents.bicep - the agent catalogue (SDD 4.2 "one container app per agent type", SDD 13.1 identity table).
// Pure data, the same for every environment and both deployment models. To add an agent, add an entry here (or,
// for one environment / a customer extension, in the additionalAgents parameter). No module changes are needed:
// queues, subscriptions, KEDA rules, identities and role assignments are all derived from these entries.
import { agentSpec } from 'types.bicep'

@export()
var defaultAgents agentSpec[] = [
  {
    name: 'intake'
    description: 'SARIF / GitHub webhook: validates, stores the raw file (claim check), enqueues a run.'
    ingress: 'external'
    targetPort: 8080
    alwaysOn: true
    sends: ['runs']
    blobWrite: ['raw']
    keyVault: true
    hostsIntake: true
  }
  {
    name: 'agent-api'
    description: 'REST API, SSE live feed and dashboard (POC: secagent serve).'
    ingress: 'internal'
    targetPort: 8795
    alwaysOn: true
    sends: ['runs']
    subscribes: ['dashboard']
    blobRead: ['raw', 'evidence', 'context']
    blobWrite: ['exports']
    sql: 'inserter'
  }
  {
    name: 'orchestrator'
    description: 'Agent Framework workflow host. Sole writer of Finding.status; publishes run-events; opens PRs.'
    alwaysOn: true
    consumes: ['runs', 'results']
    dispatchesWork: true
    publishesEvents: true
    blobRead: ['raw', 'evidence', 'context']
    keyVault: true
    sql: 'writer'
    hostsIntake: true
  }
  {
    name: 'scanner'
    description: 'gitleaks, trivy, semgrep, binary check, Black Duck adapter; normalises to canonical Findings.'
    size: 'heavy'
    consumes: ['scan']
    sends: ['results']
    blobWrite: ['raw']
    keyVault: true
  }
  {
    name: 'triage'
    description: 'Triage agent (small model tier) returning a proposal; policy layer decides.'
    consumes: ['triage']
    sends: ['results']
    blobRead: ['raw']
    blobWrite: ['context']
    model: true
    sql: 'inserter'
  }
  {
    name: 'fixer-library'
    description: 'Library (dependency) fixer.'
    size: 'heavy'
    consumes: ['fix-library']
    sends: ['results']
    blobRead: ['raw']
    blobWrite: ['context']
    model: true
    sql: 'inserter'
  }
  {
    name: 'fixer-secret'
    description: 'Secrets fixer.'
    size: 'heavy'
    consumes: ['fix-secret']
    sends: ['results']
    blobRead: ['raw']
    blobWrite: ['context']
    model: true
    sql: 'inserter'
  }
  {
    name: 'fixer-code'
    description: 'Unsafe-code fixer.'
    size: 'heavy'
    consumes: ['fix-code']
    sends: ['results']
    blobRead: ['raw']
    blobWrite: ['context']
    model: true
    sql: 'inserter'
  }
  {
    name: 'fixer-binary'
    description: 'Binary artefact / licence fixer.'
    size: 'heavy'
    consumes: ['fix-binary']
    sends: ['results']
    blobRead: ['raw']
    blobWrite: ['context']
    model: true
    sql: 'inserter'
  }
  {
    name: 'verifier'
    description: 'Rescan, no-new-findings check, dotnet test, evidence, short summary.'
    size: 'heavy'
    consumes: ['verify']
    sends: ['results']
    blobRead: ['raw']
    blobWrite: ['evidence']
    model: true
    sql: 'inserter'
  }
  {
    name: 'audit-writer'
    description: 'Consumes run-events (audit subscription) into the audit trail and evidence.'
    subscribes: ['audit']
    blobWrite: ['evidence']
    sql: 'inserter'
  }
]

@export()
@description('Blob layout (SDD 11.4). perTenant containers get a -<tenant> suffix in multi-tenant deployments.')
var blobLayout = [
  { purpose: 'raw', perTenant: true, immutable: false }
  { purpose: 'evidence', perTenant: true, immutable: true }
  { purpose: 'context', perTenant: true, immutable: false }
  { purpose: 'exports', perTenant: false, immutable: false }
]

@export()
@description('Run request queue: RunQueueConvention.QueueName in SecAgent.Abstractions. Always session-enabled (SessionId = run target).')
var runQueue = 'runs'

@export()
@description('Name of the run progress topic.')
var runEventsTopic = 'run-events'
