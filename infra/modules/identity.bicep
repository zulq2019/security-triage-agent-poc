// identity.bicep - user-assigned managed identities, one per agent (SDD 13.1, NFR-01). Names come from the caller
// (naming convention lives in main.bicep). Roles are granted separately by role-assignments.bicep.
import { identityInfo } from '../types.bicep'

@description('Azure region.')
param location string

@description('Identity names, for example [ id-orchestrator-dev, id-triage-dev ].')
param identityNames string[]

@description('Tags applied to every identity.')
param tags object

resource identities 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = [
  for n in identityNames: {
    name: n
    location: location
    tags: tags
  }
]

@description('One entry per name, in the same order as identityNames.')
output identities identityInfo[] = [
  for (n, i) in identityNames: {
    name: identities[i].name
    id: identities[i].id
    principalId: identities[i].properties.principalId
    clientId: identities[i].properties.clientId
  }
]
