// identity.bicep - one user-assigned managed identity per app (SDD 13.1, NFR-01).
// Roles are granted separately (rbac.bicep) so each identity gets only what its app needs.

@description('Azure region.')
param location string

@description('App keys, for example [ intake, orchestrator, triage, fixer-library ]. One identity is created per key.')
param appKeys string[]

@description('Environment name, used in the identity name: id-<app>-<env>.')
param environmentName string

@description('Tags applied to every identity.')
param tags object

resource identities 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = [
  for key in appKeys: {
    name: 'id-${key}-${environmentName}'
    location: location
    tags: union(tags, { app: key })
  }
]

@description('One entry per app key, in the same order as appKeys.')
output identities array = [
  for (key, i) in appKeys: {
    key: key
    name: identities[i].name
    id: identities[i].id
    principalId: identities[i].properties.principalId
    clientId: identities[i].properties.clientId
  }
]
