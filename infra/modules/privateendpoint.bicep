// privateendpoint.bicep - one private endpoint plus its DNS zone group (reused for every PaaS service).

@description('Azure region.')
param location string

@description('Private endpoint name.')
param name string

@description('Subnet for the private endpoint.')
param subnetId string

@description('Resource id of the target service.')
param targetResourceId string

@description('Sub-resource (group id), for example blob, vault, sqlServer, namespace, account, registry.')
param groupId string

@description('Private DNS zone the endpoint registers its A record in.')
param privateDnsZoneId string

@description('Tags.')
param tags object

resource pe 'Microsoft.Network/privateEndpoints@2025-05-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    subnet: { id: subnetId }
    privateLinkServiceConnections: [
      {
        name: name
        properties: {
          privateLinkServiceId: targetResourceId
          groupIds: [groupId]
        }
      }
    ]
  }
}

resource dnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-05-01' = {
  parent: pe
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: replace(groupId, '.', '-')
        properties: { privateDnsZoneId: privateDnsZoneId }
      }
    ]
  }
}

output id string = pe.id
