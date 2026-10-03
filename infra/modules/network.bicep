// network.bicep - VNet for the Container Apps environment and private endpoints, NSGs, and the private DNS zones
// the private endpoints register in (SDD 13.2). Only deployed when enablePrivateNetworking = true.

@description('Azure region.')
param location string

@description('VNet name.')
param vnetName string

@description('VNet address space, for example 10.40.0.0/16. Must not overlap with networks it will be peered to [ask the network team].')
param addressPrefix string

@description('Subnet for the Container Apps environment (workload profiles). /27 is the minimum; /24 leaves room to grow.')
param containerAppsSubnetPrefix string

@description('Subnet for private endpoints.')
param privateEndpointSubnetPrefix string

@description('Create the Azure OpenAI private DNS zone.')
param includeOpenAiZone bool

@description('Create the Azure Container Registry private DNS zone.')
param includeAcrZone bool

@description('Optional custom DNS servers for the VNet (hub DNS / resolver). Empty = Azure-provided DNS.')
param dnsServers string[]

@description('Tags.')
param tags object

// Private DNS zone names. environment().suffixes keeps these correct in sovereign clouds.
var zoneBlob = 'privatelink.blob.${environment().suffixes.storage}'
var zoneKeyVault = 'privatelink${environment().suffixes.keyvaultDns}'
var zoneSql = 'privatelink${environment().suffixes.sqlServerHostname}'
var zoneServiceBus = 'privatelink.servicebus.windows.net'
var zoneOpenAi = 'privatelink.openai.azure.com'
var zoneAcr = 'privatelink${environment().suffixes.acrLoginServer}'

var zoneSpecs = concat(
  [
    { key: 'blob', name: zoneBlob }
    { key: 'vault', name: zoneKeyVault }
    { key: 'sql', name: zoneSql }
    { key: 'servicebus', name: zoneServiceBus }
  ],
  includeOpenAiZone ? [{ key: 'openai', name: zoneOpenAi }] : [],
  includeAcrZone ? [{ key: 'acr', name: zoneAcr }] : []
)

resource nsgAca 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: 'nsg-${vnetName}-aca'
  location: location
  tags: tags
  properties: {
    // Default rules allow VNet-internal traffic and Azure Load Balancer probes. Inbound from the internet to the
    // external intake app arrives through the environment's public load balancer on 443.
    securityRules: [
      {
        name: 'AllowHttpsInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: containerAppsSubnetPrefix
          destinationPortRanges: ['443']
        }
      }
    ]
  }
}

resource nsgPe 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: 'nsg-${vnetName}-pe'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowAcaSubnetInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: containerAppsSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: privateEndpointSubnetPrefix
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [addressPrefix] }
    dhcpOptions: empty(dnsServers) ? null : { dnsServers: dnsServers }
    subnets: [
      {
        name: 'snet-aca'
        properties: {
          addressPrefix: containerAppsSubnetPrefix
          networkSecurityGroup: { id: nsgAca.id }
          delegations: [
            {
              name: 'aca'
              properties: { serviceName: 'Microsoft.App/environments' }
            }
          ]
        }
      }
      {
        name: 'snet-pe'
        properties: {
          addressPrefix: privateEndpointSubnetPrefix
          networkSecurityGroup: { id: nsgPe.id }
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

resource zones 'Microsoft.Network/privateDnsZones@2024-06-01' = [
  for z in zoneSpecs: {
    name: z.name
    location: 'global'
    tags: tags
  }
]

resource zoneLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [
  for (z, i) in zoneSpecs: {
    parent: zones[i]
    name: 'link-${vnetName}'
    location: 'global'
    tags: tags
    properties: {
      registrationEnabled: false
      virtualNetwork: { id: vnet.id }
    }
  }
]

output vnetId string = vnet.id
output containerAppsSubnetId string = vnet.properties.subnets[0].id
output privateEndpointSubnetId string = vnet.properties.subnets[1].id

@description('Private DNS zone ids by service key: blob, vault, sql, servicebus (+ openai, acr when included).')
output dnsZoneIds object = toObject(
  range(0, length(zoneSpecs)),
  i => zoneSpecs[i].key,
  i => resourceId('Microsoft.Network/privateDnsZones', zoneSpecs[i].name)
)
