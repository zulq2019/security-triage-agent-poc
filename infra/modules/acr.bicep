// acr.bicep - container registry for the agent images. Admin user off: apps pull with their managed identity (AcrPull).

@description('Azure region.')
param location string

@description('Registry name (5-50 alphanumeric, globally unique).')
param name string

@description('Basic, Standard or Premium. Private endpoints need Premium.')
@allowed(['Basic', 'Standard', 'Premium'])
param sku string

@description('Disable public network access (Premium + private endpoint only).')
param disablePublicNetworkAccess bool

@description('Tags.')
param tags object

resource acr 'Microsoft.ContainerRegistry/registries@2025-04-01' = {
  name: name
  location: location
  tags: tags
  sku: { name: sku }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: (sku == 'Premium' && disablePublicNetworkAccess) ? 'Disabled' : 'Enabled'
    zoneRedundancy: sku == 'Premium' ? 'Enabled' : 'Disabled'
  }
}

output id string = acr.id
output name string = acr.name
output loginServer string = acr.properties.loginServer
