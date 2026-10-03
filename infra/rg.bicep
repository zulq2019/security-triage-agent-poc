// rg.bicep - OPTIONAL subscription-scope step: create the resource group with the standard tags.
// Only used when the deployer has rights at subscription scope (deploy.sh --create-rg). If the Azure team creates
// the resource group for you, skip this and deploy main.bicep straight into it.
targetScope = 'subscription'

@description('Resource group name, for example rg-secagent-dev-uks.')
param resourceGroupName string

@description('Region (UK South by default).')
param location string = 'uksouth'

@description('Tags for the resource group (resources get their own tags from main.bicep).')
param tags object

resource rg 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

output resourceGroupId string = rg.id
