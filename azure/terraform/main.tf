# Azure Platform Infrastructure - Terraform Configuration
# Optional: Use Terraform for infrastructure as code

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "resource_group_name" {
  description = "Name of the resource group"
  default     = "platform-rg"
}

variable "location" {
  description = "Azure region"
  default     = "eastus"
}

variable "aks_cluster_name" {
  description = "Name of the AKS cluster"
  default     = "platform-aks"
}

variable "acr_name" {
  description = "Name of the Azure Container Registry"
  default     = "platformacr"
}

variable "node_count" {
  description = "Number of AKS nodes"
  default     = 3
}

resource "azurerm_resource_group" "platform" {
  name     = var.resource_group_name
  location = var.location
}

resource "azurerm_container_registry" "platform" {
  name                = var.acr_name
  resource_group_name = azurerm_resource_group.platform.name
  location            = azurerm_resource_group.platform.location
  sku                 = "Basic"
  admin_enabled       = true
}

resource "azurerm_kubernetes_cluster" "platform" {
  name                = var.aks_cluster_name
  location            = azurerm_resource_group.platform.location
  resource_group_name = azurerm_resource_group.platform.name
  dns_prefix          = var.aks_cluster_name
  kubernetes_version  = "1.28"

  default_node_pool {
    name       = "default"
    node_count = var.node_count
    vm_size    = "Standard_D2s_v3"
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
  }

  oms_agent {
    enabled                    = true
    log_analytics_workspace_id = azurerm_log_analytics_workspace.platform.id
  }
}

resource "azurerm_log_analytics_workspace" "platform" {
  name                = "${var.aks_cluster_name}-logs"
  location            = azurerm_resource_group.platform.location
  resource_group_name = azurerm_resource_group.platform.name
  sku                 = "PerGB2018"
}

resource "azurerm_role_assignment" "acr_pull" {
  principal_id                     = azurerm_kubernetes_cluster.platform.kubelet_identity[0].object_id
  role_definition_name             = "AcrPull"
  scope                            = azurerm_container_registry.platform.id
  skip_service_principal_aad_check = true
}

output "aks_cluster_name" {
  value = azurerm_kubernetes_cluster.platform.name
}

output "acr_login_server" {
  value = azurerm_container_registry.platform.login_server
}

output "resource_group_name" {
  value = azurerm_resource_group.platform.name
}

