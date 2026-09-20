# =====================================================================
# Azure Sentinel Honeypot - Enterprise Terraform Configuration
# Author: Ajit Nayak
# Description: Provisions Resource Group, Log Analytics Workspace, 
#              Azure Sentinel Solution, Virtual Network, Subnet, 
#              Network Security Group (with honeypot-tuned inbound rules), 
#              Public IP, Network Interface, and Windows Virtual Machine.
# =====================================================================

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "location" {
  type        = string
  default     = "East US"
  description = "Azure region for deploying honeypot infrastructure."
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Environment tag."
}

variable "admin_username" {
  type        = string
  default     = "honeypotadmin"
  description = "Administrator username for the Windows honeypot VM."
}

resource "random_password" "admin_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "azurerm_resource_group" "rg" {
  name     = "rg-sentinel-honeypot-prod"
  location = var.location
  tags = {
    Environment = var.environment
    Project     = "AzureSentinelHoneypot"
    ManagedBy   = "Terraform"
  }
}

resource "azurerm_log_analytics_workspace" "law" {
  name                = "law-sentinel-honeypot-${random_id.workspace_suffix.hex}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = azurerm_resource_group.rg.tags
}

resource "random_id" "workspace_suffix" {
  byte_length = 4
}

resource "azurerm_sentinel_solution" "sentinel" {
  depends_on           = [azurerm_log_analytics_workspace.law]
  resource_group_name  = azurerm_resource_group.rg.name
  workspace_name       = azurerm_log_analytics_workspace.law.name
  product              = "SecurityInsights"
  publisher            = "Microsoft"

  plan {
    publisher          = "Microsoft"
    product            = "OMSGallery/SecurityInsights"
    name               = "SecurityInsights"
    promotion_code     = ""
  }
}

resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-honeypot-prod"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = azurerm_resource_group.rg.tags
}

resource "azurerm_subnet" "subnet" {
  name                 = "snet-honeypot"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_security_group" "nsg" {
  name                = "nsg-honeypot-exposed"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "Allow-RDP-Internet"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-SMB-Internet"
    priority                   = 1010
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "445"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = azurerm_resource_group.rg.tags
}

resource "azurerm_subnet_network_security_group_association" "nsg_assoc" {
  subnet_id                 = azurerm_subnet.subnet.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

resource "azurerm_public_ip" "pip" {
  name                = "pip-honeypot-vm"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = azurerm_resource_group.rg.tags
}

resource "azurerm_network_interface" "nic" {
  name                = "nic-honeypot-vm"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip.id
  }

  tags = azurerm_resource_group.rg.tags
}

resource "azurerm_windows_virtual_machine" "vm" {
  name                  = "vm-honeypot-01"
  resource_group_name   = azurerm_resource_group.rg.name
  location              = azurerm_resource_group.rg.location
  size                  = "Standard_B2s"
  admin_username        = var.admin_username
  admin_password        = random_password.admin_password.result
  network_interface_ids = [azurerm_network_interface.nic.id]

  os_disk {
    name                 = "osdisk-honeypot"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-Datacenter"
    version   = "latest"
  }

  enable_automatic_updates = true
  provision_vm_agent       = true

  tags = azurerm_resource_group.rg.tags
}

output "resource_group_name" {
  value       = azurerm_resource_group.rg.name
  description = "The name of the provisioned resource group."
}

output "log_analytics_workspace_name" {
  value       = azurerm_log_analytics_workspace.law.name
  description = "The name of the Log Analytics Workspace."
}

output "honeypot_public_ip" {
  value       = azurerm_public_ip.pip.ip_address
  description = "Public IP address of the honeypot VM for attack ingestion."
}

output "admin_password" {
  value       = random_password.admin_password.result
  sensitive   = true
  description = "Generated administrator password for the Windows VM."
}
