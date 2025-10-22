
## Setup Guide

### Create azurevm.pkr.hcl 
 
 ``` bash
source azure-arm vm {
  client_id       = var.client_id
  client_secret   = var.client_secret
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id

  location                          = var.location
  managed_image_name                = "${var.image_name}-${var.image_version}"
  managed_image_resource_group_name = var.gallery_resource_group

  #virtual_network_name                = "vnet-eastus"
  #virtual_network_subnet_name         = "snet-eastus-1"
  #virtual_network_resource_group_name = "weblogic-rg"

  os_disk_size_gb      = 250 # in GB
  disk_additional_size = [32, 100, 100]

  shared_image_gallery_destination {
    subscription   = var.subscription_id
    resource_group = var.gallery_resource_group
    gallery_name   = var.gallery_name
    image_name     = var.image_name
    image_version  = var.image_version
    replication_regions = [
      var.location,
      "West US"
    ]

  }

  communicator    = "ssh"
  os_type         = "Linux"
  image_offer     = "RHEL"
  image_publisher = "RedHat"
  image_sku       = "810-gen2"

  vm_size = "Standard_D2as_v6"


}

```
### Craete build.pkr.hcl

``` bash
locals {
  as_root   = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E bash '{{ .Path }}'"
  as_oracle = "chmod +x {{ .Path }}; {{ .Vars }} sudo -u oracle -g oracle -E bash '{{ .Path }}'"
}

build {
  sources = [
    "source.azure-arm.vm"
  ]
  
  provisioner "file" {
    source      = "../recepies/.env"
    destination = "/tmp/.env"
  }
  
  provisioner "file" {
    source      = "../certs/ca_bundle.crt"
    destination = "/tmp/ca_bundle.crt"
  }
  
  provisioner "file" {
    source      = "../certs/certificate.crt"
    destination = "/tmp/certificate.crt"
  }
  
  provisioner "file" {
    source      = "../certs/private.key"
    destination = "/tmp/private.key"
  }
  
  provisioner "shell" {
    execute_command = local.as_root
    environment_vars = [
      "CREDENTIAL_ENV=/tmp/.env",
    ]
    scripts = [
      "../recepies/configure-disk-mounts.sh",
      "../recepies/configure_ownership.sh",
      "../recepies/create-folder.sh",
      "../recepies/download_packages.sh",
      "../recepies/fs_mount.sh",
    ]
  }
  
  provisioner "shell" {
    execute_command = local.as_oracle
    environment_vars = [
      "CREDENTIAL_ENV=/tmp/.env",
    ]
    scripts = [
      "../recepies/install-ora-weblogic.sh",
      "../recepies/domain-create.sh",
    ]
  }
  
  # Create Dynamic Cluster (OFFLINE mode - no Admin Server needed)
  provisioner "shell" {
    execute_command = local.as_oracle
    environment_vars = [
      "CREDENTIAL_ENV=/tmp/.env",
    ]
    scripts = [
      "../recepies/create-dynamic-cluster.sh",
    ]
  }
  
  provisioner "shell" {
    execute_command = local.as_root
    scripts = [
      "../recepies/enable-wls-startup.sh",
    ]
  }
  
  provisioner "shell" {
    execute_command = local.as_oracle
    environment_vars = [
      "CREDENTIAL_ENV=/tmp/.env",
    ]
    scripts = [
      "../recepies/upload_domain.sh",
    ]
  }
  
  provisioner "shell" {
    execute_command = local.as_root
    inline = [
      "rm -f /tmp/.env /tmp/ca_bundle.crt /tmp/certificate.crt /tmp/private.key /tmp/create_dynamic_cluster.py",
      "sync"
    ]
  }
  
  provisioner "shell" {
    execute_command = local.as_root
    inline = [
      "/usr/sbin/waagent -force -deprovision+user && export HISTSIZE=0 && sync"
    ]
    only = ["azure-arm"]
  }
}

```

### Create plugins.pkr.hcl

```bash
packer {
  required_plugins {
    azure = {
      source  = "github.com/hashicorp/azure"
      version = "~> 2"
    }
  }
}
```

### Create variables.pkr.hcl

``` bash
variable subscription_id {
  type = string
  default = ""
}
variable tenant_id {
  type = string
  default = ""
}
variable client_id {
  type = string
  default = ""
}
variable client_secret {
  type = string
  default = ""
}
variable location {
  type = string
  default = "East US"
}
variable image_name {
  type = string
  default = "weblogic-golden"
}
variable image_version {
  type = string
  default = "1.12.0"
}
variable gallery_resource_group {
  type = string
  default = "wls_vm_packer_pg"
}
variable gallery_name {
  type = string
  default = "gallery_packer_wls"
}
```

