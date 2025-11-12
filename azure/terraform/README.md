# Terraform Infrastructure

Optional Terraform configuration for provisioning Azure resources.

## Usage

```bash
cd azure/terraform

# Initialize Terraform
terraform init

# Plan changes
terraform plan

# Apply changes
terraform apply

# Destroy resources
terraform destroy
```

## Variables

Override variables in `terraform.tfvars`:

```hcl
resource_group_name = "platform-rg"
location            = "eastus"
aks_cluster_name    = "platform-aks"
acr_name            = "platformacr"
node_count          = 3
```

