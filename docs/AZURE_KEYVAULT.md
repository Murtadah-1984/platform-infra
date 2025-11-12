# Azure Key Vault Integration

This platform uses Azure Key Vault with CSI Secret Store driver for secure secret management instead of Kubernetes Secrets.

## Architecture

- **CSI Secret Store Driver**: Mounts secrets from Azure Key Vault directly into pods
- **Workload Identity**: Managed identities for pod authentication (no service principal secrets)
- **Automatic Rotation**: Secrets rotate automatically based on Key Vault policies
- **RBAC**: Role-based access control for Key Vault access

## Components

### 1. Azure Key Vault CSI Driver

The CSI driver is installed via Helmfile and provides:
- Secret mounting from Azure Key Vault
- Automatic secret rotation
- Sync to Kubernetes Secrets (optional)

### 2. SecretProviderClass

Each microservice has a `SecretProviderClass` that defines:
- Which secrets to fetch from Key Vault
- Managed identity to use for authentication
- Secret rotation configuration

### 3. Workload Identity

Each service uses a managed identity with:
- Federated credentials for OIDC authentication
- RBAC permissions to access Key Vault
- No secrets stored in Kubernetes

## Setup

### Prerequisites

- AKS cluster with OIDC issuer enabled
- Workload Identity enabled on AKS
- Azure Key Vault created
- Managed identities created for each service

### Quick Setup

```bash
# Run automated setup script
./scripts/setup-keyvault.sh
```

This script:
1. Creates Azure Key Vault
2. Enables OIDC issuer on AKS (if not enabled)
3. Creates managed identities for each service
4. Grants Key Vault access permissions
5. Creates federated credentials
6. Creates sample secrets

### Manual Setup

#### 1. Create Key Vault

```bash
az keyvault create \
    --name platform-kv \
    --resource-group platform-rg \
    --location eastus \
    --enable-rbac-authorization true
```

#### 2. Enable OIDC Issuer on AKS

```bash
az aks update \
    --resource-group platform-rg \
    --name platform-aks \
    --enable-oidc-issuer \
    --enable-workload-identity
```

#### 3. Create Managed Identity

```bash
# Create identity
az identity create \
    --name identity-identity \
    --resource-group platform-rg \
    --location eastus

# Get client ID
IDENTITY_CLIENT_ID=$(az identity show \
    --name identity-identity \
    --resource-group platform-rg \
    --query clientId -o tsv)

# Get principal ID
IDENTITY_PRINCIPAL_ID=$(az identity show \
    --name identity-identity \
    --resource-group platform-rg \
    --query principalId -o tsv)
```

#### 4. Grant Key Vault Access

```bash
# Get Key Vault resource ID
KEY_VAULT_ID=$(az keyvault show \
    --name platform-kv \
    --resource-group platform-rg \
    --query id -o tsv)

# Grant Key Vault Secrets User role
az role assignment create \
    --role "Key Vault Secrets User" \
    --assignee "$IDENTITY_PRINCIPAL_ID" \
    --scope "$KEY_VAULT_ID"
```

#### 5. Create Federated Credential

```bash
# Get OIDC issuer URL
OIDC_ISSUER=$(az aks show \
    --resource-group platform-rg \
    --name platform-aks \
    --query "oidcIssuerProfile.issuerUrl" -o tsv)

# Create federated credential
az identity federated-credential create \
    --name identity-federated-credential \
    --identity-name identity-identity \
    --resource-group platform-rg \
    --issuer "$OIDC_ISSUER" \
    --subject "system:serviceaccount:platform:identity" \
    --audience api://AzureADTokenExchange
```

#### 6. Store Secrets in Key Vault

```bash
az keyvault secret set \
    --vault-name platform-kv \
    --name "Identity-DatabaseConnection" \
    --value "Host=postgres-ha;Port=5432;Database=platformdb;Username=postgres;Password=YourPassword"
```

## Configuration

### Environment Variables

Update `environments/*.yaml` with Key Vault configuration:

```yaml
azure:
  keyVault:
    name: platform-kv
    tenantId: "your-tenant-id"
    managedIdentityClientId: "your-managed-identity-client-id"
```

### Secret Names

Secrets in Key Vault follow naming convention:
- `Identity-DatabaseConnection`
- `Identity-RedisConnection`
- `Identity-JwtSecret`
- `Payment-DatabaseConnection`
- `Payment-RabbitMQConnection`
- `Notification-RabbitMQConnection`
- `Notification-SmtpHost`
- `Notification-SmtpPassword`

## Secret Rotation

### Automatic Rotation

Secrets rotate automatically based on Key Vault rotation policies:

1. **Set Rotation Policy** in Azure Portal or CLI:

```bash
az keyvault secret set-attributes \
    --vault-name platform-kv \
    --name Identity-JwtSecret \
    --expires 2025-12-31T00:00:00Z
```

2. **Configure Rotation Policy**:

```bash
az keyvault secret set-attributes \
    --vault-name platform-kv \
    --name Identity-JwtSecret \
    --rotation-policy @rotation-policy.json
```

Example `rotation-policy.json`:
```json
{
  "lifetimeActions": [
    {
      "trigger": {
        "timeBeforeExpiry": "P30D"
      },
      "action": {
        "type": "Rotate"
      }
    }
  ],
  "attributes": {
    "enabled": true
  }
}
```

### Manual Rotation

```bash
# Update secret value
az keyvault secret set \
    --vault-name platform-kv \
    --name Identity-JwtSecret \
    --value "new-secret-value"

# Restart pods to pick up new secret
kubectl rollout restart deployment/identity -n platform
```

## Troubleshooting

### Pods can't access secrets

1. **Check managed identity**:
```bash
kubectl describe serviceaccount identity -n platform
# Should show: azure.workload.identity/client-id annotation
```

2. **Check federated credential**:
```bash
az identity federated-credential list \
    --identity-name identity-identity \
    --resource-group platform-rg
```

3. **Check Key Vault permissions**:
```bash
az role assignment list \
    --scope "/subscriptions/.../resourceGroups/.../providers/Microsoft.KeyVault/vaults/platform-kv" \
    --query "[?principalName=='identity-identity']"
```

4. **Check pod logs**:
```bash
kubectl logs deployment/identity -n platform
```

### Secret rotation not working

1. **Check rotation policy**:
```bash
az keyvault secret show \
    --vault-name platform-kv \
    --name Identity-JwtSecret \
    --query "attributes"
```

2. **Check CSI driver logs**:
```bash
kubectl logs -n kube-system -l app=secrets-store-csi-driver
```

3. **Verify SecretProviderClass**:
```bash
kubectl describe secretproviderclass identity-secrets -n platform
```

## Security Best Practices

1. **Enable RBAC** on Key Vault (not access policies)
2. **Use managed identities** (no service principal secrets)
3. **Enable soft delete** on Key Vault
4. **Enable purge protection** for production
5. **Rotate secrets regularly** (set expiration dates)
6. **Monitor access** with Azure Monitor
7. **Use separate Key Vaults** per environment
8. **Limit network access** with Key Vault firewall rules

## Migration from Kubernetes Secrets

If migrating from Kubernetes Secrets:

1. **Create secrets in Key Vault**:
```bash
# Export existing secret
kubectl get secret identity-secrets -n platform -o jsonpath='{.data.database-connection}' | base64 -d

# Store in Key Vault
az keyvault secret set \
    --vault-name platform-kv \
    --name Identity-DatabaseConnection \
    --value "$(kubectl get secret identity-secrets -n platform -o jsonpath='{.data.database-connection}' | base64 -d)"
```

2. **Update environment values** with Key Vault configuration
3. **Deploy updated charts**:
```bash
helmfile sync
```

4. **Verify secrets are mounted**:
```bash
kubectl exec deployment/identity -n platform -- ls -la /mnt/secrets-store
```

5. **Delete old Kubernetes secrets** (after verification):
```bash
kubectl delete secret identity-secrets -n platform
```

