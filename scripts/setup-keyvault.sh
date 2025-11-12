#!/bin/bash
set -e

# Azure Key Vault Setup Script
# Creates Key Vault and configures managed identities for workload authentication

RESOURCE_GROUP="${RESOURCE_GROUP:-platform-rg}"
KEY_VAULT_NAME="${KEY_VAULT_NAME:-platform-kv}"
LOCATION="${LOCATION:-eastus}"
AKS_CLUSTER="${AKS_CLUSTER:-platform-aks}"
NAMESPACE="${NAMESPACE:-platform}"

echo "🔐 Setting up Azure Key Vault for Kubernetes secrets..."

# Get Azure subscription and tenant ID
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

echo "📋 Subscription ID: $SUBSCRIPTION_ID"
echo "📋 Tenant ID: $TENANT_ID"

# Create Key Vault
echo "🔑 Creating Azure Key Vault: $KEY_VAULT_NAME"
az keyvault create \
    --name "$KEY_VAULT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --enable-rbac-authorization true \
    --output none

# Get AKS OIDC issuer URL
echo "🔍 Getting AKS OIDC issuer URL..."
OIDC_ISSUER=$(az aks show \
    --resource-group "$RESOURCE_GROUP" \
    --name "$AKS_CLUSTER" \
    --query "oidcIssuerProfile.issuerUrl" -o tsv)

if [ -z "$OIDC_ISSUER" ]; then
    echo "⚠️  OIDC issuer not found. Enabling OIDC issuer..."
    az aks update \
        --resource-group "$RESOURCE_GROUP" \
        --name "$AKS_CLUSTER" \
        --enable-oidc-issuer \
        --enable-workload-identity \
        --output none
    
    OIDC_ISSUER=$(az aks show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$AKS_CLUSTER" \
        --query "oidcIssuerProfile.issuerUrl" -o tsv)
fi

echo "✅ OIDC Issuer: $OIDC_ISSUER"

# Create managed identities for each service
SERVICES=("identity" "payment" "notification")

for SERVICE in "${SERVICES[@]}"; do
    IDENTITY_NAME="${SERVICE}-identity"
    
    echo "👤 Creating managed identity: $IDENTITY_NAME"
    az identity create \
        --name "$IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --output none
    
    IDENTITY_CLIENT_ID=$(az identity show \
        --name "$IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query clientId -o tsv)
    
    IDENTITY_PRINCIPAL_ID=$(az identity show \
        --name "$IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query principalId -o tsv)
    
    echo "✅ Identity Client ID: $IDENTITY_CLIENT_ID"
    
    # Grant Key Vault Secrets User role to managed identity
    echo "🔐 Granting Key Vault Secrets User role to $IDENTITY_NAME..."
    az role assignment create \
        --role "Key Vault Secrets User" \
        --assignee "$IDENTITY_PRINCIPAL_ID" \
        --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$KEY_VAULT_NAME" \
        --output none
    
    # Create federated credential for workload identity
    echo "🔗 Creating federated credential for $SERVICE..."
    az identity federated-credential create \
        --name "${SERVICE}-federated-credential" \
        --identity-name "$IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --issuer "$OIDC_ISSUER" \
        --subject "system:serviceaccount:$NAMESPACE:$SERVICE" \
        --audience api://AzureADTokenExchange \
        --output none
    
    echo "✅ Configured managed identity for $SERVICE"
done

# Create sample secrets in Key Vault
echo "📝 Creating sample secrets in Key Vault..."
echo "⚠️  Note: Update these with your actual values!"

# Identity service secrets
az keyvault secret set \
    --vault-name "$KEY_VAULT_NAME" \
    --name "Identity-DatabaseConnection" \
    --value "Host=postgres-ha;Port=5432;Database=platformdb;Username=postgres;Password=CHANGE_ME" \
    --output none

az keyvault secret set \
    --vault-name "$KEY_VAULT_NAME" \
    --name "Identity-RedisConnection" \
    --value "redis:6379,password=CHANGE_ME" \
    --output none

az keyvault secret set \
    --vault-name "$KEY_VAULT_NAME" \
    --name "Identity-JwtSecret" \
    --value "CHANGE_ME_JWT_SECRET" \
    --output none

# Payment service secrets
az keyvault secret set \
    --vault-name "$KEY_VAULT_NAME" \
    --name "Payment-DatabaseConnection" \
    --value "Host=postgres-ha;Port=5432;Database=platformdb;Username=postgres;Password=CHANGE_ME" \
    --output none

az keyvault secret set \
    --vault-name "$KEY_VAULT_NAME" \
    --name "Payment-RabbitMQConnection" \
    --value "amqp://admin:CHANGE_ME@rabbitmq:5672" \
    --output none

# Notification service secrets
az keyvault secret set \
    --vault-name "$KEY_VAULT_NAME" \
    --name "Notification-RabbitMQConnection" \
    --value "amqp://admin:CHANGE_ME@rabbitmq:5672" \
    --output none

az keyvault secret set \
    --vault-name "$KEY_VAULT_NAME" \
    --name "Notification-SmtpHost" \
    --value "smtp.example.com" \
    --output none

az keyvault secret set \
    --vault-name "$KEY_VAULT_NAME" \
    --name "Notification-SmtpPassword" \
    --value "CHANGE_ME" \
    --output none

echo ""
echo "✅ Azure Key Vault setup complete!"
echo ""
echo "📝 Next steps:"
echo "  1. Update secrets in Key Vault with actual values:"
echo "     az keyvault secret set --vault-name $KEY_VAULT_NAME --name <secret-name> --value <actual-value>"
echo ""
echo "  2. Update environments/*.yaml with:"
echo "     - keyVault.name: $KEY_VAULT_NAME"
echo "     - keyVault.tenantId: $TENANT_ID"
echo "     - keyVault.managedIdentityClientId: (get from above output)"
echo ""
echo "  3. Enable secret rotation policies in Azure Key Vault portal"
echo ""
echo "  4. Deploy with: helmfile sync"

