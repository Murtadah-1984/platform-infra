#!/bin/bash
set -e

# Script to set up Azure AKS cluster
# Usage: ./scripts/setup-aks.sh [environment]

ENVIRONMENT="${1:-dev}"
RESOURCE_GROUP="platform-rg-${ENVIRONMENT}"
AKS_CLUSTER="platform-aks-${ENVIRONMENT}"
LOCATION="${AZURE_LOCATION:-eastus}"
NODE_COUNT="${NODE_COUNT:-3}"
NODE_VM_SIZE="${NODE_VM_SIZE:-Standard_D2s_v3}"

echo "🚀 Setting up AKS cluster: $AKS_CLUSTER in $RESOURCE_GROUP"

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI is not installed. Please install it first."
    exit 1
fi

# Login to Azure (if not already logged in)
echo "🔐 Checking Azure login..."
az account show &> /dev/null || az login

# Create resource group
echo "📦 Creating resource group: $RESOURCE_GROUP"
az group create \
    --name "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --output none

# Create AKS cluster
echo "🏗️  Creating AKS cluster: $AKS_CLUSTER"
az aks create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$AKS_CLUSTER" \
    --node-count "$NODE_COUNT" \
    --node-vm-size "$NODE_VM_SIZE" \
    --enable-managed-identity \
    --enable-azure-rbac \
    --network-plugin azure \
    --enable-addons monitoring \
    --generate-ssh-keys \
    --output none

# Get ACR name from environment or create new
ACR_NAME="${ACR_NAME:-platformacr${ENVIRONMENT}}"
echo "📦 Setting up Azure Container Registry: $ACR_NAME"

# Check if ACR exists, create if not
if ! az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
    echo "🏗️  Creating ACR: $ACR_NAME"
    az acr create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$ACR_NAME" \
        --sku Basic \
        --output none
fi

# Attach ACR to AKS
echo "🔗 Attaching ACR to AKS cluster"
az aks update \
    --resource-group "$RESOURCE_GROUP" \
    --name "$AKS_CLUSTER" \
    --attach-acr "$ACR_NAME" \
    --output none

# Get credentials
echo "🔑 Getting AKS credentials"
az aks get-credentials \
    --resource-group "$RESOURCE_GROUP" \
    --name "$AKS_CLUSTER" \
    --overwrite-existing

# Verify cluster access
echo "✅ Verifying cluster access..."
kubectl cluster-info

echo "✅ AKS cluster setup complete!"
echo "📝 Next steps:"
echo "   1. Run: ./scripts/create-secrets.sh $ENVIRONMENT"
echo "   2. Run: ./scripts/deploy-all.sh $ENVIRONMENT"

