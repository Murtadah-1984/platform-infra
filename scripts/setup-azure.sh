#!/bin/bash
set -e

# Azure Platform Infrastructure Setup Script
# This script sets up Azure resources for the platform

RESOURCE_GROUP="${RESOURCE_GROUP:-platform-rg}"
LOCATION="${LOCATION:-eastus}"
AKS_CLUSTER="${AKS_CLUSTER:-platform-aks}"
ACR_NAME="${ACR_NAME:-platformacr}"
NODE_COUNT="${NODE_COUNT:-3}"
NODE_VM_SIZE="${NODE_VM_SIZE:-Standard_D2s_v3}"

echo "🚀 Setting up Azure infrastructure..."

# Login check
echo "📋 Checking Azure login..."
az account show > /dev/null 2>&1 || {
    echo "❌ Not logged in to Azure. Please run: az login"
    exit 1
}

# Create resource group
echo "📦 Creating resource group: $RESOURCE_GROUP"
az group create \
    --name "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --output none

# Create Azure Container Registry
echo "🐳 Creating Azure Container Registry: $ACR_NAME"
az acr create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$ACR_NAME" \
    --sku Basic \
    --admin-enabled true \
    --output none

# Get ACR login server
ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" --query loginServer -o tsv)
echo "✅ ACR Login Server: $ACR_LOGIN_SERVER"

# Create AKS cluster
echo "☸️  Creating AKS cluster: $AKS_CLUSTER"
az aks create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$AKS_CLUSTER" \
    --node-count "$NODE_COUNT" \
    --node-vm-size "$NODE_VM_SIZE" \
    --enable-addons monitoring \
    --enable-managed-identity \
    --attach-acr "$ACR_NAME" \
    --generate-ssh-keys \
    --output none

# Get AKS credentials
echo "🔑 Getting AKS credentials..."
az aks get-credentials \
    --resource-group "$RESOURCE_GROUP" \
    --name "$AKS_CLUSTER" \
    --overwrite-existing

# Create namespaces
echo "📁 Creating Kubernetes namespaces..."
kubectl create namespace infrastructure --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace platform --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace gateway --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -

echo "✅ Azure infrastructure setup complete!"
echo ""
echo "📝 Next steps:"
echo "  1. Update environments/*.yaml with your ACR name: $ACR_NAME"
echo "  2. Create Kubernetes secrets for services"
echo "  3. Install ArgoCD: kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml"
echo "  4. Deploy with: helmfile sync"

