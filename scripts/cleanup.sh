#!/bin/bash
set -e

# Script to cleanup platform infrastructure
# Usage: ./scripts/cleanup.sh [environment] [--delete-cluster]

ENVIRONMENT="${1:-dev}"
DELETE_CLUSTER="${2:-false}"

echo "🧹 Cleaning up platform infrastructure for environment: $ENVIRONMENT"

# Confirm deletion
read -p "⚠️  Are you sure you want to delete all resources? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "❌ Cleanup cancelled."
    exit 0
fi

# Set environment
export HELMFILE_ENVIRONMENT="$ENVIRONMENT"

# Delete Helm releases
echo "🗑️  Deleting Helm releases..."
helmfile -e "$ENVIRONMENT" destroy || true

# Delete namespaces
echo "🗑️  Deleting namespaces..."
kubectl delete namespace platform --ignore-not-found=true
kubectl delete namespace infrastructure --ignore-not-found=true
kubectl delete namespace monitoring --ignore-not-found=true
kubectl delete namespace gateway --ignore-not-found=true
kubectl delete namespace argocd --ignore-not-found=true

# Wait for namespace deletion
echo "⏳ Waiting for namespace cleanup..."
sleep 10

# Delete PVCs if any remain
echo "🗑️  Cleaning up persistent volumes..."
kubectl delete pvc --all --all-namespaces --ignore-not-found=true || true

# Optionally delete the entire cluster
if [ "$DELETE_CLUSTER" == "--delete-cluster" ]; then
    RESOURCE_GROUP="platform-rg-${ENVIRONMENT}"
    AKS_CLUSTER="platform-aks-${ENVIRONMENT}"
    
    read -p "⚠️  Delete AKS cluster $AKS_CLUSTER? (yes/no): " DELETE_AKS
    if [ "$DELETE_AKS" == "yes" ]; then
        echo "🗑️  Deleting AKS cluster: $AKS_CLUSTER"
        az aks delete \
            --resource-group "$RESOURCE_GROUP" \
            --name "$AKS_CLUSTER" \
            --yes \
            --no-wait || true
        
        echo "🗑️  Deleting resource group: $RESOURCE_GROUP"
        az group delete \
            --name "$RESOURCE_GROUP" \
            --yes \
            --no-wait || true
    fi
fi

echo "✅ Cleanup complete!"

