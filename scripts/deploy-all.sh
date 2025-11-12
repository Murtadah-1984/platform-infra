#!/bin/bash
set -e

# Script to deploy all platform components
# Usage: ./scripts/deploy-all.sh [environment]

ENVIRONMENT="${1:-dev}"

echo "🚀 Deploying platform infrastructure for environment: $ENVIRONMENT"

# Check if helmfile is installed
if ! command -v helmfile &> /dev/null; then
    echo "❌ Helmfile is not installed. Please install it first."
    echo "   Visit: https://github.com/helmfile/helmfile"
    exit 1
fi

# Check if kubectl is configured
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ kubectl is not configured or cluster is not accessible."
    exit 1
fi

# Set environment
export HELMFILE_ENVIRONMENT="$ENVIRONMENT"

echo "📦 Deploying infrastructure components..."
helmfile -e "$ENVIRONMENT" sync

echo "⏳ Waiting for infrastructure to be ready..."
kubectl wait --for=condition=ready pod \
    --selector=app.kubernetes.io/name=postgresql-ha \
    --namespace=infrastructure \
    --timeout=300s || true

kubectl wait --for=condition=ready pod \
    --selector=app.kubernetes.io/name=redis \
    --namespace=infrastructure \
    --timeout=300s || true

kubectl wait --for=condition=ready pod \
    --selector=app.kubernetes.io/name=rabbitmq \
    --namespace=infrastructure \
    --timeout=300s || true

echo "📊 Deploying monitoring stack..."
helmfile -e "$ENVIRONMENT" sync --selector name=prometheus-stack

echo "🔐 Verifying secrets..."
if ! kubectl get secret identity-secrets -n platform &> /dev/null; then
    echo "⚠️  Warning: Secrets not found. Run: ./scripts/create-secrets.sh $ENVIRONMENT"
fi

echo "🌐 Deploying microservices..."
helmfile -e "$ENVIRONMENT" sync --selector name=identity
helmfile -e "$ENVIRONMENT" sync --selector name=payment
helmfile -e "$ENVIRONMENT" sync --selector name=notification

echo "⏳ Waiting for services to be ready..."
kubectl wait --for=condition=available deployment \
    --all \
    --namespace=platform \
    --timeout=300s || true

echo "✅ Deployment complete!"
echo "📝 Check status with: kubectl get pods --all-namespaces"

