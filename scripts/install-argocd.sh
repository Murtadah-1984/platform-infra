#!/bin/bash
set -e

# Install ArgoCD on AKS
echo "🚀 Installing ArgoCD..."

# Create namespace
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -

# Install ArgoCD
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Wait for ArgoCD to be ready
echo "⏳ Waiting for ArgoCD to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/argocd-server -n argocd

# Get initial admin password
echo ""
echo "🔑 ArgoCD Admin Credentials:"
echo "   Username: admin"
echo "   Password: $(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)"
echo ""

# Port forward instructions
echo "📡 To access ArgoCD UI, run:"
echo "   kubectl port-forward svc/argocd-server -n argocd 8080:443"
echo ""
echo "   Then visit: https://localhost:8080"
echo ""

# Install ArgoCD CLI (optional)
if ! command -v argocd &> /dev/null; then
    echo "💡 To install ArgoCD CLI:"
    echo "   curl -sSL -o /usr/local/bin/argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64"
    echo "   chmod +x /usr/local/bin/argocd"
fi

echo "✅ ArgoCD installation complete!"

