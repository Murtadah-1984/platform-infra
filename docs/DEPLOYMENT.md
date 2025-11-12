# Deployment Guide

## Prerequisites

- Azure CLI installed and configured
- kubectl installed
- Helm 3.x installed
- Helmfile installed
- Access to Azure subscription

## Quick Start

### 1. Setup Azure Resources

```bash
# Make script executable
chmod +x scripts/setup-azure.sh

# Run setup (customize variables as needed)
RESOURCE_GROUP=platform-rg \
  AKS_CLUSTER=platform-aks \
  ACR_NAME=platformacr \
  ./scripts/setup-azure.sh
```

### 2. Install ArgoCD

```bash
chmod +x scripts/install-argocd.sh
./scripts/install-argocd.sh
```

### 3. Create Secrets

```bash
chmod +x scripts/create-secrets.sh
./scripts/create-secrets.sh dev
```

### 4. Deploy Infrastructure

#### Option A: Using Helmfile Directly

```bash
# Deploy all components
helmfile sync

# Deploy specific environment
helmfile -e production sync

# Deploy specific service
helmfile -l name=identity sync
```

#### Option B: Using ArgoCD

```bash
# Apply ArgoCD Applications
kubectl apply -f argocd/applications/

# ArgoCD will automatically sync from Git
```

#### Option C: Using Make

```bash
# Install all
make install

# Deploy to specific environment
make deploy-prod
```

## Environment-Specific Deployment

### Development

```bash
helmfile -e dev sync
```

### Staging

```bash
helmfile -e staging sync
```

### Production

```bash
helmfile -e production sync
```

## Verification

```bash
# Check all pods
kubectl get pods -A

# Check services
kubectl get svc -A

# Check ingress
kubectl get ingress -A

# Check ArgoCD applications
kubectl get applications -n argocd
```

## Troubleshooting

### Pods not starting

```bash
# Check pod logs
kubectl logs -n platform <pod-name>

# Check pod events
kubectl describe pod -n platform <pod-name>
```

### ArgoCD sync issues

```bash
# Check ArgoCD application status
kubectl describe application -n argocd <app-name>

# Check ArgoCD logs
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-server
```

### Database connection issues

```bash
# Verify PostgreSQL is running
kubectl get pods -n infrastructure | grep postgres

# Test connection
kubectl exec -it -n infrastructure postgres-ha-postgresql-ha-postgresql-0 -- psql -U postgres
```

## Rollback

```bash
# Rollback using Helmfile
helmfile -e production rollback

# Rollback specific release
helmfile -l name=identity rollback
```

## Cleanup

```bash
# Remove all components
helmfile destroy

# Remove ArgoCD
kubectl delete namespace argocd

# Remove Azure resources (careful!)
az group delete --name platform-rg --yes --no-wait
```

