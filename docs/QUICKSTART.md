# Quick Start Guide

Get your platform infrastructure up and running in minutes!

## Prerequisites Checklist

- [ ] Azure CLI installed (`az --version`)
- [ ] kubectl installed (`kubectl version --client`)
- [ ] Helm 3.x installed (`helm version`)
- [ ] Helmfile installed (`helmfile version`)
- [ ] Azure subscription with appropriate permissions
- [ ] Git repository cloned: `git clone https://github.com/Murtadah-1984/platform-infra.git`

## 5-Minute Setup

### Step 1: Azure Login & Setup (2 minutes)

```bash
# Login to Azure
az login

# Run automated setup script
cd platform-infra
./scripts/setup-azure.sh
```

This creates:
- Resource group
- Azure Container Registry (ACR)
- AKS cluster
- Kubernetes namespaces

### Step 2: Install ArgoCD (1 minute)

```bash
./scripts/install-argocd.sh
```

### Step 3: Create Secrets (1 minute)

```bash
./scripts/create-secrets.sh dev
```

Follow the prompts to enter:
- PostgreSQL password
- Redis password
- RabbitMQ password
- JWT secret key
- SMTP credentials

### Step 4: Deploy (1 minute)

```bash
# Option A: Using Helmfile
helmfile sync

# Option B: Using Make
make install

# Option C: Using ArgoCD (GitOps)
kubectl apply -f argocd/applications/
```

## Verify Deployment

```bash
# Check all pods
kubectl get pods -A

# Check services
kubectl get svc -A

# Check ArgoCD applications
kubectl get applications -n argocd
```

## Access Services

### ArgoCD UI

```bash
kubectl port-forward svc/argocd-server -n argocd 8080:443
# Visit: https://localhost:8080
# Username: admin
# Password: (get from install script output)
```

### Grafana

```bash
kubectl port-forward svc/prometheus-stack-grafana -n monitoring 3000:80
# Visit: http://localhost:3000
# Default credentials: admin / (check values.yaml)
```

## Next Steps

1. **Update Repository URLs**: Edit `argocd/applications/*.yaml` if using different Git repo
2. **Configure Domains**: Update `environments/*.yaml` with your domain names
3. **Build & Push Images**: Build your microservice images and push to ACR
4. **Customize Values**: Adjust resource limits, replicas in `charts/*/values.yaml`

## Troubleshooting

### Pods not starting?

```bash
# Check pod logs
kubectl logs -n platform <pod-name>

# Check events
kubectl describe pod -n platform <pod-name>
```

### ArgoCD sync issues?

```bash
# Check application status
kubectl describe application -n argocd <app-name>

# Manual sync
argocd app sync <app-name>
```

### Database connection errors?

```bash
# Verify PostgreSQL is running
kubectl get pods -n infrastructure | grep postgres

# Test connection
kubectl exec -it -n infrastructure postgres-ha-postgresql-ha-postgresql-0 -- psql -U postgres
```

## Production Deployment

For production, update environment values:

```bash
# Edit production environment
vim environments/production.yaml

# Deploy to production
helmfile -e production sync
```

## Cleanup

To remove everything:

```bash
# Remove all Helm releases
helmfile destroy

# Remove ArgoCD
kubectl delete namespace argocd

# Remove Azure resources (careful!)
az group delete --name platform-rg --yes --no-wait
```

## Need Help?

- [Deployment Guide](DEPLOYMENT.md) - Detailed instructions
- [Architecture](ARCHITECTURE.md) - System design
- [GitHub Issues](https://github.com/Murtadah-1984/platform-infra/issues) - Report problems

