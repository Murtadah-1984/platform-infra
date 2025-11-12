# Platform Infrastructure

Azure Cloud infrastructure setup for microservice platform using ArgoCD and Helm.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Azure](https://img.shields.io/badge/Azure-0078D4?logo=azure&logoColor=white)](https://azure.microsoft.com)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![ArgoCD](https://img.shields.io/badge/ArgoCD-EF7B4D?logo=argo&logoColor=white)](https://argoproj.github.io/argo-cd/)

## Architecture

- **Orchestration**: Kubernetes (AKS)
- **GitOps**: ArgoCD
- **Package Management**: Helm/Helmfile
- **API Gateway**: Kong
- **Monitoring**: Prometheus + Grafana
- **Message Queue**: RabbitMQ
- **Cache**: Redis
- **Database**: PostgreSQL HA

## Structure

```
.
├── helmfile.yaml              # Main helmfile configuration
├── Makefile                   # Helper commands
├── environments/              # Environment-specific values
│   ├── default.yaml
│   ├── dev.yaml
│   ├── staging.yaml
│   └── production.yaml
├── charts/                    # Helm charts
│   ├── identity/              # Identity microservice
│   ├── payment/               # Payment microservice
│   ├── notification/         # Notification microservice
│   ├── postgres-ha/           # PostgreSQL HA
│   ├── rabbitmq/              # RabbitMQ values
│   ├── redis/                 # Redis values
│   ├── prometheus-stack/      # Prometheus + Grafana
│   ├── kong-gateway/          # Kong API Gateway
│   └── argocd/                # ArgoCD configuration
├── argocd/                    # ArgoCD Application manifests
│   └── applications/
│       ├── platform-infrastructure.yaml
│       ├── infrastructure-components.yaml
│       └── microservices.yaml
├── scripts/                   # Automation scripts
│   ├── setup-azure.sh
│   ├── install-argocd.sh
│   └── create-secrets.sh
├── .github/workflows/         # CI/CD pipelines
│   └── deploy.yml
├── azure/terraform/           # Optional Terraform IaC
│   └── main.tf
└── docs/                      # Documentation
    ├── DEPLOYMENT.md
    └── ARCHITECTURE.md
```

## Prerequisites

- Azure CLI
- kubectl configured for AKS
- Helm 3.x
- Helmfile
- ArgoCD CLI (optional)

## Quick Start

### Prerequisites

- Azure CLI installed and configured
- kubectl installed
- Helm 3.x installed
- Helmfile installed
- Access to Azure subscription

### Automated Setup

```bash
# 1. Setup Azure resources (AKS, ACR, namespaces)
./scripts/setup-azure.sh

# 2. Install ArgoCD
./scripts/install-argocd.sh

# 3. Create Kubernetes secrets
./scripts/create-secrets.sh dev

# 4. Deploy infrastructure
helmfile sync
# or
make install
```

### Manual Setup

#### 1. Azure Resources

```bash
# Login to Azure
az login

# Create resource group
az group create --name platform-rg --location eastus

# Create AKS cluster
az aks create \
  --resource-group platform-rg \
  --name platform-aks \
  --node-count 3 \
  --enable-addons monitoring \
  --enable-managed-identity \
  --generate-ssh-keys

# Get AKS credentials
az aks get-credentials --resource-group platform-rg --name platform-aks
```

#### 2. Install ArgoCD

```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

#### 3. Deploy with Helmfile

```bash
# Install all components
helmfile sync

# Deploy specific environment
helmfile -e production sync

# Deploy specific release
helmfile -l name=identity sync
```

#### 4. Deploy with ArgoCD

```bash
# Update repository URL in argocd/applications/*.yaml
# Then apply ArgoCD Applications
kubectl apply -f argocd/applications/

# Access ArgoCD UI
kubectl port-forward svc/argocd-server -n argocd 8080:443
# Default username: admin
# Get password: kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

For detailed deployment instructions, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Configuration

### Environment Variables

Update `environments/*.yaml` with:
- Azure resource names
- Image registry URLs
- Domain names
- Resource limits

### Secrets Management

This platform uses **Azure Key Vault** with CSI Secret Store driver instead of Kubernetes Secrets.

#### Setup Azure Key Vault

```bash
# Run automated setup script
./scripts/setup-keyvault.sh
```

This script:
- Creates Azure Key Vault
- Enables OIDC issuer on AKS
- Creates managed identities for each service
- Grants Key Vault access permissions
- Creates federated credentials for workload identity
- Creates sample secrets

#### Update Environment Configuration

After running the setup script, update `environments/*.yaml` with:
- Key Vault name
- Tenant ID
- Managed Identity Client IDs (one per service)

For detailed instructions, see [Azure Key Vault Documentation](docs/AZURE_KEYVAULT.md).

## Services

### Microservices

- **Identity**: Authentication and authorization (`identity.platform.local`)
- **Payment**: Payment processing (`payment.platform.local`) - [Integration Guide](docs/PAYMENT_INTEGRATION.md)
- **Notification**: Notifications and alerts (`notification.platform.local`)

### Infrastructure

- **PostgreSQL HA**: Primary + 2 read replicas
- **RabbitMQ**: 3-node cluster
- **Redis**: Master + 2 replicas
- **Kong Gateway**: API Gateway with LoadBalancer
- **Monitoring Stack**: Prometheus + Grafana + Loki + Promtail
- **ArgoCD**: GitOps deployment

> 📊 **See [Deployment Summary](docs/DEPLOYMENT_SUMMARY.md) for complete component overview**

## Monitoring

- **Grafana**: `http://grafana.monitoring.svc.cluster.local`
- **Prometheus**: `http://prometheus.monitoring.svc.cluster.local`
- **Kong Admin**: `http://kong-admin.gateway.svc.cluster.local:8001`

## CI/CD

ArgoCD watches the Git repository and automatically syncs changes. Update charts and values, then commit to trigger deployment.

GitHub Actions workflow (`.github/workflows/deploy.yml`) provides automated deployment on push to main/develop branches.

## Scripts

- `scripts/setup-azure.sh` - Setup Azure resources (AKS, ACR)
- `scripts/install-argocd.sh` - Install ArgoCD on cluster
- `scripts/setup-keyvault.sh` - Setup Azure Key Vault with managed identities

## Security

- All services run as non-root users
- Network policies restrict inter-pod communication
- **Azure Key Vault** integration via CSI Secret Store driver
- **Workload Identity** for pod authentication (no service principal secrets)
- **Automatic secret rotation** via Key Vault policies
- TLS enabled for all ingress endpoints
- Security contexts with read-only filesystem
- RBAC configured for service accounts

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License.

## Additional Documentation

- [Quick Start Guide](docs/QUICKSTART.md) - Get started in 5 minutes
- [Deployment Summary](docs/DEPLOYMENT_SUMMARY.md) - Complete component overview and deployment status
- [Deployment Guide](docs/DEPLOYMENT.md) - Detailed deployment instructions
- [Architecture Overview](docs/ARCHITECTURE.md) - System architecture and design
- [Payment Service Integration](docs/PAYMENT_INTEGRATION.md) - Complete Payment microservice integration guide
- [Terraform Infrastructure](azure/terraform/README.md) - Infrastructure as Code setup

