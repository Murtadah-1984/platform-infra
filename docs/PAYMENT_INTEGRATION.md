# 💳 Payment Microservice - Infrastructure Integration Guide

Complete guide for integrating the Payment microservice with the platform infrastructure (AKS, ArgoCD, Helm).

## 📋 Overview

The Payment microservice is **already configured** in the infrastructure repository and ready for deployment. This guide explains the integration points and how to deploy it.

## 🏗️ Architecture Integration

### Current Infrastructure Stack

```
┌─────────────────────────────────────────┐
│ Kong Gateway (API Gateway)              │
│   └─ Routes to: payment.platform.local │
├─────────────────────────────────────────┤
│ Platform Namespace                      │
│   ├─ Identity Service                   │
│   ├─ Payment Service ← This Service     │
│   └─ Notification Service               │
├─────────────────────────────────────────┤
│ Infrastructure Namespace                │
│   ├─ PostgreSQL HA (Primary + Replicas)│
│   ├─ RabbitMQ (3-node cluster)         │
│   └─ Redis (Master + Replicas)          │
└─────────────────────────────────────────┘
```

### Payment Service Dependencies

- **PostgreSQL**: Database for payment transactions
- **RabbitMQ**: Event publishing (payment completed, failed, etc.)
- **Redis**: Caching (payment provider catalog, rate limiting)
- **Identity Service**: JWT token validation (OIDC/OAuth2)
- **Kong Gateway**: API routing and rate limiting

## 🔧 Integration Points

### 1. Helm Chart Configuration

**Location**: `charts/services/payment/`

The Payment service is configured as a Helm chart with:

- **Deployment**: Stateless pods with health probes
- **Service**: ClusterIP for internal communication
- **Ingress**: Kong Gateway integration
- **HPA**: Horizontal Pod Autoscaling (2-10 replicas)
- **Secrets**: Azure Key Vault CSI driver integration

### 2. ArgoCD Application

**Location**: `argocd/applications/microservices.yaml`

The Payment service is included in the microservices ArgoCD application:

```yaml
selectors:
  - name=payment  # Payment service selector
```

### 3. Helmfile Release

**Location**: `helmfile.yaml`

Payment service is defined as a Helm release:

```yaml
- name: payment
  namespace: platform
  chart: ./charts/services/payment
  values:
    - ./charts/services/payment/values.yaml
```

## 🚀 Deployment Steps

### Prerequisites

1. **Azure Resources**:
   - AKS cluster created
   - Azure Container Registry (ACR)
   - Azure Key Vault

2. **Infrastructure Components**:
   - PostgreSQL HA deployed
   - RabbitMQ deployed
   - Redis deployed
   - Kong Gateway deployed

3. **Secrets in Azure Key Vault**:
   - `Payment-DatabaseConnection`: PostgreSQL connection string
   - `Payment-RabbitMQConnection`: RabbitMQ connection string
   - `Payment-RedisConnection`: Redis connection string (if needed)

### Step 1: Build and Push Docker Image

```bash
# Navigate to Payment service directory
cd services/Payment

# Build Docker image
docker build -t payment-api:latest .

# Tag for ACR
docker tag payment-api:latest platformacr.azurecr.io/payment:latest

# Login to ACR
az acr login --name platformacr

# Push to ACR
docker push platformacr.azurecr.io/payment:latest
```

### Step 2: Configure Environment Values

Update `environments/default.yaml` (or environment-specific file):

```yaml
payment:
  azureKeyVault:
    name: platform-kv
    tenantId: "<your-tenant-id>"
    managedIdentityClientId: "<payment-service-identity-client-id>"
```

### Step 3: Setup Azure Key Vault Secrets

```bash
# Run setup script (if not already done)
./scripts/setup-keyvault.sh

# Or manually create secrets
az keyvault secret set \
  --vault-name platform-kv \
  --name Payment-DatabaseConnection \
  --value "Host=postgres-ha-postgresql-ha-pgpool.infrastructure.svc.cluster.local;Port=5432;Database=PaymentDb;Username=postgres;Password=<password>"

az keyvault secret set \
  --vault-name platform-kv \
  --name Payment-RabbitMQConnection \
  --value "amqp://user:password@rabbitmq.infrastructure.svc.cluster.local:5672"
```

### Step 4: Deploy via Helmfile

```bash
# Deploy all services (including Payment)
helmfile sync

# Or deploy only Payment service
helmfile -l name=payment sync
```

### Step 5: Deploy via ArgoCD (GitOps)

```bash
# Apply ArgoCD Application
kubectl apply -f argocd/applications/microservices.yaml

# ArgoCD will automatically sync the Payment service
# Access ArgoCD UI to monitor deployment
kubectl port-forward svc/argocd-server -n argocd 8080:443
```

## 🔐 Configuration Details

### Environment Variables

The Payment service expects these environment variables (configured in `charts/services/payment/values.yaml`):

```yaml
env:
  - name: ASPNETCORE_ENVIRONMENT
    value: "Production"
  - name: ASPNETCORE_URLS
    value: "http://+:8080"
  - name: ConnectionStrings__DefaultConnection
    valueFrom:
      secretKeyRef:
        name: payment-secrets
        key: database-connection
  - name: RabbitMQ__ConnectionString
    valueFrom:
      secretKeyRef:
        name: payment-secrets
        key: rabbitmq-connection
```

### Azure Key Vault Integration

The service uses **Azure Key Vault CSI Secret Store Driver** for secure secret management:

1. **SecretProviderClass** (`charts/services/payment/templates/secretproviderclass.yaml`):
   - Mounts secrets from Azure Key Vault
   - Uses Workload Identity for authentication
   - No service principal secrets required

2. **Volume Mount**:
   - Secrets mounted at `/mnt/secrets-store`
   - Also available as Kubernetes Secrets for environment variables

### Database Connection

The Payment service connects to PostgreSQL HA:

- **Service**: `postgres-ha-postgresql-ha-pgpool.infrastructure.svc.cluster.local`
- **Port**: `5432`
- **Database**: `PaymentDb`
- **Connection String**: Stored in Azure Key Vault

### RabbitMQ Integration

For event publishing (domain events):

- **Service**: `rabbitmq.infrastructure.svc.cluster.local`
- **Port**: `5672`
- **Connection String**: Stored in Azure Key Vault

### Identity Service Integration

JWT authentication is handled by the Identity microservice:

- **Authority**: `https://identity.platform.local` (or configured domain)
- **Audience**: `payment-service`
- **JWKS Endpoint**: Automatically discovered from Identity service

## 🌐 API Gateway (Kong) Integration

### Ingress Configuration

The Payment service ingress is configured in `charts/services/payment/values.yaml`:

```yaml
ingress:
  enabled: true
  className: "nginx"
  annotations:
    konghq.com/plugins: "rate-limiting,request-validator"
  hosts:
    - host: payment.platform.local
      paths:
        - path: /
          pathType: Prefix
```

### Kong Route Configuration

Configure Kong to route to Payment service:

```yaml
# Kong route (configured separately or via Kong Ingress Controller)
apiVersion: configuration.konghq.com/v1
kind: KongIngress
metadata:
  name: payment-route
spec:
  upstream:
    host: payment.platform.svc.cluster.local
    port: 80
```

## 📊 Monitoring & Observability

### Health Checks

- **Liveness**: `GET /health` (port 8080)
- **Readiness**: `GET /health/ready` (port 8080)

### Prometheus Metrics

The service exposes Prometheus metrics at `/metrics`:

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    namespace: monitoring
```

### OpenTelemetry Tracing

Configured for distributed tracing:

- **Jaeger**: `jaeger-agent:6831`
- **Zipkin**: `http://zipkin:9411/api/v2/spans`

## 🔄 Service Communication

### Internal Service Discovery

Services communicate via Kubernetes DNS:

- **Payment → Identity**: `http://identity.platform.svc.cluster.local`
- **Payment → Notification**: `http://notification.platform.svc.cluster.local`
- **Payment → PostgreSQL**: `postgres-ha-postgresql-ha-pgpool.infrastructure.svc.cluster.local`
- **Payment → RabbitMQ**: `rabbitmq.infrastructure.svc.cluster.local`

### Network Policies

Ensure network policies allow communication:

```yaml
# Payment service can reach:
# - Infrastructure namespace (PostgreSQL, RabbitMQ, Redis)
# - Platform namespace (Identity, Notification)
# - Kong Gateway
```

## 🧪 Testing Integration

### 1. Verify Deployment

```bash
# Check pods
kubectl get pods -n platform -l app=payment

# Check service
kubectl get svc -n platform payment

# Check ingress
kubectl get ingress -n platform payment
```

### 2. Test Health Endpoints

```bash
# Port forward to service
kubectl port-forward -n platform svc/payment 8080:80

# Test health
curl http://localhost:8080/health
curl http://localhost:8080/health/ready
```

### 3. Test API Endpoints

```bash
# Get payment providers (no auth required)
curl https://payment.platform.local/api/v1/payments/providers/IQ

# Create payment (requires JWT token)
curl -X POST https://payment.platform.local/api/v1/payments \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{"amount": 100, "currency": "USD", "provider": "Stripe"}'
```

## 🔧 Troubleshooting

### Common Issues

1. **Secrets not loading**:
   ```bash
   # Check SecretProviderClass
   kubectl get secretproviderclass -n platform
   
   # Check secrets volume mount
   kubectl describe pod -n platform -l app=payment
   ```

2. **Database connection failed**:
   ```bash
   # Verify PostgreSQL service
   kubectl get svc -n infrastructure postgres-ha-postgresql-ha-pgpool
   
   # Test connection from Payment pod
   kubectl exec -n platform -it <payment-pod> -- \
     psql -h postgres-ha-postgresql-ha-pgpool.infrastructure.svc.cluster.local -U postgres
   ```

3. **Identity service not reachable**:
   ```bash
   # Check Identity service
   kubectl get svc -n platform identity
   
   # Test from Payment pod
   kubectl exec -n platform -it <payment-pod> -- \
     curl http://identity.platform.svc.cluster.local/health
   ```

## 📚 Additional Resources

- [Payment Service README](../services/Payment/README.md)
- [Kubernetes Deployment Guide](../services/Payment/docs/03-Infrastructure/Kubernetes_Deployment.md)
- [Architecture Documentation](../services/Payment/docs/01-Architecture/System_Architecture.md)
- [Platform Architecture](./ARCHITECTURE.md)
- [Azure Key Vault Setup](./AZURE_KEYVAULT.md)

## ✅ Integration Checklist

- [ ] Azure Key Vault configured with secrets
- [ ] Docker image built and pushed to ACR
- [ ] Environment values configured (`environments/*.yaml`)
- [ ] Infrastructure components deployed (PostgreSQL, RabbitMQ, Redis)
- [ ] Identity service deployed and accessible
- [ ] Payment service deployed via Helmfile or ArgoCD
- [ ] Health checks passing
- [ ] Kong Gateway routing configured
- [ ] Monitoring and metrics working
- [ ] Network policies configured
- [ ] Service communication verified

---

**Next Steps**: After successful integration, configure Kong Gateway routes and test end-to-end payment flows.

