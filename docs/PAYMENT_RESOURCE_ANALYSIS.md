# 🔍 Payment Service Resource Analysis

Analysis of Payment service implementation to ensure it uses only shared cluster resources.

## ❌ Issues Found: Standalone Resources

The Payment service currently deploys **standalone resources** that should be removed and replaced with shared infrastructure:

### 1. Standalone PostgreSQL Deployment ❌

**File**: `services/Payment/k8s/postgres-deployment.yaml`

**Problem**: Deploys its own PostgreSQL instance instead of using shared PostgreSQL HA cluster.

**Resources Created**:
- PostgreSQL Deployment (1 replica)
- PostgreSQL Service (`postgres-service`)
- PersistentVolumeClaim (10Gi storage)
- PostgreSQL Secret

**Should Use**: 
- Shared PostgreSQL HA: `postgres-ha-postgresql-ha-pgpool.infrastructure.svc.cluster.local:5432`
- Database: `PaymentDb` (created on shared cluster)

**Impact**: 
- Wastes resources (256Mi memory, 250m CPU + 10Gi storage)
- Not highly available (single instance)
- Data isolation issues
- Duplicate infrastructure

### 2. Standalone Jaeger Deployment ❌

**File**: `services/Payment/k8s/jaeger-deployment.yaml`

**Problem**: Deploys its own Jaeger instance for distributed tracing.

**Resources Created**:
- Jaeger Deployment (1 replica)
- 3 Services (jaeger-agent, jaeger-collector, jaeger-query)
- LoadBalancer service for UI
- Storage (emptyDir, 256Mi-1Gi memory)

**Should Use**: 
- **Shared Jaeger in monitoring namespace** (to be added to shared infrastructure)
- Or use Prometheus metrics only (simpler, no tracing backend needed)

**Impact**:
- Wastes resources (256Mi-1Gi memory, 200m-1000m CPU)
- Duplicate tracing infrastructure
- Additional LoadBalancer cost

**Status**: Jaeger is NOT currently in shared infrastructure. See [Observability Setup](./OBSERVABILITY_SETUP.md) for options.

### 3. Standalone Zipkin Deployment ❌

**File**: `services/Payment/k8s/zipkin-deployment.yaml`

**Problem**: Deploys its own Zipkin instance (duplicate of Jaeger).

**Resources Created**:
- Zipkin Deployment (1 replica)
- Zipkin Service (LoadBalancer)
- Storage (256Mi-512Mi memory)

**Should Use**: 
- **Shared Jaeger** (Jaeger provides Zipkin-compatible endpoint at port 9411)
- Or remove (not needed if using Jaeger)

**Impact**:
- Wastes resources (256Mi-512Mi memory, 200m-500m CPU)
- Redundant with Jaeger
- Additional LoadBalancer cost

**Status**: Zipkin is NOT needed - Jaeger provides Zipkin-compatible endpoint.

### 4. Network Policies Reference Standalone Resources ❌

**File**: `services/Payment/k8s/networkpolicies.yaml`

**Problem**: Network policies reference standalone PostgreSQL, Jaeger, and Zipkin.

**Should Reference**:
- Shared PostgreSQL in `infrastructure` namespace
- Shared observability services (if available)
- Remove references to standalone resources

### 5. Configuration Points to Standalone Services ❌

**Files**: 
- `services/Payment/k8s/configmap.yaml`
- `services/Payment/k8s/secret.yaml`

**Problem**: Connection strings and service references point to standalone deployments.

**Current**:
- `postgres-service` (standalone)
- `jaeger-agent` (standalone)
- `zipkin` (standalone)

**Should Use**:
- `postgres-ha-postgresql-ha-pgpool.infrastructure.svc.cluster.local:5432`
- Shared RabbitMQ: `rabbitmq.infrastructure.svc.cluster.local:5672`
- Shared Redis: `redis-master.infrastructure.svc.cluster.local:6379`

## ✅ Correct Implementation (Helm Chart)

The Helm chart in `charts/services/payment/` is **correctly configured** to use shared resources:

### ✅ Uses Shared PostgreSQL

```yaml
env:
  - name: ConnectionStrings__DefaultConnection
    valueFrom:
      secretKeyRef:
        name: payment-secrets
        key: database-connection
```

**Connection string** (from Azure Key Vault):
```
Host=postgres-ha-postgresql-ha-pgpool.infrastructure.svc.cluster.local;Port=5432;Database=PaymentDb;...
```

### ✅ Uses Shared RabbitMQ

```yaml
env:
  - name: RabbitMQ__ConnectionString
    valueFrom:
      secretKeyRef:
        name: payment-secrets
        key: rabbitmq-connection
```

**Connection string** (from Azure Key Vault):
```
amqp://user:password@rabbitmq.infrastructure.svc.cluster.local:5672
```

### ✅ Uses Shared Redis

The service code supports Redis caching (configured via connection string).

### ✅ Uses Shared Monitoring

- Prometheus metrics exposed via ServiceMonitor
- Health checks configured
- No standalone monitoring resources

## 📊 Resource Comparison

### Current (Standalone Resources)

| Resource | Memory | CPU | Storage | Cost |
|----------|--------|-----|---------|------|
| PostgreSQL | 256Mi-512Mi | 250m-500m | 10Gi | High |
| Jaeger | 256Mi-1Gi | 200m-1000m | - | Medium |
| Zipkin | 256Mi-512Mi | 200m-500m | - | Medium |
| **Total** | **768Mi-2Gi** | **650m-2000m** | **10Gi** | **High** |

### Correct (Shared Resources)

| Resource | Memory | CPU | Storage | Cost |
|----------|--------|-----|---------|------|
| Payment API | 256Mi-512Mi | 250m-500m | - | Low |
| **Total** | **256Mi-512Mi** | **250m-500m** | **0Gi** | **Low** |

**Savings**: ~1.5Gi memory, ~1.5 CPU cores, 10Gi storage per Payment service instance

## 🔧 Required Changes

### 1. Remove Standalone Deployments

**Files to Delete**:
- `services/Payment/k8s/postgres-deployment.yaml` ❌
- `services/Payment/k8s/jaeger-deployment.yaml` ❌
- `services/Payment/k8s/zipkin-deployment.yaml` ❌

### 2. Update Network Policies

**File**: `services/Payment/k8s/networkpolicies.yaml`

**Changes**:
- Remove references to standalone PostgreSQL
- Update to reference shared PostgreSQL in `infrastructure` namespace
- Remove references to standalone Jaeger/Zipkin
- Add references to shared RabbitMQ and Redis if needed

### 3. Update Configuration

**Files**: 
- `services/Payment/k8s/configmap.yaml`
- `services/Payment/k8s/secret.yaml`

**Changes**:
- Remove references to standalone services
- Update connection strings to use shared infrastructure
- Remove Jaeger/Zipkin endpoints (use shared observability)

### 4. Update Documentation

**Files**:
- `services/Payment/README.md`
- `services/Payment/docs/03-Infrastructure/Kubernetes_Deployment.md`

**Changes**:
- Document use of shared infrastructure
- Remove references to standalone deployments
- Update connection string examples

## ✅ Correct Deployment Method

**Use Helm Chart** (already configured correctly):

```bash
# Deploy via Helmfile (uses shared resources)
helmfile -l name=payment sync

# Or via ArgoCD
kubectl apply -f argocd/applications/microservices.yaml
```

**Do NOT use**:
```bash
# ❌ DON'T USE - Deploys standalone resources
kubectl apply -f services/Payment/k8s/
```

## 📋 Shared Infrastructure Services

### PostgreSQL HA
- **Service**: `postgres-ha-postgresql-ha-pgpool.infrastructure.svc.cluster.local`
- **Port**: `5432`
- **Database**: Create `PaymentDb` database on shared cluster
- **Namespace**: `infrastructure`

### RabbitMQ
- **Service**: `rabbitmq.infrastructure.svc.cluster.local`
- **Port**: `5672` (AMQP), `15672` (Management)
- **Namespace**: `infrastructure`

### Redis
- **Service**: `redis-master.infrastructure.svc.cluster.local`
- **Port**: `6379`
- **Namespace**: `infrastructure`

### Monitoring
- **Prometheus**: `prometheus-operated.monitoring.svc.cluster.local:9090`
- **Grafana**: `grafana.monitoring.svc.cluster.local`
- **Loki**: `loki-gateway.monitoring.svc.cluster.local:3100`
- **Namespace**: `monitoring`

## 🎯 Action Items

- [ ] Delete `services/Payment/k8s/postgres-deployment.yaml`
- [ ] Delete `services/Payment/k8s/jaeger-deployment.yaml`
- [ ] Delete `services/Payment/k8s/zipkin-deployment.yaml`
- [ ] Update `services/Payment/k8s/networkpolicies.yaml` to reference shared resources
- [ ] Update `services/Payment/k8s/configmap.yaml` to remove standalone service references
- [ ] Update `services/Payment/k8s/secret.yaml` to use shared PostgreSQL connection string
- [ ] Update documentation to reflect shared infrastructure usage
- [ ] Add note in README: "Use Helm chart deployment, not standalone k8s manifests"

## 📚 Related Documentation

- [Payment Integration Guide](./PAYMENT_INTEGRATION.md)
- [Deployment Summary](./DEPLOYMENT_SUMMARY.md)
- [Architecture Overview](./ARCHITECTURE.md)

