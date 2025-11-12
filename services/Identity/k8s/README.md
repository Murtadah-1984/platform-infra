# Identity Service - Kubernetes Deployment Manifests

This directory contains all Kubernetes manifests for deploying the Identity microservice.

## Files

- `namespace.yaml` - Platform namespace
- `configmap.yaml` - Non-sensitive configuration
- `secret.yaml` - Sensitive configuration (replace values!)
- `serviceaccount.yaml` - Service account for the pod
- `rbac.yaml` - Role-based access control
- `identity-deployment.yaml` - Main deployment
- `service.yaml` - Kubernetes service
- `hpa.yaml` - Horizontal Pod Autoscaler
- `networkpolicies.yaml` - Network security policies
- `secretproviderclass.yaml` - Azure Key Vault integration
- `ingress.yaml` - Ingress configuration

## Deployment Order

1. Namespace
2. ConfigMap
3. Secret (or SecretProviderClass for Azure Key Vault)
4. ServiceAccount
5. RBAC
6. Deployment
7. Service
8. HPA
9. NetworkPolicies
10. Ingress

## Quick Deploy

```bash
# Apply all manifests
kubectl apply -f k8s/

# Or deploy in order
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml  # Update values first!
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/identity-deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/networkpolicies.yaml
kubectl apply -f k8s/ingress.yaml
```

## Configuration

### Update Secrets

Before deploying, update `secret.yaml` with actual values:

```yaml
stringData:
  database-connection: "Host=...;Port=5432;Database=identitydb;Username=...;Password=..."
  redis-connection: "redis-master:6379,password=..."
  jwt-secret: "Your32+CharacterSecretKeyHere"
```

### Azure Key Vault (Recommended for Production)

Use `secretproviderclass.yaml` instead of `secret.yaml`:

1. Update `userAssignedIdentityID` with your managed identity
2. Update `keyvaultName` with your Key Vault name
3. Update `tenantId` with your Azure tenant ID
4. Ensure secrets exist in Key Vault:
   - `Identity-DatabaseConnection`
   - `Identity-RedisConnection`
   - `Identity-JwtSecret`

## Verification

```bash
# Check pods
kubectl get pods -n platform -l app=identity-api

# Check services
kubectl get svc -n platform

# Check HPA
kubectl get hpa -n platform

# View logs
kubectl logs -n platform -l app=identity-api --tail=100

# Test health endpoint
kubectl port-forward -n platform svc/identity-service 8080:80
curl http://localhost:8080/health
```

## Troubleshooting

See [Kubernetes Deployment Guide](../docs/03-Infrastructure/Kubernetes_Deployment.md) for detailed troubleshooting.

