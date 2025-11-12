# Troubleshooting Guide

## Common Issues and Solutions

### Cluster Access Issues

**Problem:** `kubectl` commands fail with authentication errors.

**Solution:**
```bash
# Re-authenticate with Azure
az login
az aks get-credentials --resource-group <rg-name> --name <cluster-name> --overwrite-existing
```

---

### Pods Stuck in Pending State

**Problem:** Pods remain in `Pending` state.

**Possible Causes:**
1. Insufficient node resources
2. Node selector/affinity constraints
3. Persistent volume claims not bound

**Solution:**
```bash
# Check pod events
kubectl describe pod <pod-name> -n <namespace>

# Check node resources
kubectl top nodes

# Check PVC status
kubectl get pvc -n <namespace>
```

---

### Database Connection Failures

**Problem:** Microservices cannot connect to PostgreSQL.

**Solution:**
```bash
# Verify PostgreSQL is running
kubectl get pods -n infrastructure -l app.kubernetes.io/name=postgresql-ha

# Check service endpoints
kubectl get endpoints postgres-ha-postgresql-ha-pgpool -n infrastructure

# Test connection from a pod
kubectl run -it --rm debug --image=postgres:15 --restart=Never -- \
  psql -h postgres-ha-postgresql-ha-pgpool.infrastructure.svc.cluster.local -U postgres
```

---

### Redis Connection Issues

**Problem:** Services cannot connect to Redis.

**Solution:**
```bash
# Verify Redis pods
kubectl get pods -n infrastructure -l app.kubernetes.io/name=redis

# Check Redis service
kubectl get svc redis -n infrastructure

# Test Redis connection
kubectl run -it --rm redis-test --image=redis:7 --restart=Never -- \
  redis-cli -h redis.infrastructure.svc.cluster.local -a <password>
```

---

### RabbitMQ Connection Problems

**Problem:** Message queue connections fail.

**Solution:**
```bash
# Check RabbitMQ status
kubectl get pods -n infrastructure -l app.kubernetes.io/name=rabbitmq

# Access RabbitMQ management UI
kubectl port-forward svc/rabbitmq 15672:15672 -n infrastructure
# Open http://localhost:15672 (admin/<password>)
```

---

### Helmfile Deployment Failures

**Problem:** `helmfile sync` fails with errors.

**Solution:**
```bash
# Check Helmfile status
helmfile -e <environment> list

# Dry-run to see what would be deployed
helmfile -e <environment> diff

# Check Helm releases
helm list -A

# View failed release details
helm status <release-name> -n <namespace>
```

---

### Image Pull Errors

**Problem:** Pods fail with `ImagePullBackOff` error.

**Solution:**
```bash
# Verify ACR access
az acr login --name <acr-name>

# Check AKS-ACR integration
az aks check-acr --name <cluster-name> --resource-group <rg-name> --acr <acr-name>

# Verify image exists
az acr repository list --name <acr-name>
```

---

### Secret Provider Class Issues

**Problem:** Azure Key Vault secrets not mounting.

**Solution:**
```bash
# Check Secret Provider Class
kubectl get secretproviderclass -n <namespace>

# Check CSI driver pods
kubectl get pods -n kube-system -l app=secrets-store-csi-driver

# View pod events for secret mount errors
kubectl describe pod <pod-name> -n <namespace>
```

---

### Ingress Not Working

**Problem:** Services not accessible via Ingress.

**Solution:**
```bash
# Check Ingress controller
kubectl get pods -n ingress-nginx

# Verify Ingress resource
kubectl get ingress -A

# Check Ingress events
kubectl describe ingress <ingress-name> -n <namespace>

# Test ingress controller
kubectl get svc -n ingress-nginx
```

---

### High Memory/CPU Usage

**Problem:** Pods consuming excessive resources.

**Solution:**
```bash
# Check resource usage
kubectl top pods -A

# View HPA status
kubectl get hpa -A

# Check pod resource limits
kubectl describe pod <pod-name> -n <namespace>
```

---

### Monitoring Not Working

**Problem:** Prometheus/Grafana not collecting metrics.

**Solution:**
```bash
# Check Prometheus pods
kubectl get pods -n monitoring -l app.kubernetes.io/name=prometheus

# Verify ServiceMonitors
kubectl get servicemonitor -A

# Check Prometheus targets
kubectl port-forward svc/prometheus-kube-prometheus-prometheus 9090:9090 -n monitoring
# Open http://localhost:9090/targets
```

---

### ArgoCD Sync Issues

**Problem:** ArgoCD applications not syncing.

**Solution:**
```bash
# Check ArgoCD pods
kubectl get pods -n argocd

# View application status
kubectl get applications -n argocd

# Check application events
kubectl describe application <app-name> -n argocd

# Access ArgoCD UI
kubectl port-forward svc/argocd-server 8080:443 -n argocd
# Get admin password: kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

---

## Getting Help

1. **Check logs:**
   ```bash
   kubectl logs <pod-name> -n <namespace>
   kubectl logs <pod-name> -n <namespace> --previous  # Previous container instance
   ```

2. **Describe resources:**
   ```bash
   kubectl describe <resource-type> <resource-name> -n <namespace>
   ```

3. **Check events:**
   ```bash
   kubectl get events -n <namespace> --sort-by='.lastTimestamp'
   ```

4. **Verify configuration:**
   ```bash
   kubectl get <resource-type> <resource-name> -n <namespace> -o yaml
   ```

---

## Emergency Procedures

### Rollback a Deployment
```bash
helm rollback <release-name> <revision> -n <namespace>
```

### Delete Stuck Resources
```bash
kubectl delete <resource-type> <resource-name> -n <namespace> --force --grace-period=0
```

### Restart All Pods in Namespace
```bash
kubectl delete pods --all -n <namespace>
```

