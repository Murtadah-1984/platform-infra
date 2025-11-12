# Kubernetes Deployment Guide

## Overview

This guide covers deploying the Identity microservice to Kubernetes, including all required manifests and configurations.

## Prerequisites

- Kubernetes cluster (AKS recommended)
- Helm 3.x installed
- kubectl configured
- Azure Key Vault (for secrets management)
- PostgreSQL database (via infrastructure chart)
- Redis cache (via infrastructure chart)

## Deployment Methods

### Method 1: Helm Chart (Recommended)

The Identity service is deployed via Helm chart located at `charts/services/identity/`.

```bash
# Deploy using helmfile
helmfile sync

# Or deploy directly
helm install identity ./charts/services/identity \
  --namespace platform \
  --create-namespace \
  --set image.repository=platformacrprod.azurecr.io/identity \
  --set image.tag=latest
```

### Method 2: Kubernetes Manifests

Deploy using raw Kubernetes manifests from `k8s/` directory:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/identity-deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/networkpolicies.yaml
```

## Configuration

### Environment Variables

Required environment variables:

```yaml
env:
  - name: ASPNETCORE_ENVIRONMENT
    value: "Production"
  - name: ASPNETCORE_URLS
    value: "http://+:8080"
  - name: ConnectionStrings__DefaultConnection
    valueFrom:
      secretKeyRef:
        name: identity-secrets
        key: database-connection
  - name: ConnectionStrings__Redis
    valueFrom:
      secretKeyRef:
        name: identity-secrets
        key: redis-connection
  - name: Jwt__SecretKey
    valueFrom:
      secretKeyRef:
        name: identity-secrets
        key: jwt-secret
  - name: Jwt__Issuer
    value: "identity-service"
  - name: Jwt__Audience
    value: "platform-services"
```

### Secrets Management

#### Azure Key Vault CSI Driver

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: identity-secrets
  namespace: platform
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "true"
    userAssignedIdentityID: "<managed-identity-id>"
    keyvaultName: "<key-vault-name>"
    tenantId: "<tenant-id>"
    objects: |
      array:
        - |
          objectName: Identity-DatabaseConnection
          objectType: secret
          objectVersion: ""
        - |
          objectName: Identity-RedisConnection
          objectType: secret
          objectVersion: ""
        - |
          objectName: Identity-JwtSecret
          objectType: secret
          objectVersion: ""
```

#### Kubernetes Secrets (Alternative)

```bash
kubectl create secret generic identity-secrets \
  --namespace platform \
  --from-literal=database-connection="Host=postgres;Port=5432;Database=identitydb;Username=postgres;Password=..." \
  --from-literal=redis-connection="redis-master:6379,password=..." \
  --from-literal=jwt-secret="YourSuperSecretKeyThatShouldBeAtLeast32CharactersLong!"
```

## Deployment Manifest

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: identity-api
  namespace: platform
spec:
  replicas: 3
  selector:
    matchLabels:
      app: identity-api
  template:
    metadata:
      labels:
        app: identity-api
    spec:
      serviceAccountName: identity-api-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      volumes:
        - name: secrets-store
          csi:
            driver: secrets-store.csi.k8s.io
            readOnly: true
            volumeAttributes:
              secretProviderClass: identity-secrets
      containers:
        - name: identity-api
          image: platformacrprod.azurecr.io/identity:latest
          imagePullPolicy: IfNotPresent
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 10001
            runAsGroup: 10001
            capabilities:
              drop:
                - ALL
            seccompProfile:
              type: RuntimeDefault
          ports:
            - containerPort: 8080
              name: http
          envFrom:
            - configMapRef:
                name: identity-config
            - secretRef:
                name: identity-secrets
          env:
            - name: KUBERNETES_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: HOSTNAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
          livenessProbe:
            httpGet:
              path: /health/live
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 3
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          volumeMounts:
            - name: secrets-store
              mountPath: "/mnt/secrets-store"
              readOnly: true
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: identity-service
  namespace: platform
spec:
  type: ClusterIP
  selector:
    app: identity-api
  ports:
    - name: http
      port: 80
      targetPort: 8080
      protocol: TCP
```

### Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: identity-hpa
  namespace: platform
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: identity-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 50
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
        - type: Pods
          value: 2
          periodSeconds: 15
      selectPolicy: Max
```

## Database Migrations

### Option 1: Init Container

```yaml
initContainers:
  - name: migrate
    image: platformacrprod.azurecr.io/identity:latest
    command: ["dotnet", "ef", "database", "update", "--no-build"]
    env:
      - name: ConnectionStrings__DefaultConnection
        valueFrom:
          secretKeyRef:
            name: identity-secrets
            key: database-connection
```

### Option 2: Job (Recommended)

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: identity-migrate
  namespace: platform
spec:
  template:
    spec:
      containers:
        - name: migrate
          image: platformacrprod.azurecr.io/identity:latest
          command: ["dotnet", "ef", "database", "update", "--no-build"]
          env:
            - name: ConnectionStrings__DefaultConnection
              valueFrom:
                secretKeyRef:
                  name: identity-secrets
                  key: database-connection
      restartPolicy: Never
  backoffLimit: 3
```

## Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: identity-network-policy
  namespace: platform
spec:
  podSelector:
    matchLabels:
      app: identity-api
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: gateway
        - namespaceSelector:
            matchLabels:
              name: platform
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: infrastructure
      ports:
        - protocol: TCP
          port: 5432  # PostgreSQL
        - protocol: TCP
          port: 6379  # Redis
    - to:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - protocol: TCP
          port: 4317  # OTLP
```

## Service Account and RBAC

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: identity-api-sa
  namespace: platform
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: identity-api-role
  namespace: platform
rules:
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: identity-api-rolebinding
  namespace: platform
subjects:
  - kind: ServiceAccount
    name: identity-api-sa
    namespace: platform
roleRef:
  kind: Role
  name: identity-api-role
  apiGroup: rbac.authorization.k8s.io
```

## Monitoring

### ServiceMonitor (Prometheus)

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: identity-service-monitor
  namespace: platform
spec:
  selector:
    matchLabels:
      app: identity-api
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
```

## Verification

### Check Deployment Status

```bash
kubectl get pods -n platform -l app=identity-api
kubectl get svc -n platform -l app=identity-api
kubectl get hpa -n platform
```

### Check Logs

```bash
kubectl logs -n platform -l app=identity-api --tail=100
```

### Test Health Endpoints

```bash
kubectl port-forward -n platform svc/identity-service 8080:80
curl http://localhost:8080/health
curl http://localhost:8080/health/ready
```

## Troubleshooting

### Pod Not Starting

1. Check pod status: `kubectl describe pod -n platform <pod-name>`
2. Check logs: `kubectl logs -n platform <pod-name>`
3. Verify secrets: `kubectl get secret -n platform identity-secrets`
4. Check database connectivity

### Database Connection Issues

1. Verify PostgreSQL service is running
2. Check connection string in secret
3. Verify network policies allow egress
4. Test connection from pod: `kubectl exec -it -n platform <pod-name> -- nc -zv postgres 5432`

### High Memory/CPU Usage

1. Check HPA status: `kubectl get hpa -n platform`
2. Review resource limits
3. Check for memory leaks in logs
4. Scale up if needed: `kubectl scale deployment identity-api -n platform --replicas=5`

## Next Steps

- [Environment Configuration](./Environment_Configuration.md)
- [Integration Guide](../02-Integration/Integration_Guide.md)
- [System Architecture](../01-Architecture/System_Architecture.md)

