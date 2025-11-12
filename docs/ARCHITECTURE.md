# Platform Architecture

## Overview

Microservice platform deployed on Azure Kubernetes Service (AKS) using GitOps with ArgoCD and Helm.

## Components

### Infrastructure Layer

- **PostgreSQL HA**: Primary database with read replicas
- **RabbitMQ**: Message queue for async communication
- **Redis**: Caching and session storage
- **Kong Gateway**: API Gateway and routing
- **Prometheus Stack**: Monitoring and alerting
- **ArgoCD**: GitOps deployment automation

### Application Layer

- **Identity Service**: Authentication and authorization
- **Payment Service**: Payment processing
- **Notification Service**: Email and messaging

## Network Architecture

```
Internet
  │
  ├─ Kong Gateway (LoadBalancer)
  │   ├─ Identity Service
  │   ├─ Payment Service
  │   └─ Notification Service
  │
  └─ Infrastructure Services
      ├─ PostgreSQL HA
      ├─ RabbitMQ
      └─ Redis
```

## Data Flow

1. **API Requests** → Kong Gateway → Microservices
2. **Authentication** → Identity Service → Redis (sessions)
3. **Payment Processing** → Payment Service → PostgreSQL → RabbitMQ
4. **Notifications** → Notification Service ← RabbitMQ

## High Availability

- **Database**: PostgreSQL with 1 primary + 2 replicas
- **Message Queue**: RabbitMQ 3-node cluster
- **Cache**: Redis master + 2 replicas
- **Services**: Minimum 2 replicas with HPA

## Security

- Network policies restrict inter-pod communication
- Services run as non-root users
- Secrets stored in Kubernetes Secrets
- TLS enabled for all ingress endpoints
- RBAC configured for service accounts

## Monitoring

- **Metrics**: Prometheus scrapes all services
- **Dashboards**: Grafana for visualization
- **Alerts**: Alertmanager for notifications
- **Logs**: Centralized logging (optional: Azure Log Analytics)

## Scaling

- **Horizontal Pod Autoscaler**: CPU/Memory based
- **Cluster Autoscaler**: Node scaling (configured in AKS)
- **Manual Scaling**: Update replicaCount in values.yaml

## Disaster Recovery

- **Backups**: PostgreSQL automated backups (configure separately)
- **Multi-Region**: Deploy to multiple Azure regions
- **GitOps**: Infrastructure defined in Git for quick recovery

