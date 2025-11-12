# Identity Microservice - Integration Summary

## Overview

This document provides a comprehensive summary of the Identity microservice integration with the platform infrastructure.

## Project Structure

```
services/Identity/
├── src/
│   ├── Identity.API/              # Presentation layer
│   ├── Identity.Application/     # Application layer (use cases)
│   ├── Identity.Domain/           # Domain layer (entities, interfaces)
│   └── Identity.Infrastructure/  # Infrastructure layer (persistence, services)
├── k8s/                           # Kubernetes manifests
│   ├── namespace.yaml
│   ├── configmap.yaml
│   ├── secret.yaml
│   ├── serviceaccount.yaml
│   ├── rbac.yaml
│   ├── identity-deployment.yaml
│   ├── service.yaml
│   ├── hpa.yaml
│   ├── networkpolicies.yaml
│   ├── secretproviderclass.yaml
│   └── ingress.yaml
├── docs/                          # Comprehensive documentation
│   ├── README.md
│   ├── 01-Architecture/
│   ├── 02-Integration/
│   └── 03-Infrastructure/
├── Dockerfile
├── docker-compose.yml
├── Identity.sln
└── README.md
```

## Architecture Compliance

### ✅ Clean Architecture

- **Domain Layer**: Pure business logic, no dependencies
- **Application Layer**: Use cases, depends only on Domain
- **Infrastructure Layer**: Implements Domain interfaces
- **Presentation Layer**: Thin controllers, delegates to Application

### ✅ SOLID Principles

- **Single Responsibility**: Each class has one reason to change
- **Open/Closed**: Behaviors extend functionality without modification
- **Liskov Substitution**: Interfaces properly implemented
- **Interface Segregation**: Focused, small interfaces
- **Dependency Inversion**: Depend on abstractions, not implementations

### ✅ Stateless Microservice

- No in-memory state
- JWT tokens validated statelessly
- Refresh tokens in Redis (distributed)
- Horizontal scaling ready
- Kubernetes-native

## Infrastructure Integration

### Database (PostgreSQL)

- **Connection**: `postgres-ha-postgresql-ha-postgresql.infrastructure.svc.cluster.local:5432`
- **Database**: `identitydb`
- **Schema**: Users, Roles, Permissions, RefreshTokens
- **Migrations**: EF Core migrations

### Cache (Redis)

- **Connection**: `redis-master.infrastructure.svc.cluster.local:6379`
- **Usage**: Token blacklist, distributed caching
- **TTL**: Configurable per token type

### API Gateway (Kong)

- **Route**: `identity.platform.com`
- **Authentication**: JWT validation
- **Rate Limiting**: Configured in Kong
- **TLS**: Let's Encrypt certificates

### Monitoring

- **Prometheus**: Metrics at `/metrics`
- **Grafana**: Dashboards for visualization
- **Jaeger**: Distributed tracing
- **Loki**: Log aggregation

## Deployment

### Helm Chart

Deployed via Helm chart at `charts/services/identity/`:

```yaml
# In helmfile.yaml
- name: identity
  namespace: platform
  chart: ./charts/services/identity
  values:
    - ./charts/services/identity/values.yaml
```

### Kubernetes Manifests

All manifests in `k8s/` directory:

1. Namespace: `platform`
2. ConfigMap: Non-sensitive config
3. Secret/SecretProviderClass: Sensitive data (Azure Key Vault)
4. ServiceAccount: Pod identity
5. RBAC: Permissions
6. Deployment: Application pods
7. Service: ClusterIP service
8. HPA: Auto-scaling
9. NetworkPolicy: Security policies
10. Ingress: External access

## Configuration

### Environment Variables

- `ASPNETCORE_ENVIRONMENT`: Production
- `ASPNETCORE_URLS`: `http://+:8080`
- `ConnectionStrings__DefaultConnection`: PostgreSQL connection
- `ConnectionStrings__Redis`: Redis connection
- `Jwt__SecretKey`: JWT signing key
- `Jwt__Issuer`: `identity-service`
- `Jwt__Audience`: `platform-services`

### Secrets Management

**Production**: Azure Key Vault via CSI driver
- `Identity-DatabaseConnection`
- `Identity-RedisConnection`
- `Identity-JwtSecret`

**Development**: Kubernetes Secrets (not recommended for production)

## API Endpoints

### Authentication

- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `GET /api/v1/auth/me` - Current user (authenticated)

### Health Checks

- `GET /health` - General health
- `GET /health/live` - Liveness probe
- `GET /health/ready` - Readiness probe

### Metrics

- `GET /metrics` - Prometheus metrics

## Integration with Other Services

### Payment Service

Payment service validates JWT tokens from Identity:

```csharp
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = "https://identity.platform.com";
        options.Audience = "platform-services";
    });
```

### Notification Service

Similar JWT validation pattern.

## Security

### Authentication

- JWT access tokens (1 hour expiration)
- Refresh tokens (stored in Redis)
- Password hashing (PBKDF2 with SHA-256)
- Token revocation support

### Authorization

- Role-based access control (RBAC)
- Permission-based authorization
- Claims in JWT tokens
- Policy-based authorization in ASP.NET Core

### Network Security

- Network policies restrict pod communication
- TLS for external endpoints
- Rate limiting (per endpoint)
- CORS configuration

## Scaling

### Horizontal Pod Autoscaler

- **Min Replicas**: 2
- **Max Replicas**: 10
- **CPU Target**: 70%
- **Memory Target**: 80%

### Manual Scaling

```bash
kubectl scale deployment identity-api -n platform --replicas=5
```

## Observability

### Metrics

- HTTP request rate
- HTTP request duration
- Authentication success/failure
- Registration count
- Login count
- Error rate

### Logging

- Structured logging (Serilog)
- Correlation IDs
- Log levels: Information, Warning, Error
- Centralized in Loki

### Tracing

- OpenTelemetry instrumentation
- Jaeger integration
- Request correlation
- Distributed tracing across services

## Testing

### Local Development

```bash
docker-compose up -d
cd src/Identity.API
dotnet ef database update
dotnet run
```

### Integration Tests

```bash
dotnet test
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Verify PostgreSQL service is running
   - Check connection string in secret
   - Verify network policies allow egress

2. **Redis Connection Failed**
   - Verify Redis service is running
   - Check connection string in secret
   - Verify network policies

3. **JWT Token Validation Fails**
   - Verify secret key matches
   - Check issuer and audience
   - Ensure token not expired

4. **Pod Not Starting**
   - Check pod logs: `kubectl logs -n platform -l app=identity-api`
   - Verify secrets exist
   - Check resource limits

## Next Steps

1. **Deploy to Kubernetes**:
   ```bash
   kubectl apply -f k8s/
   ```

2. **Verify Deployment**:
   ```bash
   kubectl get pods -n platform -l app=identity-api
   kubectl get svc -n platform
   ```

3. **Test Endpoints**:
   ```bash
   kubectl port-forward -n platform svc/identity-service 8080:80
   curl http://localhost:8080/health
   ```

4. **Configure API Gateway**:
   - Update Kong routes
   - Configure JWT validation
   - Set up rate limiting

5. **Integrate with Other Services**:
   - Update Payment service JWT configuration
   - Update Notification service JWT configuration
   - Test end-to-end authentication flow

## Documentation

- [System Architecture](./01-Architecture/System_Architecture.md)
- [Authentication Flow](./01-Architecture/Authentication_Flow.md)
- [Integration Guide](./02-Integration/Integration_Guide.md)
- [Kubernetes Deployment](./03-Infrastructure/Kubernetes_Deployment.md)
- [Environment Configuration](./03-Infrastructure/Environment_Configuration.md)

## Support

For issues or questions:
1. Check documentation in `docs/` directory
2. Review Kubernetes logs
3. Check Prometheus metrics
4. Review Jaeger traces

