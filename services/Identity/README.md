# Identity Microservice

Production-ready Identity microservice built with .NET 8, following Clean Architecture, SOLID principles, and stateless microservice design for Kubernetes deployment.

## Features

- ✅ User registration and authentication
- ✅ JWT token generation and validation
- ✅ Role-based access control (RBAC)
- ✅ Permission-based authorization
- ✅ Refresh token management
- ✅ Password hashing (PBKDF2)
- ✅ Rate limiting
- ✅ Health checks
- ✅ Distributed tracing (OpenTelemetry)
- ✅ Prometheus metrics
- ✅ Structured logging (Serilog)
- ✅ Kubernetes-ready

## Architecture

This microservice follows **Clean Architecture** with clear separation of concerns:

- **Domain Layer**: Business entities and interfaces
- **Application Layer**: Use cases and business logic
- **Infrastructure Layer**: Persistence and external services
- **Presentation Layer**: HTTP API and controllers

## Quick Start

### Local Development

```bash
# Start dependencies
docker-compose up -d

# Run migrations
cd src/Identity.API
dotnet ef database update

# Run the service
dotnet run
```

### Docker

```bash
docker-compose up
```

The service will be available at `http://localhost:5000`

## API Endpoints

### Authentication

- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - Login with credentials
- `GET /api/v1/auth/me` - Get current user (requires authentication)

### Health Checks

- `GET /health` - General health check
- `GET /health/live` - Liveness probe
- `GET /health/ready` - Readiness probe

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- [Overview](./docs/README.md)
- [System Architecture](./docs/01-Architecture/System_Architecture.md)
- [Authentication Flow](./docs/01-Architecture/Authentication_Flow.md)
- [Integration Guide](./docs/02-Integration/Integration_Guide.md)
- [Kubernetes Deployment](./docs/03-Infrastructure/Kubernetes_Deployment.md)
- [Environment Configuration](./docs/03-Infrastructure/Environment_Configuration.md)

## Kubernetes Deployment

See [Kubernetes Deployment Guide](./docs/03-Infrastructure/Kubernetes_Deployment.md) for production deployment instructions.

All Kubernetes manifests are in the `k8s/` directory.

## Configuration

See [Environment Configuration](./docs/03-Infrastructure/Environment_Configuration.md) for detailed configuration options.

## Testing

```bash
dotnet test
```

## Technology Stack

- .NET 8
- ASP.NET Core
- Entity Framework Core
- PostgreSQL
- Redis
- MediatR
- FluentValidation
- Serilog
- OpenTelemetry
- Prometheus

## License

[Your License Here]

