# Identity Microservice

Production-ready Identity microservice built with .NET 8, following Clean Architecture, SOLID principles, and stateless microservice design for Kubernetes deployment.

## Overview

The Identity microservice provides authentication and authorization services for the platform, including:
- User registration and authentication
- JWT token generation and validation
- Role-based access control (RBAC)
- Permission-based authorization
- Refresh token management

## Architecture

This microservice follows **Clean Architecture** with clear separation of concerns:

```
Identity.API (Presentation)
    ↓
Identity.Application (Use Cases)
    ↓
Identity.Domain (Business Logic)
    ↑
Identity.Infrastructure (Persistence & External Services)
```

### Key Principles

- **SOLID**: All layers follow SOLID principles
- **Stateless**: No in-memory state, suitable for horizontal scaling
- **Kubernetes-Ready**: Health checks, metrics, distributed tracing
- **Secure**: JWT authentication, password hashing, rate limiting

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

## Configuration

See [Environment Configuration](./03-Infrastructure/Environment_Configuration.md) for detailed configuration options.

## Documentation

- [Architecture Overview](./01-Architecture/System_Architecture.md)
- [Authentication Flow](./01-Architecture/Authentication_Flow.md)
- [Kubernetes Deployment](./03-Infrastructure/Kubernetes_Deployment.md)
- [Integration Guide](./02-Integration/Integration_Guide.md)

## Testing

```bash
dotnet test
```

## Deployment

See [Kubernetes Deployment Guide](./03-Infrastructure/Kubernetes_Deployment.md) for production deployment instructions.

