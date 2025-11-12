# Identity Microservice - System Architecture

## Overview

The Identity microservice is built following **Clean Architecture** principles with clear layer separation and dependency inversion.

## Architecture Layers

### 1. Domain Layer (`Identity.Domain`)

**Purpose**: Contains business entities, value objects, domain events, and interfaces.

**Components**:
- **Entities**: `User`, `Role`, `Permission`, `UserRole`, `RolePermission`, `RefreshToken`
- **Interfaces**: `IUserRepository`, `IPasswordHasher`, `IJwtTokenService`
- **Enums**: Domain-specific enumerations
- **Exceptions**: Domain-specific exceptions

**Rules**:
- No dependencies on other layers
- Pure business logic
- Framework-agnostic

### 2. Application Layer (`Identity.Application`)

**Purpose**: Contains use cases, DTOs, commands, queries, and handlers.

**Components**:
- **Commands**: `RegisterUserCommand`, `LoginCommand`
- **Handlers**: `RegisterUserCommandHandler`, `LoginCommandHandler`
- **DTOs**: `RegisterUserDto`, `LoginDto`, `AuthResponseDto`
- **Behaviors**: `ValidationBehavior`, `LoggingBehavior`
- **Validators**: FluentValidation validators

**Patterns**:
- **CQRS**: Commands and Queries separation
- **MediatR**: Mediator pattern for request handling
- **FluentValidation**: Input validation

**Rules**:
- Depends only on Domain layer
- No infrastructure concerns
- Stateless operations

### 3. Infrastructure Layer (`Identity.Infrastructure`)

**Purpose**: Implements persistence, external services, and infrastructure concerns.

**Components**:
- **Data**: `IdentityDbContext` (EF Core)
- **Repositories**: `UserRepository`
- **Services**: `PasswordHasher`, `JwtTokenService`
- **Caching**: Redis integration
- **Health Checks**: Database and Redis health checks

**Rules**:
- Implements Domain interfaces
- Handles all external dependencies
- Framework-specific implementations

### 4. Presentation Layer (`Identity.API`)

**Purpose**: HTTP API, controllers, middleware, and configuration.

**Components**:
- **Controllers**: `AuthController`
- **Middleware**: Rate limiting, authentication, authorization
- **Configuration**: Dependency injection, OpenTelemetry, health checks

**Rules**:
- Thin controllers (delegate to Application layer)
- No business logic
- Framework-specific (ASP.NET Core)

## Dependency Flow

```
Presentation → Application → Domain ← Infrastructure
```

**Key Principle**: Dependencies point inward. Outer layers depend on inner layers, not vice versa.

## Design Patterns

### Repository Pattern

Domain defines `IUserRepository`, Infrastructure implements it. This follows Dependency Inversion Principle.

### CQRS (Command Query Responsibility Segregation)

- **Commands**: `RegisterUserCommand`, `LoginCommand` (write operations)
- **Queries**: Future queries for read operations

### Mediator Pattern

MediatR handles request routing, enabling:
- Decoupled request/response handling
- Pipeline behaviors (validation, logging)
- Easy testing

### Strategy Pattern

`IPasswordHasher` and `IJwtTokenService` allow different implementations without changing business logic.

## Stateless Design

The service is **completely stateless**:

- ✅ No in-memory session storage
- ✅ JWT tokens stored in Redis (distributed)
- ✅ Database for persistent data
- ✅ No static mutable state
- ✅ Horizontal scaling ready

## Security Architecture

### Authentication Flow

1. User registers/logs in
2. Service validates credentials
3. JWT access token generated
4. Refresh token stored in Redis
5. Tokens returned to client

### Authorization Flow

1. Client sends JWT token in Authorization header
2. Service validates token signature
3. Claims extracted (roles, permissions)
4. Authorization policies applied
5. Request authorized or denied

### Token Management

- **Access Tokens**: Short-lived (1 hour), stateless validation
- **Refresh Tokens**: Long-lived, stored in Redis
- **Token Revocation**: Blacklist in Redis cache

## Scalability

### Horizontal Scaling

- Stateless design enables multiple replicas
- Load balancer distributes requests
- Shared Redis cache for token management
- PostgreSQL database (can use read replicas)

### Performance Optimizations

- Redis caching for token blacklist
- Connection pooling for database
- Async/await throughout
- EF Core query optimization

## Observability

### Metrics

- Prometheus metrics endpoint (`/metrics`)
- Custom business metrics
- HTTP request metrics

### Logging

- Serilog structured logging
- Correlation IDs
- Log levels: Information, Warning, Error

### Tracing

- OpenTelemetry distributed tracing
- Jaeger integration
- Request correlation across services

## Database Schema

```
Users
├── Id (PK)
├── Email (Unique)
├── Username (Unique)
├── PasswordHash
└── ...

Roles
├── Id (PK)
├── Name (Unique)
└── ...

UserRoles (Many-to-Many)
├── UserId (FK)
└── RoleId (FK)

Permissions
├── Id (PK)
├── Name (Unique)
├── Resource
└── Action

RolePermissions (Many-to-Many)
├── RoleId (FK)
└── PermissionId (FK)

RefreshTokens
├── Id (PK)
├── UserId (FK)
├── Token (Unique)
└── ExpiresAt
```

## Technology Stack

- **.NET 8**: Runtime and framework
- **ASP.NET Core**: Web framework
- **Entity Framework Core**: ORM
- **PostgreSQL**: Database
- **Redis**: Distributed cache
- **MediatR**: Mediator pattern
- **FluentValidation**: Validation
- **Serilog**: Logging
- **OpenTelemetry**: Observability
- **Prometheus**: Metrics

## Next Steps

- [Authentication Flow](./Authentication_Flow.md)
- [Kubernetes Deployment](../03-Infrastructure/Kubernetes_Deployment.md)
- [Integration Guide](../02-Integration/Integration_Guide.md)

