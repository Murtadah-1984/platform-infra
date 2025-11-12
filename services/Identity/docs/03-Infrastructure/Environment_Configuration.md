# Environment Configuration

## Overview

This document describes all configuration options for the Identity microservice across different environments.

## Configuration Sources

Configuration is loaded in the following order (later sources override earlier):

1. `appsettings.json` (base configuration)
2. `appsettings.{Environment}.json` (environment-specific)
3. Environment variables
4. Azure Key Vault (production)

## Connection Strings

### PostgreSQL

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=postgres-ha-postgresql-ha-postgresql.infrastructure.svc.cluster.local;Port=5432;Database=identitydb;Username=postgres;Password=<password>;Pooling=true;Minimum Pool Size=5;Maximum Pool Size=100;"
  }
}
```

**Parameters**:
- `Host`: PostgreSQL hostname
- `Port`: PostgreSQL port (default: 5432)
- `Database`: Database name
- `Username`: Database username
- `Password`: Database password
- `Pooling`: Enable connection pooling
- `Minimum Pool Size`: Minimum connections
- `Maximum Pool Size`: Maximum connections

### Redis

```json
{
  "ConnectionStrings": {
    "Redis": "redis-master.infrastructure.svc.cluster.local:6379,password=<password>,abortConnect=false,connectTimeout=5000"
  }
}
```

**Parameters**:
- `Host:Port`: Redis endpoint
- `password`: Redis password
- `abortConnect`: Abort if connection fails
- `connectTimeout`: Connection timeout in milliseconds

## JWT Configuration

```json
{
  "Jwt": {
    "SecretKey": "<32+ character secret key>",
    "Issuer": "identity-service",
    "Audience": "platform-services",
    "ExpirationMinutes": 60
  }
}
```

**Parameters**:
- `SecretKey`: Secret key for signing tokens (minimum 32 characters)
- `Issuer`: Token issuer identifier
- `Audience`: Token audience identifier
- `ExpirationMinutes`: Access token expiration time

**Security Note**: In production, store `SecretKey` in Azure Key Vault.

## Rate Limiting

```json
{
  "IpRateLimiting": {
    "EnableEndpointRateLimiting": true,
    "StackBlockedRequests": false,
    "RealIpHeader": "X-Real-IP",
    "ClientIdHeader": "X-ClientId",
    "HttpStatusCode": 429,
    "GeneralRules": [
      {
        "Endpoint": "*",
        "Period": "1m",
        "Limit": 100
      },
      {
        "Endpoint": "POST:/api/v1/auth/register",
        "Period": "1m",
        "Limit": 5
      },
      {
        "Endpoint": "POST:/api/v1/auth/login",
        "Period": "1m",
        "Limit": 10
      }
    ]
  }
}
```

**Parameters**:
- `EnableEndpointRateLimiting`: Enable per-endpoint limits
- `StackBlockedRequests`: Stack blocked requests
- `RealIpHeader`: Header for real IP (behind proxy)
- `GeneralRules`: Rate limiting rules

## Logging Configuration

### Serilog

```json
{
  "Serilog": {
    "Using": ["Serilog.Sinks.Console", "Serilog.Sinks.File"],
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft": "Warning",
        "System": "Warning"
      }
    },
    "WriteTo": [
      {
        "Name": "Console",
        "Args": {
          "outputTemplate": "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}"
        }
      },
      {
        "Name": "File",
        "Args": {
          "path": "logs/identity-.txt",
          "rollingInterval": "Day"
        }
      }
    ]
  }
}
```

**Log Levels**:
- `Trace`: Very detailed logs
- `Debug`: Debug information
- `Information`: General information
- `Warning`: Warnings
- `Error`: Errors
- `Fatal`: Critical errors

## OpenTelemetry Configuration

### Environment Variables

```bash
JAEGER_AGENT_HOST=jaeger-agent.monitoring.svc.cluster.local
JAEGER_AGENT_PORT=6831
OTLP_ENDPOINT=http://jaeger-collector.monitoring.svc.cluster.local:4317
```

### Configuration

```csharp
builder.Services.AddOpenTelemetry()
    .WithTracing(b =>
    {
        b.AddAspNetCoreInstrumentation()
         .AddEntityFrameworkCoreInstrumentation()
         .AddHttpClientInstrumentation()
         .AddJaegerExporter(options =>
         {
             options.AgentHost = Environment.GetEnvironmentVariable("JAEGER_AGENT_HOST");
             options.AgentPort = int.Parse(Environment.GetEnvironmentVariable("JAEGER_AGENT_PORT") ?? "6831");
         });
    })
    .WithMetrics(b =>
    {
        b.AddAspNetCoreInstrumentation()
         .AddHttpClientInstrumentation()
         .AddPrometheusExporter();
    });
```

## Health Checks

Health checks are automatically configured for:
- PostgreSQL database
- Redis cache
- Entity Framework Core context

**Endpoints**:
- `/health` - General health
- `/health/live` - Liveness (excludes database)
- `/health/ready` - Readiness (includes database)

## Environment-Specific Configurations

### Development

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Debug"
    }
  },
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Port=5432;Database=identitydb_dev;Username=postgres;Password=postgres"
  }
}
```

### Staging

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information"
    }
  },
  "ConnectionStrings": {
    "DefaultConnection": "Host=postgres-staging;Port=5432;Database=identitydb_staging;Username=postgres;Password=<staging-password>"
  }
}
```

### Production

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning"
    }
  },
  "ConnectionStrings": {
    "DefaultConnection": ""
  },
  "Jwt": {
    "SecretKey": ""
  }
}
```

**Note**: Production values loaded from Azure Key Vault.

## Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: identity-config
  namespace: platform
data:
  ASPNETCORE_ENVIRONMENT: "Production"
  ASPNETCORE_URLS: "http://+:8080"
  Jwt__Issuer: "identity-service"
  Jwt__Audience: "platform-services"
  Jwt__ExpirationMinutes: "60"
```

## Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: identity-secrets
  namespace: platform
type: Opaque
stringData:
  database-connection: "Host=postgres;Port=5432;Database=identitydb;Username=postgres;Password=<password>"
  redis-connection: "redis-master:6379,password=<password>"
  jwt-secret: "<32+ character secret key>"
```

## Azure Key Vault Integration

### Secret Names

- `Identity-DatabaseConnection`: PostgreSQL connection string
- `Identity-RedisConnection`: Redis connection string
- `Identity-JwtSecret`: JWT signing key

### Configuration

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: identity-secrets
spec:
  provider: azure
  parameters:
    keyvaultName: "<key-vault-name>"
    tenantId: "<tenant-id>"
    objects: |
      array:
        - |
          objectName: Identity-DatabaseConnection
          objectType: secret
        - |
          objectName: Identity-RedisConnection
          objectType: secret
        - |
          objectName: Identity-JwtSecret
          objectType: secret
```

## Feature Flags

```json
{
  "FeatureManagement": {
    "EnableRefreshTokens": true,
    "EnableMfa": false,
    "EnableEmailVerification": true
  }
}
```

## CORS Configuration

```csharp
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("https://app.platform.com")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});
```

## Validation

### Password Requirements

- Minimum length: 8 characters
- Must contain: uppercase, lowercase, digit
- Configurable via `RegisterUserCommandValidator`

### Email Validation

- Standard email format validation
- Unique constraint in database

### Username Validation

- Minimum length: 3 characters
- Maximum length: 50 characters
- Alphanumeric and underscore allowed
- Unique constraint in database

## Security Best Practices

1. **Never commit secrets** to version control
2. **Use Azure Key Vault** for production secrets
3. **Rotate secrets regularly** (JWT secret, database passwords)
4. **Use strong passwords** for database and Redis
5. **Enable HTTPS** in production
6. **Configure CORS** appropriately
7. **Set appropriate rate limits**

## Troubleshooting

### Configuration Not Loading

1. Check file paths
2. Verify environment variable names (use double underscore `__` for nested)
3. Check Azure Key Vault permissions
4. Review logs for configuration errors

### Connection String Issues

1. Verify hostname resolution
2. Check network policies
3. Test connectivity from pod
4. Verify credentials

### JWT Token Issues

1. Verify secret key matches
2. Check issuer and audience
3. Verify token expiration
4. Check clock skew

## Next Steps

- [Kubernetes Deployment](./Kubernetes_Deployment.md)
- [Integration Guide](../02-Integration/Integration_Guide.md)

