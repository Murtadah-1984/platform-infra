# Identity Service Integration Guide

## Overview

This guide explains how to integrate the Identity microservice with other services in the platform.

## Authentication Integration

### JWT Token Validation

Other microservices validate JWT tokens issued by the Identity service.

#### Option 1: JWKS Endpoint (Recommended)

Identity service exposes a JWKS (JSON Web Key Set) endpoint for public key distribution.

**Endpoint**: `GET /api/v1/auth/.well-known/jwks.json`

**Response**:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-id",
      "n": "modulus...",
      "e": "AQAB"
    }
  ]
}
```

**Client Service Configuration** (ASP.NET Core):

```csharp
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = "https://identity.platform.com";
        options.Audience = "platform-services";
        options.RequireHttpsMetadata = true;
        // Automatically fetches JWKS from /.well-known/jwks.json
    });
```

#### Option 2: Shared Secret Key

For symmetric key validation (simpler, less secure):

```csharp
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(sharedSecretKey)),
            ValidateIssuer = true,
            ValidIssuer = "identity-service",
            ValidateAudience = true,
            ValidAudience = "platform-services",
            ValidateLifetime = true
        };
    });
```

### Token Usage in Client Services

```csharp
[ApiController]
[Authorize]
public class PaymentController : ControllerBase
{
    [HttpGet("payments")]
    [Authorize(Policy = "PaymentsRead")]
    public IActionResult GetPayments()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        // Use user context...
    }
}
```

## API Gateway Integration (Kong)

### Kong JWT Plugin Configuration

```yaml
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: jwt-auth
  namespace: gateway
config:
  uri_param_names:
    - token
  cookie_names:
    - jwt
  header_names:
    - Authorization
  claims_to_verify:
    - exp
  key_claim_name: iss
  secret_is_base64: false
  run_on_preflight: true
plugins:
  - name: jwt
```

### Route Configuration

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: identity-ingress
  namespace: platform
  annotations:
    konghq.com/plugins: jwt-auth
spec:
  rules:
    - host: identity.platform.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: identity-service
                port:
                  number: 80
```

## Service-to-Service Communication

### Direct HTTP Calls

```csharp
public class UserServiceClient
{
    private readonly HttpClient _httpClient;

    public UserServiceClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<UserDto> GetUserAsync(Guid userId, string accessToken)
    {
        _httpClient.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", accessToken);
        
        var response = await _httpClient.GetAsync($"/api/v1/users/{userId}");
        response.EnsureSuccessStatusCode();
        
        return await response.Content.ReadFromJsonAsync<UserDto>();
    }
}
```

### Service Account Authentication

For service-to-service calls, use service accounts:

1. Create service account in Identity service
2. Generate long-lived token
3. Store in Kubernetes Secret
4. Use in service configuration

## Database Integration

### Shared Database Pattern (Not Recommended)

❌ **Avoid**: Sharing database between services

### Database per Service (Recommended)

✅ **Use**: Each service has its own database

**Identity Service Database**:
- Users
- Roles
- Permissions
- Refresh Tokens

**Other Services**:
- Reference user by ID only
- No direct database joins

## Event-Driven Integration

### User Created Event

When a user registers, publish an event:

```csharp
// In Identity Service
public class UserCreatedEvent
{
    public Guid UserId { get; set; }
    public string Email { get; set; }
    public string Username { get; set; }
    public DateTime CreatedAt { get; set; }
}

// Publish via RabbitMQ
await _messageBus.PublishAsync(new UserCreatedEvent
{
    UserId = user.Id,
    Email = user.Email,
    Username = user.Username,
    CreatedAt = user.CreatedAt
});
```

### Consuming Events in Other Services

```csharp
// In Payment Service
public class UserCreatedEventHandler : IEventHandler<UserCreatedEvent>
{
    public async Task Handle(UserCreatedEvent @event)
    {
        // Create user profile in Payment service
        // Or sync user data
    }
}
```

## Health Check Integration

### Kubernetes Probes

Identity service exposes health check endpoints:

- `/health` - General health
- `/health/live` - Liveness probe
- `/health/ready` - Readiness probe

**Kubernetes Configuration**:

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 5
```

## Monitoring Integration

### Prometheus Metrics

Identity service exposes metrics at `/metrics`:

```
http_requests_total{method="POST",endpoint="/api/v1/auth/login",status="200"} 150
http_request_duration_seconds{method="POST",endpoint="/api/v1/auth/login"} 0.05
identity_registrations_total 25
identity_logins_total 150
```

### Grafana Dashboard

Create dashboard with:
- Request rate
- Error rate
- Response time
- Authentication success/failure rate

## Logging Integration

### Structured Logging

Identity service uses Serilog with structured logging:

```json
{
  "Timestamp": "2024-01-01T12:00:00Z",
  "Level": "Information",
  "Message": "User logged in successfully",
  "UserId": "guid",
  "Email": "user@example.com",
  "ServiceName": "Identity.API"
}
```

### Centralized Logging

- **Loki**: Log aggregation
- **Promtail**: Log collection
- **Grafana**: Log visualization

## Testing Integration

### Integration Tests

```csharp
[Fact]
public async Task PaymentService_ShouldValidateJwtToken()
{
    // Arrange
    var identityClient = _factory.CreateClient();
    var loginResponse = await identityClient.PostAsJsonAsync("/api/v1/auth/login", 
        new { Email = "test@example.com", Password = "Password123!" });
    var authResult = await loginResponse.Content.ReadFromJsonAsync<AuthResponseDto>();
    
    // Act
    var paymentClient = _factory.CreateClient();
    paymentClient.DefaultRequestHeaders.Authorization = 
        new AuthenticationHeaderValue("Bearer", authResult.AccessToken);
    var response = await paymentClient.GetAsync("/api/v1/payments");
    
    // Assert
    response.EnsureSuccessStatusCode();
}
```

## Security Best Practices

### Token Storage

- ✅ Store tokens in HTTP-only cookies (web apps)
- ✅ Store tokens in secure storage (mobile apps)
- ❌ Never store tokens in localStorage (XSS risk)

### Token Refresh

- ✅ Implement automatic token refresh
- ✅ Refresh before expiration (e.g., 5 minutes before)
- ✅ Handle refresh failures gracefully

### CORS Configuration

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

## Troubleshooting

### Common Issues

1. **Token Validation Fails**
   - Check issuer and audience match
   - Verify secret key is correct
   - Ensure token not expired

2. **CORS Errors**
   - Verify CORS configuration
   - Check allowed origins
   - Ensure credentials included

3. **Service Unavailable**
   - Check health endpoints
   - Verify database connectivity
   - Check Redis connectivity

## Next Steps

- [Kubernetes Deployment](../03-Infrastructure/Kubernetes_Deployment.md)
- [Environment Configuration](../03-Infrastructure/Environment_Configuration.md)
- [System Architecture](../01-Architecture/System_Architecture.md)

