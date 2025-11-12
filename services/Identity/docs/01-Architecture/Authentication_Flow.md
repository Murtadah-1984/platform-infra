# Authentication Flow

## Overview

This document describes the authentication and authorization flows in the Identity microservice.

## User Registration Flow

```
┌─────────┐      ┌──────────────┐      ┌─────────────┐      ┌──────────┐
│ Client  │─────▶│ AuthController│─────▶│ MediatR     │─────▶│ Handler  │
└─────────┘      └──────────────┘      └─────────────┘      └──────────┘
                                                                    │
                                                                    ▼
                                                           ┌─────────────────┐
                                                           │ UserRepository  │
                                                           └─────────────────┘
                                                                    │
                                                                    ▼
                                                           ┌─────────────────┐
                                                           │ PasswordHasher   │
                                                           └─────────────────┘
                                                                    │
                                                                    ▼
                                                           ┌─────────────────┐
                                                           │ JwtTokenService │
                                                           └─────────────────┘
                                                                    │
                                                                    ▼
                                                           ┌─────────┐
                                                           │ Response │
                                                           └─────────┘
```

### Steps

1. **Client** sends `POST /api/v1/auth/register` with user details
2. **AuthController** receives request, creates `RegisterUserCommand`
3. **MediatR** routes command to `RegisterUserCommandHandler`
4. **Handler** validates:
   - Email uniqueness
   - Username uniqueness
5. **Handler** creates user:
   - Hashes password using `PasswordHasher`
   - Saves to database via `UserRepository`
6. **Handler** generates tokens:
   - Access token via `JwtTokenService`
   - Refresh token via `JwtTokenService`
7. **Response** returned to client with tokens

## User Login Flow

```
┌─────────┐      ┌──────────────┐      ┌─────────────┐      ┌──────────┐
│ Client  │─────▶│ AuthController│─────▶│ MediatR     │─────▶│ Handler  │
└─────────┘      └──────────────┘      └─────────────┘      └──────────┘
                                                                    │
                                                                    ▼
                                                           ┌─────────────────┐
                                                           │ UserRepository  │
                                                           │ (GetByEmail/     │
                                                           │  GetByUsername)  │
                                                           └─────────────────┘
                                                                    │
                                                                    ▼
                                                           ┌─────────────────┐
                                                           │ PasswordHasher   │
                                                           │ (Verify)         │
                                                           └─────────────────┘
                                                                    │
                                                                    ▼
                                                           ┌─────────────────┐
                                                           │ JwtTokenService  │
                                                           │ (Generate tokens)│
                                                           └─────────────────┘
                                                                    │
                                                                    ▼
                                                           ┌─────────┐
                                                           │ Response │
                                                           └─────────┘
```

### Steps

1. **Client** sends `POST /api/v1/auth/login` with credentials
2. **AuthController** receives request, creates `LoginCommand`
3. **MediatR** routes command to `LoginCommandHandler`
4. **Handler** finds user:
   - Tries email first, then username
5. **Handler** validates:
   - User exists
   - User is active
   - Password matches (via `PasswordHasher.VerifyPassword`)
6. **Handler** updates last login timestamp
7. **Handler** generates tokens:
   - Access token with user claims, roles, permissions
   - Refresh token
8. **Response** returned to client with tokens

## Token Validation Flow

```
┌─────────┐      ┌──────────────┐      ┌─────────────────┐
│ Client  │─────▶│ API Gateway  │─────▶│ Identity Service│
│ (with   │      │ (Kong)       │      │ (or other      │
│  JWT)   │      │              │      │  microservice) │
└─────────┘      └──────────────┘      └─────────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │ JWT Middleware  │
                                    │ (Validate)      │
                                    └─────────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │ Extract Claims  │
                                    │ (Roles, Scopes) │
                                    └─────────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │ Authorization   │
                                    │ Policies        │
                                    └─────────────────┘
```

### Steps

1. **Client** includes JWT in `Authorization: Bearer <token>` header
2. **JWT Middleware** validates:
   - Token signature (using secret key)
   - Token expiration
   - Issuer and audience
3. **Claims** extracted from token:
   - User ID (`sub`)
   - Email
   - Roles (`role` claims)
   - Permissions (`scope` claims)
4. **Authorization** policies check:
   - Required roles
   - Required permissions (scopes)
5. **Request** proceeds if authorized

## Token Refresh Flow

```
┌─────────┐      ┌──────────────┐      ┌─────────────┐
│ Client  │─────▶│ AuthController│─────▶│ Handler     │
│ (with   │      │              │      │             │
│ refresh │      │              │      │             │
│ token)  │      │              │      │             │
└─────────┘      └──────────────┘      └─────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │ Validate Refresh│
                                    │ Token           │
                                    └─────────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │ Generate New    │
                                    │ Access Token    │
                                    └─────────────────┘
```

### Steps

1. **Client** sends refresh token
2. **Service** validates refresh token:
   - Token exists in Redis
   - Token not expired
   - Token not revoked
3. **Service** generates new access token
4. **Service** optionally generates new refresh token
5. **Response** returned with new tokens

## Password Hashing

### Algorithm: PBKDF2 with SHA-256

- **Salt Size**: 16 bytes (random per password)
- **Hash Size**: 32 bytes
- **Iterations**: 100,000

### Process

1. Generate random salt
2. Derive key using PBKDF2
3. Combine salt + hash
4. Store as Base64 string

### Verification

1. Extract salt from stored hash
2. Hash input password with same salt
3. Compare hashes (constant-time comparison)

## JWT Token Structure

### Access Token Claims

```json
{
  "sub": "user-id-guid",
  "email": "user@example.com",
  "unique_name": "username",
  "jti": "token-id-guid",
  "iat": 1234567890,
  "exp": 1234571490,
  "role": ["User", "Admin"],
  "scope": ["identity.read", "identity.write", "payment.read"]
}
```

### Token Validation

- **Signature**: HMAC SHA-256
- **Expiration**: 1 hour (configurable)
- **Issuer**: `identity-service`
- **Audience**: `platform-services`

## Security Considerations

### Password Security

- ✅ Never stored in plain text
- ✅ Strong hashing algorithm (PBKDF2)
- ✅ High iteration count (100,000)
- ✅ Unique salt per password

### Token Security

- ✅ Short-lived access tokens (1 hour)
- ✅ Secure token storage (Redis)
- ✅ Token revocation support
- ✅ HTTPS required in production

### Rate Limiting

- Registration: 5 requests/minute
- Login: 10 requests/minute
- General: 100 requests/minute

## Integration with Other Services

### Payment Service

Payment service validates JWT tokens from Identity service:

1. Payment service receives request with JWT
2. Validates token signature using Identity service's public key (JWKS)
3. Extracts claims (roles, permissions)
4. Authorizes based on `payment.*` scopes

### API Gateway (Kong)

Kong can validate tokens before forwarding to microservices:

1. Client sends request to Kong
2. Kong validates JWT
3. Kong forwards request with user context
4. Microservice trusts Kong's validation

## Next Steps

- [System Architecture](./System_Architecture.md)
- [Integration Guide](../02-Integration/Integration_Guide.md)
- [Kubernetes Deployment](../03-Infrastructure/Kubernetes_Deployment.md)

