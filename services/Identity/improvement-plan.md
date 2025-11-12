# Identity Microservice - Enterprise Grade Remediation Plan

## Executive Summary

Your Identity microservice has a solid foundation with Clean Architecture, CQRS, and stateless design. However, to become a **production-grade, enterprise-level authorization component** supporting all authentication methods, significant enhancements are needed.

## Current State Assessment

### ✅ Strengths
- Clean Architecture with proper layer separation
- Stateless design (scalable)
- CQRS + MediatR implementation
- OpenTelemetry observability
- Kubernetes-ready with HPA
- Health checks and monitoring

### ⚠️ Critical Gaps

| Category | Current State | Enterprise Requirement |
|----------|--------------|----------------------|
| **Auth Methods** | Username/Password + JWT only | OAuth2, OIDC, SAML, LDAP, MFA, Biometrics, Passwordless |
| **Authorization** | Basic RBAC | ABAC, Policy-based (OPA), Fine-grained permissions |
| **Security** | Basic JWT | Certificate-based, Hardware tokens, PKI, Zero Trust |
| **Standards** | Custom JWT | Full OIDC/OAuth2 compliance, SAML 2.0 |
| **Multi-tenancy** | None | Complete tenant isolation |
| **Audit** | Basic logging | Comprehensive audit trail, compliance reporting |
| **Account Security** | None | Lockout, breach detection, anomaly detection |
| **Compliance** | None | GDPR, SOC2, PCI-DSS, HIPAA ready |

---

## 🎯 Remediation Roadmap

### Phase 1: Foundation Enhancement (Weeks 1-4)

#### 1.1 OAuth2 & OpenID Connect (OIDC) Full Implementation

**Current Issue**: Custom JWT implementation, not standards-compliant

**Solution**: Implement full OAuth2.0 + OIDC server

```csharp
// Domain Layer - Add OAuth2 Entities
public class Client : Entity
{
    public string ClientId { get; private set; }
    public string ClientSecret { get; private set; }
    public List<string> AllowedGrantTypes { get; private set; }
    public List<string> RedirectUris { get; private set; }
    public List<string> AllowedScopes { get; private set; }
    public bool RequireClientSecret { get; private set; }
    public bool RequirePkce { get; private set; }
    public int AccessTokenLifetime { get; private set; }
    public int RefreshTokenLifetime { get; private set; }
}

public class AuthorizationCode : Entity
{
    public string Code { get; private set; }
    public string ClientId { get; private set; }
    public Guid UserId { get; private set; }
    public string RedirectUri { get; private set; }
    public List<string> Scopes { get; private set; }
    public string CodeChallenge { get; private set; } // PKCE
    public string CodeChallengeMethod { get; private set; }
    public DateTime ExpiresAt { get; private set; }
    public bool IsUsed { get; private set; }
}

public class Consent : Entity
{
    public Guid UserId { get; private set; }
    public string ClientId { get; private set; }
    public List<string> GrantedScopes { get; private set; }
    public DateTime ExpiresAt { get; private set; }
}
```

**OAuth2 Grant Types to Support**:
- Authorization Code + PKCE (for web/mobile apps)
- Client Credentials (service-to-service)
- Refresh Token
- Device Code (for IoT/TV apps)
- Resource Owner Password (legacy, discouraged)

**OIDC Endpoints to Implement**:
```
/.well-known/openid-configuration
/.well-known/jwks.json
/connect/authorize
/connect/token
/connect/userinfo
/connect/endsession
/connect/revocation
/connect/introspection
```

#### 1.2 Multi-Factor Authentication (MFA)

**Add MFA Entities**:

```csharp
public class MfaMethod : Entity
{
    public Guid UserId { get; private set; }
    public MfaType Type { get; private set; } // TOTP, SMS, Email, Hardware
    public string Identifier { get; private set; } // Phone, Email, or Secret
    public bool IsVerified { get; private set; }
    public bool IsPreferred { get; private set; }
    public DateTime? LastUsedAt { get; private set; }
}

public enum MfaType
{
    TOTP,           // Time-based OTP (Google Authenticator)
    SMS,            // SMS code
    Email,          // Email code
    WebAuthn,       // FIDO2/WebAuthn (biometrics, security keys)
    BackupCodes,    // One-time backup codes
    Push            // Push notification approval
}

public class MfaChallenge : Entity
{
    public Guid UserId { get; private set; }
    public MfaType Type { get; private set; }
    public string Code { get; private set; }
    public DateTime ExpiresAt { get; private set; }
    public bool IsUsed { get; private set; }
    public int AttemptCount { get; private set; }
}
```

**MFA Flow Implementation**:

```csharp
// Application Layer - Commands
public record LoginCommand : IRequest<LoginStepResult>
{
    public string EmailOrUsername { get; init; }
    public string Password { get; init; }
    public string? MfaCode { get; init; }
    public Guid? ChallengeId { get; init; }
}

public class LoginStepResult
{
    public bool RequiresMfa { get; set; }
    public Guid? ChallengeId { get; set; }
    public List<MfaType> AvailableMethods { get; set; }
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
}

public class LoginCommandHandler : IRequestHandler<LoginCommand, LoginStepResult>
{
    public async Task<LoginStepResult> Handle(LoginCommand request, CancellationToken ct)
    {
        // Step 1: Validate credentials
        var user = await ValidateCredentials(request.EmailOrUsername, request.Password);
        
        // Step 2: Check if MFA required
        var mfaMethods = await _mfaRepository.GetUserMethods(user.Id);
        if (mfaMethods.Any() && string.IsNullOrEmpty(request.MfaCode))
        {
            // Send MFA challenge
            var challenge = await CreateMfaChallenge(user.Id, mfaMethods.First().Type);
            return new LoginStepResult
            {
                RequiresMfa = true,
                ChallengeId = challenge.Id,
                AvailableMethods = mfaMethods.Select(m => m.Type).ToList()
            };
        }
        
        // Step 3: Verify MFA if provided
        if (!string.IsNullOrEmpty(request.MfaCode))
        {
            await VerifyMfaCode(request.ChallengeId.Value, request.MfaCode);
        }
        
        // Step 4: Issue tokens
        return await IssueTokens(user);
    }
}
```

**TOTP Implementation** (Google Authenticator compatible):

```csharp
public interface ITotpService
{
    string GenerateSecret();
    string GenerateQrCodeUri(string identifier, string secret, string issuer);
    bool ValidateCode(string secret, string code, int window = 1);
}

public class TotpService : ITotpService
{
    public string GenerateSecret()
    {
        var bytes = new byte[20];
        RandomNumberGenerator.Fill(bytes);
        return Base32Encoding.ToString(bytes);
    }
    
    public string GenerateQrCodeUri(string identifier, string secret, string issuer)
    {
        return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(identifier)}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}";
    }
    
    public bool ValidateCode(string secret, string code, int window = 1)
    {
        var counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        
        for (int i = -window; i <= window; i++)
        {
            var hash = ComputeTotp(secret, counter + i);
            if (hash == code)
                return true;
        }
        return false;
    }
    
    private string ComputeTotp(string secret, long counter)
    {
        var key = Base32Encoding.ToBytes(secret);
        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(counterBytes);
            
        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(counterBytes);
        
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     (hash[offset + 3] & 0xFF);
                     
        var otp = binary % 1000000;
        return otp.ToString("D6");
    }
}
```

#### 1.3 WebAuthn/FIDO2 (Passwordless & Biometrics)

**Add WebAuthn Support**:

```csharp
public class WebAuthnCredential : Entity
{
    public Guid UserId { get; private set; }
    public byte[] CredentialId { get; private set; }
    public byte[] PublicKey { get; private set; }
    public uint SignatureCounter { get; private set; }
    public string CredentialType { get; private set; }
    public List<string> Transports { get; private set; }
    public bool IsBackupEligible { get; private set; }
    public bool IsBackedUp { get; private set; }
    public string AttestationFormat { get; private set; }
    public DateTime LastUsedAt { get; private set; }
    public string? DeviceName { get; private set; }
}

// Use Fido2NetLib library
public class WebAuthnService : IWebAuthnService
{
    private readonly IFido2 _fido2;
    
    public async Task<CredentialCreateOptions> GetRegistrationOptionsAsync(User user)
    {
        var existingKeys = await _repository.GetUserCredentialsAsync(user.Id);
        
        var authenticatorSelection = new AuthenticatorSelection
        {
            AuthenticatorAttachment = "platform", // or "cross-platform"
            RequireResidentKey = false,
            UserVerification = "required"
        };
        
        var options = _fido2.RequestNewCredential(
            new Fido2User
            {
                Id = user.Id.ToByteArray(),
                Name = user.Email,
                DisplayName = user.Username
            },
            existingKeys.Select(k => new PublicKeyCredentialDescriptor(k.CredentialId)).ToList(),
            authenticatorSelection,
            AttestationConveyancePreference.None
        );
        
        return options;
    }
    
    public async Task<bool> VerifyRegistrationAsync(
        AuthenticatorAttestationRawResponse attestationResponse,
        CredentialCreateOptions options)
    {
        var success = await _fido2.MakeNewCredentialAsync(
            attestationResponse,
            options,
            async (args, cancellationToken) =>
            {
                var existingCredential = await _repository.GetByCredentialIdAsync(args.CredentialId);
                return existingCredential == null;
            }
        );
        
        if (success.Status == "ok")
        {
            var credential = new WebAuthnCredential(/*...*/);
            await _repository.AddAsync(credential);
            return true;
        }
        
        return false;
    }
}
```

---

### Phase 2: Enterprise Authentication Methods (Weeks 5-8)

#### 2.1 SAML 2.0 Support

**Add SAML Service Provider**:

```csharp
// Domain
public class SamlIdentityProvider : Entity
{
    public string EntityId { get; private set; }
    public string SingleSignOnUrl { get; private set; }
    public string SingleLogoutUrl { get; private set; }
    public string X509Certificate { get; private set; }
    public bool SignAuthRequests { get; private set; }
    public bool WantAssertionsSigned { get; private set; }
    public string NameIdFormat { get; private set; }
    public Dictionary<string, string> AttributeMapping { get; private set; }
}

// Infrastructure - Use Sustainsys.Saml2 or similar
public class SamlService : ISamlService
{
    public async Task<SamlAuthenticationRequest> CreateAuthRequestAsync(
        SamlIdentityProvider idp, 
        string returnUrl)
    {
        var authnRequest = new Saml2AuthenticationRequest
        {
            Issuer = new EntityId(_configuration.ServiceProviderEntityId),
            DestinationUrl = new Uri(idp.SingleSignOnUrl),
            AssertionConsumerServiceUrl = new Uri(_configuration.AssertionConsumerServiceUrl),
            RequestedAuthnContext = new Saml2RequestedAuthnContext(
                new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"))
        };
        
        var binding = new Saml2RedirectBinding();
        var result = binding.Bind(authnRequest);
        
        return new SamlAuthenticationRequest
        {
            RedirectUrl = result.Location.ToString(),
            RelayState = returnUrl
        };
    }
    
    public async Task<SamlAuthenticationResult> ProcessResponseAsync(string samlResponse)
    {
        var binding = new Saml2PostBinding();
        var unbindResult = binding.Unbind(new HttpRequestData("POST"), null);
        
        var result = unbindResult.Data;
        result.CheckConditions();
        
        var identity = new ClaimsIdentity(result.ClaimsIdentities.First());
        
        return new SamlAuthenticationResult
        {
            IsAuthenticated = true,
            NameId = identity.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            Attributes = identity.Claims.ToDictionary(c => c.Type, c => c.Value)
        };
    }
}
```

#### 2.2 LDAP/Active Directory Integration

```csharp
public class LdapAuthenticationService : ILdapAuthenticationService
{
    private readonly LdapConnection _connection;
    
    public async Task<LdapAuthenticationResult> AuthenticateAsync(
        string username, 
        string password)
    {
        try
        {
            // Search for user
            var searchRequest = new SearchRequest(
                _configuration.BaseDn,
                $"(&(objectClass=person)(sAMAccountName={username}))",
                SearchScope.Subtree,
                "distinguishedName", "mail", "memberOf", "displayName"
            );
            
            var searchResponse = (SearchResponse)await _connection.SendRequestAsync(searchRequest);
            
            if (searchResponse.Entries.Count == 0)
                return LdapAuthenticationResult.Failed("User not found");
            
            var entry = searchResponse.Entries[0];
            var userDn = entry.Attributes["distinguishedName"][0].ToString();
            
            // Bind to verify password
            var bindRequest = new BindRequest(userDn, password);
            var bindResponse = (BindResponse)await _connection.SendRequestAsync(bindRequest);
            
            if (bindResponse.ResultCode != ResultCode.Success)
                return LdapAuthenticationResult.Failed("Invalid credentials");
            
            // Extract groups
            var groups = entry.Attributes["memberOf"]
                .GetValues(typeof(string))
                .Cast<string>()
                .Select(dn => ExtractCnFromDn(dn))
                .ToList();
            
            return LdapAuthenticationResult.Success(
                email: entry.Attributes["mail"][0].ToString(),
                displayName: entry.Attributes["displayName"][0].ToString(),
                groups: groups
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "LDAP authentication failed");
            return LdapAuthenticationResult.Failed("Authentication error");
        }
    }
    
    public async Task SyncUserAsync(string username)
    {
        var ldapUser = await GetLdapUserAsync(username);
        var user = await _userRepository.GetByExternalIdAsync($"ldap:{username}");
        
        if (user == null)
        {
            user = User.CreateFromExternalProvider(
                email: ldapUser.Email,
                username: username,
                externalId: $"ldap:{username}",
                provider: "ldap"
            );
            await _userRepository.AddAsync(user);
        }
        else
        {
            user.UpdateFromExternalProvider(ldapUser.Email, ldapUser.DisplayName);
        }
        
        // Sync groups to roles
        await SyncGroupsToRoles(user, ldapUser.Groups);
    }
}
```

#### 2.3 Social Login (OAuth2 Providers)

```csharp
public class ExternalAuthenticationService
{
    public async Task<ExternalAuthResult> AuthenticateGoogleAsync(string code)
    {
        // Exchange code for tokens
        var tokenResponse = await _httpClient.PostAsync(
            "https://oauth2.googleapis.com/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["code"] = code,
                ["client_id"] = _config.GoogleClientId,
                ["client_secret"] = _config.GoogleClientSecret,
                ["redirect_uri"] = _config.RedirectUri,
                ["grant_type"] = "authorization_code"
            })
        );
        
        var tokens = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();
        
        // Get user info
        var userInfoResponse = await _httpClient.GetAsync(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            request => request.Headers.Authorization = 
                new AuthenticationHeaderValue("Bearer", tokens.AccessToken)
        );
        
        var userInfo = await userInfoResponse.Content.ReadFromJsonAsync<GoogleUserInfo>();
        
        // Find or create user
        var user = await _userRepository.GetByExternalIdAsync($"google:{userInfo.Id}");
        if (user == null)
        {
            user = User.CreateFromExternalProvider(
                email: userInfo.Email,
                username: userInfo.Email,
                externalId: $"google:{userInfo.Id}",
                provider: "google"
            );
            user.MarkEmailAsVerified(); // Google emails are verified
            await _userRepository.AddAsync(user);
        }
        
        return ExternalAuthResult.Success(user);
    }
}

// Support multiple providers
public interface IExternalAuthProvider
{
    string ProviderName { get; }
    Task<ExternalAuthResult> AuthenticateAsync(string code, string? state = null);
}

// Implement for: Google, Microsoft, GitHub, Facebook, Apple, etc.
```

---

### Phase 3: Advanced Authorization (Weeks 9-12)

#### 3.1 Attribute-Based Access Control (ABAC)

```csharp
// Domain
public class Policy : Entity
{
    public string Name { get; private set; }
    public string Description { get; private set; }
    public PolicyEffect Effect { get; private set; } // Allow or Deny
    public List<PolicyStatement> Statements { get; private set; }
}

public class PolicyStatement
{
    public List<string> Actions { get; set; } // e.g., ["payment:read", "payment:create"]
    public List<string> Resources { get; set; } // e.g., ["payment:*", "payment:123"]
    public Dictionary<string, object> Conditions { get; set; }
}

public enum PolicyEffect
{
    Allow,
    Deny
}

// Application
public class AuthorizationService : IAuthorizationService
{
    public async Task<bool> AuthorizeAsync(
        Guid userId,
        string action,
        string resource,
        Dictionary<string, object> context)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        var roles = await _roleRepository.GetUserRolesAsync(userId);
        var policies = await _policyRepository.GetPoliciesForRolesAsync(roles.Select(r => r.Id));
        
        // Evaluate policies
        var denyPolicies = policies.Where(p => p.Effect == PolicyEffect.Deny);
        foreach (var policy in denyPolicies)
        {
            if (await EvaluatePolicyAsync(policy, action, resource, context, user))
                return false; // Explicit deny
        }
        
        var allowPolicies = policies.Where(p => p.Effect == PolicyEffect.Allow);
        foreach (var policy in allowPolicies)
        {
            if (await EvaluatePolicyAsync(policy, action, resource, context, user))
                return true; // Explicit allow
        }
        
        return false; // Default deny
    }
    
    private async Task<bool> EvaluatePolicyAsync(
        Policy policy,
        string action,
        string resource,
        Dictionary<string, object> context,
        User user)
    {
        foreach (var statement in policy.Statements)
        {
            // Check action matches
            if (!MatchesPattern(action, statement.Actions))
                continue;
            
            // Check resource matches
            if (!MatchesPattern(resource, statement.Resources))
                continue;
            
            // Evaluate conditions
            if (!EvaluateConditions(statement.Conditions, context, user))
                continue;
            
            return true;
        }
        
        return false;
    }
    
    private bool EvaluateConditions(
        Dictionary<string, object> conditions,
        Dictionary<string, object> context,
        User user)
    {
        foreach (var condition in conditions)
        {
            switch (condition.Key)
            {
                case "IpAddress":
                    if (!EvaluateIpCondition(condition.Value, context))
                        return false;
                    break;
                    
                case "TimeOfDay":
                    if (!EvaluateTimeCondition(condition.Value))
                        return false;
                    break;
                    
                case "UserAttribute":
                    if (!EvaluateUserAttributeCondition(condition.Value, user))
                        return false;
                    break;
                    
                // Add more condition types
            }
        }
        
        return true;
    }
}
```

#### 3.2 Open Policy Agent (OPA) Integration

```csharp
public class OpaAuthorizationService : IAuthorizationService
{
    private readonly HttpClient _opaClient;
    
    public async Task<bool> AuthorizeAsync(
        Guid userId,
        string action,
        string resource,
        Dictionary<string, object> context)
    {
        var input = new
        {
            user = new
            {
                id = userId,
                roles = await GetUserRolesAsync(userId),
                attributes = await GetUserAttributesAsync(userId)
            },
            action = action,
            resource = resource,
            context = context
        };
        
        var response = await _opaClient.PostAsJsonAsync(
            "/v1/data/authz/allow",
            new { input }
        );
        
        var result = await response.Content.ReadFromJsonAsync<OpaDecision>();
        return result.Result;
    }
}

// OPA Policy (Rego)
/*
package authz

default allow = false

# Allow admins everything
allow {
    input.user.roles[_] == "admin"
}

# Allow payment read for users with payment:read permission
allow {
    input.action == "payment:read"
    input.user.roles[_].permissions[_] == "payment:read"
}

# Allow resource owners to modify their own resources
allow {
    input.action == "payment:update"
    input.resource == sprintf("payment:%v", [input.user.id])
}

# Business hours restriction
allow {
    input.action == "sensitive:operation"
    business_hours
}

business_hours {
    time.now_ns() >= time.parse_rfc3339_ns("09:00:00Z")
    time.now_ns() <= time.parse_rfc3339_ns("17:00:00Z")
}
*/
```

---

### Phase 4: Security Hardening (Weeks 13-16)

#### 4.1 Account Security & Breach Detection

```csharp
public class AccountSecurityService
{
    // Password breach detection using Have I Been Pwned API
    public async Task<bool> IsPasswordBreachedAsync(string password)
    {
        var sha1 = SHA1.HashData(Encoding.UTF8.GetBytes(password));
        var hashString = BitConverter.ToString(sha1).Replace("-", "");
        
        var prefix = hashString.Substring(0, 5);
        var suffix = hashString.Substring(5);
        
        var response = await _httpClient.GetStringAsync(
            $"https://api.pwnedpasswords.com/range/{prefix}"
        );
        
        return response.Contains(suffix, StringComparison.OrdinalIgnoreCase);
    }
    
    // Account lockout
    public class AccountLockout : Entity
    {
        public Guid UserId { get; private set; }
        public int FailedAttempts { get; private set; }
        public DateTime? LockedUntil { get; private set; }
        public DateTime LastAttemptAt { get; private set; }
        
        public bool IsLocked() => LockedUntil.HasValue && LockedUntil > DateTime.UtcNow;
        
        public void RecordFailedAttempt()
        {
            FailedAttempts++;
            LastAttemptAt = DateTime.UtcNow;
            
            if (FailedAttempts >= 5)
            {
                LockedUntil = DateTime.UtcNow.AddMinutes(30);
            }
        }
        
        public void ResetFailedAttempts()
        {
            FailedAttempts = 0;
            LockedUntil = null;
        }
    }
    
    // Suspicious activity detection
    public async Task<bool> DetectSuspiciousActivityAsync(
        Guid userId,
        string ipAddress,
        string userAgent)
    {
        var recentLogins = await _loginHistoryRepository
            .GetRecentLoginsAsync(userId, TimeSpan.FromDays(30));
        
        // Check for unusual location
        var currentLocation = await _geoIpService.GetLocationAsync(ipAddress);
        var previousLocations = recentLogins
            .Select(l => l.Location)
            .Distinct()
            .ToList();
        
        if (!previousLocations.Any(loc => IsSameRegion(loc, currentLocation)))
        {
            await _notificationService.SendSecurityAlertAsync(
                userId,
                "Login from new location",
                currentLocation
            );
            return true;
        }
        
        // Check for rapid location changes (impossible travel)
        var lastLogin = recentLogins.FirstOrDefault();
        if (lastLogin != null)
        {
            var timeDiff = DateTime.UtcNow - lastLogin.Timestamp;
            var distance = CalculateDistance(lastLogin.Location, currentLocation);
            
            if (IsImpossibleTravel(distance, timeDiff))
            {
                await _notificationService.SendSecurityAlertAsync(
                    userId,
                    "Impossible travel detected",
                    $"Distance: {distance}km in {timeDiff.TotalHours}h"
                );
                return true;
            }
        }
        
        return false;
    }
}

// Login history for analytics
public class LoginHistory : Entity
{
    public Guid UserId { get; private set; }
    public DateTime Timestamp { get; private set; }
    public string IpAddress { get; private set; }
    public GeoLocation Location { get; private set; }
    public string UserAgent { get; private set; }
    public bool WasSuccessful { get; private set; }
    public string? FailureReason { get; private set; }
    public bool WasSuspicious { get; private set; }
}
```

#### 4.2 Comprehensive Audit Logging

```csharp
public class AuditLog : Entity
{
    public Guid? UserId { get; private set; }
    public string EventType { get; private set; } // LOGIN, LOGOUT, PERMISSION_CHANGE, etc.
    public string Action { get; private set; }
    public string Resource { get; private set; }
    public string IpAddress { get; private set; }
    public string UserAgent { get; private set; }
    public Dictionary<string, object> Metadata { get; private set; }
    public AuditResult Result { get; private set; }
    public string? FailureReason { get; private set; }
    public DateTime Timestamp { get; private set; }
    public string CorrelationId { get; private set; }
}

public enum AuditResult
{
    Success,
    Failure,
    Denied
}

// Middleware for automatic auditing
public class AuditMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var correlationId = context.TraceIdentifier;
        var stopwatch = Stopwatch.StartNew();
        
        try
        {
            await next(context);
            
            await LogAuditEventAsync(new AuditLog
            {
                UserId = context.User.GetUserId(),
                EventType = DetermineEventType(context),
                Action = $"{context.Request.Method} {context.Request.Path}",
                IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                UserAgent = context.Request.Headers["User-Agent"],
                Result = context.Response.StatusCode < 400 
                    ? AuditResult.Success 
                    : AuditResult.Failure,
                Timestamp = DateTime.UtcNow,
                CorrelationId = correlationId,
                Metadata = new Dictionary<string, object>
                {
                    ["ResponseTime"] = stopwatch.ElapsedMilliseconds,
                    ["StatusCode"] = context.Response.StatusCode
                }
            });
        }
        catch (Exception ex)
        {
            await LogAuditEventAsync(new AuditLog
            {
                EventType = "ERROR",
                Result = AuditResult.Failure,
                FailureReason = ex.Message,
                CorrelationId = correlationId
            });
            throw;
        }
    }
}
```

#### 4.3 Certificate-Based Authentication

```csharp
public class CertificateAuthenticationService
{
    public async Task<CertificateAuthResult> AuthenticateAsync(X509Certificate2 certificate)
    {
        // Validate certificate
        if (certificate == null)
            return CertificateAuthResult.Failed("No certificate provided");
        
        if (DateTime.UtcNow < certificate.NotBefore || DateTime.UtcNow > certificate.NotAfter)
            return CertificateAuthResult.Failed("Certificate expired or not yet valid");
        
        // Verify against trusted CAs
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        
        if (!chain.Build(certificate))
            return CertificateAuthResult.Failed("Certificate chain validation failed");
        
        // Check CRL/OCSP
        if (await IsCertificateRevokedAsync(certificate))
            return CertificateAuthResult.Failed("Certificate has been revoked");
        
        // Extract subject from certificate
        var subject = certificate.Subject;
        var thumbprint = certificate.Thumbprint;
        
        // Find user by certificate
        var user = await _userRepository.GetByCertificateThumbprintAsync(thumbprint);
        if (user == null)
            return CertificateAuthResult.Failed("User not found for certificate");
        
        return CertificateAuthResult.Success(user);
    }
}

// ASP.NET Core configuration
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.ValidateCertificateUse = true;
        options.RevocationMode = X509RevocationMode.Online;
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = async context =>
            {
                var result = await certificateAuthService.AuthenticateAsync(
                    context.ClientCertificate);
                
                if (result.IsAuthenticated)
                {
                    var claims = new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, result.User.Id.ToString()),
                        new Claim(ClaimTypes.Name, result.User.Username)
                    };
                    
                    context.Principal = new ClaimsPrincipal(
                        new ClaimsIdentity(claims, context.Scheme.Name));
                    context.Success();
                }
                else
                {
                    context.Fail(result.FailureReason);
                }
            }
        };
    });
```

---

### Phase 5: Multi-Tenancy & Isolation (Weeks 17-20)

#### 5.1 Tenant Isolation

```csharp
// Domain
public class Tenant : Entity
{
    public string Name { get; private set; }
    public string Subdomain { get; private set; }
    public string? CustomDomain { get; private set; }
    public TenantStatus Status { get; private set; }
    public TenantPlan Plan { get; private set; }
    public Dictionary<string, object> Settings { get; private set; }
    public DateTime CreatedAt { get; private set; }
}

public enum TenantStatus
{
    Active,
    Suspended,
    Trial,
    Cancelled
}

// Multi-tenant user model
public class User : Entity
{
    public Guid TenantId { get; private set; }
    public Tenant Tenant { get; private set; }
    // ... rest of properties
}

// Tenant resolution middleware
public class TenantResolutionMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var tenant = await ResolveTenantAsync(context);
        
        if (tenant == null)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("Tenant not found");
            return;
        }
        
        if (tenant.Status != TenantStatus.Active)
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsync("Tenant is not active");
            return;
        }
        
        context.Items["TenantId"] = tenant.Id;
        context.Items["Tenant"] = tenant;
        
        await next(context);
    }
    
    private async Task<Tenant?> ResolveTenantAsync(HttpContext context)
    {
        // Strategy 1: Subdomain
        var host = context.Request.Host.Host;
        if (host.Contains('.'))
        {
            var subdomain = host.Split('.')[0];
            var tenant = await _tenantRepository.GetBySubdomainAsync(subdomain);
            if (tenant != null) return tenant;
        }
        
        // Strategy 2: Custom domain
        var customDomain = await _tenantRepository.GetByCustomDomainAsync(host);
        if (customDomain != null) return customDomain;
        
        // Strategy 3: Header
        if (context.Request.Headers.TryGetValue("X-Tenant-Id", out var tenantId))
        {
            return await _tenantRepository.GetByIdAsync(Guid.Parse(tenantId));
        }
        
        // Strategy 4: Query parameter (least secure, use for development only)
        if (context.Request.Query.TryGetValue("tenant", out var tenantParam))
        {
            return await _tenantRepository.GetBySubdomainAsync(tenantParam);
        }
        
        return null;
    }
}

// Database-per-tenant or schema-per-tenant
public class MultiTenantDbContext : DbContext
{
    private readonly Guid _tenantId;
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>()
            .HasQueryFilter(u => u.TenantId == _tenantId);
        
        modelBuilder.Entity<Role>()
            .HasQueryFilter(r => r.TenantId == _tenantId);
        
        // Apply global filter to all tenant-specific entities
    }
}
```

---

### Phase 6: Observability & Compliance (Weeks 21-24)

#### 6.1 Enhanced Monitoring & Alerting

```csharp
// Custom metrics
public class IdentityMetrics
{
    private static readonly Counter LoginAttempts = Metrics.CreateCounter(
        "identity_login_attempts_total",
        "Total number of login attempts",
        new CounterConfiguration
        {
            LabelNames = new[] { "result", "provider", "tenant" }
        }
    );
    
    private static readonly Counter RegistrationTotal = Metrics.CreateCounter(
        "identity_registrations_total",
        "Total number of user registrations",
        new CounterConfiguration
        {
            LabelNames = new[] { "provider", "tenant" }
        }
    );
    
    private static readonly Histogram LoginDuration = Metrics.CreateHistogram(
        "identity_login_duration_seconds",
        "Login operation duration",
        new HistogramConfiguration
        {
            LabelNames = new[] { "provider", "tenant" },
            Buckets = Histogram.ExponentialBuckets(0.001, 2, 10)
        }
    );
    
    private static readonly Gauge ActiveSessions = Metrics.CreateGauge(
        "identity_active_sessions",
        "Number of active user sessions",
        new GaugeConfiguration
        {
            LabelNames = new[] { "tenant" }
        }
    );
    
    private static readonly Counter MfaChallenges = Metrics.CreateCounter(
        "identity_mfa_challenges_total",
        "Total MFA challenges",
        new CounterConfiguration
        {
            LabelNames = new[] { "type", "result", "tenant" }
        }
    );
    
    private static readonly Counter SuspiciousActivity = Metrics.CreateCounter(
        "identity_suspicious_activity_total",
        "Suspicious activity detected",
        new CounterConfiguration
        {
            LabelNames = new[] { "type", "tenant" }
        }
    );
}

// Alerting rules (Prometheus)
/*
groups:
  - name: identity_alerts
    interval: 30s
    rules:
      - alert: HighFailedLoginRate
        expr: rate(identity_login_attempts_total{result="failed"}[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High failed login rate"
          description: "Failed login rate is {{ $value }} per second"
      
      - alert: AccountLockoutSpike
        expr: rate(identity_account_lockouts_total[5m]) > 5
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Account lockout spike detected"
          
      - alert: SuspiciousActivityDetected
        expr: increase(identity_suspicious_activity_total[10m]) > 5
        labels:
          severity: critical
        annotations:
          summary: "Multiple suspicious activities detected"
*/
```

#### 6.2 GDPR Compliance

```csharp
public class GdprComplianceService
{
    // Right to access
    public async Task<UserDataExport> ExportUserDataAsync(Guid userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        var loginHistory = await _loginHistoryRepository.GetByUserIdAsync(userId);
        var auditLogs = await _auditLogRepository.GetByUserIdAsync(userId);
        var mfaMethods = await _mfaRepository.GetByUserIdAsync(userId);
        
        return new UserDataExport
        {
            PersonalInfo = new
            {
                user.Email,
                user.Username,
                user.CreatedAt,
                user.LastLoginAt
            },
            LoginHistory = loginHistory,
            AuditTrail = auditLogs,
            MfaMethods = mfaMethods.Select(m => new { m.Type, m.IsVerified }),
            RequestedAt = DateTime.UtcNow
        };
    }
    
    // Right to erasure
    public async Task DeleteUserDataAsync(Guid userId, string reason)
    {
        await _auditService.LogAsync(new AuditLog
        {
            UserId = userId,
            EventType = "GDPR_DELETION_REQUESTED",
            Metadata = new Dictionary<string, object> { ["Reason"] = reason }
        });
        
        // Anonymize instead of hard delete for audit compliance
        var user = await _userRepository.GetByIdAsync(userId);
        user.Anonymize(); // Replace PII with "DELETED_USER_[ID]"
        
        // Delete sensitive data
        await _mfaRepository.DeleteByUserIdAsync(userId);
        await _refreshTokenRepository.DeleteByUserIdAsync(userId);
        
        // Keep audit logs but anonymize
        await _auditLogRepository.AnonymizeUserDataAsync(userId);
        
        user.MarkAsDeleted();
        await _userRepository.UpdateAsync(user);
    }
    
    // Data portability
    public async Task<byte[]> ExportUserDataAsJsonAsync(Guid userId)
    {
        var export = await ExportUserDataAsync(userId);
        var json = JsonSerializer.Serialize(export, new JsonSerializerOptions
        {
            WriteIndented = true
        });
        return Encoding.UTF8.GetBytes(json);
    }
    
    // Consent management
    public class UserConsent : Entity
    {
        public Guid UserId { get; private set; }
        public ConsentType Type { get; private set; }
        public bool IsGranted { get; private set; }
        public DateTime GrantedAt { get; private set; }
        public DateTime? RevokedAt { get; private set; }
        public string IpAddress { get; private set; }
        public string UserAgent { get; private set; }
    }
    
    public enum ConsentType
    {
        TermsOfService,
        PrivacyPolicy,
        MarketingEmails,
        Analytics,
        Cookies
    }
}
```

---

## 🏗️ Updated Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     API Gateway (Kong/Istio)                     │
│  - Rate Limiting  - TLS Termination  - Request Routing          │
└─────────────────────────────────────────────────────────────────┘
                                 │
                ┌────────────────┼────────────────┐
                │                │                │
        ┌───────▼────────┐ ┌────▼────┐ ┌────────▼────────┐
        │   OAuth2/OIDC  │ │   SAML  │ │   Certificate   │
        │   Endpoints    │ │   SP    │ │   Auth          │
        └────────────────┘ └─────────┘ └─────────────────┘
                │                │                │
        ┌───────▼────────────────▼────────────────▼─────┐
        │         Identity Microservice (ASP.NET Core)  │
        │                                                 │
        │  ┌─────────────────────────────────────────┐  │
        │  │       Presentation Layer                │  │
        │  │  - Controllers  - Middleware  - Filters │  │
        │  └─────────────────────────────────────────┘  │
        │                      │                         │
        │  ┌─────────────────────────────────────────┐  │
        │  │       Application Layer (MediatR)       │  │
        │  │  - Commands  - Queries  - Handlers      │  │
        │  │  - Validators  - Behaviors              │  │
        │  └─────────────────────────────────────────┘  │
        │                      │                         │
        │  ┌─────────────────────────────────────────┐  │
        │  │           Domain Layer                  │  │
        │  │  - Entities  - Value Objects            │  │
        │  │  - Domain Services  - Interfaces        │  │
        │  └─────────────────────────────────────────┘  │
        │                      │                         │
        │  ┌─────────────────────────────────────────┐  │
        │  │       Infrastructure Layer              │  │
        │  │  - Repositories  - External Services    │  │
        │  │  - LDAP  - SAML  - WebAuthn  - TOTP    │  │
        │  └─────────────────────────────────────────┘  │
        └─────────────────────────────────────────────┘
                │                │                │
    ┌───────────▼─┐  ┌──────────▼─┐  ┌──────────▼──────┐
    │ PostgreSQL  │  │   Redis    │  │  RabbitMQ       │
    │  (User DB)  │  │ (Sessions) │  │  (Events)       │
    └─────────────┘  └────────────┘  └─────────────────┘
                                              │
                        ┌─────────────────────┼──────────────────┐
                        │                     │                  │
                ┌───────▼────────┐  ┌────────▼────────┐ ┌──────▼──────┐
                │  Prometheus/   │  │   Loki/ELK      │ │  Jaeger/    │
                │  Grafana       │  │   (Logs)        │ │  Zipkin     │
                │  (Metrics)     │  │                 │ │  (Traces)   │
                └────────────────┘  └─────────────────┘ └─────────────┘
```

---

## 📋 Implementation Checklist

### Phase 1 (Weeks 1-4): Foundation

#### Week 1: OAuth2/OIDC Core Infrastructure
- [ ] **Domain Layer**
  - [ ] Create `Client` entity with grant types, scopes, redirect URIs
  - [ ] Create `AuthorizationCode` entity with PKCE support
  - [ ] Create `Consent` entity for user consent tracking
  - [ ] Create `RefreshToken` entity
  - [ ] Create domain events: `ClientCreatedEvent`, `TokenIssuedEvent`, `TokenRevokedEvent`
  - [ ] Define domain interfaces: `IOAuth2Service`, `IClientRepository`, `ITokenProvider`
- [ ] **Infrastructure Layer**
  - [ ] Install OpenIddict or IdentityServer4
  - [ ] Configure EF Core entities and migrations
  - [ ] Implement `ClientRepository` with tenant isolation (SOLID: Repository pattern)
  - [ ] Implement token storage (Redis for stateless validation)
  - [ ] **Token Provider Factory (Strategy Pattern)**
    - [ ] Create `ITokenProvider` interface (Strategy pattern)
    - [ ] Implement `JwtTokenProvider` (JWT tokens)
    - [ ] Implement `ReferenceTokenProvider` (opaque tokens stored in Redis)
    - [ ] Create `TokenProviderFactory` (Factory pattern) to select provider based on client config
  - [ ] **Outbox Pattern**
    - [ ] Create `OutboxMessage` entity (Id, Type, Payload, CreatedAt, ProcessedAt)
    - [ ] Implement `IOutboxRepository` with EF Core
    - [ ] Create background job to publish outbox messages to RabbitMQ
  - [ ] Configure Redis connection (connection pooling, retry policy)
  - [ ] Configure RabbitMQ connection for event publishing
- [ ] **Application Layer (CQRS)**
  - [ ] Create `AuthorizeCommand` + `AuthorizeCommandHandler` (CQRS)
  - [ ] Create `TokenCommand` + `TokenCommandHandler` (CQRS)
  - [ ] Create `RefreshTokenCommand` + handler (CQRS)
  - [ ] Add FluentValidation validators
  - [ ] Implement outbox pattern in handlers (save events to outbox, not direct publish)
- [ ] **Presentation Layer**
  - [ ] Create `OAuth2Controller` with `/connect/authorize` endpoint
  - [ ] Create `/connect/token` endpoint
  - [ ] Add PKCE validation middleware
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_oauth2_authorize_requests_total` (counter, labels: client_id, grant_type, result)
    - [ ] `identity_oauth2_token_issued_total` (counter, labels: client_id, token_type)
    - [ ] `identity_oauth2_token_validation_duration_seconds` (histogram)
  - [ ] Register metrics endpoint `/metrics`
- [ ] **API Versioning Strategy**
  - [ ] **Presentation Layer**
    - [ ] Implement URL-based versioning (`/api/v1/`, `/api/v2/`)
    - [ ] Create versioning middleware (SOLID: Single Responsibility)
    - [ ] Add deprecation headers (`Sunset`, `Deprecation`)
    - [ ] Create versioning strategy documentation
    - [ ] Add API version to Prometheus metrics (labels: `api_version`)
  - [ ] **Post-Feature Deliverables**
    - [ ] Create ADR for API versioning strategy
    - [ ] Document version migration guide
- [ ] **Rate Limiting Implementation**
  - [ ] **Infrastructure Layer**
    - [ ] Install `AspNetCoreRateLimit` package
    - [ ] Implement rate limiting middleware (SOLID: Single Responsibility)
    - [ ] Use Redis for distributed rate limiting
    - [ ] Configure rate limits per endpoint:
      - [ ] `/connect/token`: 20 req/min per client
      - [ ] `/api/auth/register`: 5 req/min per IP
      - [ ] `/api/auth/login`: 10 req/min per IP
      - [ ] General API: 100 req/min per user
  - [ ] **Observability**
    - [ ] Add Prometheus metrics:
      - [ ] `identity_rate_limit_exceeded_total` (counter, labels: endpoint, client_id, ip)
      - [ ] `identity_rate_limit_remaining` (gauge, labels: endpoint, client_id)
- [ ] **Idempotency Infrastructure**
  - [ ] **Domain Layer**
    - [ ] Create `IdempotencyKey` value object
    - [ ] Create `ProcessedCommand` entity (command type, idempotency key, timestamp, result)
  - [ ] **Application Layer**
    - [ ] Create `IdempotencyBehavior` for MediatR pipeline (SOLID: Open/Closed Principle)
    - [ ] Store processed commands in Redis (TTL: 24 hours)
    - [ ] Return cached result if command already processed
  - [ ] **Infrastructure**
    - [ ] Use Redis for idempotency key storage
  - [ ] **Post-Feature Deliverables**
    - [ ] Write unit tests for idempotency behavior
    - [ ] Write integration tests (duplicate command handling)
    - [ ] Create ADR for idempotency strategy
- [ ] **JWT Key Rotation**
  - [ ] **Domain Layer**
    - [ ] Create `SigningKey` entity (key ID, key material, created, expires, is_active)
    - [ ] Create domain events: `SigningKeyRotatedEvent`
  - [ ] **Key Rotation Strategy Pattern**
    - [ ] Create `IKeyRotationStrategy` interface (Strategy pattern)
    - [ ] Implement `ActivePlusPreviousStrategy` (support active + one previous key)
    - [ ] Create `KeyRotationStrategyFactory` (Factory pattern)
  - [ ] **Application Layer (CQRS)**
    - [ ] Create `RotateSigningKeyCommand` + handler (CQRS)
    - [ ] Create `GetActiveSigningKeysQuery` + handler (CQRS)
    - [ ] Auto-rotate every 90 days (background job)
    - [ ] Graceful transition period (7 days overlap)
    - [ ] Publish events to outbox: `SigningKeyRotatedEvent`
  - [ ] **Infrastructure**
    - [ ] Store signing keys in Azure Key Vault (Infrastructure: external service)
    - [ ] Cache active keys in Redis (TTL: 1 hour)
    - [ ] Update JWKS endpoint to expose multiple keys
  - [ ] **Post-Feature Deliverables**
    - [ ] Create ADR for key rotation strategy
    - [ ] Document manual rotation procedure
- [ ] **Security Scanning Pipeline**
  - [ ] **Static Analysis (SAST)**
    - [ ] Integrate SonarQube or Checkmarx
    - [ ] Scan for OWASP Top 10 vulnerabilities
    - [ ] Scan for secrets in code (GitGuardian, TruffleHog)
    - [ ] Fail build on critical vulnerabilities
  - [ ] **Dependency Scanning**
    - [ ] Integrate Snyk or Dependabot
    - [ ] Scan NuGet packages for vulnerabilities
    - [ ] Auto-update dependencies with security patches
  - [ ] **Dynamic Analysis (DAST)**
    - [ ] Integrate OWASP ZAP or Burp Suite
    - [ ] Run DAST against staging environment
    - [ ] Test for injection, XSS, CSRF, etc.
  - [ ] **Container Scanning**
    - [ ] Scan Docker images with Trivy or Clair
    - [ ] Scan for CVEs in base images
    - [ ] Use minimal base images (Alpine or distroless)
- [ ] **Blue-Green Deployment Strategy**
  - [ ] **Kubernetes Configuration**
    - [ ] Create blue/green deployment manifests
    - [ ] Implement traffic switching with Istio/Kong
    - [ ] Add health checks for deployment readiness
    - [ ] Implement automatic rollback on failure
  - [ ] **Database Migrations**
    - [ ] Use backward-compatible migrations only
    - [ ] Test migrations on blue environment first
    - [ ] Support rollback migrations
  - [ ] **Post-Deployment**
    - [ ] Monitor metrics during cutover
    - [ ] Implement smoke tests after cutover
    - [ ] Document deployment procedure
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (Domain, Application layers)
  - [ ] Write integration tests (OAuth2 flows, token validation)
  - [ ] Write API documentation (Swagger/OpenAPI)
  - [ ] Create ADR (Architecture Decision Record) for token provider strategy
  - [ ] Update improvement-plan.md to mark Week 1 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 2: OIDC Endpoints & Standards
- [ ] **Domain Layer**
  - [ ] Create domain events: `UserInfoRequestedEvent`, `SessionEndedEvent`, `TokenRevokedEvent`
- [ ] **OIDC Discovery**
  - [ ] Implement `/.well-known/openid-configuration` endpoint (cache in Redis)
  - [ ] Implement `/.well-known/jwks.json` (JWKS endpoint, cache in Redis)
  - [ ] Add issuer validation
  - [ ] Use Redis for discovery document caching (TTL: 1 hour)
- [ ] **User Info & Session**
  - [ ] Implement `/connect/userinfo` endpoint (CQRS: `GetUserInfoQuery` + handler)
  - [ ] Implement `/connect/endsession` (CQRS: `EndSessionCommand` + handler)
  - [ ] Implement `/connect/revocation` (CQRS: `RevokeTokenCommand` + handler)
  - [ ] Implement `/connect/introspection` (CQRS: `IntrospectTokenQuery` + handler)
  - [ ] Publish events to outbox: `SessionEndedEvent`, `TokenRevokedEvent`
- [ ] **Grant Types (Strategy Pattern)**
  - [ ] Create `IGrantTypeHandler` interface (Strategy pattern)
  - [ ] Implement `AuthorizationCodeGrantHandler` (Authorization Code + PKCE)
  - [ ] Implement `ClientCredentialsGrantHandler` (service-to-service)
  - [ ] Implement `RefreshTokenGrantHandler` (Refresh Token flow)
  - [ ] Implement `DeviceCodeGrantHandler` (Device Code flow - RFC 8628)
  - [ ] Create `GrantTypeHandlerFactory` (Factory pattern) to select handler
- [ ] **Infrastructure**
  - [ ] Use Redis for token introspection caching
  - [ ] Use RabbitMQ for session end events
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_oidc_discovery_requests_total` (counter)
    - [ ] `identity_oidc_userinfo_requests_total` (counter, labels: result)
    - [ ] `identity_oidc_token_revocation_total` (counter)
    - [ ] `identity_oidc_session_end_total` (counter)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (all grant type handlers)
  - [ ] Write integration tests for all OIDC endpoints
  - [ ] Run OIDC conformance tests (certified OIDC provider tests)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for grant type strategy pattern
  - [ ] Update improvement-plan.md to mark Week 2 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 3: Multi-Factor Authentication (MFA)
- [ ] **Domain Layer**
  - [ ] Create `MfaMethod` entity (TOTP, SMS, Email, WebAuthn)
  - [ ] Create `MfaChallenge` entity
  - [ ] Create domain events: `MfaMethodAddedEvent`, `MfaChallengeCreatedEvent`, `MfaVerifiedEvent`, `MfaFailedEvent`
  - [ ] Define `IMfaService` interface (SOLID: Interface Segregation)
- [ ] **MFA Provider Strategy Pattern**
  - [ ] Create `IMfaProvider` interface (Strategy pattern)
  - [ ] Implement `TotpMfaProvider` (RFC 6238 compliant)
  - [ ] Implement `SmsMfaProvider` (Twilio/AWS SNS integration)
  - [ ] Implement `EmailMfaProvider` (SMTP integration)
  - [ ] Create `MfaProviderFactory` (Factory pattern) to select provider
- [ ] **TOTP Implementation**
  - [ ] Implement `TotpService` (RFC 6238 compliant, SOLID: Single Responsibility)
  - [ ] Generate QR codes for Google Authenticator (use Redis for secret storage)
  - [ ] Add time-window validation (30s windows, configurable)
  - [ ] Create `SetupTotpCommand` + handler (CQRS)
  - [ ] Create `VerifyTotpCommand` + handler (CQRS)
- [ ] **SMS/Email MFA**
  - [ ] Create `SmsMfaService` with Twilio/AWS SNS integration (Infrastructure: external service)
  - [ ] Create `EmailMfaService` with SMTP integration (Infrastructure: SMTP client)
  - [ ] Implement code generation (6-digit, expires in 5min, stored in Redis)
  - [ ] Add rate limiting (max 3 attempts per challenge, use Redis for counters)
  - [ ] Store MFA codes in Redis with TTL (5 minutes)
- [ ] **Application Layer (CQRS)**
  - [ ] Update `LoginCommand` to support MFA flow (CQRS)
  - [ ] Create `MfaChallengeCommand` + handler (CQRS)
  - [ ] Create `VerifyMfaCommand` + handler (CQRS)
  - [ ] Publish events to outbox: `MfaChallengeCreatedEvent`, `MfaVerifiedEvent`
- [ ] **Circuit Breaker Infrastructure**
  - [ ] **Infrastructure Layer**
    - [ ] Install Polly package for resilience
    - [ ] Implement circuit breaker for Twilio/AWS SNS
    - [ ] Implement circuit breaker for SMTP
    - [ ] Add retry policies with exponential backoff
    - [ ] Configure circuit breaker thresholds:
      - [ ] Failure threshold: 50% in 10 seconds
      - [ ] Break duration: 30 seconds
      - [ ] Minimum throughput: 10 requests
  - [ ] **Observability**
    - [ ] Add Prometheus metrics:
      - [ ] `identity_circuit_breaker_state` (gauge, labels: service, state)
      - [ ] `identity_circuit_breaker_opened_total` (counter, labels: service)
- [ ] **Infrastructure**
  - [ ] Configure Twilio/AWS SNS for SMS delivery
  - [ ] Configure SMTP for email delivery
  - [ ] Use Redis for MFA code storage and rate limiting
  - [ ] Publish MFA events to RabbitMQ via outbox
- [ ] **Presentation Layer**
  - [ ] Add MFA endpoints: `/api/mfa/setup`, `/api/mfa/verify` (CQRS)
  - [ ] Update login response to indicate MFA required
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_mfa_challenges_total` (counter, labels: type, result)
    - [ ] `identity_mfa_verification_duration_seconds` (histogram, labels: type)
    - [ ] `identity_mfa_failed_attempts_total` (counter, labels: type, reason)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (all MFA providers)
  - [ ] Write integration tests (MFA flows, SMS/Email delivery)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for MFA provider strategy
  - [ ] Update improvement-plan.md to mark Week 3 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 4: WebAuthn/FIDO2 & Database Schema
- [ ] **Domain Layer**
  - [ ] Create `WebAuthnCredential` entity
  - [ ] Create domain events: `WebAuthnCredentialRegisteredEvent`, `WebAuthnAuthenticatedEvent`
  - [ ] Define `IWebAuthnService` interface (SOLID: Interface Segregation)
- [ ] **WebAuthn/FIDO2**
  - [ ] Install `Fido2NetLib` package
  - [ ] Implement `WebAuthnService` (registration + authentication, SOLID: Single Responsibility)
  - [ ] Create `RegisterWebAuthnCommand` + handler (CQRS)
  - [ ] Create `AuthenticateWebAuthnCommand` + handler (CQRS)
  - [ ] Create `/api/webauthn/register` endpoint (CQRS)
  - [ ] Create `/api/webauthn/authenticate` endpoint (CQRS)
  - [ ] Add credential backup/restore support
  - [ ] Store WebAuthn challenges in Redis (TTL: 5 minutes)
- [ ] **Database Schema Updates**
  - [ ] Create migration for OAuth2 tables (Clients, AuthorizationCodes, Consents)
  - [ ] Create migration for MFA tables (MfaMethods, MfaChallenges)
  - [ ] Create migration for WebAuthn tables (WebAuthnCredentials)
  - [ ] Create migration for OutboxMessage table
  - [ ] Add indexes for performance (ClientId, UserId, ExpiresAt, TenantId)
  - [ ] Add database constraints (FKs, unique constraints)
  - [ ] Add composite indexes for multi-tenant queries
- [ ] **Infrastructure**
  - [ ] Use Redis for WebAuthn challenge storage
  - [ ] Publish WebAuthn events to RabbitMQ via outbox
  - [ ] Configure PostgreSQL connection pooling
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_webauthn_registrations_total` (counter, labels: result)
    - [ ] `identity_webauthn_authentications_total` (counter, labels: result)
    - [ ] `identity_webauthn_operation_duration_seconds` (histogram)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (WebAuthn service, all entities)
  - [ ] Write integration tests:
    - [ ] End-to-end OAuth2 flow tests
    - [ ] MFA flow integration tests
    - [ ] WebAuthn registration/authentication tests
    - [ ] Token validation and revocation tests
    - [ ] Multi-tenant isolation tests
    - [ ] Outbox pattern tests (event publishing)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create database migration documentation
  - [ ] Create ADR for outbox pattern implementation
- [ ] **Load Testing & Performance Baselines**
  - [ ] **Performance Testing**
    - [ ] Use k6 or JMeter for load tests
    - [ ] Test scenarios:
      - [ ] Login flow: 1000 req/s sustained, 5000 req/s peak
      - [ ] Token validation: 10,000 req/s sustained
      - [ ] MFA verification: 500 req/s sustained
      - [ ] OAuth2 authorization code flow: 500 req/s sustained
    - [ ] Establish performance baselines:
      - [ ] Login: p50=45ms, p95=180ms, p99=450ms, throughput=1200 req/s
      - [ ] Token validation: p50=10ms, p95=50ms, p99=100ms, throughput=10000 req/s
      - [ ] MFA: p50=60ms, p95=200ms, p99=500ms, throughput=600 req/s
      - [ ] p50 < 50ms, p95 < 200ms, p99 < 500ms (general target)
      - [ ] 0.1% error rate max
    - [ ] Test database connection pooling under load
    - [ ] Test Redis connection pooling under load
  - [ ] **Observability**
    - [ ] Monitor resource usage during load tests
    - [ ] Identify bottlenecks in Grafana dashboards
  - [ ] **Performance Regression Testing**
    - [ ] Integrate performance tests into CI/CD
    - [ ] Fail build if performance degrades >20%
    - [ ] Monitor performance trends in Grafana
  - [ ] **Post-Test Actions**
    - [ ] Document performance baselines
    - [ ] Create performance regression tests
    - [ ] Optimize identified bottlenecks
  - [ ] **Post-Feature Deliverables**
    - [ ] Write comprehensive unit tests (WebAuthn service, all entities)
    - [ ] Write integration tests:
      - [ ] End-to-end OAuth2 flow tests
      - [ ] MFA flow integration tests
      - [ ] WebAuthn registration/authentication tests
      - [ ] Token validation and revocation tests
      - [ ] Multi-tenant isolation tests
      - [ ] Outbox pattern tests (event publishing)
    - [ ] Update API documentation (OpenAPI spec)
    - [ ] Create database migration documentation
    - [ ] Create ADR for outbox pattern implementation
    - [ ] Update improvement-plan.md to mark Week 4 tasks as completed
    - [ ] Commit changes with descriptive message
    - [ ] Push to repository

### Phase 2 (Weeks 5-8): Enterprise Auth

#### Week 5: SAML 2.0 Service Provider
- [ ] **Domain Layer**
  - [ ] Create `SamlIdentityProvider` entity (EntityId, SSO URL, certificates)
  - [ ] Create `SamlAssertion` value object
  - [ ] Create domain events: `SamlLoginInitiatedEvent`, `SamlLoginCompletedEvent`, `SamlLogoutEvent`
  - [ ] Define `ISamlService` interface (SOLID: Interface Segregation)
- [ ] **Infrastructure Layer**
  - [ ] Install `Sustainsys.Saml2.AspNetCore2` package
  - [ ] Implement `SamlService` (auth request, response processing, SOLID: Single Responsibility)
  - [ ] Configure certificate management (signing, encryption, store in K8S secrets)
  - [ ] Implement `SamlIdentityProviderRepository` (SOLID: Repository pattern)
  - [ ] Store SAML request state in Redis (TTL: 10 minutes)
- [ ] **Application Layer (CQRS)**
  - [ ] Create `InitiateSamlLoginCommand` + handler (CQRS)
  - [ ] Create `ProcessSamlResponseCommand` + handler (CQRS)
  - [ ] Create `ProcessSamlLogoutCommand` + handler (CQRS)
  - [ ] Add SAML attribute mapping logic (Strategy pattern for attribute mapping)
  - [ ] Publish events to outbox: `SamlLoginInitiatedEvent`, `SamlLoginCompletedEvent`
- [ ] **Presentation Layer**
  - [ ] Create `/saml/login` endpoint (initiate SSO, CQRS)
  - [ ] Create `/saml/acs` endpoint (assertion consumer service, CQRS)
  - [ ] Create `/saml/logout` endpoint (CQRS)
  - [ ] Add SAML metadata endpoint `/saml/metadata` (cache in Redis)
- [ ] **Infrastructure**
  - [ ] Use Redis for SAML request state storage
  - [ ] Publish SAML events to RabbitMQ via outbox
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_saml_login_requests_total` (counter, labels: idp, result)
    - [ ] `identity_saml_logout_requests_total` (counter, labels: idp)
    - [ ] `identity_saml_assertion_processing_duration_seconds` (histogram)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (SAML service, attribute mapping)
  - [ ] Write integration tests with SAML IdP simulator
  - [ ] Test attribute mapping and user provisioning
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for SAML integration
  - [ ] Update improvement-plan.md to mark Week 5 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 6: LDAP/Active Directory Integration
- [ ] **Domain Layer**
  - [ ] Create `LdapConfiguration` value object
  - [ ] Create `LdapUser` entity for synced users
  - [ ] Create domain events: `LdapUserSyncedEvent`, `LdapGroupsSyncedEvent`, `LdapLoginEvent`
  - [ ] Define `ILdapAuthenticationService` interface (SOLID: Interface Segregation)
- [ ] **Infrastructure Layer**
  - [ ] Install `Novell.Directory.Ldap.NETStandard` package
  - [ ] Implement `LdapConnectionService` (connection pooling, SOLID: Single Responsibility)
  - [ ] Implement `LdapAuthenticationService` (bind, search, group sync)
  - [ ] Add LDAP configuration (BaseDN, filters, attribute mapping, store in K8S ConfigMap)
  - [ ] Use Redis for LDAP connection pooling state
- [ ] **Application Layer (CQRS)**
  - [ ] Create `LdapLoginCommand` + handler (CQRS)
  - [ ] Create `SyncLdapUserCommand` + handler (CQRS, background job)
  - [ ] Create `SyncLdapGroupsCommand` + handler (CQRS, background job)
  - [ ] Publish events to outbox: `LdapUserSyncedEvent`, `LdapGroupsSyncedEvent`
- [ ] **Presentation Layer**
  - [ ] Create `/api/auth/ldap/login` endpoint (CQRS)
  - [ ] Create `/api/admin/ldap/sync` endpoint (background job, CQRS)
- [ ] **Infrastructure**
  - [ ] Configure LDAP connection pooling (max connections, timeout)
  - [ ] Publish LDAP sync events to RabbitMQ via outbox
- [ ] **Database**
  - [ ] Add migration for `LdapUser` table
  - [ ] Add `ExternalProvider` field to `User` entity
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_ldap_login_attempts_total` (counter, labels: result)
    - [ ] `identity_ldap_sync_operations_total` (counter, labels: type, result)
    - [ ] `identity_ldap_connection_duration_seconds` (histogram)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (LDAP services, mocked responses)
  - [ ] Write integration tests with test LDAP server
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for LDAP integration
  - [ ] Update improvement-plan.md to mark Week 6 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 7: Social Login (OAuth2 Providers)
- [ ] **Domain Layer**
  - [ ] Create `ExternalProvider` entity (Google, Microsoft, GitHub, etc.)
  - [ ] Create `ExternalAuthResult` value object
  - [ ] Create domain events: `ExternalLoginEvent`, `ExternalAccountLinkedEvent`, `UserProvisionedEvent`
  - [ ] Define `IExternalAuthProvider` interface (SOLID: Interface Segregation)
- [ ] **External Auth Provider Strategy Pattern**
  - [ ] Create `IExternalAuthProvider` interface (Strategy pattern)
  - [ ] Implement `GoogleAuthProvider` (OAuth2 code exchange, SOLID: Single Responsibility)
  - [ ] Implement `MicrosoftAuthProvider` (Azure AD)
  - [ ] Implement `GitHubAuthProvider`
  - [ ] Implement `AppleAuthProvider` (Sign in with Apple)
  - [ ] Create `ExternalAuthProviderFactory` (Factory pattern) to select provider
- [ ] **Application Layer (CQRS)**
  - [ ] Create `ExternalLoginCommand` + handler (CQRS)
  - [ ] Create `LinkExternalAccountCommand` + handler (CQRS)
  - [ ] Add user provisioning logic (auto-create on first login)
  - [ ] Publish events to outbox: `ExternalLoginEvent`, `ExternalAccountLinkedEvent`, `UserProvisionedEvent`
- [ ] **Presentation Layer**
  - [ ] Create `/api/auth/external/{provider}/login` endpoint (CQRS)
  - [ ] Create `/api/auth/external/{provider}/callback` endpoint (CQRS)
  - [ ] Add state parameter validation (CSRF protection, store state in Redis with TTL)
- [ ] **Infrastructure**
  - [ ] Store OAuth2 state tokens in Redis (TTL: 10 minutes)
  - [ ] Configure HTTP clients for external providers (retry policy, timeout)
  - [ ] Publish external auth events to RabbitMQ via outbox
- [ ] **Configuration**
  - [ ] Add provider secrets to K8S secrets
  - [ ] Configure redirect URIs per environment
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_external_login_attempts_total` (counter, labels: provider, result)
    - [ ] `identity_external_account_linked_total` (counter, labels: provider)
    - [ ] `identity_external_auth_duration_seconds` (histogram, labels: provider)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (all external providers)
  - [ ] Write integration tests (mock external provider responses)
  - [ ] Test user linking and account merging
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for external auth provider strategy
  - [ ] Update improvement-plan.md to mark Week 7 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 8: Device Code Flow & Admin UI
- [ ] **Domain Layer**
  - [ ] Create `DeviceCode` entity
  - [ ] Create domain events: `DeviceCodeIssuedEvent`, `DeviceCodeVerifiedEvent`
  - [ ] Define `IDeviceCodeService` interface (SOLID: Interface Segregation)
- [ ] **OAuth2 Enhancements**
  - [ ] Implement Device Code grant type (RFC 8628)
  - [ ] Create `IssueDeviceCodeCommand` + handler (CQRS)
  - [ ] Create `VerifyDeviceCodeCommand` + handler (CQRS)
  - [ ] Add `/connect/device` endpoint (device authorization, CQRS)
  - [ ] Add polling mechanism for device code verification (store in Redis)
  - [ ] Complete PKCE implementation (if not done in Phase 1)
- [ ] **Admin UI - Client Management (CQRS)**
  - [ ] Create `ClientManagementController` (CRUD operations)
  - [ ] Create `CreateClientCommand` + handler (CQRS)
  - [ ] Create `UpdateClientCommand` + handler (CQRS)
  - [ ] Create `DeleteClientCommand` + handler (CQRS)
  - [ ] Create `GetClientQuery` + handler (CQRS)
  - [ ] Create `RotateClientSecretCommand` + handler (CQRS)
  - [ ] Add client validation (redirect URIs, scopes, FluentValidation)
  - [ ] Create admin endpoints: `/api/admin/clients` (CQRS)
  - [ ] Publish events to outbox: `ClientCreatedEvent`, `ClientUpdatedEvent`, `ClientSecretRotatedEvent`
- [ ] **Infrastructure**
  - [ ] Store device codes in Redis (TTL: 10 minutes, polling interval: 5 seconds)
  - [ ] Publish client management events to RabbitMQ via outbox
- [ ] **Service Mesh Integration (Istio)**
  - [ ] **Istio Configuration**
    - [ ] Create VirtualService for traffic routing
    - [ ] Create DestinationRule for load balancing
    - [ ] Configure mutual TLS (mTLS) between services
    - [ ] Configure circuit breaking at service mesh level
    - [ ] Configure retry policies
  - [ ] **Testing**
    - [ ] Test mTLS between Identity and Payment services
    - [ ] Test traffic splitting (canary deployments)
    - [ ] Test fault injection (chaos engineering)
    - [ ] Monitor service mesh metrics in Grafana
  - [ ] **Observability**
    - [ ] Integrate Kiali for service mesh visualization
    - [ ] Export Istio metrics to Prometheus
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_device_code_issued_total` (counter)
    - [ ] `identity_device_code_verified_total` (counter, labels: result)
    - [ ] `identity_client_management_operations_total` (counter, labels: operation, result)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (device code flow, client management)
  - [ ] Write integration tests (device code flow, admin API)
  - [ ] Admin API tests with authorization checks
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for device code flow
  - [ ] Update improvement-plan.md to mark Week 8 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

### Phase 3 (Weeks 9-12): Advanced Authorization

#### Week 9: ABAC Engine Foundation
- [ ] **Domain Layer**
  - [ ] Create `Policy` entity (name, effect, statements)
  - [ ] Create `PolicyStatement` value object (actions, resources, conditions)
  - [ ] Create `Permission` entity (fine-grained permissions)
  - [ ] Create domain events: `PolicyCreatedEvent`, `PolicyUpdatedEvent`, `PolicyEvaluatedEvent`
  - [ ] Define `IAuthorizationService` interface (SOLID: Interface Segregation)
- [ ] **Condition Evaluator Strategy Pattern**
  - [ ] Create `IConditionEvaluator` interface (Strategy pattern)
  - [ ] Implement `IpAddressConditionEvaluator` (IP-based conditions)
  - [ ] Implement `TimeOfDayConditionEvaluator` (time-based conditions)
  - [ ] Implement `UserAttributeConditionEvaluator` (user attribute conditions)
  - [ ] Create `ConditionEvaluatorFactory` (Factory pattern) to select evaluator
- [ ] **Application Layer (CQRS)**
  - [ ] Create `AuthorizationService` (policy evaluation engine, SOLID: Single Responsibility)
  - [ ] Create `AuthorizeCommand` + handler (CQRS)
  - [ ] Create `EvaluatePolicyQuery` + handler (CQRS)
  - [ ] Add policy matching logic (wildcards, patterns)
  - [ ] Publish events to outbox: `PolicyEvaluatedEvent`
- [ ] **Infrastructure Layer**
  - [ ] Implement `PolicyRepository` (SOLID: Repository pattern)
  - [ ] Add caching layer for policies (Redis, TTL: 1 hour)
  - [ ] Use Redis for policy evaluation results caching
- [ ] **Presentation Layer**
  - [ ] Create authorization middleware (SOLID: Open/Closed Principle)
  - [ ] Add `[Authorize(Policy = "...")]` attribute support
- [ ] **Database**
  - [ ] Create migration for `Policies`, `PolicyStatements`, `Permissions` tables
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_policy_evaluations_total` (counter, labels: policy, result)
    - [ ] `identity_policy_evaluation_duration_seconds` (histogram)
    - [ ] `identity_authorization_denials_total` (counter, labels: reason)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (policy evaluation, condition evaluators)
  - [ ] Write integration tests (authorization flows)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for ABAC engine design
  - [ ] Update improvement-plan.md to mark Week 9 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 10: Open Policy Agent (OPA) Integration
- [ ] **Domain Layer**
  - [ ] Create domain events: `OpaPolicyEvaluatedEvent`, `OpaPolicyUpdatedEvent`
  - [ ] Define `IOpaAuthorizationService` interface (SOLID: Interface Segregation)
- [ ] **Authorization Service Strategy Pattern**
  - [ ] Create `IAuthorizationService` interface (Strategy pattern)
  - [ ] Implement `OpaAuthorizationService` (OPA-based authorization)
  - [ ] Implement `AbacAuthorizationService` (ABAC fallback)
  - [ ] Create `AuthorizationServiceFactory` (Factory pattern) to select service
- [ ] **Infrastructure Layer**
  - [ ] Install OPA client library or create HTTP client (SOLID: Dependency Inversion)
  - [ ] Create OPA policy templates (Rego language)
  - [ ] Add OPA connection configuration (K8S ConfigMap)
  - [ ] Use Redis for OPA evaluation results caching
  - [ ] Configure HTTP client with retry policy and circuit breaker
- [ ] **Application Layer (CQRS)**
  - [ ] Create `OpaAuthorizeCommand` + handler (CQRS)
  - [ ] Implement policy input transformation (user → OPA input)
  - [ ] Add fallback to ABAC if OPA unavailable (Strategy pattern)
  - [ ] Publish events to outbox: `OpaPolicyEvaluatedEvent`
- [ ] **OPA Policies**
  - [ ] Create base authorization policy (allow/deny rules)
  - [ ] Create role-based policy
  - [ ] Create resource-owner policy
  - [ ] Create time-based conditional access policy
- [ ] **Infrastructure**
  - [ ] Publish OPA evaluation events to RabbitMQ via outbox
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_opa_evaluations_total` (counter, labels: policy, result)
    - [ ] `identity_opa_evaluation_duration_seconds` (histogram)
    - [ ] `identity_opa_fallback_to_abac_total` (counter)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (OPA service, fallback logic)
  - [ ] Write integration tests with OPA server
  - [ ] Test policy evaluation scenarios
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for OPA integration
  - [ ] Update improvement-plan.md to mark Week 10 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 11: Fine-Grained Permissions & Policy Management
- [ ] **Domain Layer**
  - [ ] Create `Permission` entity (action:resource format)
  - [ ] Create `RolePermission` junction entity
  - [ ] Add permission inheritance (role → permissions)
  - [ ] Create domain events: `PolicyCreatedEvent`, `PolicyUpdatedEvent`, `PermissionGrantedEvent`
  - [ ] Define `IPermissionService` interface (SOLID: Interface Segregation)
- [ ] **Application Layer (CQRS)**
  - [ ] Create `CreatePolicyCommand` + handler (CQRS)
  - [ ] Create `UpdatePolicyCommand` + handler (CQRS)
  - [ ] Create `DeletePolicyCommand` + handler (CQRS)
  - [ ] Create `GetPolicyQuery` + handler (CQRS)
  - [ ] Create `EvaluatePolicyQuery` + handler (CQRS)
  - [ ] Implement permission checking service (SOLID: Single Responsibility)
  - [ ] Publish events to outbox: `PolicyCreatedEvent`, `PolicyUpdatedEvent`
- [ ] **Presentation Layer**
  - [ ] Create `/api/admin/policies` endpoints (CRUD, CQRS)
  - [ ] Create `/api/admin/permissions` endpoints (CQRS)
  - [ ] Add policy evaluation endpoint `/api/authz/evaluate` (CQRS)
- [ ] **Infrastructure**
  - [ ] Use Redis for permission cache (TTL: 30 minutes)
  - [ ] Publish policy management events to RabbitMQ via outbox
- [ ] **Database**
  - [ ] Create migration for permissions and role-permission mapping
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_policy_management_operations_total` (counter, labels: operation, result)
    - [ ] `identity_permission_checks_total` (counter, labels: result)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (policy management, permissions)
  - [ ] Write integration tests (policy CRUD, permission inheritance)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for permission model
  - [ ] Update improvement-plan.md to mark Week 11 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 12: Conditional Access & Policy UI
- [ ] **Domain Layer**
  - [ ] Create domain events: `ConditionalAccessEvaluatedEvent`, `AccessDeniedEvent`
  - [ ] Define `IConditionalAccessService` interface (SOLID: Interface Segregation)
- [ ] **Conditional Access Strategy Pattern**
  - [ ] Create `IConditionalAccessRule` interface (Strategy pattern)
  - [ ] Implement `LocationBasedAccessRule` (IP geolocation)
  - [ ] Implement `TimeBasedAccessRule` (business hours)
  - [ ] Implement `DeviceBasedAccessRule` (device fingerprinting)
  - [ ] Create `ConditionalAccessRuleFactory` (Factory pattern)
- [ ] **Conditional Access**
  - [ ] Create `ConditionalAccessService` (SOLID: Single Responsibility)
  - [ ] Create `EvaluateConditionalAccessCommand` + handler (CQRS)
  - [ ] Use Redis for device fingerprinting storage
  - [ ] Use MaxMind GeoIP2 for location detection (Infrastructure: external service)
- [ ] **Policy Management UI (API)**
  - [ ] Create policy builder endpoints (CQRS)
  - [ ] Add policy validation endpoint (CQRS: `ValidatePolicyQuery`)
  - [ ] Create policy testing endpoint (dry-run evaluation, CQRS: `TestPolicyQuery`)
- [ ] **Infrastructure**
  - [ ] Publish conditional access events to RabbitMQ via outbox
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_conditional_access_evaluations_total` (counter, labels: rule_type, result)
    - [ ] `identity_access_denials_total` (counter, labels: reason)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (all conditional access rules)
  - [ ] Write integration tests (conditional access flows)
  - [ ] Policy evaluation performance tests
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for conditional access
  - [ ] Update improvement-plan.md to mark Week 12 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

### Phase 4 (Weeks 13-16): Security

#### Week 13: Account Security & Lockout
- [ ] **Domain Layer**
  - [ ] Create `AccountLockout` entity (failed attempts, locked until)
  - [ ] Create `LoginHistory` entity (IP, location, user agent)
  - [ ] Create domain events: `AccountLockedEvent`, `AccountUnlockedEvent`, `FailedLoginAttemptEvent`
  - [ ] Define `IAccountSecurityService` interface (SOLID: Interface Segregation)
- [ ] **Application Layer (CQRS)**
  - [ ] Implement `AccountSecurityService` (lockout logic, SOLID: Single Responsibility)
  - [ ] Create `RecordFailedLoginCommand` + handler (CQRS)
  - [ ] Create `UnlockAccountCommand` + handler (CQRS)
  - [ ] Add lockout policy (max attempts, lockout duration, configurable)
  - [ ] Publish events to outbox: `AccountLockedEvent`, `AccountUnlockedEvent`
- [ ] **Infrastructure**
  - [ ] Use Redis for lockout state (distributed locking, TTL)
  - [ ] Use Redis for failed login attempt counters
  - [ ] Publish security events to RabbitMQ via outbox
- [ ] **Presentation Layer**
  - [ ] Update login endpoint to check lockout status (CQRS)
  - [ ] Create `/api/admin/accounts/{id}/unlock` endpoint (CQRS)
- [ ] **Database**
  - [ ] Create migration for `AccountLockouts` and `LoginHistory` tables
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_account_lockouts_total` (counter)
    - [ ] `identity_failed_login_attempts_total` (counter, labels: user_id)
    - [ ] `identity_account_unlocks_total` (counter)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (lockout logic, security service)
  - [ ] Write integration tests (account lockout flow, concurrent attempts)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for account security
  - [ ] Update improvement-plan.md to mark Week 13 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 14: Breach Detection & Suspicious Activity
- [ ] **Domain Layer**
  - [ ] Create domain events: `PasswordBreachDetectedEvent`, `SuspiciousActivityDetectedEvent`
  - [ ] Define `IBreachDetectionService` and `ISuspiciousActivityService` interfaces (SOLID: Interface Segregation)
- [ ] **Detection Strategy Pattern**
  - [ ] Create `ISuspiciousActivityDetector` interface (Strategy pattern)
  - [ ] Implement `ImpossibleTravelDetector` (impossible travel detection)
  - [ ] Implement `NewLocationDetector` (new location detection)
  - [ ] Implement `AnomalyDetector` (unusual login patterns)
  - [ ] Create `SuspiciousActivityDetectorFactory` (Factory pattern)
- [ ] **Infrastructure Layer**
  - [ ] Integrate Have I Been Pwned API (password breach detection, Infrastructure: external service)
  - [ ] Implement `BreachDetectionService` (SOLID: Single Responsibility)
  - [ ] Add MaxMind GeoIP2 integration (geolocation, Infrastructure: external service)
  - [ ] Create `GeolocationService` (SOLID: Single Responsibility)
  - [ ] Configure HTTP clients with retry and circuit breaker
  - [ ] Implement circuit breaker for HIBP API
  - [ ] Implement circuit breaker for MaxMind GeoIP2
  - [ ] Configure circuit breaker thresholds:
    - [ ] Failure threshold: 50% in 10 seconds
    - [ ] Break duration: 30 seconds
    - [ ] Minimum throughput: 10 requests
- [ ] **Application Layer (CQRS)**
  - [ ] Create `CheckPasswordBreachCommand` + handler (CQRS)
  - [ ] Create `DetectSuspiciousActivityCommand` + handler (CQRS)
  - [ ] Publish events to outbox: `PasswordBreachDetectedEvent`, `SuspiciousActivityDetectedEvent`
- [ ] **Infrastructure**
  - [ ] Use Redis for login history cache (recent logins for analysis)
  - [ ] Publish security alerts to RabbitMQ via outbox
- [ ] **Presentation Layer**
  - [ ] Add breach check to password change endpoint (CQRS)
  - [ ] Create `/api/security/alerts` endpoint (CQRS: `GetSecurityAlertsQuery`)
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_password_breaches_detected_total` (counter)
    - [ ] `identity_suspicious_activities_detected_total` (counter, labels: type)
    - [ ] `identity_breach_check_duration_seconds` (histogram)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (all detectors, breach detection)
  - [ ] Write integration tests (mocked HIBP API, suspicious activity flows)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for security detection
  - [ ] Update improvement-plan.md to mark Week 14 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 15: Comprehensive Audit Logging
- [ ] **Domain Layer**
  - [ ] Create `AuditLog` entity (event type, action, resource, metadata)
  - [ ] Create `AuditResult` enum (Success, Failure, Denied)
  - [ ] Create domain events: `AuditLogCreatedEvent` (for downstream systems)
  - [ ] Define `IAuditService` interface (SOLID: Interface Segregation)
- [ ] **Infrastructure Layer**
  - [ ] Implement `AuditRepository` (EF Core, SOLID: Repository pattern)
  - [ ] Add audit log archiving (move old logs to cold storage, background job)
  - [ ] Implement structured logging (Serilog with audit sink)
  - [ ] Use Redis for audit log batching (reduce DB writes)
- [ ] **Application Layer (CQRS)**
  - [ ] Create `LogAuditEventCommand` + handler (CQRS)
  - [ ] Create `QueryAuditLogsQuery` + handler (CQRS)
  - [ ] Add audit event types (LOGIN, LOGOUT, PERMISSION_CHANGE, etc.)
  - [ ] Publish events to outbox: `AuditLogCreatedEvent` (for analytics)
- [ ] **Presentation Layer**
  - [ ] Create audit middleware (automatic request logging, SOLID: Open/Closed Principle)
  - [ ] Create `/api/admin/audit-logs` endpoint (query, filter, export, CQRS)
- [ ] **Infrastructure**
  - [ ] Publish audit events to RabbitMQ via outbox (for analytics pipeline)
- [ ] **Database**
  - [ ] Create migration for `AuditLogs` table with indexes (partitioned by date for performance)
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_audit_logs_created_total` (counter, labels: event_type, result)
    - [ ] `identity_audit_log_write_duration_seconds` (histogram)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (audit service, middleware)
  - [ ] Write integration tests (audit logging flows)
  - [ ] Performance tests (high-volume audit writes)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for audit logging architecture
  - [ ] Update improvement-plan.md to mark Week 15 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 16: Certificate Authentication & Security Headers
- [ ] **Certificate Authentication**
  - [ ] **Domain Layer**
    - [ ] Create `UserCertificate` entity (thumbprint, subject, issuer)
    - [ ] Create domain events: `CertificateRegisteredEvent`, `CertificateAuthenticatedEvent`
    - [ ] Define `ICertificateAuthService` interface (SOLID: Interface Segregation)
  - [ ] **Infrastructure Layer**
    - [ ] Implement `CertificateAuthenticationService` (X.509 validation, SOLID: Single Responsibility)
    - [ ] Add certificate revocation checking (CRL/OCSP, Infrastructure: external service)
    - [ ] Implement certificate chain validation
    - [ ] Store certificates in K8S secrets
  - [ ] **Application Layer (CQRS)**
    - [ ] Create `AuthenticateWithCertificateCommand` + handler (CQRS)
    - [ ] Create `RegisterCertificateCommand` + handler (CQRS)
    - [ ] Publish events to outbox: `CertificateRegisteredEvent`, `CertificateAuthenticatedEvent`
  - [ ] **Presentation Layer**
    - [ ] Configure ASP.NET Core certificate authentication
    - [ ] Create `/api/auth/certificate` endpoint (CQRS)
- [ ] **Security Headers Middleware**
  - [ ] Implement security headers middleware (SOLID: Single Responsibility):
    - [ ] HSTS (Strict-Transport-Security)
    - [ ] X-Content-Type-Options
    - [ ] X-Frame-Options
    - [ ] Content-Security-Policy
    - [ ] X-XSS-Protection
    - [ ] Referrer-Policy
  - [ ] Add configuration for header values (K8S ConfigMap)
- [ ] **Infrastructure**
  - [ ] Publish certificate events to RabbitMQ via outbox
- [ ] **Chaos Engineering Tests**
  - [ ] **Failure Scenarios**
    - [ ] Test PostgreSQL failure (use read replicas, graceful degradation)
    - [ ] Test Redis failure (circuit breaker, degraded mode)
    - [ ] Test RabbitMQ failure (outbox pattern resilience)
    - [ ] Test network partition (multi-region failover)
    - [ ] Test pod termination (graceful shutdown, no data loss)
    - [ ] Test cascading failures (circuit breakers working)
  - [ ] **Tools**
    - [ ] Use Chaos Mesh or Litmus Chaos
    - [ ] Run chaos experiments in staging environment
  - [ ] **Post-Test Actions**
    - [ ] Document failure modes and mitigations
    - [ ] Update runbooks with recovery procedures
    - [ ] Create ADR for resilience patterns
- [ ] **Penetration Testing**
  - [ ] **External Pen Test**
    - [ ] Hire external security firm (OPTIONAL but recommended)
    - [ ] Test authentication/authorization bypasses
    - [ ] Test injection attacks (SQL, LDAP, JWT)
    - [ ] Test session management
    - [ ] Test MFA bypasses
    - [ ] Test rate limiting bypasses
  - [ ] **Internal Pen Test**
    - [ ] Test service-to-service authentication
    - [ ] Test privilege escalation
    - [ ] Test multi-tenant isolation
  - [ ] **Post-Test Actions**
    - [ ] Remediate all critical/high findings
    - [ ] Document vulnerabilities and fixes
    - [ ] Re-test after remediation
    - [ ] Create security assessment report
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_certificate_authentications_total` (counter, labels: result)
    - [ ] `identity_certificate_registrations_total` (counter)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (certificate validation, security headers)
  - [ ] Write integration tests (certificate authentication flow)
  - [ ] Security headers validation tests
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for certificate authentication
  - [ ] Update improvement-plan.md to mark Week 16 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

### Phase 5 (Weeks 17-20): Multi-Tenancy

#### Week 17: Tenant Isolation Foundation
- [ ] **Domain Layer**
  - [ ] Create `Tenant` entity (name, subdomain, custom domain, status)
  - [ ] Add `TenantId` to all tenant-scoped entities (User, Role, Policy)
  - [ ] Create `TenantStatus` enum (Active, Suspended, Trial, Cancelled)
  - [ ] Create domain events: `TenantCreatedEvent`, `TenantUpdatedEvent`
  - [ ] Define `ITenantRepository` interface (SOLID: Interface Segregation)
- [ ] **Infrastructure Layer**
  - [ ] Implement `TenantRepository` (SOLID: Repository pattern)
  - [ ] Add EF Core global query filters (automatic tenant filtering, SOLID: Open/Closed Principle)
  - [ ] Implement tenant-scoped DbContext factory (Factory pattern)
  - [ ] Use Redis for tenant metadata caching
- [ ] **Database**
  - [ ] Create migration for `Tenants` table
  - [ ] Add `TenantId` column to existing tables
  - [ ] Add composite indexes (TenantId + other keys)
- [ ] **Database Backup & Disaster Recovery**
  - [ ] **Backup Strategy**
    - [ ] Implement automated PostgreSQL backups:
      - [ ] Full backup: Daily at 2 AM UTC
      - [ ] Incremental backup: Every 4 hours
      - [ ] Transaction log backup: Every 15 minutes
    - [ ] Store backups in S3 with versioning (Infrastructure: external storage)
    - [ ] Encrypt backups at rest (AES-256)
    - [ ] Retention: 30 days daily, 12 months weekly
  - [ ] **Disaster Recovery**
    - [ ] Test backup restoration monthly
    - [ ] Implement point-in-time recovery (PITR)
    - [ ] Document RTO: 15 minutes, RPO: 5 minutes
    - [ ] Test multi-region failover quarterly
    - [ ] Implement automated DR testing
  - [ ] **Multi-Tenant Considerations**
    - [ ] Support tenant-level backup/restore
    - [ ] Test tenant data isolation in backups
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_tenants_total` (gauge, labels: status)
    - [ ] `identity_backup_operations_total` (counter, labels: type, result)
    - [ ] `identity_backup_duration_seconds` (histogram)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (tenant isolation, query filters)
  - [ ] Write integration tests (multi-tenant data access)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for multi-tenancy architecture
  - [ ] Update improvement-plan.md to mark Week 17 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 18: Tenant Resolution & Middleware
- [ ] **Domain Layer**
  - [ ] Create domain events: `TenantResolvedEvent`, `TenantResolutionFailedEvent`
- [ ] **Tenant Resolution Strategy Pattern**
  - [ ] Create `ITenantResolutionStrategy` interface (Strategy pattern)
  - [ ] Implement `SubdomainTenantResolutionStrategy` (subdomain-based)
  - [ ] Implement `CustomDomainTenantResolutionStrategy` (custom domain-based)
  - [ ] Implement `HeaderTenantResolutionStrategy` (header-based)
  - [ ] Implement `QueryParameterTenantResolutionStrategy` (query parameter-based, dev only)
  - [ ] Create `TenantResolutionStrategyFactory` (Factory pattern)
- [ ] **Infrastructure Layer**
  - [ ] Implement `TenantResolutionMiddleware` (SOLID: Single Responsibility)
  - [ ] Implement tenant caching (Redis, TTL: 1 hour)
- [ ] **Application Layer (CQRS)**
  - [ ] Create `ResolveTenantCommand` + handler (CQRS)
  - [ ] Add tenant validation (status check, active only)
  - [ ] Publish events to outbox: `TenantResolvedEvent`
- [ ] **Presentation Layer**
  - [ ] Register tenant resolution middleware (early in pipeline)
  - [ ] Add tenant context to HttpContext.Items
- [ ] **Infrastructure**
  - [ ] Publish tenant resolution events to RabbitMQ via outbox
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_tenant_resolutions_total` (counter, labels: strategy, result)
    - [ ] `identity_tenant_resolution_duration_seconds` (histogram)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (all resolution strategies)
  - [ ] Write integration tests (tenant resolution flows, isolation)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for tenant resolution
  - [ ] Update improvement-plan.md to mark Week 18 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 19: Database Per Tenant & Tenant Management API
- [ ] **Database Strategy Pattern**
  - [ ] Create `IDatabaseStrategy` interface (Strategy pattern)
  - [ ] Implement `DatabasePerTenantStrategy` (database-per-tenant)
  - [ ] Implement `SchemaPerTenantStrategy` (schema-per-tenant, alternative)
  - [ ] Create `DatabaseStrategyFactory` (Factory pattern)
  - [ ] Implement database-per-tenant connection factory
  - [ ] Add tenant database mapping (TenantId → ConnectionString, store in Redis)
  - [ ] Add tenant database provisioning service (SOLID: Single Responsibility)
- [ ] **Tenant Management API (CQRS)**
  - [ ] **Application Layer**
    - [ ] Create `CreateTenantCommand` + handler (CQRS)
    - [ ] Create `UpdateTenantCommand` + handler (CQRS)
    - [ ] Create `SuspendTenantCommand` + handler (CQRS)
    - [ ] Create `ActivateTenantCommand` + handler (CQRS)
    - [ ] Create `GetTenantQuery` + handler (CQRS)
    - [ ] Publish events to outbox: `TenantCreatedEvent`, `TenantUpdatedEvent`, `TenantSuspendedEvent`
  - [ ] **Presentation Layer**
    - [ ] Create `/api/admin/tenants` endpoints (CRUD, CQRS)
    - [ ] Create `/api/admin/tenants/{id}/suspend` endpoint (CQRS)
    - [ ] Create `/api/admin/tenants/{id}/activate` endpoint (CQRS)
- [ ] **Infrastructure**
  - [ ] Publish tenant management events to RabbitMQ via outbox
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_tenant_management_operations_total` (counter, labels: operation, result)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (database strategies, tenant management)
  - [ ] Write integration tests (multi-tenant database isolation, API)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for database per tenant strategy
  - [ ] Update improvement-plan.md to mark Week 19 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 20: Tenant Admin Portal & Branding
- [ ] **Domain Layer**
  - [ ] Create `TenantBranding` entity (logo, colors, custom CSS)
  - [ ] Create domain events: `TenantBrandingUpdatedEvent`
- [ ] **Tenant Admin Portal (API) - CQRS**
  - [ ] Create tenant settings endpoints (CQRS: `GetTenantSettingsQuery`, `UpdateTenantSettingsCommand`)
  - [ ] Create tenant user management endpoints (scoped to tenant, CQRS)
  - [ ] Create tenant analytics endpoints (CQRS: `GetTenantAnalyticsQuery`)
- [ ] **Tenant-Specific Branding**
  - [ ] Create `UpdateTenantBrandingCommand` + handler (CQRS)
  - [ ] Create `/api/tenant/branding` endpoint (CQRS)
  - [ ] Add branding to JWT claims (for frontend consumption)
  - [ ] Cache branding in Redis (TTL: 1 hour)
  - [ ] Publish events to outbox: `TenantBrandingUpdatedEvent`
- [ ] **Infrastructure**
  - [ ] Publish branding events to RabbitMQ via outbox
- [ ] **Database**
  - [ ] Create migration for `TenantBranding` table
- [ ] **Database Performance Optimization**
  - [ ] **Query Optimization**
    - [ ] Analyze slow queries with pg_stat_statements
    - [ ] Add missing indexes based on query patterns
    - [ ] Optimize N+1 queries with EF Core eager loading
    - [ ] Use query hints for complex queries
  - [ ] **Connection Pooling**
    - [ ] Tune connection pool settings:
      - [ ] Min: 10, Max: 100 per instance
      - [ ] Connection lifetime: 15 minutes
      - [ ] Test under load
  - [ ] **Read Replicas**
    - [ ] Configure PostgreSQL read replicas
    - [ ] Route read queries to replicas
    - [ ] Implement read/write splitting in repository layer (Strategy pattern)
  - [ ] **Partitioning**
    - [ ] Partition AuditLogs table by date (monthly)
    - [ ] Partition LoginHistory table by date (monthly)
    - [ ] Test partition pruning performance
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_tenant_branding_updates_total` (counter)
    - [ ] `identity_database_query_duration_seconds` (histogram, labels: query_type)
    - [ ] `identity_database_connection_pool_usage` (gauge)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (branding, tenant admin APIs)
  - [ ] Write integration tests (multi-tenant end-to-end flows)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for tenant branding
  - [ ] Update improvement-plan.md to mark Week 20 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

### Phase 6 (Weeks 21-24): Compliance

#### Week 21: GDPR Right to Access
- [ ] **Domain Layer**
  - [ ] Create `UserDataExport` value object
  - [ ] Create `DataExportRequest` entity
  - [ ] Create domain events: `DataExportRequestedEvent`, `DataExportCompletedEvent`
  - [ ] Define `IGdprComplianceService` interface (SOLID: Interface Segregation)
- [ ] **Data Aggregation Strategy Pattern**
  - [ ] Create `IDataSource` interface (Strategy pattern)
  - [ ] Implement `UserProfileDataSource` (user profile data)
  - [ ] Implement `LoginHistoryDataSource` (login history)
  - [ ] Implement `AuditLogDataSource` (audit logs)
  - [ ] Implement `MfaDataSource` (MFA methods)
  - [ ] Implement `ConsentDataSource` (OAuth2 consents)
  - [ ] Create `DataSourceFactory` (Factory pattern)
- [ ] **Application Layer (CQRS)**
  - [ ] Implement `GdprComplianceService.ExportUserDataAsync()` (SOLID: Single Responsibility)
  - [ ] Create `ExportUserDataCommand` + handler (CQRS, background job)
  - [ ] Create `GetDataExportStatusQuery` + handler (CQRS)
  - [ ] Aggregate user data from all sources using strategy pattern
  - [ ] Publish events to outbox: `DataExportRequestedEvent`, `DataExportCompletedEvent`
- [ ] **Presentation Layer**
  - [ ] Create `/api/gdpr/export` endpoint (CQRS)
  - [ ] Create `/api/gdpr/export/{id}/status` endpoint (CQRS)
  - [ ] Add data export format (JSON, CSV)
  - [ ] Implement async export (background job for large datasets)
- [ ] **Infrastructure**
  - [ ] Store export files in S3 or blob storage (Infrastructure: external storage)
  - [ ] Use Redis for export job status tracking
  - [ ] Publish GDPR events to RabbitMQ via outbox
- [ ] **Database**
  - [ ] Create migration for `DataExportRequests` table
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_gdpr_export_requests_total` (counter)
    - [ ] `identity_gdpr_export_duration_seconds` (histogram)
    - [ ] `identity_gdpr_export_size_bytes` (histogram)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (all data sources, export service)
  - [ ] Write integration tests (data export completeness, format validation)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for GDPR data export
  - [ ] Update improvement-plan.md to mark Week 21 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 22: GDPR Right to Erasure
- [ ] **Domain Layer**
  - [ ] Create domain events: `DataDeletionRequestedEvent`, `DataAnonymizedEvent`, `DataDeletedEvent`
- [ ] **Anonymization Strategy Pattern**
  - [ ] Create `IAnonymizationStrategy` interface (Strategy pattern)
  - [ ] Implement `UserProfileAnonymizationStrategy` (anonymize user profile)
  - [ ] Implement `AuditLogAnonymizationStrategy` (anonymize audit logs)
  - [ ] Create `AnonymizationStrategyFactory` (Factory pattern)
- [ ] **Application Layer (CQRS)**
  - [ ] Implement `GdprComplianceService.DeleteUserDataAsync()` (SOLID: Single Responsibility)
  - [ ] Create `DeleteUserDataCommand` + handler (CQRS, background job)
  - [ ] Create `GetDeletionStatusQuery` + handler (CQRS)
  - [ ] Implement data anonymization (not hard delete for audit compliance)
- [ ] **Saga Pattern for Data Deletion**
  - [ ] **Application Layer**
    - [ ] Create `DataDeletionSaga` (orchestrator, SOLID: Single Responsibility)
    - [ ] Implement compensation logic for failed steps:
      - [ ] Step 1: Anonymize user profile (compensate: restore from backup)
      - [ ] Step 2: Delete MFA methods (compensate: restore)
      - [ ] Step 3: Anonymize audit logs (compensate: restore)
      - [ ] Step 4: Revoke sessions (compensate: N/A, log only)
    - [ ] Store saga state in Redis (distributed locking)
    - [ ] Implement saga timeout handling (1 hour max)
  - [ ] **Infrastructure**
    - [ ] Use Redis for saga state management
    - [ ] Publish saga events to RabbitMQ via outbox
  - [ ] **Post-Feature Deliverables**
    - [ ] Write unit tests for saga orchestration and compensation
    - [ ] Write integration tests for saga failure scenarios
    - [ ] Create ADR for saga pattern usage
- [ ] **Application Layer (CQRS) - Continued**
  - [ ] Add cascade deletion logic using saga pattern:
    - [ ] Anonymize user profile (replace PII with "DELETED_USER_{ID}")
    - [ ] Delete MFA methods, refresh tokens
    - [ ] Anonymize audit logs (keep structure, remove PII)
    - [ ] Revoke all active sessions (use Redis for session revocation)
  - [ ] Publish events to outbox: `DataDeletionRequestedEvent`, `DataAnonymizedEvent`
- [ ] **Presentation Layer**
  - [ ] Create `/api/gdpr/delete` endpoint (CQRS)
  - [ ] Create `/api/gdpr/delete/{id}/status` endpoint (CQRS)
  - [ ] Add deletion confirmation (2FA required)
  - [ ] Create deletion request workflow
- [ ] **Infrastructure**
  - [ ] Use Redis for deletion job status tracking
  - [ ] Publish deletion events to RabbitMQ via outbox
- [ ] **Database**
  - [ ] Add soft delete flag to `Users` table
  - [ ] Create migration for anonymization support
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_gdpr_deletion_requests_total` (counter)
    - [ ] `identity_gdpr_deletion_duration_seconds` (histogram)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (anonymization strategies, deletion service)
  - [ ] Write integration tests (data deletion, anonymization verification)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for GDPR data deletion
  - [ ] Update improvement-plan.md to mark Week 22 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 23: Consent Management & Data Export
- [ ] **Consent Management**
  - [ ] **Domain Layer**
    - [ ] Create `UserConsent` entity (type, granted, revoked, timestamps)
    - [ ] Create `ConsentType` enum (TermsOfService, PrivacyPolicy, Marketing, etc.)
    - [ ] Create domain events: `ConsentGrantedEvent`, `ConsentRevokedEvent`
    - [ ] Define `IConsentService` interface (SOLID: Interface Segregation)
  - [ ] **Application Layer (CQRS)**
    - [ ] Create `GrantConsentCommand` + handler (CQRS)
    - [ ] Create `RevokeConsentCommand` + handler (CQRS)
    - [ ] Create `GetUserConsentsQuery` + handler (CQRS)
    - [ ] Publish events to outbox: `ConsentGrantedEvent`, `ConsentRevokedEvent`
  - [ ] **Presentation Layer**
    - [ ] Create `/api/consents` endpoints (grant, revoke, list, CQRS)
    - [ ] Add consent check middleware (enforce required consents, SOLID: Open/Closed Principle)
- [ ] **Data Export Enhancements**
  - [ ] Add export scheduling (recurring exports, background job)
  - [ ] Add export encryption (PGP encryption for sensitive data, Infrastructure: encryption service)
  - [ ] Implement export delivery (email, S3, secure download link)
  - [ ] Use Redis for export scheduling state
- [ ] **Infrastructure**
  - [ ] Publish consent events to RabbitMQ via outbox
  - [ ] Configure S3 for export file storage
- [ ] **Database**
  - [ ] Create migration for `UserConsents` table
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_consent_operations_total` (counter, labels: operation, type)
    - [ ] `identity_data_export_deliveries_total` (counter, labels: method, result)
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (consent management, export enhancements)
  - [ ] Write integration tests (consent flows, export delivery)
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for consent management
  - [ ] Update improvement-plan.md to mark Week 23 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

#### Week 24: Compliance Reporting & Privacy Dashboard
- [ ] **Compliance Reporting**
  - [ ] **Report Generation Strategy Pattern**
    - [ ] Create `IComplianceReportGenerator` interface (Strategy pattern)
    - [ ] Implement `Soc2ReportGenerator` (SOC2 template)
    - [ ] Implement `PciDssReportGenerator` (PCI-DSS template)
    - [ ] Implement `HipaaReportGenerator` (HIPAA template)
    - [ ] Create `ComplianceReportGeneratorFactory` (Factory pattern)
  - [ ] **Application Layer (CQRS)**
    - [ ] Create `GenerateComplianceReportCommand` + handler (CQRS, background job)
    - [ ] Create `GetComplianceReportQuery` + handler (CQRS)
    - [ ] Implement report generation using strategy pattern
    - [ ] Add data retention policy enforcement
    - [ ] Publish events to outbox: `ComplianceReportGeneratedEvent`
  - [ ] **Presentation Layer**
    - [ ] Create `/api/admin/compliance/reports` endpoint (CQRS)
    - [ ] Add report export (PDF, JSON)
- [ ] **Privacy Dashboard (API) - CQRS**
  - [ ] Create privacy settings endpoints (CQRS: `GetPrivacySettingsQuery`, `UpdatePrivacySettingsCommand`)
  - [ ] Create data activity timeline endpoint (CQRS: `GetDataActivityTimelineQuery`)
  - [ ] Create consent history endpoint (CQRS: `GetConsentHistoryQuery`)
  - [ ] Create data sharing endpoints (third-party integrations, CQRS)
- [ ] **Infrastructure**
  - [ ] Store compliance reports in S3 or blob storage
  - [ ] Use Redis for report generation job status
  - [ ] Publish compliance events to RabbitMQ via outbox
- [ ] **Database**
  - [ ] Create migration for compliance reports and data retention policies
- [ ] **Observability**
  - [ ] Add Prometheus metrics:
    - [ ] `identity_compliance_reports_generated_total` (counter, labels: report_type)
    - [ ] `identity_compliance_report_generation_duration_seconds` (histogram)
- [ ] **Living Architecture Documentation**
  - [ ] **Diagrams**
    - [ ] Maintain C4 model diagrams (Context, Container, Component, Code)
    - [ ] Update sequence diagrams for all auth flows
    - [ ] Create deployment diagrams for K8S
    - [ ] Generate ER diagrams from database schema
  - [ ] **Tools**
    - [ ] Use PlantUML or Mermaid for diagrams as code
    - [ ] Integrate diagrams into CI/CD (auto-update on changes)
    - [ ] Generate API docs from OpenAPI spec
  - [ ] **Documentation Site**
    - [ ] Create documentation site with Docusaurus or MkDocs
    - [ ] Include architecture, API docs, runbooks, ADRs
    - [ ] Host on GitHub Pages or internal wiki
- [ ] **Post-Feature Deliverables**
  - [ ] Write comprehensive unit tests (all report generators, privacy dashboard)
  - [ ] Write integration tests (compliance report generation, privacy dashboard APIs)
  - [ ] End-to-end GDPR workflow tests
  - [ ] Update API documentation (OpenAPI spec)
  - [ ] Create ADR for compliance reporting
  - [ ] Update improvement-plan.md to mark Week 24 tasks as completed
  - [ ] Commit changes with descriptive message
  - [ ] Push to repository

---

## 🛠️ Updated Technology Stack

### Core Framework
- **.NET 8** - Runtime
- **ASP.NET Core** - Web framework
- **Entity Framework Core** - ORM

### Authentication Libraries
- **IdentityServer** or **OpenIddict** - OAuth2/OIDC server
- **Sustainsys.Saml2** - SAML 2.0 implementation
- **Novell.Directory.Ldap.NETStandard** - LDAP client
- **Fido2NetLib** - WebAuthn/FIDO2
- **OtpNet** - TOTP implementation

### Authorization
- **Open Policy Agent (OPA)** - Policy engine
- Custom ABAC engine

### Security
- **Azure Key Vault** - Secrets management
- **Have I Been Pwned API** - Breach detection
- **MaxMind GeoIP2** - Geolocation

### Infrastructure
- **PostgreSQL** - Primary database
- **Redis** - Caching & sessions
- **RabbitMQ** - Event bus
- **Kong/Istio** - API Gateway

### Observability
- **Prometheus** - Metrics
- **Grafana** - Dashboards
- **Loki** - Log aggregation
- **Jaeger/Zipkin** - Distributed tracing
- **OpenTelemetry** - Instrumentation

---

## 🔐 Updated Kubernetes Deployment

### Secrets Management

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: identity-secrets
  namespace: platform
type: Opaque
stringData:
  # Database
  database-connection: "Host=postgres;Port=5432;Database=identitydb;Username=postgres;Password=..."
  
  # Redis
  redis-connection: "redis-master:6379,password=..."
  
  # JWT
  jwt-secret: "..."
  jwt-private-key: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
  jwt-public-key: |
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----
  
  # OAuth2 Clients
  google-client-secret: "..."
  microsoft-client-secret: "..."
  github-client-secret: "..."
  
  # SAML
  saml-signing-certificate: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  saml-signing-key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
  
  # LDAP
  ldap-bind-password: "..."
  
  # External APIs
  hibp-api-key: "..."
  maxmind-license-key: "..."
```

### Enhanced Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: identity-api
  namespace: platform
spec:
  replicas: 5
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 2
      maxUnavailable: 0
  selector:
    matchLabels:
      app: identity-api
  template:
    metadata:
      labels:
        app: identity-api
        version: v2.0
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: identity-api-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app
                      operator: In
                      values:
                        - identity-api
                topologyKey: kubernetes.io/hostname
      
      initContainers:
        - name: wait-for-postgres
          image: busybox:latest
          command: ['sh', '-c', 'until nc -z postgres 5432; do sleep 1; done']
        
        - name: wait-for-redis
          image: busybox:latest
          command: ['sh', '-c', 'until nc -z redis-master 6379; do sleep 1; done']
        
        - name: migrate-database
          image: platformacrprod.azurecr.io/identity:v2.0
          command: ["dotnet", "ef", "database", "update"]
          envFrom:
            - secretRef:
                name: identity-secrets
      
      containers:
        - name: identity-api
          image: platformacrprod.azurecr.io/identity:v2.0
          imagePullPolicy: Always
          
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            capabilities:
              drop: ["ALL"]
          
          ports:
            - containerPort: 8080
              name: http
              protocol: TCP
            - containerPort: 8081
              name: metrics
              protocol: TCP
          
          env:
            - name: ASPNETCORE_ENVIRONMENT
              value: "Production"
            - name: ASPNETCORE_URLS
              value: "http://+:8080"
            - name: KUBERNETES_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: POD_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.podIP
          
          envFrom:
            - configMapRef:
                name: identity-config
            - secretRef:
                name: identity-secrets
          
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
          
          startupProbe:
            httpGet:
              path: /health/startup
              port: 8080
            initialDelaySeconds: 0
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 30
          
          resources:
            requests:
              memory: "512Mi"
              cpu: "500m"
            limits:
              memory: "1Gi"
              cpu: "1000m"
          
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: secrets-store
              mountPath: /mnt/secrets-store
              readOnly: true
      
      volumes:
        - name: tmp
          emptyDir: {}
        - name: secrets-store
          csi:
            driver: secrets-store.csi.k8s.io
            readOnly: true
            volumeAttributes:
              secretProviderClass: identity-secrets
```

---

## 📊 Performance & Scalability Targets

### Performance Metrics
- **Response Time**: p50 < 50ms, p95 < 200ms, p99 < 500ms
- **Throughput**: 10,000+ requests/second per instance
- **Token Generation**: < 10ms
- **MFA Validation**: < 50ms
- **LDAP Auth**: < 200ms

### Scalability
- **Horizontal Scaling**: 2-50 replicas based on HPA
- **Database**: Read replicas for queries
- **Cache Hit Rate**: > 90% for token validation
- **Connection Pooling**: Min 10, Max 100 per instance

### Availability
- **Uptime**: 99.99% (4.38 minutes downtime/month)
- **Zero-downtime deployments**
- **Multi-region support**
- **Disaster recovery**: RTO < 15 minutes, RPO < 5 minutes

---

## 🎓 Training & Documentation

### Developer Documentation
- Architecture decision records (ADRs)
- API documentation (Swagger/OpenAPI)
- Integration guides per auth method
- Troubleshooting runbooks

### Operations
- Deployment playbooks
- Incident response procedures
- Backup and recovery procedures
- Scaling guidelines

### Security
- Security best practices
- Threat model
- Penetration testing results
- Compliance certifications

---

## ✅ Definition of Done

Your Identity microservice will be considered **production-grade** and **enterprise-ready** when:

1. ✅ Supports 10+ authentication methods
2. ✅ Full OAuth2/OIDC compliance
3. ✅ SAML 2.0 support
4. ✅ LDAP/AD integration
5. ✅ MFA (TOTP, SMS, WebAuthn)
6. ✅ Passwordless authentication
7. ✅ ABAC + OPA integration
8. ✅ Multi-tenant with complete isolation
9. ✅ Comprehensive audit logging
10. ✅ GDPR/SOC2/PCI-DSS compliant
11. ✅ 99.99% uptime
12. ✅ < 200ms p95 response time
13. ✅ Zero-downtime deployments
14. ✅ Security hardened (pen-tested)
15. ✅ Full observability (metrics, logs, traces)

---

## 💰 Estimated Effort

- **Phase 1-2**: 8 weeks (OAuth2, OIDC, MFA, SAML, LDAP)
- **Phase 3-4**: 8 weeks (ABAC, OPA, Security hardening)
- **Phase 5-6**: 8 weeks (Multi-tenancy, Compliance)
- **Testing & Hardening**: 4 weeks
- **Documentation**: 2 weeks

**Total**: ~30 weeks with 2-3 senior engineers

---

This remediation plan transforms your Identity service into a **rock-solid, enterprise-grade authorization component** that can serve as a reusable foundation for all future projects. The architecture is battle-tested, standards-compliant, and production-ready. 
