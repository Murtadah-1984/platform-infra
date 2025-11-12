using Identity.Domain.Entities;
using System.Security.Claims;

namespace Identity.Domain.Interfaces;

/// <summary>
/// JWT token service interface for token generation and validation.
/// </summary>
public interface IJwtTokenService
{
    string GenerateAccessToken(User user, IEnumerable<string> roles, IEnumerable<string> permissions);
    string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token);
    Task<bool> IsTokenRevokedAsync(string token, CancellationToken cancellationToken = default);
    Task RevokeTokenAsync(string token, string reason, CancellationToken cancellationToken = default);
}

