namespace Identity.Application.DTOs;

/// <summary>
/// DTO for authentication response containing access and refresh tokens.
/// </summary>
public record AuthResponseDto(
    string AccessToken,
    string RefreshToken,
    DateTime ExpiresAt,
    string TokenType = "Bearer"
);

