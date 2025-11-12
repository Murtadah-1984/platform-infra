namespace Identity.Application.DTOs;

/// <summary>
/// DTO for user login request.
/// </summary>
public record LoginDto(
    string EmailOrUsername,
    string Password
);

