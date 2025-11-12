namespace Identity.Application.DTOs;

/// <summary>
/// DTO for user registration request.
/// </summary>
public record RegisterUserDto(
    string Email,
    string Username,
    string Password,
    string? FirstName,
    string? LastName
);

