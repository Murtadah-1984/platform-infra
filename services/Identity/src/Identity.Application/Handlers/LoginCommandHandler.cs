using Identity.Application.Commands;
using Identity.Application.DTOs;
using Identity.Domain.Interfaces;
using MediatR;
using Microsoft.Extensions.Logging;

namespace Identity.Application.Handlers;

/// <summary>
/// Handler for user login following CQRS and Single Responsibility Principle.
/// </summary>
public class LoginCommandHandler : IRequestHandler<LoginCommand, AuthResponseDto>
{
    private readonly IUserRepository _userRepository;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly ILogger<LoginCommandHandler> _logger;

    public LoginCommandHandler(
        IUserRepository userRepository,
        IPasswordHasher passwordHasher,
        IJwtTokenService jwtTokenService,
        ILogger<LoginCommandHandler> logger)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
        _jwtTokenService = jwtTokenService;
        _logger = logger;
    }

    public async Task<AuthResponseDto> Handle(LoginCommand request, CancellationToken cancellationToken)
    {
        var dto = request.Dto;

        // Find user by email or username
        var user = await _userRepository.GetByEmailAsync(dto.EmailOrUsername, cancellationToken)
            ?? await _userRepository.GetByUsernameAsync(dto.EmailOrUsername, cancellationToken);

        if (user == null)
        {
            throw new UnauthorizedAccessException("Invalid credentials.");
        }

        if (!user.IsActive)
        {
            throw new UnauthorizedAccessException("User account is inactive.");
        }

        // Verify password
        if (!_passwordHasher.VerifyPassword(dto.Password, user.PasswordHash))
        {
            throw new UnauthorizedAccessException("Invalid credentials.");
        }

        // Update last login
        user.LastLoginAt = DateTime.UtcNow;
        await _userRepository.UpdateAsync(user, cancellationToken);

        _logger.LogInformation("User logged in successfully. UserId: {UserId}, Email: {Email}", 
            user.Id, user.Email);

        // Generate tokens
        var roles = user.UserRoles?.Select(ur => ur.Role.Name).ToList() ?? new List<string>();
        var permissions = user.UserRoles?
            .SelectMany(ur => ur.Role.RolePermissions)
            .Select(rp => rp.Permission.Name)
            .Distinct()
            .ToList() ?? new List<string>();

        var accessToken = _jwtTokenService.GenerateAccessToken(user, roles, permissions);
        var refreshToken = _jwtTokenService.GenerateRefreshToken();

        return new AuthResponseDto(
            AccessToken: accessToken,
            RefreshToken: refreshToken,
            ExpiresAt: DateTime.UtcNow.AddHours(1)
        );
    }
}

