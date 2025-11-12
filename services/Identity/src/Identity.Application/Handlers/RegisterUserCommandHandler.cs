using Identity.Application.Commands;
using Identity.Application.DTOs;
using Identity.Domain.Entities;
using Identity.Domain.Interfaces;
using MediatR;
using Microsoft.Extensions.Logging;

namespace Identity.Application.Handlers;

/// <summary>
/// Handler for user registration following CQRS and Single Responsibility Principle.
/// </summary>
public class RegisterUserCommandHandler : IRequestHandler<RegisterUserCommand, AuthResponseDto>
{
    private readonly IUserRepository _userRepository;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly ILogger<RegisterUserCommandHandler> _logger;

    public RegisterUserCommandHandler(
        IUserRepository userRepository,
        IPasswordHasher passwordHasher,
        IJwtTokenService jwtTokenService,
        ILogger<RegisterUserCommandHandler> logger)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
        _jwtTokenService = jwtTokenService;
        _logger = logger;
    }

    public async Task<AuthResponseDto> Handle(RegisterUserCommand request, CancellationToken cancellationToken)
    {
        var dto = request.Dto;

        // Check if user already exists
        if (await _userRepository.ExistsByEmailAsync(dto.Email, cancellationToken))
        {
            throw new InvalidOperationException("User with this email already exists.");
        }

        if (await _userRepository.ExistsByUsernameAsync(dto.Username, cancellationToken))
        {
            throw new InvalidOperationException("User with this username already exists.");
        }

        // Create new user
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = dto.Email,
            Username = dto.Username,
            PasswordHash = _passwordHasher.HashPassword(dto.Password),
            FirstName = dto.FirstName,
            LastName = dto.LastName,
            IsEmailVerified = false,
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        var createdUser = await _userRepository.CreateAsync(user, cancellationToken);

        _logger.LogInformation("User registered successfully. UserId: {UserId}, Email: {Email}", 
            createdUser.Id, createdUser.Email);

        // Generate tokens
        var accessToken = _jwtTokenService.GenerateAccessToken(createdUser, Enumerable.Empty<string>(), Enumerable.Empty<string>());
        var refreshToken = _jwtTokenService.GenerateRefreshToken();

        return new AuthResponseDto(
            AccessToken: accessToken,
            RefreshToken: refreshToken,
            ExpiresAt: DateTime.UtcNow.AddHours(1)
        );
    }
}

