using Identity.Application.DTOs;
using MediatR;

namespace Identity.Application.Commands;

/// <summary>
/// Command for user registration following CQRS pattern.
/// </summary>
public record RegisterUserCommand(RegisterUserDto Dto) : IRequest<AuthResponseDto>;

