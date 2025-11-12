using Identity.Application.DTOs;
using MediatR;

namespace Identity.Application.Commands;

/// <summary>
/// Command for user login following CQRS pattern.
/// </summary>
public record LoginCommand(LoginDto Dto) : IRequest<AuthResponseDto>;

