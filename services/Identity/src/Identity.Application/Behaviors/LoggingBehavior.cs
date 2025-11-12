using MediatR;
using Microsoft.Extensions.Logging;

namespace Identity.Application.Behaviors;

/// <summary>
/// Logging behavior for MediatR pipeline following Open/Closed Principle.
/// </summary>
public class LoggingBehavior<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>
{
    private readonly ILogger<LoggingBehavior<TRequest, TResponse>> _logger;

    public LoggingBehavior(ILogger<LoggingBehavior<TRequest, TResponse>> logger)
    {
        _logger = logger;
    }

    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling {RequestName}", typeof(TRequest).Name);

        try
        {
            var response = await next();
            _logger.LogInformation("Handled {RequestName}", typeof(TRequest).Name);
            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling {RequestName}", typeof(TRequest).Name);
            throw;
        }
    }
}

