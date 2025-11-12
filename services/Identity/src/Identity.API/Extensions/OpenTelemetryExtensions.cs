using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Identity.API.Extensions;

/// <summary>
/// Extension methods for OpenTelemetry configuration.
/// </summary>
public static class OpenTelemetryExtensions
{
    public static IServiceCollection AddIdentityOpenTelemetry(
        this IServiceCollection services,
        IConfiguration configuration,
        IWebHostEnvironment environment)
    {
        var serviceName = "Identity.API";
        var serviceVersion = "1.0.0";

        services.AddOpenTelemetry()
            .ConfigureResource(resource => resource
                .AddService(serviceName: serviceName, serviceVersion: serviceVersion)
                .AddAttributes(new Dictionary<string, object>
                {
                    ["deployment.environment"] = environment.EnvironmentName
                }))
            .WithTracing(builder =>
            {
                builder
                    .AddAspNetCoreInstrumentation()
                    .AddEntityFrameworkCoreInstrumentation()
                    .AddHttpClientInstrumentation();

                // Jaeger exporter
                var jaegerHost = Environment.GetEnvironmentVariable("JAEGER_AGENT_HOST") ?? "localhost";
                var jaegerPort = int.Parse(Environment.GetEnvironmentVariable("JAEGER_AGENT_PORT") ?? "6831");
                builder.AddJaegerExporter(options =>
                {
                    options.AgentHost = jaegerHost;
                    options.AgentPort = jaegerPort;
                });

                // Zipkin exporter
                var zipkinEndpoint = Environment.GetEnvironmentVariable("ZIPKIN_ENDPOINT");
                if (!string.IsNullOrEmpty(zipkinEndpoint))
                {
                    builder.AddZipkinExporter(options =>
                    {
                        options.Endpoint = new Uri(zipkinEndpoint);
                    });
                }
            })
            .WithMetrics(builder =>
            {
                builder
                    .AddAspNetCoreInstrumentation()
                    .AddHttpClientInstrumentation()
                    .AddPrometheusExporter();
            });

        return services;
    }
}

