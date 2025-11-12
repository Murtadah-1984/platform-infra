# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy solution and project files
COPY ["Identity.sln", "./"]
COPY ["src/Identity.API/Identity.API.csproj", "src/Identity.API/"]
COPY ["src/Identity.Application/Identity.Application.csproj", "src/Identity.Application/"]
COPY ["src/Identity.Domain/Identity.Domain.csproj", "src/Identity.Domain/"]
COPY ["src/Identity.Infrastructure/Identity.Infrastructure.csproj", "src/Identity.Infrastructure/"]

# Restore dependencies
RUN dotnet restore "src/Identity.API/Identity.API.csproj"

# Copy all source files
COPY . .

# Build and publish
WORKDIR "/src/src/Identity.API"
RUN dotnet build "Identity.API.csproj" -c Release -o /app/build
RUN dotnet publish "Identity.API.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# Install EF Core tools for migrations
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser -u 10001 appuser

# Copy published files
COPY --from=build /app/publish .

# Create directory for app data and set ownership
RUN mkdir -p /app/data && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Entry point
ENTRYPOINT ["dotnet", "Identity.API.dll"]

