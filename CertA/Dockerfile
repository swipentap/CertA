FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["CertA/CertA.csproj", "CertA/"]
RUN dotnet restore "CertA/CertA.csproj"
COPY . .
WORKDIR "/src/CertA"
RUN dotnet build "./CertA.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./CertA.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
# Self-signed cert generated in build stage (has openssl)
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates wget && rm -rf /var/lib/apt/lists/* \
    && openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /tmp/key.pem -out /tmp/cert.pem -subj "/CN=localhost" \
    && openssl pkcs12 -export -out /app/cert.pfx -inkey /tmp/key.pem -in /tmp/cert.pem -passout pass: \
    && chown ${APP_UID:-1654}:${APP_UID:-1654} /app/cert.pfx
COPY --from=publish /app/publish .
COPY --from=build /src/CertA/Scripts ./Scripts
RUN mkdir -p /app/DataProtection-Keys && chown ${APP_UID:-1654}:${APP_UID:-1654} /app/DataProtection-Keys
USER $APP_UID
ENTRYPOINT ["dotnet", "CertA.dll"]
