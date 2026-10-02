FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY Directory.Build.props ./
COPY src/TencentOidcPoc.Core/TencentOidcPoc.Core.csproj src/TencentOidcPoc.Core/
COPY src/TencentOidcPoc.Configurator/TencentOidcPoc.Configurator.csproj src/TencentOidcPoc.Configurator/
COPY src/TencentOidcPoc.LoginDemo/TencentOidcPoc.LoginDemo.csproj src/TencentOidcPoc.LoginDemo/
COPY tests/TencentOidcPoc.Tests/TencentOidcPoc.Tests.csproj tests/TencentOidcPoc.Tests/

RUN dotnet restore src/TencentOidcPoc.Configurator/TencentOidcPoc.Configurator.csproj \
 && dotnet restore src/TencentOidcPoc.LoginDemo/TencentOidcPoc.LoginDemo.csproj \
 && dotnet restore tests/TencentOidcPoc.Tests/TencentOidcPoc.Tests.csproj

COPY src ./src
COPY tests ./tests

RUN dotnet build src/TencentOidcPoc.Configurator/TencentOidcPoc.Configurator.csproj -c Release --no-restore \
 && dotnet build src/TencentOidcPoc.LoginDemo/TencentOidcPoc.LoginDemo.csproj -c Release --no-restore \
 && dotnet build tests/TencentOidcPoc.Tests/TencentOidcPoc.Tests.csproj -c Release --no-restore \
 && dotnet run --project tests/TencentOidcPoc.Tests/TencentOidcPoc.Tests.csproj -c Release --no-build

RUN dotnet publish src/TencentOidcPoc.Configurator/TencentOidcPoc.Configurator.csproj -c Release --no-build -o /out/configurator \
 && dotnet publish src/TencentOidcPoc.LoginDemo/TencentOidcPoc.LoginDemo.csproj -c Release --no-build -o /out/login-demo

FROM mcr.microsoft.com/dotnet/runtime:8.0 AS runtime
WORKDIR /app
RUN useradd --create-home --uid 10001 appuser \
 && mkdir -p /state \
 && chown appuser:appuser /state
COPY --from=build /out/configurator /app/configurator
COPY --from=build /out/login-demo /app/login-demo
USER appuser
ENTRYPOINT ["dotnet"]
