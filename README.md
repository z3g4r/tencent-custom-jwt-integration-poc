# Tencent Cloud custom JWT / static JWKS PoC

Self-contained **C#/.NET 8** proof of concept running only in **Linux containers**.

It demonstrates this trust chain:

```text
Configurator container (one-time bootstrap)
  Tencent SecretId/SecretKey
        |
        +--> generate local RSA-2048 key pair
        +--> convert public key to JWK/JWKS
        +--> Base64(JWKS) -> Tencent CAM Create/UpdateOIDCConfig
        +--> create/update CAM role trust policy
        +--> persist only local PoC state (private key, JWKS, metadata)

Login-demo container (no Tencent bootstrap secret)
  local RSA private key
        |
        +--> mint RS256 JWT (iss/aud/sub/kid)
        +--> STS AssumeRoleWithWebIdentity (Authorization: SKIP)
        +--> temporary SecretId/SecretKey/Token
        +--> STS GetCallerIdentity using temporary credentials
```

No JWKS endpoint is exposed. `jwks.json` is only a local representation of the public key which the configurator Base64-encodes and uploads as Tencent CAM `IdentityKey`.

## Prerequisites

- Docker Engine / Docker Desktop with Linux containers.
- A Tencent Cloud account.
- A bootstrap Tencent API key for the configurator.
- Network access from the containers to `cam.intl.tencentcloudapi.com` and `sts.intl.tencentcloudapi.com`.

The login demonstrator deliberately receives blank `TENCENT_SECRET_ID` and `TENCENT_SECRET_KEY`; it can only use the locally signed JWT to obtain temporary STS credentials.

## 1. Configure

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```dotenv
TENCENT_SECRET_ID=...
TENCENT_SECRET_KEY=...
```

For a PoC, the defaults create:

- OIDC provider: `custom-jwt-poc`
- issuer: `https://example.com/tencent-oidc-poc`
- audience: `tencent-custom-jwt-poc`
- subject: `poc-workload`
- role: `CustomJwtPocRole`

`OIDC_ISSUER` is used as an identifier and becomes the JWT `iss` claim and the `oidc:iss` role condition. Tencent documents the IdP URL as a standard HTTP(S) URL and the role requires `oidc:iss` to equal the configured IdP URL. This PoC does not publish OIDC discovery or JWKS at that URL.


## .NET project layout

The repository intentionally does not use a Visual Studio solution file. It is an SDK-style .NET repository intended for `dotnet` CLI, Docker, Linux and macOS workflows:

```text
.
├── Directory.Build.props
├── global.json
├── Dockerfile
├── docker-compose.yml
├── src/
│   ├── TencentOidcPoc.Core/
│   ├── TencentOidcPoc.Configurator/
│   └── TencentOidcPoc.LoginDemo/
└── tests/
    └── TencentOidcPoc.Tests/
```

Common compiler settings are centralized in `Directory.Build.props`. Each application is built directly from its SDK-style `.csproj`; no `.sln` is required.

For local development with the .NET SDK installed, you can build directly with:

```bash
dotnet build src/TencentOidcPoc.Configurator/TencentOidcPoc.Configurator.csproj
dotnet build src/TencentOidcPoc.LoginDemo/TencentOidcPoc.LoginDemo.csproj
dotnet run --project tests/TencentOidcPoc.Tests/TencentOidcPoc.Tests.csproj
```

The supported PoC execution path remains Docker Compose so runtime behavior is Linux-container-only.

## 2. Build

```bash
docker compose build
```

The Docker build compiles all projects and executes the built-in C# self-tests. No third-party application NuGet packages are used.

## 3. Run the configurator

```bash
docker compose run --rm configurator
```

The configurator:

1. creates `state/private-key.pem` if it does not already exist;
2. derives `state/jwks.json` from the RSA public key;
3. calls STS `GetCallerIdentity` with the bootstrap key to determine the root account UIN;
4. calls CAM `CreateOIDCConfig`, or `UpdateOIDCConfig` when the provider already exists;
5. creates or updates the role trust policy;
6. writes non-secret metadata to `state/poc-metadata.json`.

The bootstrap SecretId/SecretKey are read only from environment variables and are never written to `/state` by the application.

## 4. Run the login demonstrator

```bash
docker compose run --rm login-demo
```

The demonstrator:

1. loads the locally generated private key;
2. mints a short-lived RS256 JWT with matching `kid`, `iss`, `aud`, and `sub`;
3. calls `AssumeRoleWithWebIdentity` with `Authorization: SKIP`;
4. receives temporary Tencent credentials;
5. signs a normal TC3 request with those temporary credentials and calls `GetCallerIdentity`.

A successful final output proves that Tencent accepted the custom JWT signature against the public key/JWKS uploaded during bootstrap.

## State and key handling

`./state` is a bind mount so both containers see the same key material. The private key is created with mode `0600` on Linux/macOS-compatible filesystems where .NET can set Unix file modes.

For a production architecture, do **not** persist an issuer private key in a local bind mount. Replace `KeyMaterialService`/`JwtIssuer` with Vault Transit, Vault Identity Tokens, an HSM/KMS-backed signer, or another controlled signing service. This repository intentionally keeps signing local to make the Tencent verification behavior easy to prove.

## Least privilege for the bootstrap credential

Do not use a root-account key for normal use. Create a dedicated CAM identity with only the operations required for this PoC. The configurator calls these Tencent APIs:

- `sts:GetCallerIdentity`
- `cam:CreateOIDCConfig`
- `cam:UpdateOIDCConfig`
- `cam:GetRole`
- `cam:CreateRole`
- `cam:UpdateAssumeRolePolicy`

The exact CAM policy should be validated in your Tencent account before use because Tencent authorization resource granularity differs between operations.

## Security design notes

- The role trust policy pins **issuer**, **audience**, and **subject**.
- The JWT lifetime defaults to 5 minutes.
- The login container receives no long-lived Tencent credentials.
- The private key never leaves the local state volume; only the public JWKS is uploaded to Tencent.
- The configurator does not enable `AutoRotateKey`. Tencent documents its default as `0` in the current API, so the uploaded `IdentityKey` remains the verification material instead of enabling automatic key retrieval/rotation.
- Temporary credentials are only printed in redacted form.
- The demo action is `GetCallerIdentity`, avoiding creation of billable resources.

## Cleanup

The project intentionally does not automatically delete cloud-side trust configuration. Delete the `CustomJwtPocRole` role and `custom-jwt-poc` OIDC provider in CAM when the PoC is finished, then remove local key material:

```bash
rm -rf state/private-key.pem state/jwks.json state/poc-metadata.json
```


## Run the full PoC

The Compose file orders the services so that the configurator must complete successfully before the login demonstrator starts:

```bash
docker compose up --build
```

You can still run each phase independently:

```bash
docker compose run --rm configurator
docker compose run --rm login-demo
```

The configurator is idempotent for the PoC: it reuses the local RSA key, updates an existing OIDC provider, waits until the provider is visible and enabled in CAM, and then creates or updates the role trust policy. It also retries Tencent's specific `InvalidParameter.PrincipalError` for a newly created provider, because role-principal resolution can lag behind successful provider creation.

## Architecture

The code is split by responsibility rather than placing all logic in two large `Program.cs` files:

- `Configuration/` - environment and persisted metadata.
- `Crypto/` - RSA lifecycle, JWKS conversion, Base64URL, JWT issuance.
- `Tencent/Tc3Signer.cs` - Tencent API v3 request signing.
- `Tencent/TencentApiClient.cs` - transport/error handling.
- `Tencent/TencentCamService.cs` - OIDC provider and role orchestration.
- `Tencent/TencentStsService.cs` - identity and web-identity federation.
- `src/TencentOidcPoc.Configurator/Program.cs` - composition root for bootstrap.
- `src/TencentOidcPoc.LoginDemo/Program.cs` - composition root for the actual federation demo.

This keeps crypto, API transport, cloud orchestration and entry-point concerns separate and makes the components independently testable.

## VS Code

Open the repository root directly in VS Code:

```bash
code .
```

The repository includes `.vscode/` configuration for Linux/macOS development.

Recommended extensions are offered automatically by VS Code:

- C#
- C# Dev Kit
- Docker

Available tasks (`Terminal` -> `Run Task...`):

- `dotnet: build all` - builds both executables and the test harness.
- `dotnet: test harness` - runs the local cryptographic/configuration checks.
- `docker: build` - builds the Linux container image.
- `docker: configurator` - runs the bootstrap configurator in Docker.
- `docker: login demo` - runs the federated-login demonstrator in Docker.
- `docker: full PoC` - runs configurator and login demo sequentially.
- `docker: cleanup local state` - removes locally generated PoC key/JWKS/metadata state only; it does not delete Tencent resources.

The `Run and Debug` view also contains:

- `Debug Configurator (local .NET)`
- `Debug Login Demo (local .NET)`

Both use the repository `.env`. The login debug profile explicitly blanks `TENCENT_SECRET_ID` and `TENCENT_SECRET_KEY`, matching the Docker Compose security property: the login demonstration must succeed using only the JWT -> STS temporary-credential flow.

The debug profiles execute locally with the .NET 8 SDK. The Docker tasks continue to use Linux containers only.


## Tencent CAM OIDC trust-policy compatibility

This revision uses the trust-policy form documented by HashiCorp for Tencent Cloud dynamic OIDC credentials:

```text
principal: qcs::cam::uin/<ACCOUNT_UIN>:oidc-provider/<PROVIDER_NAME>
action:    name/sts:AssumeRoleWithWebIdentity
```

This intentionally differs from some TKE-specific Tencent examples that use `oidcProvider` and omit the `name/` action prefix. The previous PoC variant using that TKE form was rejected by CAM with `InvalidParameter.PrincipalError` on a live account, so this revision follows the Tencent pattern used by HashiCorp's tested federation guidance.
