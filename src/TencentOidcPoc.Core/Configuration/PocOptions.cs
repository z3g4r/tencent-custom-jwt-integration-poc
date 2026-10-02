namespace TencentOidcPoc.Core.Configuration;

public sealed record PocOptions(
    string TencentSecretId,
    string TencentSecretKey,
    string Region,
    string OidcProviderName,
    string Issuer,
    string Audience,
    string Subject,
    string RoleName,
    string StateDirectory,
    int JwtLifetimeSeconds,
    int SessionDurationSeconds)
{
    public string PrivateKeyPath => Path.Combine(StateDirectory, "private-key.pem");
    public string JwksPath => Path.Combine(StateDirectory, "jwks.json");
    public string MetadataPath => Path.Combine(StateDirectory, "poc-metadata.json");

    public static PocOptions FromEnvironment(bool requireTencentBootstrapCredentials)
    {
        var secretId = Environment.GetEnvironmentVariable("TENCENT_SECRET_ID") ?? string.Empty;
        var secretKey = Environment.GetEnvironmentVariable("TENCENT_SECRET_KEY") ?? string.Empty;

        if (requireTencentBootstrapCredentials && (string.IsNullOrWhiteSpace(secretId) || string.IsNullOrWhiteSpace(secretKey)))
        {
            throw new InvalidOperationException("TENCENT_SECRET_ID and TENCENT_SECRET_KEY are required for the configurator.");
        }

        return new PocOptions(
            secretId,
            secretKey,
            Get("TENCENT_REGION", "ap-singapore"),
            Get("OIDC_PROVIDER_NAME", "custom-jwt-poc"),
            Get("OIDC_ISSUER", "https://example.com/tencent-oidc-poc"),
            Get("OIDC_AUDIENCE", "tencent-custom-jwt-poc"),
            Get("OIDC_SUBJECT", "poc-workload"),
            Get("TENCENT_ROLE_NAME", "CustomJwtPocRole"),
            Get("STATE_DIRECTORY", "/state"),
            GetInt("JWT_LIFETIME_SECONDS", 300, 60, 3600),
            GetInt("TENCENT_SESSION_DURATION_SECONDS", 1800, 900, 43200));
    }

    private static string Get(string name, string defaultValue) =>
        string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name))
            ? defaultValue
            : Environment.GetEnvironmentVariable(name)!;

    private static int GetInt(string name, int defaultValue, int min, int max)
    {
        var raw = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(raw)) return defaultValue;
        if (!int.TryParse(raw, out var value) || value < min || value > max)
            throw new InvalidOperationException($"{name} must be an integer in range {min}..{max}.");
        return value;
    }
}
