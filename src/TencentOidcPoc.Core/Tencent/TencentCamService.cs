using System.Text;
using System.Text.Json;

namespace TencentOidcPoc.Core.Tencent;

public sealed class TencentCamService
{
    private const string Host = "cam.intl.tencentcloudapi.com";
    private const string Version = "2019-01-16";
    private readonly TencentApiClient _client;
    private readonly TencentCredentials _bootstrapCredentials;

    public TencentCamService(TencentApiClient client, TencentCredentials bootstrapCredentials)
    {
        _client = client;
        _bootstrapCredentials = bootstrapCredentials;
    }

    public async Task EnsureOidcProviderAsync(
        string name,
        string identityUrl,
        string clientId,
        string jwksJson,
        CancellationToken cancellationToken = default)
    {
        var identityKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(jwksJson));
        var body = new
        {
            IdentityUrl = identityUrl,
            IdentityKey = identityKey,
            ClientId = new[] { clientId },
            Name = name,
            Description = "Self-contained custom JWT PoC; public verification key is uploaded as JWKS."
        };

        try
        {
            await CallAsync("CreateOIDCConfig", body, cancellationToken);
            Console.WriteLine($"Created Tencent CAM OIDC provider '{name}'.");
        }
        catch (TencentApiException ex) when (IsAlreadyExists(ex))
        {
            await CallAsync("UpdateOIDCConfig", body, cancellationToken);
            Console.WriteLine($"Updated existing Tencent CAM OIDC provider '{name}'.");
        }
    }

    public async Task EnsureOidcRoleAsync(
        string accountId,
        string providerName,
        string roleName,
        string issuer,
        string audience,
        string subject,
        CancellationToken cancellationToken = default)
    {
        var policyDocument = BuildOidcTrustPolicy(accountId, providerName, issuer, audience, subject);

        try
        {
            await CallAsync("GetRole", new { RoleName = roleName }, cancellationToken);
            await CallAsync("UpdateAssumeRolePolicy", new
            {
                RoleName = roleName,
                PolicyDocument = policyDocument
            }, cancellationToken);
            Console.WriteLine($"Updated trust policy for existing role '{roleName}'.");
        }
        catch (TencentApiException ex) when (IsNotFound(ex))
        {
            await CallAsync("CreateRole", new
            {
                RoleName = roleName,
                PolicyDocument = policyDocument,
                Description = "Role used by the custom JWT / static JWKS PoC.",
                ConsoleLogin = 0,
                SessionDuration = 43200
            }, cancellationToken);
            Console.WriteLine($"Created Tencent CAM role '{roleName}'.");
        }
    }

    public static string BuildOidcTrustPolicy(
        string accountId,
        string providerName,
        string issuer,
        string audience,
        string subject)
    {
        var document = new
        {
            version = "2.0",
            statement = new[]
            {
                new
                {
                    effect = "allow",
                    principal = new
                    {
                        federated = new[] { $"qcs::cam::uin/{accountId}:oidcProvider/{providerName}" }
                    },
                    action = new[] { "sts:AssumeRoleWithWebIdentity" },
                    condition = new
                    {
                        string_equal = new Dictionary<string, object>
                        {
                            ["oidc:iss"] = new[] { issuer },
                            ["oidc:aud"] = new[] { audience },
                            ["oidc:sub"] = new[] { subject }
                        }
                    }
                }
            }
        };

        return JsonSerializer.Serialize(document);
    }

    private Task<JsonElement> CallAsync(string action, object body, CancellationToken cancellationToken) =>
        _client.SendSignedAsync(
            Host,
            "cam",
            action,
            Version,
            null,
            body,
            _bootstrapCredentials,
            cancellationToken);

    private static bool IsAlreadyExists(TencentApiException ex) =>
        ex.Code.Contains("InUse", StringComparison.OrdinalIgnoreCase) ||
        ex.Code.Contains("Exist", StringComparison.OrdinalIgnoreCase) ||
        ex.Message.Contains("already", StringComparison.OrdinalIgnoreCase);

    private static bool IsNotFound(TencentApiException ex) =>
        ex.Code.Contains("NotExist", StringComparison.OrdinalIgnoreCase) ||
        ex.Code.Contains("NotFound", StringComparison.OrdinalIgnoreCase) ||
        ex.Message.Contains("not exist", StringComparison.OrdinalIgnoreCase);
}
