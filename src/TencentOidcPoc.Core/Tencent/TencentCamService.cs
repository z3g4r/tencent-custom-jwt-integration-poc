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
            Description = "Self-contained custom JWT PoC; public verification key is uploaded as JWKS.",
            AutoRotateKey = 0
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

        await WaitForOidcProviderAsync(name, identityUrl, clientId, cancellationToken);
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

        const int maxAttempts = 12;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                await CreateOrUpdateRoleAsync(roleName, policyDocument, cancellationToken);
                return;
            }
            catch (TencentApiException ex) when (IsPrincipalNotReady(ex) && attempt < maxAttempts)
            {
                Console.WriteLine(
                    $"Tencent has not resolved the new OIDC provider as a role principal yet " +
                    $"(attempt {attempt}/{maxAttempts}); retrying.");
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            }
        }
    }

    private async Task CreateOrUpdateRoleAsync(
        string roleName,
        string policyDocument,
        CancellationToken cancellationToken)
    {
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

    private async Task WaitForOidcProviderAsync(
        string name,
        string expectedIdentityUrl,
        string expectedClientId,
        CancellationToken cancellationToken)
    {
        const int maxAttempts = 12;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                var response = await CallAsync("DescribeOIDCConfig", new { Name = name }, cancellationToken);
                var providerName = response.GetProperty("Name").GetString();
                var identityUrl = response.GetProperty("IdentityUrl").GetString();
                var status = response.GetProperty("Status").GetInt32();
                var clientIds = response.GetProperty("ClientId")
                    .EnumerateArray()
                    .Select(x => x.GetString())
                    .Where(x => x is not null)
                    .Cast<string>()
                    .ToArray();

                if (providerName == name &&
                    identityUrl == expectedIdentityUrl &&
                    status == 11 &&
                    clientIds.Contains(expectedClientId, StringComparer.Ordinal))
                {
                    Console.WriteLine($"OIDC provider '{name}' is visible and enabled in CAM.");
                    return;
                }
            }
            catch (TencentApiException ex) when (IsNotFound(ex) && attempt < maxAttempts)
            {
                // The create/update operation may be visible to the write path before the read path.
            }

            if (attempt < maxAttempts)
            {
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            }
        }

        throw new InvalidOperationException(
            $"OIDC provider '{name}' was created/updated but did not become visible as an enabled CAM provider.");
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

    private static bool IsPrincipalNotReady(TencentApiException ex) =>
        ex.Code.Equals("InvalidParameter.PrincipalError", StringComparison.OrdinalIgnoreCase) ||
        (ex.Code.Contains("Principal", StringComparison.OrdinalIgnoreCase) &&
         ex.Message.Contains("principal", StringComparison.OrdinalIgnoreCase));
}
