using TencentOidcPoc.Core.Configuration;
using TencentOidcPoc.Core.Crypto;
using TencentOidcPoc.Core.Tencent;

try
{
    var options = PocOptions.FromEnvironment(requireTencentBootstrapCredentials: false);
    var metadata = PocMetadata.Load(options.MetadataPath);
    var keyMaterial = new KeyMaterialService().Load(options.PrivateKeyPath, options.JwksPath);

    if (!string.Equals(metadata.KeyId, keyMaterial.KeyId, StringComparison.Ordinal))
        throw new InvalidOperationException("The private key does not match the key configured by the configurator.");

    var jwt = new JwtIssuer().IssueRs256(
        keyMaterial.PrivateKeyPem,
        keyMaterial.KeyId,
        metadata.Issuer,
        metadata.Audience,
        metadata.Subject,
        TimeSpan.FromSeconds(options.JwtLifetimeSeconds));

    Console.WriteLine($"Minted RS256 JWT locally (kid={keyMaterial.KeyId}, lifetime={options.JwtLifetimeSeconds}s). No Tencent SecretId/SecretKey is used for federation.");

    using var api = new TencentApiClient();
    var sts = new TencentStsService(api);
    var sessionName = $"custom-jwt-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}";

    var assumed = await sts.AssumeRoleWithWebIdentityAsync(
        metadata.OidcProviderName,
        jwt,
        metadata.RoleArn,
        sessionName,
        options.SessionDurationSeconds,
        options.Region);

    Console.WriteLine($"AssumeRoleWithWebIdentity succeeded. Temporary SecretId={Redact(assumed.TmpSecretId)}, expires={assumed.Expiration}");

    var temporaryCredentials = new TencentCredentials(
        assumed.TmpSecretId,
        assumed.TmpSecretKey,
        assumed.Token);

    var caller = await sts.GetCallerIdentityAsync(temporaryCredentials, options.Region);
    Console.WriteLine("GetCallerIdentity using only the temporary credentials succeeded:");
    Console.WriteLine($"  Type        : {caller.Type}");
    Console.WriteLine($"  AccountId   : {caller.AccountId}");
    Console.WriteLine($"  UserId      : {caller.UserId}");
    Console.WriteLine($"  PrincipalId : {caller.PrincipalId}");
    Console.WriteLine($"  ARN         : {caller.Arn}");
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    Environment.ExitCode = 1;
}

static string Redact(string value) => value.Length <= 8 ? "***" : $"{value[..4]}...{value[^4..]}";
