using TencentOidcPoc.Core.Configuration;
using TencentOidcPoc.Core.Crypto;
using TencentOidcPoc.Core.Tencent;

try
{
    var options = PocOptions.FromEnvironment(requireTencentBootstrapCredentials: true);
    var keyService = new KeyMaterialService();
    var keyMaterial = keyService.EnsureKeyMaterial(options.PrivateKeyPath, options.JwksPath);

    Console.WriteLine($"RSA key ready. kid={keyMaterial.KeyId}");
    Console.WriteLine($"JWKS written to {options.JwksPath}");

    using var api = new TencentApiClient();
    var bootstrapCredentials = new TencentCredentials(options.TencentSecretId, options.TencentSecretKey);
    var sts = new TencentStsService(api);
    var identity = await sts.GetCallerIdentityAsync(bootstrapCredentials, options.Region);

    Console.WriteLine($"Bootstrap identity: {identity.Type}; root account UIN={identity.AccountId}");

    var cam = new TencentCamService(api, bootstrapCredentials);
    await cam.EnsureOidcProviderAsync(
        options.OidcProviderName,
        options.Issuer,
        options.Audience,
        keyMaterial.JwksJson);

    await cam.EnsureOidcRoleAsync(
        identity.AccountId,
        options.OidcProviderName,
        options.RoleName,
        options.Issuer,
        options.Audience,
        options.Subject);

    var roleArn = $"qcs::cam::uin/{identity.AccountId}:roleName/{options.RoleName}";
    var metadata = new PocMetadata(
        identity.AccountId,
        options.OidcProviderName,
        options.Issuer,
        options.Audience,
        options.Subject,
        options.RoleName,
        roleArn,
        keyMaterial.KeyId);
    metadata.Save(options.MetadataPath);

    Console.WriteLine("Configuration complete.");
    Console.WriteLine($"Provider : {options.OidcProviderName}");
    Console.WriteLine($"Issuer   : {options.Issuer}");
    Console.WriteLine($"Audience : {options.Audience}");
    Console.WriteLine($"Subject  : {options.Subject}");
    Console.WriteLine($"Role ARN : {roleArn}");
    Console.WriteLine("Bootstrap Tencent credentials were used only by this configurator process and are not written to /state.");
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    Environment.ExitCode = 1;
}
