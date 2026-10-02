using System.Text.Json;

namespace TencentOidcPoc.Core.Tencent;

public sealed record AssumedRoleCredentials(
    string TmpSecretId,
    string TmpSecretKey,
    string Token,
    long ExpiredTime,
    string Expiration);

public sealed class TencentStsService
{
    private const string Host = "sts.intl.tencentcloudapi.com";
    private const string Version = "2018-08-13";
    private readonly TencentApiClient _client;

    public TencentStsService(TencentApiClient client) => _client = client;

    public async Task<TencentIdentity> GetCallerIdentityAsync(
        TencentCredentials credentials,
        string region,
        CancellationToken cancellationToken = default)
    {
        var response = await _client.SendSignedAsync(
            Host,
            "sts",
            "GetCallerIdentity",
            Version,
            region,
            new { },
            credentials,
            cancellationToken);

        return ParseIdentity(response);
    }

    public async Task<AssumedRoleCredentials> AssumeRoleWithWebIdentityAsync(
        string providerId,
        string webIdentityToken,
        string roleArn,
        string roleSessionName,
        int durationSeconds,
        string region,
        CancellationToken cancellationToken = default)
    {
        var response = await _client.SendWebIdentityAsync(
            Host,
            "AssumeRoleWithWebIdentity",
            Version,
            region,
            new
            {
                ProviderId = providerId,
                WebIdentityToken = webIdentityToken,
                RoleArn = roleArn,
                RoleSessionName = roleSessionName,
                DurationSeconds = durationSeconds
            },
            cancellationToken);

        var c = response.GetProperty("Credentials");
        return new AssumedRoleCredentials(
            c.GetProperty("TmpSecretId").GetString()!,
            c.GetProperty("TmpSecretKey").GetString()!,
            c.GetProperty("Token").GetString()!,
            response.GetProperty("ExpiredTime").GetInt64(),
            response.GetProperty("Expiration").GetString()!);
    }

    private static TencentIdentity ParseIdentity(JsonElement response) => new(
        response.GetProperty("AccountId").GetString()!,
        response.GetProperty("UserId").GetString()!,
        response.GetProperty("PrincipalId").GetString()!,
        response.GetProperty("Arn").GetString()!,
        response.GetProperty("Type").GetString()!);
}
