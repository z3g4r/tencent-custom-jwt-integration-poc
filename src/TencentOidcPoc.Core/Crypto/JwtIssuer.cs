using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TencentOidcPoc.Core.Crypto;

public sealed class JwtIssuer
{
    public string IssueRs256(
        string privateKeyPem,
        string keyId,
        string issuer,
        string audience,
        string subject,
        TimeSpan lifetime,
        DateTimeOffset? now = null)
    {
        var issuedAt = now ?? DateTimeOffset.UtcNow;
        var header = JsonSerializer.Serialize(new { alg = "RS256", typ = "JWT", kid = keyId });
        var payload = JsonSerializer.Serialize(new
        {
            iss = issuer,
            sub = subject,
            aud = audience,
            iat = issuedAt.ToUnixTimeSeconds(),
            nbf = issuedAt.AddSeconds(-5).ToUnixTimeSeconds(),
            exp = issuedAt.Add(lifetime).ToUnixTimeSeconds(),
            jti = Guid.NewGuid().ToString("N")
        });

        var encodedHeader = Base64Url.Encode(Encoding.UTF8.GetBytes(header));
        var encodedPayload = Base64Url.Encode(Encoding.UTF8.GetBytes(payload));
        var signingInput = $"{encodedHeader}.{encodedPayload}";

        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        var signature = rsa.SignData(
            Encoding.ASCII.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return $"{signingInput}.{Base64Url.Encode(signature)}";
    }
}
