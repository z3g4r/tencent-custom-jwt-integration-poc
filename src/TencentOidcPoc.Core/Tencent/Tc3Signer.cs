using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace TencentOidcPoc.Core.Tencent;

public sealed class Tc3Signer
{
    public string BuildAuthorization(
        TencentCredentials credentials,
        string service,
        string host,
        string payload,
        long timestamp)
    {
        const string algorithm = "TC3-HMAC-SHA256";
        const string contentType = "application/json; charset=utf-8";
        const string signedHeaders = "content-type;host";

        var canonicalHeaders = $"content-type:{contentType}\nhost:{host}\n";
        var hashedPayload = Sha256Hex(payload);
        var canonicalRequest = $"POST\n/\n\n{canonicalHeaders}\n{signedHeaders}\n{hashedPayload}";
        var hashedCanonicalRequest = Sha256Hex(canonicalRequest);

        var utc = DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime;
        var date = utc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var credentialScope = $"{date}/{service}/tc3_request";
        var stringToSign = $"{algorithm}\n{timestamp}\n{credentialScope}\n{hashedCanonicalRequest}";

        var secretDate = HmacSha256(Encoding.UTF8.GetBytes("TC3" + credentials.SecretKey), date);
        var secretService = HmacSha256(secretDate, service);
        var secretSigning = HmacSha256(secretService, "tc3_request");
        var signature = Convert.ToHexString(HmacSha256(secretSigning, stringToSign)).ToLowerInvariant();

        return $"{algorithm} Credential={credentials.SecretId}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}";
    }

    private static string Sha256Hex(string input) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();

    private static byte[] HmacSha256(byte[] key, string data)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
    }
}
