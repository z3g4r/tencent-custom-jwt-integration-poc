using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TencentOidcPoc.Core.Crypto;
using TencentOidcPoc.Core.Tencent;

var failures = new List<string>();
Run("JWT is valid RS256 and carries expected claims", TestJwt, failures);
Run("JWKS contains matching RSA public key", TestJwks, failures);
Run("Trust policy binds provider, issuer, audience and subject", TestTrustPolicy, failures);

if (failures.Count > 0)
{
    Console.Error.WriteLine("FAILED:");
    foreach (var failure in failures) Console.Error.WriteLine($"- {failure}");
    return 1;
}

Console.WriteLine("All self-tests passed.");
return 0;

static void TestJwt()
{
    var dir = Path.Combine(Path.GetTempPath(), "tencent-oidc-poc-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    try
    {
        var keys = new KeyMaterialService().EnsureKeyMaterial(Path.Combine(dir, "key.pem"), Path.Combine(dir, "jwks.json"));
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var jwt = new JwtIssuer().IssueRs256(keys.PrivateKeyPem, keys.KeyId, "https://issuer.example", "aud", "sub", TimeSpan.FromMinutes(5), now);
        var parts = jwt.Split('.');
        Assert(parts.Length == 3, "JWT must contain three segments");

        using var payload = JsonDocument.Parse(Encoding.UTF8.GetString(Decode(parts[1])));
        Assert(payload.RootElement.GetProperty("iss").GetString() == "https://issuer.example", "iss mismatch");
        Assert(payload.RootElement.GetProperty("aud").GetString() == "aud", "aud mismatch");
        Assert(payload.RootElement.GetProperty("sub").GetString() == "sub", "sub mismatch");
        Assert(payload.RootElement.GetProperty("exp").GetInt64() == 1_700_000_300, "exp mismatch");

        using var rsa = RSA.Create();
        rsa.ImportFromPem(keys.PrivateKeyPem);
        Assert(rsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Decode(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), "JWT signature invalid");
    }
    finally { Directory.Delete(dir, true); }
}

static void TestJwks()
{
    var dir = Path.Combine(Path.GetTempPath(), "tencent-oidc-poc-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    try
    {
        var keys = new KeyMaterialService().EnsureKeyMaterial(Path.Combine(dir, "key.pem"), Path.Combine(dir, "jwks.json"));
        using var doc = JsonDocument.Parse(keys.JwksJson);
        var jwk = doc.RootElement.GetProperty("keys").EnumerateArray().First();
        Assert(jwk.GetProperty("kty").GetString() == "RSA", "kty mismatch");
        Assert(jwk.GetProperty("alg").GetString() == "RS256", "alg mismatch");
        Assert(jwk.GetProperty("kid").GetString() == keys.KeyId, "kid mismatch");

        using var rsa = RSA.Create();
        rsa.ImportFromPem(keys.PrivateKeyPem);
        var p = rsa.ExportParameters(false);
        Assert(jwk.GetProperty("n").GetString() == Base64Url.Encode(p.Modulus!), "modulus mismatch");
        Assert(jwk.GetProperty("e").GetString() == Base64Url.Encode(p.Exponent!), "exponent mismatch");
    }
    finally { Directory.Delete(dir, true); }
}

static void TestTrustPolicy()
{
    var json = TencentCamService.BuildOidcTrustPolicy("123", "provider", "https://issuer", "aud", "sub");
    Assert(json.Contains("qcs::cam::uin/123:oidc-provider/provider", StringComparison.Ordinal), "provider ARN missing");
    Assert(json.Contains("name/sts:AssumeRoleWithWebIdentity", StringComparison.Ordinal), "web identity action missing");
    Assert(json.Contains("oidc:iss", StringComparison.Ordinal), "iss condition missing");
    Assert(json.Contains("oidc:aud", StringComparison.Ordinal), "aud condition missing");
    Assert(json.Contains("oidc:sub", StringComparison.Ordinal), "sub condition missing");
}

static byte[] Decode(string input)
{
    var padded = input.Replace('-', '+').Replace('_', '/');
    padded += new string('=', (4 - padded.Length % 4) % 4);
    return Convert.FromBase64String(padded);
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static void Run(string name, Action test, ICollection<string> failures)
{
    try { test(); Console.WriteLine($"PASS: {name}"); }
    catch (Exception ex) { failures.Add($"{name}: {ex.Message}"); }
}
