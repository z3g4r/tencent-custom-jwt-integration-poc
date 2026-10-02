using System.Security.Cryptography;
using System.Text.Json;

namespace TencentOidcPoc.Core.Crypto;

public sealed record KeyMaterial(string PrivateKeyPem, string KeyId, string JwksJson);

public sealed class KeyMaterialService
{
    public KeyMaterial EnsureKeyMaterial(string privateKeyPath, string jwksPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(privateKeyPath)!);

        using var rsa = RSA.Create();
        string privatePem;

        if (File.Exists(privateKeyPath))
        {
            privatePem = File.ReadAllText(privateKeyPath);
            rsa.ImportFromPem(privatePem);
        }
        else
        {
            rsa.KeySize = 2048;
            privatePem = rsa.ExportRSAPrivateKeyPem();
            File.WriteAllText(privateKeyPath, privatePem);
            TryRestrictPrivateKeyPermissions(privateKeyPath);
        }

        var keyId = ComputeKeyId(rsa);
        var jwks = BuildJwks(rsa, keyId);
        File.WriteAllText(jwksPath, jwks);
        return new KeyMaterial(privatePem, keyId, jwks);
    }

    public KeyMaterial Load(string privateKeyPath, string jwksPath)
    {
        if (!File.Exists(privateKeyPath))
            throw new FileNotFoundException("Private key not found. Run the configurator first.", privateKeyPath);

        using var rsa = RSA.Create();
        var privatePem = File.ReadAllText(privateKeyPath);
        rsa.ImportFromPem(privatePem);
        var keyId = ComputeKeyId(rsa);
        var jwks = File.Exists(jwksPath) ? File.ReadAllText(jwksPath) : BuildJwks(rsa, keyId);
        return new KeyMaterial(privatePem, keyId, jwks);
    }

    private static string ComputeKeyId(RSA rsa)
    {
        var spki = rsa.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(spki);
        return Base64Url.Encode(hash[..16]);
    }

    private static string BuildJwks(RSA rsa, string keyId)
    {
        var p = rsa.ExportParameters(false);
        var doc = new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    kid = keyId,
                    alg = "RS256",
                    n = Base64Url.Encode(p.Modulus!),
                    e = Base64Url.Encode(p.Exponent!)
                }
            }
        };

        return JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
    }

    private static void TryRestrictPrivateKeyPermissions(string path)
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}
