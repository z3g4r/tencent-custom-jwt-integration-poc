using System.Text.Json;

namespace TencentOidcPoc.Core.Configuration;

public sealed record PocMetadata(
    string AccountId,
    string OidcProviderName,
    string Issuer,
    string Audience,
    string Subject,
    string RoleName,
    string RoleArn,
    string KeyId)
{
    public void Save(string path)
    {
        var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
    }

    public static PocMetadata Load(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("PoC metadata not found. Run the configurator first.", path);
        return JsonSerializer.Deserialize<PocMetadata>(File.ReadAllText(path))
               ?? throw new InvalidOperationException("PoC metadata is invalid.");
    }
}
