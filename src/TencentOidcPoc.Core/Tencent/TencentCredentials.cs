namespace TencentOidcPoc.Core.Tencent;

public sealed record TencentCredentials(string SecretId, string SecretKey, string? Token = null);
