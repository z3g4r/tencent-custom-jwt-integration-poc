namespace TencentOidcPoc.Core.Tencent;

public sealed class TencentApiException : Exception
{
    public string Code { get; }
    public string? RequestId { get; }

    public TencentApiException(string code, string message, string? requestId = null)
        : base($"Tencent API error {code}: {message}")
    {
        Code = code;
        RequestId = requestId;
    }
}
