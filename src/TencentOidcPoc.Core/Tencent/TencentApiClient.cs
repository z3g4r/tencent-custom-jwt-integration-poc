using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace TencentOidcPoc.Core.Tencent;

public sealed class TencentApiClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly Tc3Signer _signer;
    private readonly bool _ownsClient;

    public TencentApiClient(HttpClient? httpClient = null, Tc3Signer? signer = null)
    {
        _httpClient = httpClient ?? new HttpClient();
        _signer = signer ?? new Tc3Signer();
        _ownsClient = httpClient is null;
    }

    public async Task<JsonElement> SendSignedAsync(
        string host,
        string service,
        string action,
        string version,
        string? region,
        object body,
        TencentCredentials credentials,
        CancellationToken cancellationToken = default)
    {
        var payload = JsonSerializer.Serialize(body);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var authorization = _signer.BuildAuthorization(credentials, service, host, payload, timestamp);

        using var request = BuildRequest(host, action, version, region, payload, timestamp);
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        if (!string.IsNullOrWhiteSpace(credentials.Token))
            request.Headers.TryAddWithoutValidation("X-TC-Token", credentials.Token);

        return await SendAsync(request, cancellationToken);
    }

    public async Task<JsonElement> SendWebIdentityAsync(
        string host,
        string action,
        string version,
        string region,
        object body,
        CancellationToken cancellationToken = default)
    {
        var payload = JsonSerializer.Serialize(body);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        using var request = BuildRequest(host, action, version, region, payload, timestamp);
        request.Headers.TryAddWithoutValidation("Authorization", "SKIP");
        return await SendAsync(request, cancellationToken);
    }

    private static HttpRequestMessage BuildRequest(
        string host,
        string action,
        string version,
        string? region,
        string payload,
        long timestamp)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, $"https://{host}/")
        {
            Content = new StringContent(payload, Encoding.UTF8)
        };
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json; charset=utf-8");
        request.Headers.Host = host;
        request.Headers.TryAddWithoutValidation("X-TC-Action", action);
        request.Headers.TryAddWithoutValidation("X-TC-Version", version);
        request.Headers.TryAddWithoutValidation("X-TC-Timestamp", timestamp.ToString());
        if (!string.IsNullOrWhiteSpace(region))
            request.Headers.TryAddWithoutValidation("X-TC-Region", region);
        return request;
    }

    private async Task<JsonElement> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        var json = await response.Content.ReadAsStringAsync(cancellationToken);

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement.Clone();

        if (!root.TryGetProperty("Response", out var responseElement))
            throw new InvalidOperationException($"Unexpected Tencent API response: {json}");

        if (responseElement.TryGetProperty("Error", out var error))
        {
            var code = error.GetProperty("Code").GetString() ?? "Unknown";
            var message = error.GetProperty("Message").GetString() ?? "Unknown error";
            var requestId = responseElement.TryGetProperty("RequestId", out var id) ? id.GetString() : null;
            throw new TencentApiException(code, message, requestId);
        }

        response.EnsureSuccessStatusCode();
        return responseElement.Clone();
    }

    public void Dispose()
    {
        if (_ownsClient) _httpClient.Dispose();
    }
}
