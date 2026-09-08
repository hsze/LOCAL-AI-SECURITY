using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Azure.Core;

internal sealed class OutputSafetyClient(HttpClient httpClient, TokenCredential credential, Uri endpoint)
{
    private static readonly TokenRequestContext TokenContext =
        new(["https://cognitiveservices.azure.com/.default"]);

    public async Task<IReadOnlyDictionary<string, int>> AnalyzeAsync(
        string text,
        CancellationToken cancellationToken = default)
    {
        AccessToken token = await credential.GetTokenAsync(TokenContext, cancellationToken);
        using HttpRequestMessage request = new(
            HttpMethod.Post,
            new Uri(endpoint, "/contentsafety/text:analyze?api-version=2024-09-01"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        request.Content = JsonContent.Create(new { text, outputType = "EightSeverityLevels" });

        using HttpResponseMessage response = await httpClient.SendAsync(request, cancellationToken);
        string body = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        using JsonDocument document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("categoriesAnalysis").EnumerateArray()
            .ToDictionary(
                item => item.GetProperty("category").GetString()!,
                item => item.GetProperty("severity").GetInt32(),
                StringComparer.OrdinalIgnoreCase);
    }
}
