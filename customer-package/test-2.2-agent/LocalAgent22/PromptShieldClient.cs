using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Azure.Core;

internal sealed class PromptShieldClient(HttpClient httpClient, TokenCredential credential, Uri endpoint)
{
    private static readonly TokenRequestContext TokenContext =
        new(["https://cognitiveservices.azure.com/.default"]);

    public async Task<bool> IsAttackAsync(string prompt, CancellationToken cancellationToken = default)
    {
        AccessToken token = await credential.GetTokenAsync(TokenContext, cancellationToken);
        using HttpRequestMessage request = new(
            HttpMethod.Post,
            new Uri(endpoint, "/contentsafety/text:shieldPrompt?api-version=2024-09-01"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        request.Content = JsonContent.Create(new
        {
            userPrompt = prompt,
            documents = Array.Empty<string>(),
        });

        using HttpResponseMessage response = await httpClient.SendAsync(request, cancellationToken);
        string body = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        using JsonDocument document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("userPromptAnalysis")
            .GetProperty("attackDetected").GetBoolean();
    }
}
