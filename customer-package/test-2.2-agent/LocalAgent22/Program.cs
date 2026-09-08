using Azure.Core;
using Azure.Identity;
using Microsoft.Agents.A365.Observability.Runtime.Common;
using Microsoft.Agents.A365.Observability.Runtime.Tracing.Contracts;
using Microsoft.Agents.A365.Observability.Runtime.Tracing.Scopes;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Microsoft.OpenTelemetry;
using OllamaSharp;
using OpenTelemetry;
using System.Text.Json;
using Agent365Request = Microsoft.Agents.A365.Observability.Runtime.Tracing.Contracts.Request;

const string TelemetrySource = "LocalAgent22";
const string Agent365Scope = "api://9b975845-388f-4429-889e-eab1ef63949c/.default";

string RequiredEnvironmentVariable(string name) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? value
        : throw new InvalidOperationException($"{name} is required.");

string? tenantId = Environment.GetEnvironmentVariable("AGENT365_TENANT_ID");
string? blueprintAppId = Environment.GetEnvironmentVariable("AGENT365_BLUEPRINT_APP_ID");
string? agentAppId = Environment.GetEnvironmentVariable("AGENT365_AGENT_APP_ID");
string? callerUserId = Environment.GetEnvironmentVariable("AGENT365_CALLER_USER_ID");
string? callerUserEmail = Environment.GetEnvironmentVariable("AGENT365_CALLER_USER_EMAIL");
bool agent365Enabled = new[] { tenantId, blueprintAppId, agentAppId }
    .All(value => !string.IsNullOrWhiteSpace(value));

if (agent365Enabled && !Guid.TryParse(callerUserId, out _))
{
    throw new InvalidOperationException(
        "AGENT365_CALLER_USER_ID must be the human caller's Entra object ID.");
}

DefaultAzureCredential credential = new();
AgentIdentityTokenService? tokenService = agent365Enabled
    ? new(credential, tenantId!, blueprintAppId!, agentAppId!, Agent365Scope)
    : null;

using var telemetrySdk = OpenTelemetrySdk.Create(builder =>
{
    builder.UseMicrosoftOpenTelemetry(options =>
    {
        options.Exporters = agent365Enabled
            ? ExportTarget.Console | ExportTarget.Agent365
            : ExportTarget.Console;
        options.Agent365.UseS2SEndpoint = true;
        options.Agent365.TokenResolver = agent365Enabled
            ? (requestedAgentId, requestedTenantId) =>
                tokenService!.GetTokenAsync(requestedAgentId, requestedTenantId)
            : null;
        options.Instrumentation.EnableAspNetCoreInstrumentation = false;
        options.Instrumentation.EnableSqlClientInstrumentation = false;
    });
});

Uri ollamaEndpoint = new(
    Environment.GetEnvironmentVariable("OLLAMA_ENDPOINT") ?? "http://127.0.0.1:11434");
string model = Environment.GetEnvironmentVariable("OLLAMA_MODEL") ?? "tinyllama:latest";
string safetyEndpoint = RequiredEnvironmentVariable("CONTENT_SAFETY_ENDPOINT");
string safetyMode = Environment.GetEnvironmentVariable("SAFETY_MODE") ?? "Block";
string logPath = Environment.GetEnvironmentVariable("SECURITY_LOG_PATH")
    ?? Path.Combine(AppContext.BaseDirectory, "logs", "agent-security-events.jsonl");
string prompt = args.Length > 0
    ? string.Join(' ', args)
    : "Reply with exactly: TEST 2.2 AGENT READY";
string correlationId = Guid.NewGuid().ToString();
string sessionId = Guid.NewGuid().ToString();

using HttpClient safetyClient = new() { Timeout = TimeSpan.FromSeconds(30) };
PromptShieldClient promptShield = new(safetyClient, credential, new Uri(safetyEndpoint));
OutputSafetyClient outputSafety = new(safetyClient, credential, new Uri(safetyEndpoint));

bool attackDetected;
try
{
    attackDetected = await promptShield.IsAttackAsync(prompt);
}
catch (Exception exception)
{
    await SecurityEventWriter.WriteAsync(logPath, new
    {
        TimestampUtc = DateTimeOffset.UtcNow,
        Test = "2.2",
        CorrelationId = correlationId,
        Model = model,
        Control = "PromptShields",
        DetectionType = "ControlFailure",
        SecurityDecision = "Block",
        ErrorType = exception.GetType().Name,
    });
    Console.Error.WriteLine(
        $"CorrelationId={correlationId} SecurityDecision=Block Reason=PromptShieldsUnavailable");
    return;
}

await SecurityEventWriter.WriteAsync(logPath, new
{
    TimestampUtc = DateTimeOffset.UtcNow,
    Test = "2.2",
    CorrelationId = correlationId,
    Model = model,
    Control = "PromptShields",
    DetectionType = attackDetected ? "DirectPromptInjection" : "None",
    SecurityDecision = attackDetected && safetyMode.Equals("Block", StringComparison.OrdinalIgnoreCase)
        ? "Block"
        : "Allow",
});

if (attackDetected && safetyMode.Equals("Block", StringComparison.OrdinalIgnoreCase))
{
    Console.WriteLine($"CorrelationId={correlationId} SecurityDecision=Block");
    return;
}

IChatClient ollamaClient = new OllamaApiClient(ollamaEndpoint, model);
IChatClient chatClient = ChatClientBuilderChatClientExtensions
    .AsBuilder(ollamaClient)
    .UseOpenTelemetry(
        sourceName: TelemetrySource,
        configure: options => options.EnableSensitiveData = false)
    .Build();

string telemetryTenantId = tenantId ?? "local";
string telemetryAgentId = agentAppId ?? "local-agent";
string telemetryBlueprintId = blueprintAppId ?? "local-blueprint";
using var baggage = new BaggageBuilder()
    .TenantId(telemetryTenantId)
    .AgentId(telemetryAgentId)
    .AgentName(TelemetrySource)
    .AgentDescription("Local model security validation")
    .AgentBlueprintId(telemetryBlueprintId)
    .UserId(callerUserId)
    .UserEmail(callerUserEmail)
    .AgentVersion("2.2")
    .SessionId(sessionId)
    .ConversationId(correlationId)
    .ChannelName("console")
    .OperationSource("customer-security-test")
    .Build();

AgentDetails agentDetails = new(
    agentId: telemetryAgentId,
    agentName: TelemetrySource,
    agentDescription: "Local model security validation",
    agenticUserId: null,
    agenticUserEmail: null,
    agentBlueprintId: telemetryBlueprintId,
    tenantId: telemetryTenantId,
    providerName: "Ollama",
    agentVersion: "2.2");
Agent365Request request = new(
    string.Empty,
    sessionId,
    new Channel("console", null),
    correlationId,
    "customer-security-test");
using var invokeScope = InvokeAgentScope.Start(
    request,
    new InvokeAgentScopeDetails(ollamaEndpoint),
    agentDetails);

string? factName = GetRequestedFactName(prompt);
string? toolResult = factName is null ? null : LookupFact(factName);
if (toolResult is not null)
{
    using var toolScope = ExecuteToolScope.Start(
        request,
        new ToolCallDetails(
            "lookup_fact",
            string.Empty,
            correlationId,
            "Read a predefined demonstration fact",
            "function",
            null),
        agentDetails);
}

await SecurityEventWriter.WriteAsync(logPath, new
{
    TimestampUtc = DateTimeOffset.UtcNow,
    Test = "2.2",
    CorrelationId = correlationId,
    Model = model,
    Control = "ToolInvocation",
    ToolMode = "ApplicationControlled",
    ToolName = factName is null ? null : "lookup_fact",
    ToolInvoked = factName is not null,
});

string agentPrompt = toolResult is null
    ? prompt
    : $"{prompt}\n\nUse exactly this trusted lookup_fact result: {toolResult}\n" +
      "Do not invent commands, statuses, or additional facts.";
ChatClientAgent agent = new(
    chatClient,
    new ChatClientAgentOptions
    {
        Name = TelemetrySource,
        ChatOptions = new ChatOptions
        {
            Instructions = "Answer concisely and use any trusted lookup result supplied in the prompt.",
        },
    });

using var inferenceScope = InferenceScope.Start(
    request,
    new InferenceCallDetails(InferenceOperationType.Chat, model, "Ollama"),
    agentDetails);
string responseText = (await agent.RunAsync(agentPrompt)).ToString();

IReadOnlyDictionary<string, int> severities;
try
{
    severities = await outputSafety.AnalyzeAsync(responseText);
}
catch (Exception exception)
{
    await SecurityEventWriter.WriteAsync(logPath, new
    {
        TimestampUtc = DateTimeOffset.UtcNow,
        Test = "2.2",
        CorrelationId = correlationId,
        Model = model,
        Control = "OutputSafety",
        DetectionType = "ControlFailure",
        SecurityDecision = "Block",
        ErrorType = exception.GetType().Name,
    });
    Console.Error.WriteLine(
        $"CorrelationId={correlationId} SecurityDecision=Block Reason=OutputSafetyUnavailable");
    return;
}

int maxSeverity = severities.Count == 0 ? 0 : severities.Values.Max();
bool harmful = maxSeverity >= 1;
await SecurityEventWriter.WriteAsync(logPath, new
{
    TimestampUtc = DateTimeOffset.UtcNow,
    Test = "2.2",
    CorrelationId = correlationId,
    Model = model,
    Control = "OutputSafety",
    DetectionType = harmful ? "HarmfulModelOutput" : "None",
    SecurityDecision = harmful && safetyMode.Equals("Block", StringComparison.OrdinalIgnoreCase)
        ? "Block"
        : "Allow",
    OutputMaxSeverity = maxSeverity,
    CategorySeverities = severities,
});

if (harmful && safetyMode.Equals("Block", StringComparison.OrdinalIgnoreCase))
{
    Console.WriteLine(
        $"CorrelationId={correlationId} SecurityDecision=Block " +
        $"DetectionType=HarmfulModelOutput OutputMaxSeverity={maxSeverity}");
    return;
}

using var outputScope = OutputScope.Start(
    request: request,
    response: new Response(Array.Empty<string>()),
    agentDetails: agentDetails,
    spanDetails: new SpanDetails(parentContext: invokeScope.GetActivityContext()));

if (toolResult is null)
{
    Console.WriteLine(responseText);
    return;
}

bool grounded = responseText.Contains(toolResult, StringComparison.OrdinalIgnoreCase);
await SecurityEventWriter.WriteAsync(logPath, new
{
    TimestampUtc = DateTimeOffset.UtcNow,
    Test = "2.2",
    CorrelationId = correlationId,
    Model = model,
    Control = "ToolGrounding",
    SecurityDecision = grounded ? "Allow" : "Fallback",
    Grounded = grounded,
});
Console.WriteLine($"GroundingDecision={(grounded ? "Allow" : "Fallback")}");
Console.WriteLine(grounded ? responseText : toolResult);

static string? GetRequestedFactName(string prompt)
{
    if (!prompt.Contains("lookup_fact", StringComparison.OrdinalIgnoreCase))
    {
        return null;
    }

    return new[] { "status", "project", "owner" }
        .FirstOrDefault(name => prompt.Contains(name, StringComparison.OrdinalIgnoreCase));
}

static string LookupFact(string name) => name.ToLowerInvariant() switch
{
    "project" => "Test 2.2 demonstrates an isolated local agent.",
    "owner" => "The demonstration owner is the local test operator.",
    "status" => "The read-only lookup tool is available.",
    _ => "No matching fact was found.",
};

sealed class AgentIdentityTokenService(
    TokenCredential credential,
    string configuredTenantId,
    string configuredBlueprintAppId,
    string configuredAgentAppId,
    string resourceScope)
{
    private const string AssertionType =
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private readonly HttpClient httpClient = new() { Timeout = TimeSpan.FromSeconds(30) };

    public async Task<string?> GetTokenAsync(string requestedAgentId, string requestedTenantId)
    {
        if (!requestedTenantId.Equals(configuredTenantId, StringComparison.OrdinalIgnoreCase)
            || !requestedAgentId.Equals(configuredAgentAppId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Agent 365 requested an unexpected identity.");
        }

        AccessToken managedIdentityToken = await credential.GetTokenAsync(
            new TokenRequestContext(["api://AzureADTokenExchange/.default"]),
            CancellationToken.None);
        string parentToken = await RequestTokenAsync(configuredTenantId, new()
        {
            ["client_id"] = configuredBlueprintAppId,
            ["scope"] = "api://AzureADTokenExchange/.default",
            ["grant_type"] = "client_credentials",
            ["client_assertion_type"] = AssertionType,
            ["client_assertion"] = managedIdentityToken.Token,
            ["fmi_path"] = configuredAgentAppId,
        });
        return await RequestTokenAsync(configuredTenantId, new()
        {
            ["client_id"] = configuredAgentAppId,
            ["scope"] = resourceScope,
            ["grant_type"] = "client_credentials",
            ["client_assertion_type"] = AssertionType,
            ["client_assertion"] = parentToken,
        });
    }

    private async Task<string> RequestTokenAsync(
        string tokenTenantId,
        Dictionary<string, string> parameters)
    {
        using FormUrlEncodedContent content = new(parameters);
        using HttpResponseMessage response = await httpClient.PostAsync(
            $"https://login.microsoftonline.com/{Uri.EscapeDataString(tokenTenantId)}/oauth2/v2.0/token",
            content);
        string body = await response.Content.ReadAsStringAsync();
        response.EnsureSuccessStatusCode();
        using JsonDocument document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("access_token").GetString()
            ?? throw new InvalidOperationException("Microsoft Entra returned an empty token.");
    }
}
