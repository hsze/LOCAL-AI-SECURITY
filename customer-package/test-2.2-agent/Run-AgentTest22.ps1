[CmdletBinding()]
param(
    [string]$Prompt = 'Reply with exactly: TEST 2.2 AGENT READY',
    [ValidateSet('Audit', 'Block')]
    [string]$SafetyMode = 'Block',
    [string]$ContentSafetyEndpoint = $env:CONTENT_SAFETY_ENDPOINT,
    [string]$OllamaEndpoint = 'http://127.0.0.1:11434',
    [string]$Model = 'tinyllama:latest'
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ContentSafetyEndpoint)) {
    throw 'Set CONTENT_SAFETY_ENDPOINT or pass -ContentSafetyEndpoint.'
}

$project = Join-Path $PSScriptRoot 'LocalAgent22\LocalAgent22.csproj'
$env:CONTENT_SAFETY_ENDPOINT = $ContentSafetyEndpoint
$env:OLLAMA_ENDPOINT = $OllamaEndpoint
$env:OLLAMA_MODEL = $Model
$env:SAFETY_MODE = $SafetyMode
$env:SECURITY_LOG_PATH = Join-Path $PSScriptRoot 'logs\agent-security-events.jsonl'

dotnet run --project $project -- $Prompt
exit $LASTEXITCODE
