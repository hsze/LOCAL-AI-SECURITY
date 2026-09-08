[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SecurityLogPath,

    [Parameter(Mandatory)]
    [string]$DceEndpoint,

    [Parameter(Mandatory)]
    [string]$DcrImmutableId,

    [Parameter(Mandatory)]
    [string]$StreamName
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $SecurityLogPath)) {
    throw "Security event log not found: $SecurityLogPath"
}

$lastLine = Get-Content -LiteralPath $SecurityLogPath |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Select-Object -Last 1

if (-not $lastLine) {
    throw "Security event log is empty: $SecurityLogPath"
}

$source = $lastLine | ConvertFrom-Json
$severities = @{}
foreach ($item in @($source.outputSafetyAnalysis)) {
    $severities[[string]$item.category] = [int]$item.severity
}

$event = [ordered]@{
    TimeGenerated = [string]$source.timestampUtc
    SchemaVersion = [string]$source.schemaVersion
    CorrelationId = [string]$source.correlationId
    DeviceName = [string]$source.deviceName
    UserName = [string]$source.userName
    Model = [string]$source.model
    InputPolicyMode = [string]$source.policyMode
    OutputPolicyMode = [string]$source.outputPolicyMode
    SecurityDecision = [string]$source.securityDecision
    DetectionType = [string]$source.detectionType
    RetrievedDocument = [string]$source.retrievedDocument
    OllamaCalled = [bool]$source.ollamaCalled
    OutputMaxSeverity = [int]$source.outputMaxSeverity
    HateSeverity = [int]$severities['Hate']
    SelfHarmSeverity = [int]$severities['SelfHarm']
    SexualSeverity = [int]$severities['Sexual']
    ViolenceSeverity = [int]$severities['Violence']
    Status = [string]$source.status
    ErrorCategory = if ($source.errorType) { 'SafetyControlError' } else { '' }
}

$tokenUri = 'http://169.254.169.254/metadata/identity/oauth2/token' +
    '?api-version=2018-02-01&resource=https%3A%2F%2Fmonitor.azure.com%2F'
$token = Invoke-RestMethod -Method Get -Uri $tokenUri -Headers @{ Metadata = 'true' }
$ingestionUri = $DceEndpoint.TrimEnd('/') +
    "/dataCollectionRules/$DcrImmutableId/streams/$StreamName" +
    '?api-version=2023-01-01'

Invoke-RestMethod `
    -Method Post `
    -Uri $ingestionUri `
    -Headers @{ Authorization = "Bearer $($token.access_token)" } `
    -ContentType 'application/json' `
    -Body (ConvertTo-Json -InputObject @($event) -Depth 5 -Compress)

Write-Host "Sent metadata event $($event.CorrelationId) to $StreamName."
