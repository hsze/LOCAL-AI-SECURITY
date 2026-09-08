# KQL Validation Query Reference

This reference consolidates the useful KQL used to validate the local AI security
architecture. Replace every angle-bracket placeholder before running a query.

The queries intentionally avoid tenant, user, device, resource, agent, Blueprint,
trace, conversation, incident, and correlation identifiers from the original lab.

## Query locations

| Data | Run the query in |
|---|---|
| `AgentsInfo`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `AlertInfo`, `CloudAppEvents`, `DeviceTvm*` | Microsoft Defender portal > Hunting > Advanced Hunting |
| `<CustomTableName>_CL` | Microsoft Sentinel > Logs, or the connected Log Analytics workspace |

A custom Log Analytics table is not automatically available in Defender Advanced
Hunting. A table that returns no rows is different from a table that cannot be
resolved; preserve that distinction when recording results.

## Common parameters

Use a narrow test window whenever possible:

```kusto
let start = datetime(<test-start-utc>);
let end = datetime(<test-end-utc>);
let device = "<device-name-fragment>";
```

For ongoing hunting, replace the fixed interval with an appropriate lookback such
as `ago(24h)` or `ago(30d)`.

## Test 1: local runtime and model discovery

### Discover native local AI agents

```kusto
AgentsInfo
| where Platform == "LocalAgents"
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in~ ("Deleted", "Uninstalled")
| extend Metadata = RawAgentInfo.localAgentMetadata
| project Timestamp, AgentId, Name, Version, LifecycleStatus,
    Vendor=tostring(Metadata.vendor),
    Process=tostring(Metadata.relatedProcess),
    Device=tostring(Metadata.deviceName),
    Account=tostring(Metadata.accountName),
    TrustedProcess=tobool(Metadata.trustedProcess)
| order by Timestamp desc
```

This establishes native runtime discovery. It does not prove that each model loaded
by the runtime is represented as a separate asset.

### Hunt common local AI runtimes

```kusto
let lookback = 30d;
let runtimeExecutables = dynamic([
    "ollama.exe",
    "llama-server.exe",
    "lm studio.exe",
    "jan.exe",
    "gpt4all.exe",
    "llamafile.exe",
    "koboldcpp.exe"
]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (runtimeExecutables)
    or ProcessCommandLine has_any (
        "ollama", "llama.cpp", "llama-server", "llamafile",
        "lmstudio", "gpt4all", "koboldcpp", "text-generation-webui"
    )
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

The executable list is a hunting seed, not a complete or authoritative product
inventory.

### Correlate a runtime and named model during a test

```kusto
let start = datetime(<test-start-utc>);
let device = "<device-name-fragment>";
let model = "<model-name>";
DeviceProcessEvents
| where Timestamp >= start
| where DeviceName startswith device
| where FileName in~ ("ollama.exe", "llama-server.exe")
    or ProcessCommandLine contains model
    or InitiatingProcessCommandLine contains model
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

Model names in `pull`, `run`, `load`, or `--model` commands provide behavioral
model identity. A backend process can prove local inference while omitting the model
name if the runtime received it through a local API request.

### Isolate exact named-model activity

```kusto
let start = datetime(<test-start-utc>);
let device = "<device-name-fragment>";
let model = "<model-name>";
DeviceProcessEvents
| where Timestamp >= start
| where DeviceName startswith device
| where ProcessCommandLine contains model
    or InitiatingProcessCommandLine contains model
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

### Hunt likely local model files

```kusto
let lookback = 30d;
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FileName endswith ".gguf"
    or FileName endswith ".safetensors"
    or FileName endswith ".onnx"
    or FileName endswith ".pt"
    or FileName endswith ".pth"
    or FolderPath has_any (
        @"\.ollama\models\",
        @"\.cache\huggingface\hub\",
        @"\LM Studio\models\",
        @"\GPT4All\"
    )
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, FileSize,
    SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

No result does not prove that no model exists. Confirm with authorized endpoint or
runtime inventory when file telemetry is absent.

### Correlate runtime network activity

```kusto
let lookback = 30d;
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where InitiatingProcessFileName in~ (
    "ollama.exe",
    "lm studio.exe",
    "jan.exe",
    "gpt4all.exe",
    "llamafile.exe",
    "koboldcpp.exe"
)
    or InitiatingProcessCommandLine has_any (
        "ollama", "llama.cpp", "llamafile", "lmstudio",
        "gpt4all", "koboldcpp", "text-generation-webui"
    )
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, Protocol,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

Correlate by device, process, account, and a narrow time window. A registry URL can
support a download finding but may not identify the exact model.

## Prompt-injection alert experiment

The following query was used to check whether an MDE AI network-inspection policy
created an alert for the controlled Ollama loopback test:

```kusto
AlertInfo
| where Timestamp > ago(24h)
| where Title has "Suspicious AI prompt injection"
| project Timestamp, Title, Severity, ServiceSource, DetectionSource, AlertId
| order by Timestamp desc
```

No alert was observed in that test. Treat this as a negative validation query, not
as proof that prompts were inspected or that the endpoint was protected. The
application-level Prompt Shields controls in Tests 2.1 and 2.2 provide the validated
inline inspection path.

## Test 2.1: protected RAG and Sentinel

Replace `<CustomTableName>` with the custom Log Analytics table name without its
`_CL` suffix.

### Review recent metadata-only security events

```kusto
<CustomTableName>_CL
| where TimeGenerated > ago(24h)
| project TimeGenerated, CorrelationId, DeviceName, UserName, Model,
    SecurityDecision, DetectionType, RetrievedDocument, OllamaCalled,
    OutputMaxSeverity, ViolenceSeverity, Status
| order by TimeGenerated desc
```

### Correlate one protected RAG execution

```kusto
let correlationId = "<correlation-id>";
<CustomTableName>_CL
| where TimeGenerated > ago(24h)
| where CorrelationId == correlationId
| project TimeGenerated, CorrelationId, DeviceName, UserName, Model,
    SecurityDecision, DetectionType, RetrievedDocument, OllamaCalled,
    OutputMaxSeverity, ViolenceSeverity, Status
| order by TimeGenerated desc
```

### Reproduce the validated Sentinel analytics-rule match

```kusto
<CustomTableName>_CL
| where TimeGenerated > ago(10m)
| where SecurityDecision in~ ("Block", "Audit", "Blocked")
    or Status in~ ("Blocked", "OutputBlocked", "Failed")
    or isnotempty(DetectionType)
| project TimeGenerated, CorrelationId, DeviceName, UserName, Model,
    SecurityDecision, DetectionType, RetrievedDocument, OllamaCalled,
    OutputMaxSeverity, Status
```

The validated scheduled rule ran every five minutes over a ten-minute window and
created an incident when this query returned at least one row. Tune severity,
grouping, entity mappings, and suppression for the customer's environment.

## Test 2.2: Agent 365 and Defender

Agent 365 activity was validated in Defender's `CloudAppEvents` table. The Microsoft
365 activities connector had to be enabled before general records appeared. Purview
Audit search was validated separately in the Purview portal; it was not queried with
KQL in this test.

`RawEventData` is operation-specific and its schema can evolve. Start broad, inspect
returned JSON, and then project the fields needed for the observed `ActionType`.

### Confirm table availability and freshness

```kusto
CloudAppEvents
| summarize Rows=count(), NewestEvent=max(Timestamp), OldestEvent=min(Timestamp)
```

Interpretation:

- A table-resolution error indicates that the table is unavailable in the current
  hunting context.
- Zero rows means the table exists but has no visible data.
- A stale `NewestEvent` suggests a connector or ingestion problem.

For the smallest provisioning check:

```kusto
CloudAppEvents
| take 1
```

### Summarize agent-related activity types

```kusto
CloudAppEvents
| where Timestamp > ago(24h)
| where ActionType contains "Agent"
| summarize Events=count(), Newest=max(Timestamp) by ActionType, Application
| order by Newest desc
```

### Find activity for one Agent Identity

```kusto
let expectedAgentId = "<agent-identity-application-id>";
CloudAppEvents
| where Timestamp > ago(2d)
| extend Data = parse_json(tostring(RawEventData))
| extend
    AgentId = tostring(Data.AgentId),
    TargetAgentId = tostring(Data.TargetAgentId),
    PlatformTargetAgentId = tostring(Data.PlatformTargetAgentId)
| where AgentId == expectedAgentId
    or TargetAgentId == expectedAgentId
    or PlatformTargetAgentId == expectedAgentId
    or tostring(RawEventData) contains expectedAgentId
| project Timestamp, ActionType, Application, AgentId,
    TargetAgentId, PlatformTargetAgentId, Data
| order by Timestamp desc
```

### Summarize activity for one Agent Identity

```kusto
let expectedAgentId = "<agent-identity-application-id>";
CloudAppEvents
| where Timestamp > ago(2d)
| extend Data = parse_json(tostring(RawEventData))
| where tostring(Data.AgentId) == expectedAgentId
    or tostring(Data.TargetAgentId) == expectedAgentId
    or tostring(Data.PlatformTargetAgentId) == expectedAgentId
| summarize Events=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by ActionType, Application
| order by LastSeen desc
```

### Validate a root `InvokeAgent` event and target identity

```kusto
let expectedAgentId = "<agent-identity-application-id>";
let expectedBlueprintId = "<blueprint-application-id>";
CloudAppEvents
| where Timestamp > ago(2d)
| where ActionType == "InvokeAgent"
| extend Data = parse_json(tostring(RawEventData))
| extend
    TargetAgentId = tostring(Data.TargetAgentId),
    TargetAgentName = tostring(Data.TargetAgentName),
    TargetBlueprintId = tostring(Data.TargetAgentBlueprintID),
    AgentId = tostring(Data.AgentId),
    AgentBlueprintId = tostring(Data.AgentBlueprintId),
    ConversationId = tostring(Data.ConversationId),
    ChannelName = tostring(Data.ChannelName),
    Operation = tostring(Data.Operation)
| where TargetAgentId == expectedAgentId
| extend
    AgentIdValid = TargetAgentId == expectedAgentId,
    BlueprintIdValid = TargetBlueprintId == expectedBlueprintId
| project Timestamp, ActionType, Application, Operation,
    TargetAgentId, TargetAgentName, TargetBlueprintId,
    AgentId, AgentBlueprintId, ConversationId, ChannelName,
    AgentIdValid, BlueprintIdValid
| order by Timestamp desc
```

For `InvokeAgent`, the authoritative target fields observed during validation were
`TargetAgentId` and `TargetAgentBlueprintID`. The generic `AgentId` and
`AgentBlueprintId` fields can have different operation-specific meanings.

### Correlate a normal application run by conversation ID

```kusto
let expectedConversationId = "<conversation-id>";
CloudAppEvents
| where Timestamp > ago(24h)
| extend Data = parse_json(tostring(RawEventData))
| where tostring(Data.ConversationId) == expectedConversationId
| project Timestamp, ActionType, Application,
    Operation=tostring(Data.Operation),
    ExecutionType=tostring(Data.ExecutionType),
    UserKey=tostring(Data.UserKey),
    UserId=tostring(Data.UserId),
    OpId=tostring(Data.OpId),
    ConversationId=tostring(Data.ConversationId),
    TargetAgentId=tostring(Data.TargetAgentId),
    TargetBlueprintId=tostring(Data.TargetAgentBlueprintID)
| order by Timestamp desc
```

This query was used to prove that the normal application path, rather than only the
diagnostic ingestion probe, reached Defender with caller attribution. Review user
fields according to organizational privacy policy.

### Correlate an OpenTelemetry probe by span ID

The validated mapping was OpenTelemetry `spanId` to `RawEventData.OpId`. The full
OpenTelemetry `traceId` was not exposed in `CloudAppEvents`.

```kusto
let expectedOpId = "<otel-span-id>";
let expectedConversationId = "<conversation-id>";
CloudAppEvents
| where Timestamp > ago(1h)
| extend Data = parse_json(tostring(RawEventData))
| where tostring(Data.OpId) == expectedOpId
    or tostring(Data.ConversationId) == expectedConversationId
| project Timestamp, ActionType, Application,
    Operation=tostring(Data.Operation),
    ExecutionType=tostring(Data.ExecutionType),
    UserKey=tostring(Data.UserKey),
    UserId=tostring(Data.UserId),
    OpId=tostring(Data.OpId),
    ParentId=tostring(Data.ParentId),
    ConversationId=tostring(Data.ConversationId),
    TargetAgentId=tostring(Data.TargetAgentId),
    TargetBlueprintId=tostring(Data.TargetAgentBlueprintID)
| order by Timestamp desc
```

Allow for downstream ingestion and portal-indexing latency before resending a probe.

## Test 3.1: runtime vulnerability coverage

### Confirm the exact runtime binary observed by MDE

```kusto
let device = "<device-name-fragment>";
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceName startswith device
| where FileName =~ "ollama.exe"
| summarize LastSeen=max(Timestamp), arg_max(Timestamp, *) by DeviceId, SHA1
| project LastSeen, DeviceId, DeviceName, FolderPath, SHA1, SHA256,
    ProcessVersionInfoProductVersion, ProcessVersionInfoCompanyName
```

### Enrich the observed binary with file reputation and signature data

```kusto
let observed = DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "ollama.exe"
| summarize arg_max(Timestamp, *) by SHA1;
observed
| invoke FileProfile(SHA1, 1000)
| project DeviceName, FolderPath, SHA1, SHA256, GlobalPrevalence,
    Signer, SignatureState, CertificateValid
```

A valid signature establishes publisher identity and file integrity. It does not
establish that the runtime is patched or vulnerability-free.

### Check TVM software normalization

```kusto
DeviceTvmSoftwareInventory
| where SoftwareVendor contains "Ollama"
    or SoftwareName contains "Ollama"
| project DeviceId, DeviceName, SoftwareVendor, SoftwareName,
    SoftwareVersion, EndOfSupportStatus
```

### Check TVM software evidence and recover the device name

```kusto
let TargetDevices =
    DeviceInfo
    | where Timestamp > ago(30d)
    | where DeviceName startswith "<device-name-fragment>"
    | summarize arg_max(Timestamp, DeviceName) by DeviceId
    | project DeviceId, DeviceName;
DeviceTvmSoftwareEvidenceBeta
| where SoftwareVendor contains "Ollama"
    or SoftwareName contains "Ollama"
| join kind=inner TargetDevices on DeviceId
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion,
    DiskPaths, RegistryPaths
```

`DeviceTvmSoftwareEvidenceBeta` did not expose `DeviceName` directly during the
validation, so the query joins the latest `DeviceInfo` record by `DeviceId`.

If process evidence exists but both TVM queries return no rows, record **TVM mapping
absent**. Do not record **no vulnerabilities**. Complete the assessment with current
vendor advisories, NVD, GitHub Advisory Database, and CISA KEV evidence.

## Interpretation checklist

For each query, record:

- portal and table;
- UTC time window;
- filters and placeholders used;
- whether rows were returned;
- the evidence supported by those rows;
- visibility gaps or ingestion delay;
- the strongest conclusion the evidence permits.

Do not treat an empty result as proof of absence without first confirming table
availability, retention, sensor coverage, connector configuration, permissions, and
the expected ingestion window.
