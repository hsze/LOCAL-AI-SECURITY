# Test 1: Discover Local AI Runtime and Model Activity

## Purpose

Determine whether Microsoft Defender for Endpoint (MDE) discovers a local AI
runtime and whether Advanced Hunting identifies the model requested by a user.

This test distinguishes:

1. Runtime discovery, such as Ollama in Defender's Local agents inventory.
2. Model activity discovery, such as `ollama pull tinyllama` in process telemetry.
3. Model asset inventory, where weights or manifests become first-class assets.

The first two can succeed while the third remains unavailable.

## Prerequisites

- An authorized Windows test endpoint onboarded to MDE.
- Advanced Hunting and **Assets > AI agents > Local agents** access.
- Current Defender Antivirus platform and signatures.
- Ollama from the official distribution source.
- A test model such as `tinyllama:latest`.

Keep Ollama bound to loopback. Do not expose port `11434` for this test.

## Generate activity

Open PowerShell on the endpoint:

```powershell
$ollama = (Get-Command ollama.exe -ErrorAction Stop).Source

Get-AuthenticodeSignature $ollama |
    Select-Object Status, SignerCertificate
Get-FileHash $ollama -Algorithm SHA256
& $ollama --version

$startUtc = [DateTime]::UtcNow
& $ollama serve
```

Keep the server open. In a second PowerShell window:

```powershell
$ollama = (Get-Command ollama.exe -ErrorAction Stop).Source
& $ollama pull tinyllama
& $ollama run tinyllama 'Reply with exactly: MDE LOCAL MODEL TEST'
& $ollama ps
[DateTime]::UtcNow.ToString('o')
```

The response wording is not a discovery requirement. Record the UTC test window.

## Hunt native local-agent inventory

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

Also inspect **Assets > AI agents > Local agents**. Allow for ingestion latency.

## Hunt model activity

Set the customer device fragment and test start time:

```kusto
let start = datetime(<test-start-utc>);
let device = "<device-name-fragment>";
DeviceProcessEvents
| where Timestamp >= start
| where DeviceName startswith device
| where FileName in~ ("ollama.exe", "llama-server.exe")
    or ProcessCommandLine has_any ("ollama", "tinyllama")
    or InitiatingProcessCommandLine has_any ("ollama", "tinyllama")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

Expected behavioral evidence includes `pull tinyllama`, `run tinyllama`, and an
Ollama-launched inference backend. A backend command line may not contain the model
name when Ollama receives that name through its local API.

## Hunt likely model files

```kusto
let start = datetime(<test-start-utc>);
DeviceFileEvents
| where Timestamp >= start
| where FileName endswith ".gguf"
    or FileName endswith ".safetensors"
    or FileName endswith ".onnx"
    or FolderPath has_any (@"\.ollama\models\", @"\.cache\huggingface\hub\")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, FileSize,
    SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

No rows does not prove that no model is stored. Compare with local runtime inventory:

```powershell
& $ollama list
Get-ChildItem "$env:USERPROFILE\.ollama\models" -Recurse -File |
    Select-Object FullName, Length, LastWriteTimeUtc
```

## Pass criteria

- MDE identifies the runtime or captures its process activity.
- Process evidence attributes model pull/run activity to a device, account, and time.
- The report explicitly states whether exact model identity came from behavioral
  telemetry or first-class inventory.
- Missing file telemetry is recorded as a visibility limitation, not as absence.

## Customer conclusion template

> MDE discovered `<runtime>` on `<device>` and attributed activity to `<account>`.
> Advanced Hunting `<did/did not>` identify `<model>` by name in process telemetry.
> The model `<did/did not>` appear as a distinct managed asset. Model-level identity
> is therefore `<behavioral/first-class/not determined>` in this test.