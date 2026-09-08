# Local AI Security Validation Package

This folder is a customer-shareable copy of four local AI security tests. It contains no lab tenant IDs, Agent 365 identity IDs, subscription IDs, workspace IDs, user principal names, correlation IDs, credentials, generated configuration, logs, or compiled binaries.

The internal source runbooks and evidence remain outside this folder and are not modified by this package.

## Tests

| Test | Objective | Entry point |
|---|---|---|
| 1 | Discover a local AI runtime and named model activity with Microsoft Defender for Endpoint | `test-1-discovery/README.md` |
| 2.1 | Inspect prompts, retrieved documents, and output around a local protected RAG flow; optionally send metadata to Sentinel | `test-2.1-protected-rag/README.md` |
| 2.2 | Run a Microsoft Agent Framework application over local Ollama with inline safety and optional Agent 365 telemetry | `test-2.2-agent/README.md` |
| 3.1 | Assess runtime vulnerability coverage using Defender evidence and external advisory intelligence | `test-3.1-runtime-vulnerability/README.md` |

## Customer-supplied configuration

Depending on the tests selected, the customer supplies:

- Azure AI Content Safety endpoint and an identity authorized to call it.
- Microsoft Defender for Endpoint onboarding and Advanced Hunting access.
- Optional Microsoft Sentinel DCE endpoint, DCR immutable ID, stream name, workspace, and analytics rule.
- Optional Agent 365 tenant, Blueprint application ID, child Agent Identity application ID, and human caller identity.
- Local Ollama executable path, model-store path, endpoint, and model name.

Use environment variables or command parameters described in each runbook. Do not commit secrets, access tokens, generated identity configuration, logs, or customer evidence.

## Package layout

```text
customer-package/
  README.md
  SECURITY.md
  test-1-discovery/
  test-2.1-protected-rag/
  test-2.2-agent/
  test-3.1-runtime-vulnerability/
```

## General requirements

- Windows PowerShell 5.1 or PowerShell 7.
- Ollama installed and bound to loopback unless a separately reviewed network design requires otherwise.
- `tinyllama:latest` for exact reproduction, or another approved model with expected results adjusted accordingly.
- Relevant Microsoft security and Azure permissions for each selected test.
- .NET 8 SDK to build Test 2.2.

## Safe use

Run controlled prompts and model artifacts only in an authorized test environment. Keep raw prompts, retrieved content, responses, and model files out of centralized telemetry unless the customer's privacy, retention, and security review explicitly permits collection.
