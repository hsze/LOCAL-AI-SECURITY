# Package Security and Privacy

## Included

- Source code, reusable scripts, templates, KQL, and customer-facing procedures.
- Placeholder values such as `<tenant-id>` and required environment variables.
- Public vulnerability identifiers and public documentation links.

## Excluded

- Credentials, tokens, private keys, certificates, and connection strings.
- Tenant, subscription, workspace, resource-group, Blueprint, Agent Identity,
  managed-identity, user, device, incident, trace, span, or correlation identifiers.
- Generated Agent 365 configuration, deployment output, logs, model responses,
  retrieved customer content, and compiled binaries.
- Internal artifact hashes. Customers generate and approve hashes for their own builds.

## Before sharing

Run `scripts/Test-PackageForSensitiveData.ps1` from the package root. Review every
finding manually; automated scanning reduces risk but cannot prove that arbitrary
customer data is absent.

## Authentication

The samples use `DefaultAzureCredential` or Azure VM managed identity. Do not add
client secrets to scripts or configuration. Grant only the minimum roles required
for Content Safety, Azure Monitor ingestion, and Agent 365.

## Telemetry

Security-event samples are metadata-only. Raw prompts, retrieved documents, and
model responses remain local unless the customer explicitly approves collection,
retention, and access controls.
