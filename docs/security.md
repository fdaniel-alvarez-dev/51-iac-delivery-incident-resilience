# Security

## Secrets handling

- This repo never requires real cloud credentials for the demo.
- `artifacts/`, `.env*`, keys, credentials files, and Terraform state are gitignored.
- The CLI does not print environment variables (including `GITHUB_TOKEN`) and does not log sensitive values.

## Least privilege and auditability

In a real implementation of these checks:

- Read-only identities should be used for inventory/state validation.
- Changes should flow through PRs with reviewed plans and enforced policy checks.
- Outputs should be stored as build artifacts for traceability.

## Out of scope (intentional)

- Direct integration with AWS/Azure/GCP/Cloudflare APIs
- Running real Terraform/Kubernetes commands in CI

The repo still keeps the integration surfaces realistic via offline snapshots that match what those integrations would validate.
