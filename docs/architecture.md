# Architecture

## Goal

Provide a deterministic, offline demo that **proves** DevOps capability across:

- Multi-cloud + Kubernetes IaC guardrails and drift detection
- CI/CD reliability and safe release patterns
- Incident readiness to reduce MTTR with actionable runbooks

The demo is intentionally **provider-API free** (no AWS/Azure/GCP credentials required). In production, the same checks would read from:

- Terraform plan/state, cloud inventory, Kubernetes APIs, and CI/CD system APIs
- Centralized runbooks, incident timelines, and monitoring/SLO systems

## Data flow

1. Inputs live under `examples/`:
   - IaC snapshots: desired vs current (multi-cloud + k8s)
   - Pipeline policy surface (timeouts/retries/release strategy)
   - Incident timeline + readiness signals
2. `portfolio_proof` runs checks and produces:
   - A human-readable report: `artifacts/report.md`
   - A CI-friendly exit code (`validate`)
3. Findings map to runbooks in `docs/runbooks/`.

## Components

- CLI: `python -m portfolio_proof report|validate`
- Checks:
  - IaC drift + guardrails
  - CI/CD performance and release safety controls
  - Incident readiness + runbook linking
- Output:
  - Markdown report with risks, recommendations, and validation results

## Threat model notes (high-level)

**Assets**
- IaC definitions and environment baselines
- CI/CD pipeline definitions (release capability)
- Runbooks and incident timelines (operational knowledge)

**Threats**
- Accidental privilege expansion via drift or misconfigured IaC
- Supply-chain risks through unpinned dependencies or mutable artifacts
- Reduced resiliency from missing rollback strategy or incomplete runbooks

**Controls demonstrated here**
- Deterministic validation with explicit failures in CI
- Least-privilege mindset (no secrets, no provider credentials required for demo)
- Auditability through report outputs and runbook linkage
