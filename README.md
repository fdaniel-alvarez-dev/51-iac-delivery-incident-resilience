# 51-iac-delivery-incident-resilience

A portfolio-grade, **deterministic** DevOps repo that demonstrates how to reduce:

1) **Infrastructure drift & fragile automation** (multi-cloud IaC guardrails + drift detection)  
2) **Delivery friction** (CI/CD risk checks + release safety patterns)  
3) **On-call pain** (incident-readiness validation + actionable runbooks)

Everything runs locally with **Python 3.11+ (stdlib only)**:

```bash
make setup && make demo
```

## Why this exists (real org pain)

In fast-moving SaaS orgs, you usually see the same failure modes:

- IaC changes are hard to review, environments drift, and “works in staging” becomes a production incident.
- CI/CD pipelines get slow and flaky, so teams cut corners on tests and releases become risky.
- When incidents happen, the information needed to restore service is scattered or missing, extending MTTR.

This repo ships a runnable tool that turns those risks into **checks you can gate in CI**, plus **runbooks you can execute**.

## Architecture (inputs → checks → outputs → runbooks)

- Inputs (under `examples/`)
  - `examples/iac/*.json`: desired vs current state snapshots (multi-cloud + Kubernetes)
  - `examples/cicd/pipeline.json`: pipeline policy surface (timeouts, retries, release strategy)
  - `examples/incidents/incident.json`: incident timeline + readiness signals
- Checks
  - Drift detection and IaC guardrails
  - CI/CD reliability & release safety controls
  - Incident readiness and runbook linkage
- Outputs
  - `artifacts/report.md`: human-readable report (gitignored)
- Runbooks
  - `docs/runbooks/`: steps that map directly to report findings

See `docs/architecture.md` for details.

## Quick start

```bash
make setup
make demo
```

## Demo

The demo generates `artifacts/report.md` and prints a preview.

What to look for:

- **Drift & fragile automation**: a diff between `desired_state.json` and `current_state.json`, plus guardrails.
- **Delivery friction**: pipeline checks that catch missing timeouts/retries/canary/rollback signals.
- **On-call pressure**: incident-readiness checks that enforce timelines, comms, and runbook references.

## CLI

```bash
PYTHONPATH=src python3 -m portfolio_proof report   --examples examples --artifacts artifacts
PYTHONPATH=src python3 -m portfolio_proof validate --examples examples --strict
```

- `report`: writes `artifacts/report.md`
- `validate`: exits non-zero if key controls fail (good for CI gating)

## Security

- No secrets in code or examples.
- `artifacts/`, `.env*`, keys, credentials, and Terraform state are gitignored.
- This repo intentionally avoids calling real cloud APIs in the demo; instead it uses realistic **offline snapshots** that mirror what real integrations would validate.

See `docs/security.md`.
