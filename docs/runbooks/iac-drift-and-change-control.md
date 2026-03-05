# Runbook: IaC drift & change control

## When to use

- `validate` reports drift between desired and current state.
- You see environment-specific snowflakes or unreviewed changes.

## Goal

Restore repeatable, reviewable infrastructure changes and prevent drift from returning.

## Steps

1. **Stop the bleeding**
   - Freeze ad-hoc changes; require PR-based change control for infra.
2. **Identify drift sources**
   - Compare desired vs current inventory (this repo models this via `examples/iac/*`).
   - Look for missing tags/labels, mismatched versions, or inconsistent cluster settings.
3. **Reconcile safely**
   - Prefer converging _current → desired_ via IaC, not editing desired to match unknown reality.
   - Split changes: guardrails first, then functional changes.
4. **Add guardrails**
   - Pin toolchain versions.
   - Require ownership metadata (team, environment, data classification).
   - Enforce encryption/backup expectations for stateful services.
5. **Prevent regression**
   - Gate merges with `make lint` / `make test` and `portfolio_proof validate --strict`.

## Success criteria

- Drift delta goes to zero and stays stable across environments.
- PR reviews show predictable diffs and clear ownership.
