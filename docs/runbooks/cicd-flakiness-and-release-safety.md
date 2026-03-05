# Runbook: CI/CD flakiness & release safety

## When to use

- Pipelines are slow or flaky.
- Releases are risky (manual heroics, frequent rollbacks).

## Goal

Make delivery boring: fast feedback, predictable releases, safe rollback.

## Steps

1. **Make failures actionable**
   - Add timeouts and clear stage boundaries (build/test/scan/deploy).
2. **Reduce flakiness**
   - Quarantine or stabilize flaky tests; track them explicitly.
   - Add limited retries for known-transient steps (network, cache).
3. **Speed up feedback**
   - Parallelize tests, cache dependencies, and avoid rebuilding identical artifacts.
4. **Ship safely**
   - Prefer canary or progressive delivery.
   - Require an explicit rollback plan and criteria.
5. **Gate changes**
   - Enforce policy checks in CI (`validate --strict`) so risky changes fail early.

## Success criteria

- Pipeline time and failure rate decrease.
- Rollbacks become rare and fast when needed.
