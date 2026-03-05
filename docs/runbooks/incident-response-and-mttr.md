# Runbook: Incident response & MTTR reduction

## When to use

- An incident is declared or imminent.
- On-call lacks context: unclear owners, missing timelines, or weak comms.

## Goal

Shorten MTTR by making response predictable and information-rich.

## Steps

1. **Declare and classify**
   - Assign severity, incident commander, and comms owner.
2. **Stabilize**
   - Mitigate customer impact first (feature flags, rollback, traffic shaping).
3. **Create a clear timeline**
   - Record detection, mitigation, and resolution timestamps.
4. **Communicate**
   - Use a single source of truth and update cadence.
5. **Follow-up**
   - Identify contributing factors (drift, pipeline gaps, missing alerts).
   - Turn the lessons into guardrails validated by CI.

## Success criteria

- Accurate timeline exists within 30 minutes.
- Comms cadence is consistent and stakeholders stay informed.
- Post-incident action items become enforceable controls.
