# Competitive Teardown: NeMo Guardrails

## What it does well
- Multi-stage rails (input/dialog/retrieval/execution/output).
- Strong conversation flow controls and policy semantics.
- Mature ecosystem and model integrations.

## Gaps we must close for parity/advantage
- Retrieval and output guardrails as first-class runtime modules.
- Rich policy lifecycle (versioning, approvals, rollback).
- Enterprise observability defaults (OTel + SIEM connectors).

## Build requirements derived
1. Add retrieval guard module to scan external context and tool responses.
2. Add output guard module to inspect generated responses pre-delivery.
3. Add policy governance with immutable versions and approval workflow.
4. Add scoring and action routing (`allow`/`review`/`quarantine`/`deny`).

## Acceptance criteria
- Retrieval/output checks execute in the same evaluation pipeline.
- Decision object returns risk/confidence/action.
- Governance records policy version and approver metadata.
