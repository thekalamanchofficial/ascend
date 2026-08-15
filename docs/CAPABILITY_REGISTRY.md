# Capability Registry

The single source of truth for Ascend's capabilities. A **capability** is a durable, reusable primitive (Identity, File Objects, Permissions, ...). A **feature** is a transient, named composition of one or more capabilities and does not get its own row here — see `docs/DECISION_LOG.md` and individual feature entry points for those.

Never plan work directly against a feature. Decompose first — see `CLAUDE.md` §Workflow.

## Format

Each capability gets one row here and one charter at `docs/capabilities/<capability-name>.charter.md` (copy `_TEMPLATE.charter.md` to start one).

| Capability | Status | Owner (subagent) | Charter | Depends on | Consumed by |
|---|---|---|---|---|---|
| Cryptography & Keys | `stable` | capability-engineer | [charter](capabilities/cryptography-and-keys.charter.md) | Audit / Explainability | Identity, Permissions, Storage, File Objects |
| Identity | `stable` | capability-engineer | [charter](capabilities/identity.charter.md) | Cryptography & Keys, Audit / Explainability | Permissions, File Objects |
| Permissions | `stable` | capability-engineer | [charter](capabilities/permissions.charter.md) | Identity, Audit / Explainability | Storage, File Objects |
| Audit / Explainability | `stable` | capability-engineer | [charter](capabilities/audit-explainability.charter.md) | Identity, Permissions | Identity, Cryptography & Keys, Permissions, Storage, File Objects |
| Storage | `stable` | capability-engineer | [charter](capabilities/storage.charter.md) | Cryptography & Keys, Permissions, Audit / Explainability | File Objects |
| File Objects | `stable` | capability-engineer | [charter](capabilities/file-objects.charter.md) | Storage, Permissions, Identity, Cryptography & Keys, Audit / Explainability | (features, once chartered) |
| Session / Request Authentication | `stable` | capability-engineer | [charter](capabilities/session-authentication.charter.md) | Cryptography & Keys, Identity, Audit / Explainability | Identity, Permissions, Audit / Explainability (as the caller-identity verification layer in front of each) |

**Status values:** `proposed` → `chartering` → `gated` (passed guardian review) → `frozen` (interface contracts locked) → `building` → `stable` → `deprecated`.

## Notes

- A capability moves to `frozen` only after all applicable guardian gates (Constitution Warden always; Experience Guardian and/or Security Steward if their surface is touched) sign off on the charter — see the gate results recorded in each charter file and cross-referenced in `docs/DECISION_LOG.md`.
- "Depends on" must reference only other capabilities' published contracts in `packages/contracts`, never internal implementation details (Article 10).
- When a capability is deprecated, its replacement and migration/export path must be recorded before removal (Article 9).
- **Standing gate, binding (docs/DECISION_LOG.md, 2026-07-16):** Identity, Permissions, and Audit / Explainability are `stable` as Go packages but **not wired into `services/api/main.go`, and not exposed on any reachable network perimeter**, pending a chartered Session/Request Authentication capability (see open task). Wiring any of the three into `main.go` before that capability lands requires a fresh Security Steward gate on that specific act.
