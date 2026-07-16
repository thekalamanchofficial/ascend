# Capability Registry

The single source of truth for Ascend's capabilities. A **capability** is a durable, reusable primitive (Identity, File Objects, Permissions, ...). A **feature** is a transient, named composition of one or more capabilities and does not get its own row here — see `docs/DECISION_LOG.md` and individual feature entry points for those.

Never plan work directly against a feature. Decompose first — see `CLAUDE.md` §Workflow.

## Format

Each capability gets one row here and one charter at `docs/capabilities/<capability-name>.charter.md` (copy `_TEMPLATE.charter.md` to start one).

| Capability | Status | Owner (subagent) | Charter | Depends on | Consumed by |
|---|---|---|---|---|---|
| Cryptography & Keys | `stable` | capability-engineer | [charter](capabilities/cryptography-and-keys.charter.md) | Audit / Explainability | Identity, Permissions, Storage, File Objects |
| Identity | `gated` | capability-engineer (to spawn) | [charter](capabilities/identity.charter.md) | Cryptography & Keys, Audit / Explainability | Permissions, File Objects |
| Permissions | `gated` | capability-engineer (to spawn) | [charter](capabilities/permissions.charter.md) | Identity, Audit / Explainability | Storage, File Objects |
| Audit / Explainability | `gated` | capability-engineer (to spawn) | [charter](capabilities/audit-explainability.charter.md) | Identity, Permissions | Identity, Cryptography & Keys, Permissions, Storage, File Objects |
| Storage | `gated` | capability-engineer (to spawn) | [charter](capabilities/storage.charter.md) | Cryptography & Keys, Permissions, Audit / Explainability | File Objects |
| File Objects | `gated` | capability-engineer (to spawn) | [charter](capabilities/file-objects.charter.md) | Storage, Permissions, Identity, Cryptography & Keys, Audit / Explainability | (features, once chartered) |

**Status values:** `proposed` → `chartering` → `gated` (passed guardian review) → `frozen` (interface contracts locked) → `building` → `stable` → `deprecated`.

## Notes

- A capability moves to `frozen` only after all applicable guardian gates (Constitution Warden always; Experience Guardian and/or Security Steward if their surface is touched) sign off on the charter — see the gate results recorded in each charter file and cross-referenced in `docs/DECISION_LOG.md`.
- "Depends on" must reference only other capabilities' published contracts in `packages/contracts`, never internal implementation details (Article 10).
- When a capability is deprecated, its replacement and migration/export path must be recorded before removal (Article 9).
