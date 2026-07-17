# Mechanical constitution checks

These scripts implement the mechanical (CI-enforceable) side of `docs/CONSTITUTION.md` §Enforcement, owned by the **Constitution Warden**. Each script encodes a small, explicit convention. Real capability code has landed (Cryptography & Keys, Identity, Permissions, Audit / Explainability are all `stable` — see `docs/CAPABILITY_REGISTRY.md`), so these checks are live and enforced, not vacuous placeholders.

Run them all locally with `scripts/constitution/run-all.sh`. They're also wired as a git hook — see `.githooks/README.md`. `run-all.sh` auto-discovers every `check-*.sh` in this directory, so a new script needs no wiring into `run-all.sh` or `.github/workflows/constitution.yml` beyond simply existing here.

## Conventions each check enforces

**Go-side (`services/api/internal/**`):**

**Art. 9 — exportability (`check-export-paths.sh`)**
Any Go struct with a leading `// ascend:persisted` comment marker is a persisted data type. For each one, a function `Export<TypeName>` must exist in the same package, and a test file matching `*_export_test.go` in that package must reference it. No persisted type may ship without a proven export path.

**Art. 5 — explainability / audit events (`check-audit-events.sh`)**
Any Go function with a leading `// ascend:mutates` comment marker is a state-mutating operation. Its body (up to the next top-level `func` or EOF) must contain a call to `audit.Emit(`. The marker-line match and the body call-match are both anchored to real code (not merely a substring inside a comment) — see the 2026-07-16 decision-log entries on the crash mode and false-pass mode this closed.

**Art. 2 — files first-class (`check-file-objects.sh`)**
Any Go struct with a leading `// ascend:file-object` comment marker must declare fields covering identity, owner, and history (checked by substring match on field names: something containing `ID`, something containing `Owner`, something containing `History`).

**Art. 10 — modularity (`check-modularity.sh`)**
No file under `services/api/internal/<X>/` may import `.../internal/<Y>` for a different capability `Y`. Shared, explicitly-approved packages (`internal/platform`, `internal/audit`) and anything under `packages/contracts` are exempt — everything else must cross capability boundaries only through published contracts.

**TypeScript-side (`apps/mobile/src/capabilities/**`, `services/ai/capabilities/**`):**

**Art. 5 — explainability / audit events (`check-audit-events-ts.sh`)**
Any exported TypeScript function with a leading `// ascend:mutates` comment marker must call `logAuditEvent(` somewhere in its body — the TS-capability equivalent of `check-audit-events.sh`, using the call-name convention Cryptography & Keys already established (`apps/mobile/src/capabilities/crypto/audit.ts`). Test files (`*.test.ts`, `__tests__/`) are excluded from the scan.

There is deliberately no TS-side equivalent of `check-export-paths.sh` or `check-file-objects.sh` yet: no TS capability persists data the way a Go struct backed by a store does (Cryptography & Keys is on-device-only and its one export obligation, `ExportKeyMaterial`, is a single RPC already tested end-to-end, not a per-type pattern to check), and no TS capability owns file objects. Inventing a check with no real signal to validate would be worse than no check — add one when a TS capability actually needs it, following the same pattern as this file.

**Shared, both languages:**

**Art. 8 — privacy / data manifest (`check-data-manifests.sh`)**
Every capability directory (`services/api/internal/<capability>/`, `services/ai/capabilities/<capability>/`, `apps/mobile/src/capabilities/<capability>/`) must contain a `DATA_MANIFEST.md`. Every field listed under its `## Fields` section must have a `Purpose:` line — an undocumented field fails the build.

## Adding a new check

If a new article needs a mechanical check, add a script here following the same pattern (scan, explain the convention in this README, exit non-zero with a clear message on violation, prefer anchored/exact matches over bare substring `grep` so prose mentioning a marker can't produce a false pass or crash — see the 2026-07-16 decision-log entries for why this matters in practice, not just in theory).
