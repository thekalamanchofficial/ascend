# Mechanical constitution checks

These scripts implement the mechanical (CI-enforceable) side of `docs/CONSTITUTION.md` §Enforcement, owned by the **Constitution Warden**. Each script encodes a small, explicit convention — since Ascend has no capability code yet, they currently pass vacuously (nothing to check), but they are real checks, wired into `.github/workflows/constitution.yml`, ready to fire the moment capability code lands.

Run them all locally with `scripts/constitution/run-all.sh`. They're also wired as a git hook — see `.githooks/README.md`.

## Conventions each check enforces

**Art. 9 — exportability (`check-export-paths.sh`)**
Any Go struct with a leading `// ascend:persisted` comment marker is a persisted data type. For each one, a function `Export<TypeName>` must exist in the same package, and a test file matching `*_export_test.go` in that package must reference it. No persisted type may ship without a proven export path.

**Art. 8 — privacy / data manifest (`check-data-manifests.sh`)**
Every capability directory (`services/api/internal/<capability>/`, `services/ai/capabilities/<capability>/`) must contain a `DATA_MANIFEST.md`. Every field listed under its `## Fields` section must have a `Purpose:` line — an undocumented field fails the build.

**Art. 5 — explainability / audit events (`check-audit-events.sh`)**
Any Go function with a leading `// ascend:mutates` comment marker is a state-mutating operation. Its body (up to the next top-level `func` or EOF) must contain a call to `audit.Emit(`.

**Art. 2 — files first-class (`check-file-objects.sh`)**
Any Go struct with a leading `// ascend:file-object` comment marker must declare fields covering identity, owner, and history (checked by substring match on field names: something containing `ID`, something containing `Owner`, something containing `History`).

**Art. 10 — modularity (`check-modularity.sh`)**
No file under `services/api/internal/<X>/` may import `.../internal/<Y>` for a different capability `Y`. Shared, explicitly-approved packages (`internal/platform`, `internal/audit`) and anything under `packages/contracts` are exempt — everything else must cross capability boundaries only through published contracts.

## Adding a new check

If a new article needs a mechanical check, add a script here following the same pattern (scan, explain the convention in this README, exit non-zero with a clear message on violation), then add it to `run-all.sh` and `.github/workflows/constitution.yml`.
