# services/api

Go backend for Ascend — the primary implementation surface for chartered capabilities.

## Capability boundary

Each capability owns its own package under this service (e.g. `internal/identity`, `internal/permissions`, once chartered) and exposes only what its frozen contract in `packages/contracts` declares. Capabilities may depend on each other's **published contracts only**, never on each other's internal packages (Article 10) — this is enforced mechanically in `.github/workflows/constitution.yml`.

HTTP routing uses `go-chi/chi` (see `docs/DECISION_LOG.md`, 2026-07-06) precisely because it stays a thin layer over `net/http` — each capability can expose a plain `http.Handler` without framework coupling.

Every state-mutating handler must emit an audit event into the shared audit substrate (Article 5) and every persisted type must have an export path (Article 9) — see the Audit/Explainability and the relevant capability's charter.

## Status

Scaffolding only — a health-check endpoint and module wiring. No capability logic yet; see `docs/CAPABILITY_REGISTRY.md`.
