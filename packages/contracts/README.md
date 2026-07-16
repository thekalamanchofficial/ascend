# packages/contracts

The single source of truth for Ascend's capability interfaces. This package is load-bearing for Article 10 (modularity): every capability depends on other capabilities **only** through what is published here — never through another capability's internal implementation.

## Format

Protocol Buffers, managed with [Buf](https://buf.build). See `docs/DECISION_LOG.md` (2026-07-06, "Contracts source of truth") for the rationale: three consumer languages (Go, TypeScript, Python) and a need to cover both request/response capability interfaces and internal domain events in one schema system.

- `proto/` — `.proto` source files, one package per capability (e.g. `proto/ascend/identity/v1/identity.proto`), added as each capability's charter is frozen.
- `buf.yaml` — module config and lint/breaking-change rules.
- `buf.gen.yaml` — codegen config: generates Go types/gRPC stubs into `services/api`, TypeScript types into `gen/ts` (consumed by `apps/mobile`), and Python types into `gen/python` (consumed by `services/ai`).

## Workflow

1. A capability charter is gated by the guardians and its §3 Interface section is frozen (see root `CLAUDE.md` §Workflow).
2. Add or amend the corresponding `.proto` file here.
3. Run Buf lint + breaking-change check (wired into `.github/workflows/constitution.yml`) before merge — a breaking change to a frozen contract is itself a constitutional question (Art. 10) and should go back through the charter process, not be pushed through silently.
4. Regenerate bindings; capability engineers implement against the generated types, never hand-roll a parallel definition.

## Status

Scaffolding only — no capability `.proto` files yet. Contracts get added as each Phase 1 capability charter is frozen; see `docs/CAPABILITY_REGISTRY.md`.
