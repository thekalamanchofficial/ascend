# apps/mobile

React Native / Expo client for Ascend.

## Capability boundary

This app holds **no capability logic of its own**. It is a thin composition layer: it renders UI and wires user intent to capabilities exposed via `packages/contracts`. Any logic that decides *what is allowed* or *what a capability does* belongs in `services/api` (or `services/ai` for AI-assistant behavior) behind a chartered capability — not here.

State: Zustand for local/UI state, TanStack Query for server state. See `docs/CONSTITUTION.md` and root `CLAUDE.md` before adding any new screen or flow — decompose the request into capabilities first.

## Status

Scaffolding only. No feature code yet — see `docs/CAPABILITY_REGISTRY.md` for what's chartered and buildable.
