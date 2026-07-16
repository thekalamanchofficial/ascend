# services/ai

Python AI assistant service for Ascend.

## Capability boundary

This service is **assistant-only**, per the AI philosophy in `docs/CONSTITUTION.md` and root `CLAUDE.md`: it may recommend, organize, summarize, explain, and automate on behalf of a user, but it never silently takes control and never acts as the owner of a decision. Any capability this service exposes must route user-visible actions through explicit confirmation or a user-defined automation rule (Article 6, 11) and must emit an audit event for anything it does on the user's behalf (Article 5).

It consumes other capabilities (Identity, Permissions, File Objects, etc.) only through their published contracts in `packages/contracts`, never by reaching into `services/api` internals (Article 10).

## Status

Scaffolding only — no assistant logic yet; see `docs/CAPABILITY_REGISTRY.md`.
