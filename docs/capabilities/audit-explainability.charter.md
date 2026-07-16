# Capability Charter: Audit / Explainability

## 1. Name and one-line purpose

**Audit / Explainability** — the standard "why/when/by-what-rule" event substrate every state-changing action in Ascend emits into (Art. 5). Cross-cutting, like logging, but user-facing and user-owned.

## 2. Article 17 answer (asked first)

Yes. Article 5 exists because platforms today make consequential decisions about a user's communication silently. This capability is the literal mechanism by which "the user can discover why, when, and by what rule" becomes true — without it, Article 5 is an aspiration other capabilities can't actually fulfill.

## 3. Interface

**Exposes:**
- `Emit(actor, action, resource, rule_reference, metadata)` — the single call every other capability's state-mutating operations use; this is the contract `check-audit-events.sh` mechanically expects (`audit.Emit(...)`) once capability code lands.
- `Query(subject, filters) -> [events]` — a user's own audit trail, queryable by resource, time range, or action type.
- `Explain(event_id) -> human_readable_rationale` — turns a raw event into a plain-language answer ("this file's permissions changed on <date> because <grantor> shared it with <subject>").
- `ExportAuditTrail(identity) -> portable_bundle` — Art. 9.

**Consumes:**
- **Identity** — to resolve actor references in emitted events to real identities (published contract only). `actor`/`subject` fields on an event are opaque contract-level identifiers, never a concrete Identity struct — resolution to a display-ready identity happens lazily, at `Query`/`Explain` call time, not at `Emit` time.
- **Permissions** — to decide who may `Query` whose events; a user's own trail is always visible to them, but visibility into others' trails (e.g. "who else can see that I viewed this file") is itself permission-gated, resolved lazily at `Query`/`Explain` time via the same opaque-reference pattern.

## 4. Constitutional obligations

- **Art. 5 (explainability):** this capability's entire purpose. Every other capability's charter references it for their own mutating operations; this charter defines the substrate they emit into and is mechanically backstopped by `check-audit-events.sh`.
- **Art. 8 (privacy):** the audit trail is itself collected data and must follow the same discipline as everything else — a documented purpose per event field, a retention policy, and no collection of content beyond what's needed to explain an action (e.g. record *that* a file was decrypted and by whom, not the plaintext).
- **Art. 9 (export):** a user's full audit trail is exportable, not just visible in-app.
- **Art. 1 (ownership):** a user's own audit trail belongs to them — they can always see the unfiltered history of actions taken on their own resources, subject only to not exposing other users' private data as a side effect.

## 5. Experience budget

Mostly invisible plumbing by default — users are not handed a raw event firehose. "Transparent when curious": every meaningful UI surface (a file, a permission change, a conversation setting) gets a small "why/when" affordance that calls `Explain`, rather than a single overwhelming audit-log screen being the only way in. A dedicated full audit trail view exists for power users who want it (Art. 12), but it's not the default lens through which the platform is experienced.

## 6. Threat model

In scope for integrity, even though visibility is Permissions' concern:

- **Tamper-evidence:** audit events, once emitted, must not be silently editable or deletable — including by platform operators — or the entire explainability guarantee is theater. Append-only storage with integrity verification (e.g. hash chaining) is a strong candidate; exact mechanism is the capability engineer's implementation decision within this constraint.
- **Over-collection risk:** because this capability sees a summary of everything happening on the platform, it is a natural point where privacy discipline (Art. 8) could quietly erode ("just log everything, we might need it"). Every event schema must be reviewed against a documented purpose, same as any other capability's data manifest.
- **Visibility leakage:** `Query`/`Explain` must not let a user infer facts about another user's private resources beyond what Permissions already allows them to know directly.

## 7. Open questions / risks

- **Mutual dependency shape with Identity and Permissions — resolved.** Per `docs/DECISION_LOG.md`, 2026-07-06 ("Foundation contracts composition: opaque references, no live cycle"): every cross-capability reference among Audit, Identity, and Permissions (`identity_ref`, `subject`, `actor`) is an opaque contract-level identifier defined in `packages/contracts`, never a concrete struct crossing a package boundary (see §3). Audit resolves actor identity and applies permission-gating lazily, at `Query`/`Explain` call time — not at `Emit` time, and not as a live construction-time dependency on Identity or Permissions being already-initialized. This closes the cycle at the contracts level: no capability requires the other two to exist yet in order to be built or to emit/query events.
- Retention policy defaults (how long events are kept, whether a user can prune their own trail) deferred to implementation, constrained by Art. 8/9 above.

## 8. Guardian gate results

| Guardian | Verdict (✅ pass / 🚫 blocked / N/A) | Notes | Date |
|---|---|---|---|
| Constitution Warden | ✅ pass (after amendment) | Initially blocked because §3/§7 hadn't been updated to state the contract-cycle resolution even after the decision-log entry existed; fixed by mirroring Identity's opaque-reference/lazy-resolution language in-charter. | 2026-07-06 |
| Experience Guardian | ✅ pass | Clearest articulation of Art. 12 among all six charters — local, contextual "why/when" affordances beat a single dense audit dashboard. | 2026-07-06 |
| Security Steward | ✅ pass | Tamper-evidence (append-only + hash chaining candidate) and over-collection/visibility-leakage risks are concretely named; retention-policy defaults flagged for a follow-up pass once set by the capability engineer. | 2026-07-06 |

**Implementation merge gate (`services/api/internal/audit`):**

| Guardian | Verdict | Notes | Date |
|---|---|---|---|
| Constitution Warden | ✅ pass | No findings — content-addressed SHA-256 hash chain verified sound (not just chain-shaped), `VerifyIntegrity` directly proven to catch both a mutated field and a broken link, export bundle independently re-verifiable outside the module. | 2026-07-16 |
| Security Steward | ✅ pass | No findings on this capability directly (the wave's one veto was on Identity's use of a signature this capability doesn't touch). | 2026-07-16 |

Also implemented: the network-reachable `Emit` HTTP endpoint (`/v1/audit/events`) that Cryptography & Keys' mobile-side `logAuditEvent` stub is waiting for — not yet wired to that stub (a future integration task), but the endpoint itself is real, not a placeholder. Not wired into `services/api/main.go` for a real network perimeter — see `docs/CAPABILITY_REGISTRY.md` Notes for the standing gate pending a Session/Request Authentication capability.

## 9. Decision log references

See `docs/DECISION_LOG.md`, 2026-07-06 entries for Phase 1 chartering, and the 2026-07-16 entries for implementation.
