# Data Manifest — Audit / Explainability

Per Art. 8 (privacy is the default; minimum data, documented purpose) and
charter §6 ("over-collection risk" — this capability sees a summary of
everything happening on the platform, which is exactly the kind of surface
where "just log everything, we might need it" quietly erodes privacy
discipline if not actively guarded).

**Standing constraint on every event this capability ever stores:** an audit
event may only record *that* an action happened, by whom, to what, and under
what rule — never the sensitive content of the action itself. E.g., record
that a file was decrypted and by whom; never the plaintext. Record that
permissions changed and what the new grant was; never unrelated private data
about the grantee. `metadata` in particular is a natural place for this
discipline to erode over time (it is free-form), so:

- `metadata` values must describe the fact of the action, not carry
  arbitrary application content.
- Values that are themselves potentially-identifying (e.g. a raw resource
  key/name a caller happens to choose) should be hashed before being placed
  in metadata, not logged verbatim — see the precedent set by
  Cryptography & Keys' `auditFingerprint` helper
  (`apps/mobile/src/capabilities/crypto/auditHash.ts`), 2026-07-16 decision
  log entry "Fix: hash SecureLocalStore key names before they reach audit
  metadata."
- `Emit` enforces a structural size guard (max 32 metadata keys, 128 chars
  per key, 2048 chars per value — see `service.go`'s `validateMetadata`) as
  a lightweight defense against accidental large-content dumping. This is a
  guard, not a substitute for caller discipline — a caller can still put the
  wrong *kind* of data in a small string; that is a code-review concern for
  every capability that calls `audit.Emit`, not something this package can
  fully enforce mechanically.

## Fields

- `event_id` — Purpose: unique, content-addressed identifier for the event; also serves as the tamper-evidence hash-chain link consumed by the next event's `prev_hash` (see the hash-chaining decision log entry). Required for `Query`/`Explain`/export to reference a specific event.
- `actor` — Purpose: records who performed the action (an opaque `identity_ref` string, resolved to a display identity lazily by a caller, not stored here) — the "who" in "who did what, when, by what rule," the minimum needed for Art. 5 explainability and for Art. 1 ownership (a user's own trail is keyed on this field).
- `action` — Purpose: records what kind of action occurred (a short machine-readable action name, e.g. `file.viewed`, `permissions.grant_changed`) — the "what," needed for filtering (`Query`'s `action_filter`) and for `Explain`'s synthesized sentence.
- `resource.resource_type` — Purpose: records what kind of resource the action targeted (e.g. `file`, `conversation`), so a user reviewing "why did something happen to my file" can filter to just that resource type. Opaque string, not a foreign-key join into another capability's storage.
- `resource.resource_id` — Purpose: records which specific resource instance was targeted — needed to answer "show me everything that happened to this exact file," the core `Query`/`Explain` use case named in the charter.
- `rule_reference` — Purpose: records which policy/rule authorized or governed the action (e.g. `permissions.share_grant`), the "by what rule" component of Art. 5 — this is what lets `Explain` say *why* an action was allowed to happen, not just that it happened.
- `metadata` — Purpose: a small, bounded set of additional key/value facts about the action that don't fit the other fields (e.g. `grantee=identity:bob` on a permission-change event) — strictly limited to describing that/how the action happened; never sensitive content itself (see the standing constraint above). Bounded in size (see `validateMetadata`) specifically to keep this field from becoming a dumping ground.
- `occurred_at_unix` — Purpose: records when the action happened (Unix seconds) — the "when" in Art. 5, and the basis for `Query`'s `since_unix`/`until_unix` time-range filters.
- `prev_hash` — Purpose: internal tamper-evidence linkage to the previous event in the global append-order chain (not part of the RPC-facing `AuditEvent` message; excluded from `Query`/`Explain` JSON, but included in the export bundle format so a user can independently verify their trail hasn't been edited, reordered, or had entries silently removed — see charter §6 "Tamper-evidence"). Purpose is integrity, not user-facing content.

## Retention

No automatic deletion or pruning is implemented in this first pass — every
emitted event persists for the lifetime of the in-memory `Store` (or its
eventual durable-storage successor). This is a documented open item, not a
silent gap: charter §7 explicitly defers "retention policy defaults (how
long events are kept, whether a user can prune their own trail)" to
implementation, constrained by Art. 8/9. Because the tamper-evidence design
is a hash chain, any future retention/pruning mechanism must be designed
alongside chain-verification semantics (e.g. a documented "chain segment"
boundary), not bolted on independently — flagged here for whoever picks up
that follow-up.
