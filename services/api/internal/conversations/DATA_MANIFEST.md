# Data Manifest — Conversations

Per `docs/CONSTITUTION.md` Art. 8 (privacy is the default; minimum data
necessary, every collected field has a documented purpose) and the
Conversations charter §4 Art. 8. This is the exhaustive list of fields this
capability collects and stores — transcribed directly from the charter's
own manifest table, not reinvented here.

## Fields

- `conversation_id`
  Purpose: opaque, stable handle to a conversation — routing and reference,
  the only identifier any caller ever needs to address a specific
  conversation (charter §3/§4).

- `participant` (two per `Conversation` record, stored internally in
  canonical sorted order as `participant_lo`/`participant_hi` — see
  `types.go`'s `Conversation` and `store.go`'s `canonicalPair`)
  Purpose: routing and inbox display — unavoidable metadata identifying who
  a conversation is between (charter §4: "purpose: routing and inbox
  display, unavoidable metadata").

- `created_at` (`created_at_unix` on `Conversation`)
  Purpose: ordering/display — when the conversation was established.

- `message_id`
  Purpose: opaque, stable handle to one message — the only identifier any
  caller ever needs to address a specific message (e.g. `ListMessages`'
  `before_message_id` cursor).

- `sender` (`identity_ref`, on `Message`)
  Purpose: delivery and display — who sent this message, required for any
  chat UI and for `SendMessage`'s own authorization check
  (`sender == caller`, `sender` holds the conversation's access grant).

- `ciphertext` (opaque, unreadable, on `Message`)
  Purpose: delivery — the actual message content, already encrypted
  client-side before this capability ever sees it (charter §6). The
  platform cannot and does not attempt to minimize `ciphertext`'s size/shape
  further, since doing so would require understanding content it must never
  understand (charter §4, verbatim).

- `sent_at` (`sent_at_unix`, on `Message`)
  Purpose: delivery and ordering — when this message was received by the
  backend; the basis for `ListMessages`' ascending chronological order and
  `ListConversations`' derived `last_message_at`.

- `session_establishment_payload` (optional, opaque, on `Message`)
  Purpose: delivery — relays the sender's X3DH-style handshake contribution
  (Cryptography & Keys charter §3) byte-for-byte, present only on a
  session-establishing/re-establishing message. Never interpreted by this
  capability (charter §3/§6).

## Not collected / not a data field

- `last_message_at` (on `ConversationSummary`, `ListConversations`' response
  shape) is **derived at query time as `MAX(sent_at)` over a conversation's
  stored messages, never a separately persisted/denormalized field**
  (charter §3/§4 Art. 8) — see `postgres_store.go`'s
  `conversationSummariesForSubject`. Not a collected field; not re-listed
  above.
- `seq` (internal `BIGSERIAL`-backed ordering key on `Message`, `types.go`)
  is this capability's own internal pagination-ordering mechanism — never
  exposed through any RPC response, export document, audit event, or error
  message. Not a field any caller has ever been told exists; not a
  "collected" field in the Art. 8 sense (it carries no information about the
  user beyond message insertion order, which `sent_at`/`message_id` already
  convey through the documented fields above).
- **`CreateConversation`'s `participant` field is never validated against
  Identity's existence** (charter §4, stated explicitly) — it is treated as
  a fully opaque reference, exactly like every other `identity_ref` this
  charter and every prior capability's charter handle. A `participant` value
  that names no real identity simply results in a conversation no one else
  will ever authenticate as. This is the deliberate design, not an
  oversight: validating existence here would create a direct
  platform-wide identity-enumeration oracle (distinguishable
  "exists"/"doesn't exist" responses to an arbitrary `identity_ref` guess)
  with no offsetting benefit, since `CreateConversation` is already bound to
  `creator == caller` (§3) and needs no cross-check against `participant`
  to be safe.
- No read receipts, no delivery receipts, no typing indicators, no message
  previews/snippets are collected or derived server-side in this freeze
  (charter §3/§7) — the server never has plaintext to preview, and an inbox
  preview is necessarily a client-side concern.
- No display name, contact information, or other personal-identity
  attribute beyond `creator`/`participant`/`sender`/`requesting_subject` is
  collected — these are opaque identity-reference strings (Identity's
  format, by convention) this package never resolves against Identity.
- No access-pattern telemetry beyond the `conversations.*` audit events
  this package emits via the injected `AuditEmitter` — not stored twice;
  Audit owns the durable event log, this package never duplicates it.
- Cryptography & Keys is consumed exclusively by the mobile client, never
  by this capability's backend (charter §3) — no key material of any kind
  is ever collected, derived, or stored here.

## Retention

A `Conversation`/`Message` row is retained for as long as its participants'
accounts exist, mirroring every other capability's own retention
precedent. **Known gap, not yet wired**, identical in shape to the one
already flagged by every sibling capability: no account-deletion signal
exists yet from any capability for this package to subscribe to, so full
per-account purge on account deletion is not yet implemented. Tracked as a
follow-up integration point — see `docs/DECISION_LOG.md`.
