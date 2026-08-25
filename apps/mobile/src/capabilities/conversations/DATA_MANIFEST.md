# Data Manifest — Conversations (mobile client)

Per `docs/CONSTITUTION.md` Art. 8 (privacy is the default; minimum data,
documented purpose) and `docs/capabilities/conversations.charter.md` §4.

This directory (`apps/mobile/src/capabilities/conversations/`) is a thin
HTTP client for the real Conversations capability implemented in
`services/api/internal/conversations` — the authoritative manifest for what
is *collected and stored server-side* is that package's own
`DATA_MANIFEST.md`. This client-side manifest documents the narrower
question that one doesn't cover: what does *this module* transmit, and
why — every field below is already documented, with the same purpose, on
the server side; nothing here is new collection.

## Fields

- `creator` / `participant` / `sender` / `requestingSubject` / `otherParticipant`
  Purpose: server-issued opaque identity-reference strings (Identity's
  format), sent so the server knows which identity is acting and, for
  `participant`, who a conversation is being started with. Not generated,
  resolved, or interpreted by this module — always caller-supplied (the
  current identity's own `identityRef`, or an `identity_ref` the user typed
  in — see `apps/mobile/src/features/conversations/screens/StartConversationScreen.tsx`'s
  own documented no-discovery limitation, matching `ShareFileScreen`'s
  precedent).

- `conversationId` / `messageId`
  Purpose: server-issued opaque identifiers, echoed back to the server on
  subsequent calls so a gated request knows which conversation/message it
  concerns. Not generated or interpreted by this module.

- `ciphertext`
  Purpose: the actual message content, already end-to-end encrypted
  client-side by Cryptography & Keys (`crypto.encryptMessage`) BEFORE it
  ever reaches this module — this module treats it as fully opaque bytes,
  base64-encodes it for transmission, and never inspects, decrypts, or logs
  it (see `audit.ts`'s hard rule).

- `sessionEstablishmentPayload`
  Purpose: opaque bytes carrying the sender's X3DH handshake contribution
  (see `sessionPayload.ts`), present only on a session-establishing
  message. Entirely opaque to this module and to the real backend alike
  (charter §3/§6) — this module relays it byte-for-byte, never parses,
  logs, or interprets its contents itself (parsing happens only in
  `apps/mobile/src/features/conversations/`, the feature-composition
  layer, which is a strictly separate module from this one).

- `beforeMessageId` / `limit`
  Purpose: pagination cursor/page-size for `listMessages` — caller-supplied
  paging state, not itself collected/retained by this module beyond the
  single request it shapes.

- `sentAtUnix` / `createdAtUnix` / `lastMessageAtUnix` (received only)
  Purpose: display/ordering only — server-computed timestamps echoed back
  by `listMessages`/`listConversations`/`getConversation`/`createConversation`.
  `lastMessageAtUnix` is always derived server-side at query time (charter
  §3/§4 Art. 8), never a value this module sends.

- `exportBlob` / `formatVersion` (received only, via `exportConversation`)
  Purpose: this capability's own stored bytes, byte-for-byte, for the
  Art. 9 layer-one export (see `index.ts`'s doc comment) — display/save
  only, never re-transmitted or interpreted by this module.

## Fields held locally by this module

None. This module is stateless — it shapes a request, calls the real
backend, and returns a parsed response; it does not itself persist
anything to `SecureLocalStore` or any other store.

**Local plaintext message history, the `conversationId -> sharedSecretHandle`
session-cache mapping, and this device's own cached `identityDhPublicKey`/
`identityDhPublicKeySignature` are held ELSEWHERE, deliberately not by this
module** — by `apps/mobile/src/features/conversations/` (a feature-
composition layer, not a capability, per `CLAUDE.md`'s "capabilities vs.
features"), all via Cryptography & Keys' `secureLocalStore`/
`secureLocalRetrieve` (charter §4/§6's binding requirement — never
`AsyncStorage`, never a plain SQLite table). See that layer's own source
comments (`localHistory.ts`, `session.ts`) for the field-level accounting
of what's stored there and why; this manifest only speaks for what THIS
thin-client module collects and transmits, which is nothing beyond the
single request/response round trips documented above.

## Explicitly out of scope (not collected)

- No message content is ever readable by this module — `ciphertext` is
  opaque bytes end to end, exactly mirroring the server-side charter's own
  structural-incapability claim (§6).
- No read receipts, delivery receipts, typing indicators, or message
  previews are collected, sent, or requested by this module (charter §4/§7)
  — the server's contract has no fields for any of these, so this module
  has no way to construct a request naming one even by mistake.
- No device/hardware fingerprint, IP address, or geolocation.
- No search/discovery data — this pass ships no query capability over
  conversation participants/content; `listConversations` returns a
  caller's own full inventory only (see `index.ts`'s own doc comment).

## Notes

- The client-side `logAuditEvent` calls in `audit.ts`/`index.ts` are a
  local dev-visibility and mechanical-CI-convention stub, not this
  capability's Art. 5 audit trail of record — see `audit.ts`'s header
  comment. The real audit trail is emitted server-side by
  `services/api/internal/conversations/service.go` for every mutating RPC
  and for every denied participant-gated read/write attempt, scoped to the
  server-verified caller, independent of anything this client module does
  or fails to do.
- `sessionPayload.ts`'s `encodeSessionEstablishmentPayload`/
  `decodeSessionEstablishmentPayload` never touch the network or any local
  store themselves — pure byte (en/de)coding, re-exported from `index.ts`
  for the feature-composition layer's convenience, not a second collection
  surface.
