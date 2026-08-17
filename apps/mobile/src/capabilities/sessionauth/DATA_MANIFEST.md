# Data Manifest — Session / Request Authentication (mobile client)

Per `docs/CONSTITUTION.md` Art. 8 (privacy is the default; minimum data,
documented purpose) and
`docs/capabilities/session-authentication.charter.md` §4.

This directory (`apps/mobile/src/capabilities/sessionauth/`) is a thin HTTP
client for the real Session/Request Authentication capability implemented
in `services/api/internal/sessionauth` — the authoritative manifest for
what is *collected and stored server-side* is
`services/api/internal/sessionauth/DATA_MANIFEST.md`. This client-side
manifest documents the narrower question that one doesn't cover: what does
*this module* transmit or hold, and why — every field below is already
documented, with the same purpose, on the server side; nothing here is new
collection.

## Fields

- `identityRef` / `deviceId`
  Purpose: server-issued opaque identifiers, sent to scope a challenge/
  session to a specific bound device. Not generated or interpreted by this
  module.

- `challengeNonce`
  Purpose: server-generated freshness value (from `getSessionChallenge`),
  echoed back unmodified as part of the signed `issueSession` message. This
  module treats it as an opaque string throughout — it is never decoded,
  inspected, or persisted beyond the single request/response round trip
  that produces and consumes it.

- `proof`
  Purpose: an Ed25519 signature (produced by Cryptography & Keys' `sign()`,
  never by this module) over the canonical IssueSession message, proving
  possession of the bound device's private key. Carries no data beyond the
  signature bytes.

- `sessionToken` / `callerSessionToken`
  Purpose: the opaque bearer credential itself, obtained from
  `issueSession` and required by this module's own callers (the onboarding
  orchestration layer, `apps/mobile/src/features/onboarding/`) to
  authorize every subsequent gated request. This module never generates,
  decodes, or inspects the token's contents — it is an opaque string
  handed to `Authorization: Bearer` headers or specific body fields exactly
  as received.

## Fields held locally by this module

None. This module is stateless — it shapes a request, calls the real
backend, and returns a parsed response. It never itself persists a
`sessionToken` to `SecureLocalStore`; that is the onboarding orchestration
layer's responsibility (which reuses Cryptography & Keys' `secureLocalStore`
rather than reimplementing local storage here), documented in that layer's
own manifest.

## Explicitly out of scope (not collected)

- No IP address, geolocation, or device hardware fingerprint of any kind.
- No user agent string.
- No password, email, or any other credential — the only thing this
  module ever sends to authenticate is a fresh Ed25519 signature
  (`proof`), computed by Cryptography & Keys, never by this module.
- No private key material of any kind ever passes through this module.

## Notes

- The client-side `logAuditEvent` calls in `audit.ts`/`index.ts` are a
  local dev-visibility and mechanical-CI-convention stub, not this
  capability's Art. 5 audit trail of record — see `audit.ts`'s header
  comment. The real audit trail is emitted server-side by
  `services/api/internal/sessionauth/service.go` for `IssueSession`,
  `RevokeSession`, and `RevokeAllSessions`, scoped to the server-verified
  caller, independent of anything this client module does or fails to do.
  This module never logs a raw `sessionToken`/`challengeNonce` to any
  audit call, local or remote.
