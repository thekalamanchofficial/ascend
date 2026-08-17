# Data Manifest — Identity (mobile client)

Per `docs/CONSTITUTION.md` Art. 8 (privacy is the default; minimum data,
documented purpose) and `docs/capabilities/identity.charter.md` §4.

This directory (`apps/mobile/src/capabilities/identity/`) is a thin HTTP
client for the real Identity capability implemented in
`services/api/internal/identity` — the authoritative manifest for what is
*collected and stored server-side* is
`services/api/internal/identity/DATA_MANIFEST.md`. This client-side
manifest documents the narrower question that one doesn't cover: what does
*this module* transmit, and why — every field below is already documented,
with the same purpose, on the server side; nothing here is new collection.

## Fields

- `displayName`
  Purpose: user-supplied at identity creation, shown to other users so
  they know who they're communicating with. Sent once, at `createIdentity`.

- `publicKey` / `firstDevicePublicKey` / `devicePublicKey`
  Purpose: cryptographic material generated on-device by Cryptography &
  Keys (`generateIdentityKeyMaterial`/`generateKeyPair`), needed to bind
  devices and verify signatures. This module only base64-encodes and
  transmits already-generated public keys — it never generates, inspects,
  or holds the corresponding private key material.

- `firstDeviceName` / `deviceName`
  Purpose: user-supplied, lets the user tell their own devices apart on
  the Devices screen.

- `authorizationProof`
  Purpose: an Ed25519 signature (produced by Cryptography & Keys' `sign()`,
  never by this module) over the canonical BindDevice message, proving
  possession of a private key. Carries no data beyond the signature bytes.

- `identityRef` / `deviceId`
  Purpose: server-issued opaque identifiers, echoed back to the server on
  subsequent calls (URL path segments) so the server knows which identity/
  device a gated request concerns. Not generated or interpreted by this
  module.

## Fields held locally by this module

None. This module is stateless — it shapes a request, calls the real
backend, and returns a parsed response; it does not itself persist
anything to `SecureLocalStore` or any other store. Local persistence of
`identityRef`/`epoch`/`deviceId`/session state for session-bootstrap
purposes is the onboarding orchestration layer's responsibility
(`apps/mobile/src/features/onboarding/`), documented in that layer's own
manifest.

## Explicitly out of scope (not collected)

- No email, phone number, or other contact identifier.
- No IP address, geolocation, or device hardware fingerprint — this module
  sends only what the Identity capability's frozen contract defines.
- No private key material of any kind ever passes through this module —
  `bindDevice`/`createIdentity`'s callers must supply an already-computed
  `authorizationProof` (a signature) and already-generated public keys;
  this module never calls Cryptography & Keys' `sign`/`generateKeyPair`
  itself, and never sees a `KeyHandle` or private key bytes.

## Notes

- The client-side `logAuditEvent` calls in `audit.ts`/`index.ts` are a
  local dev-visibility and mechanical-CI-convention stub, not this
  capability's Art. 5 audit trail of record — see `audit.ts`'s header
  comment. The real audit trail is emitted server-side by
  `services/api/internal/identity/service.go` for every mutating RPC,
  scoped to the server-verified caller, independent of anything this
  client module does or fails to do.
