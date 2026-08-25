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

- `signedPrekey` (`prekeyId`/`publicKey`/`signature`/`createdAtUnix`) /
  `oneTimePrekeys[]` (`prekeyId`/`publicKey`)
  (added 2026-08-20, prekey bundle publish/fetch amendment)
  Purpose: already-public, already-signed bytes produced by Cryptography &
  Keys' `generatePrekeyBundle` (private halves never pass through this
  module — see that capability's own manifest). `publishPrekeyBundle`
  sends these; `fetchPrekeyBundle` receives a `signedPrekey` and,
  optionally, one `oneTimePrekey` back for a DIFFERENT identity's device.
  This module base64-encodes/decodes but never generates, signs, or
  inspects the key material itself.

- `unconsumedOneTimePrekeyCount` (on `Device`, added 2026-08-20)
  Purpose: same as the server-side manifest's entry of the same name — a
  self-only, count-only passive signal, received via `listDevices`, never
  sent by this module.

- `identityDhPublicKey` / `identityDhPublicKeySignature`
  (added 2026-08-21, key-separation fix)
  Purpose: already-public, already-signed bytes produced by Cryptography &
  Keys' `generatePrekeyBundle` (identically-named response fields; the
  corresponding X25519 private key never passes through this module — see
  that capability's own manifest). `publishPrekeyBundle` sends the calling
  device's own values; `fetchPrekeyBundle` receives a DIFFERENT identity's
  device's values back. Genuinely distinct from `publicKey` above (that is
  the identity's Ed25519 *signing* key) — this module never conflates the
  two, and never generates, signs, or verifies either value itself.

- `identitySigningPublicKey` (on `FetchPrekeyBundleResponse`, added
  2026-08-21, same fix)
  Purpose: the target identity's Ed25519 signing public key, received via
  `fetchPrekeyBundle` so a caller can verify `signedPrekey`/
  `identityDhPublicKey`'s signatures without a second `resolveIdentity`
  round trip. Identical in kind to `publicKey` above — not a new category
  of data, just delivered on a different response.

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
