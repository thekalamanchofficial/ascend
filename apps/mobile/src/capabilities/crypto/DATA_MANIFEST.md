# Data Manifest — Cryptography & Keys

Per `docs/CONSTITUTION.md` Art. 8 (privacy is the default; minimum data,
documented purpose) and `docs/capabilities/cryptography-and-keys.charter.md`
§4: "the data manifest for this capability documents exactly zero collected
fields beyond public keys."

This capability is implemented entirely on-device
(`apps/mobile/src/capabilities/crypto/`) and has no server component and no
network client of any kind (see `index.ts`'s own header comment). There is
no database and nothing is "collected" in the usual sense this manifest
format assumes for a backend capability. The relevant boundary here is
different but the same in spirit: what does this module ever hand *out* —
to its callers (other capabilities), and from there potentially onward to
the rest of the platform, including a server? That crossing point is what
this manifest documents.

## Fields

- `public_key`
  Purpose: the only cryptographic material this capability ever exposes
  beyond its own boundary. `GenerateIdentityKeyMaterial`, `GenerateKeyPair`,
  and `RestoreFromRecoveryPhrase` all return a public key to their caller
  so other capabilities (Identity, Messaging, etc.) and other users can
  address this device/identity, verify its signatures (`Sign`), and
  encrypt to it (`Encrypt`). Public keys are not secret by construction —
  this is the capability's one intended, documented crossing point, not an
  incidental leak.

## Explicitly out of scope (structurally never collected — not merely "not currently collected")

- **No private key material of any kind ever leaves this module in
  plaintext.** `GenerateIdentityKeyMaterial`, `GenerateKeyPair`, and
  `RestoreFromRecoveryPhrase` return only an opaque `KeyHandle` (`{ handle:
  string }`) alongside the public key — never the private key bytes
  themselves (`keyRegistry.ts` is the only place private key bytes are
  held, in an in-memory, non-exported map). The one narrow, deliberate
  exception is `ExportKeyMaterial`: an explicit, user-confirmed operation
  (Art. 9) whose entire purpose is letting the user take their own private
  key material with them. Even there, the recipient is the user themselves
  via a direct return value, never a network call, and the operation
  refuses to run at all without `user_confirmation: true` (and now audits
  the refusal — see docs/DECISION_LOG.md, 2026-07-16 "Fix: audit
  rejected/failed attempts, not just successes").
- **No plaintext of anything this capability encrypts or decrypts is ever
  retained** after an `Encrypt`/`Decrypt` call returns. There is no
  plaintext-holding field, cache, or store anywhere in this module.
- **No recovery phrase is ever persisted or logged, in any form.**
  `generateRecoveryPhrase()`'s output is returned once, directly, to the
  immediate caller of `GenerateIdentityKeyMaterial`, and is never written
  to `SecureLocalStore`, never included in `ExportKeyMaterial`'s blob (see
  that function's own doc comment in `index.ts`), and never passed to
  `logAuditEvent` — `audit.ts`'s own doc comment states this as a hard
  rule for every call site in this module, present and future.
  `RestoreFromRecoveryPhrase` takes a phrase as input and derives key
  material from it in memory; the phrase itself is not retained after the
  call returns.
- No email, phone number, device hardware fingerprint, IP address, or
  geolocation — this capability has no concept of any of those. It
  operates purely on caller-supplied key handles, purpose strings, and
  byte buffers.
- Nothing in this module makes a network call of any kind, so "collected
  by the server" is not merely minimized here, it is structurally
  impossible for this capability's own code to cause it.

## Notes

- Audit metadata (the `logAuditEvent` calls throughout `index.ts`, each
  marked `// ascend:mutates` on the function that emits it) is a
  companion to this manifest, not a second, undocumented collection
  surface: it is documented in `audit.ts` as never carrying key material,
  plaintext, or the recovery phrase — only opaque handle strings,
  purposes, outcomes, and truncated SHA-256 fingerprints
  (`auditHash.ts`'s `auditFingerprint`) of otherwise-sensitive values such
  as a `SecureLocalStore` key name (see docs/DECISION_LOG.md, 2026-07-16
  "Fix: hash SecureLocalStore key names before they reach audit
  metadata").
- `SecureLocalStore`/`SecureLocalRetrieve` (`secureStore.ts`) hold
  arbitrary caller-supplied `value` bytes at another capability's request
  (e.g. a capability storing its own encrypted local state). This
  capability does not inspect, interpret, or document the *content* of
  those values — it has no visibility into what they represent — and only
  guarantees they are never held in plaintext at rest (OS Keychain/
  Keystore via `expo-secure-store`, or an encrypted software-vault
  fallback; see docs/DECISION_LOG.md, 2026-07-16 "SecureLocalStore/
  Retrieve: OS keychain primary, in-memory-by-default software vault
  fallback, pluggable key-provider hook"). Documenting the purpose of
  whatever a *caller* chooses to store there is that caller capability's
  own Art. 8 obligation, not this one's.
