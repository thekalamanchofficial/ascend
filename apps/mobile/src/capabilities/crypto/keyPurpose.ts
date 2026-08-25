// Purpose-string convention distinguishing signing-capable key handles
// (Ed25519) from DH-capable key handles (X25519).
//
// `GenerateKeyPairRequest` (packages/contracts/proto/ascend/crypto/v1/crypto.proto)
// only carries a free-form `purpose: string` — there is no separate
// key-type/algorithm field, and adding one would be a contract amendment.
// Ed25519 (signing) and X25519 (Diffie-Hellman) are different curves with
// different private-key semantics: the same 32 raw bytes produce two
// DIFFERENT, unrelated public keys depending which curve derives them (see
// docs/DECISION_LOG.md, 2026-07-16 "Sign RPC: Ed25519, purpose-namespaced
// key-type convention" — confirmed directly against @noble/curves before
// relying on it). Reusing one key's bytes across both purposes would be a
// textbook key-reuse-across-algorithms mistake, and silently signing with
// what the caller thinks is a DH key (or vice versa) would produce a
// signature/shared-secret that doesn't correspond to the public key the
// caller was given at generation time — a correctness bug with a real
// security consequence, not just a type error.
//
// Convention: a purpose string beginning with the `"sign:"` prefix
// requests (and, on lookup, requires) a signing-capable Ed25519 key handle.
// Every other purpose is DH-capable X25519, usable with
// Decrypt/DeriveSharedSecret but never Sign.
//
// The identity root key (GenerateIdentityKeyMaterial/
// RestoreFromRecoveryPhrase) is registered under the reserved purpose
// `"sign:identity"` — deliberately signing-capable, NOT DH-capable at
// generation time. Its primary job is proving *who* an identity/device is
// (signing device-binding assertions for Identity's `BindDevice`).
//
// CORRECTED 2026-08-20 (Constitution Warden implementation-gate finding on
// the responder-side prekey-completion amendment — this paragraph
// previously claimed "nothing calls Encrypt/Decrypt/DeriveSharedSecret with
// it," which the amendment made false): `deriveSharedSecret`/
// `completeSharedSecret` now *require* the identity key handle specifically
// and reject any other handle — the X3DH construction those charter-specify
// (docs/capabilities/cryptography-and-keys.charter.md §3, §6) needs a
// DH-capable identity key.
//
// CORRECTED AGAIN 2026-08-21 (key-separation fix, docs/DECISION_LOG.md's
// "Key-separation fix" series — the outcome of an eight-round guardian-gate
// correction; charter §3 "Required fix"): a first implementation reused the
// identity's Ed25519 signing scalar for DH via a birational Ed25519->X25519
// (Montgomery-form) conversion at the point of use, citing Signal's XEdDSA
// as precedent. Security Steward's implementation-merge-gate veto found
// that citation factually inaccurate and the underlying design a real NIST
// SP 800-57 key-separation violation against the platform's highest-
// blast-radius key — reusing one long-term scalar for both standard EdDSA
// signing AND raw X25519 DH against network-facing, attacker-influenced
// public values, with none of XEdDSA's own compensating engineering.
//
// The actual, now-frozen construction (see dhKey.ts): the identity key
// handle registered here under `"sign:identity"` still stores the raw,
// pre-RFC-8032-clamp seed (as it always has — this module's registration
// behavior is unchanged); what changed is how a DH-capable key is derived
// FROM that seed when one is needed. `deriveSharedSecret`/
// `completeSharedSecret` derive a genuinely separate DH-only scalar via a
// domain-separated KDF — `dh_scalar = HKDF(seed, "ascend-x3dh-dh-key")`,
// `identity_dh_public_key = X25519.getPublicKey(dh_scalar)` — computed
// fresh from the seed each time, never stored as a second key handle and
// never derived via any birational conversion of the Ed25519 scalar. This
// preserves "one root secret, multiple deterministic representations" (no
// new secret to generate, back up, or lose) while genuinely separating the
// signing and DH key-usage domains, closing the key-reuse violation. See
// docs/DECISION_LOG.md, 2026-08-22, "Key-separation fix implementation:
// `dhKey.ts`, `ratchet.ts`, `index.ts` — the mobile side of the eight-round
// design fix" for the full reasoning and the confirmation that `seed` here
// really is the pre-clamp bytes, not the derived signing scalar.
//
// An earlier version of this module registered it under a bare `"identity"`
// purpose and derived it as X25519, which made it silently unable to ever
// back a real signature — Sign() correctly rejected it, meaning the
// recovery-derived device-binding assertion (the one path Security Steward
// scrutinized hardest, because it's the only one that survives total
// device loss) could never actually be produced. See
// docs/DECISION_LOG.md, 2026-07-16 "Fix: identity root key must be Ed25519
// (signing-capable), not X25519".
//
// Other signing-capable keys (e.g. a per-device signing key) should use a
// purpose like `GenerateKeyPair({ purpose: "sign:device-binding" })`.
export const SIGNING_PURPOSE_PREFIX = "sign:";

export function isSigningPurpose(purpose: string): boolean {
  return purpose.startsWith(SIGNING_PURPOSE_PREFIX);
}
