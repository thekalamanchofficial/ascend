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
// `"sign:identity"` — deliberately signing-capable, NOT DH-capable. Its job
// is proving *who* an identity/device is (signing device-binding
// assertions for Identity's `BindDevice`), never confidentiality or key
// agreement; nothing calls Encrypt/Decrypt/DeriveSharedSecret with it. An
// earlier version of this module registered it under a bare `"identity"`
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
