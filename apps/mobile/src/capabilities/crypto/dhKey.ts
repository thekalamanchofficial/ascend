// The identity's DH-capable (X25519) key — charter §3's required key-
// separation fix, superseding the original (unsafe) design.
//
// CORRECTS 2026-08-21 (docs/DECISION_LOG.md, "Key-separation fix" series;
// docs/capabilities/cryptography-and-keys.charter.md §3 "Required fix"):
// the first implementation reused the identity's Ed25519 signing scalar for
// X3DH's DH terms via a birational Ed25519->X25519 (Montgomery) conversion
// (`ed25519.utils.toMontgomerySecret`/`toMontgomery`, formerly used in
// ratchet.ts). Security Steward's implementation-merge-gate veto found this
// a real NIST SP 800-57 key-separation violation against the platform's
// highest-blast-radius key: reusing one long-term scalar for both standard
// EdDSA signing AND raw X25519 DH against network-facing, attacker-
// influenced public values. The XEdDSA precedent cited to justify it does
// not transfer (XEdDSA starts from an X25519 key and defines a *custom*
// signing scheme with compensating engineering; this codebase did the
// mirror-image thing with none of that engineering).
//
// Required fix, implemented here exactly as charter §3 specifies: derive a
// genuinely separate DH-capable scalar deterministically from the same
// recovery-phrase seed via a domain-separated KDF —
//   dh_scalar = HKDF(seed, "ascend-x3dh-dh-key")
//   identity_dh_public_key = X25519.getPublicKey(dh_scalar)
// — never the signing scalar, never a birational conversion of it. This
// preserves "one root secret, multiple deterministic representations" (no
// new secret to generate, back up, or lose) while genuinely separating the
// signing and DH key-usage domains.
//
// `seed` — precisely defined, per charter §3's own round-2 correction (a
// prior looser reading would have re-derived dh_scalar from the CLAMPED
// Ed25519 signing scalar, silently reintroducing the exact cross-key-
// compromise coupling this fix exists to remove via a different mechanism):
// the raw, recovery-phrase-derived bytes fed into Ed25519 key generation,
// taken BEFORE RFC 8032's internal SHA-512 hash-and-clamp step — i.e. the
// *seed*, not the derived signing scalar. Concretely, in this codebase that
// is exactly the value `mnemonic.deriveIdentityPrivateKeyFromPhrase(phrase)`
// returns (for a fresh identity) or the equivalent freshly-generated CSPRNG
// bytes (see index.ts's `generateIdentityKeyMaterial`) — the same bytes
// stored, unmodified, as `privateKey` on the identity's "sign:identity"
// KeyRegistry entry. `ed25519.getPublicKey`/`ed25519.sign` perform RFC
// 8032's hash-and-clamp internally on THOSE bytes; this module never
// touches the clamped scalar at all, only the pre-clamp seed — see
// docs/DECISION_LOG.md, 2026-08-22, "Key-separation fix implementation:
// `dhKey.ts`, `ratchet.ts`, `index.ts` — the mobile side of the eight-round
// design fix" for the direct trace confirming this.
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

/** HKDF info/context literal — charter §3's required domain separation for the DH-capable identity scalar. */
export const X3DH_DH_KEY_INFO = new TextEncoder().encode("ascend-x3dh-dh-key");

/**
 * Derives the X25519 DH-capable scalar from the identity's raw seed bytes.
 * `seed` MUST be the pre-clamp Ed25519 seed (see module header) — passing
 * the clamped signing scalar instead would reintroduce the coupling this
 * fix removes.
 */
export function deriveDhScalar(seed: Uint8Array): Uint8Array {
  return hkdf(sha256, seed, undefined, X3DH_DH_KEY_INFO, 32);
}

/** Derives the identity's X25519 DH-capable public key directly from the seed. */
export function deriveDhPublicKey(seed: Uint8Array): Uint8Array {
  return x25519.getPublicKey(deriveDhScalar(seed));
}
