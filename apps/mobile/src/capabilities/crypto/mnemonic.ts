// Deterministic recovery-phrase <-> identity-key derivation.
//
// Charter §3: "There is exactly one root secret, with two representations:
// the opaque on-device handle and the human-writable phrase" — the phrase
// IS the seed; public_key/private_key_handle are derived from it, never a
// second independently-generated secret. This is what makes
// RestoreFromRecoveryPhrase a pure offline computation with no server
// involvement (decision log, 2026-07-06 "Recovery mechanism").
//
// BIP-39 is used purely as a well-reviewed entropy<->mnemonic encoding; we
// are not building a cryptocurrency wallet and do not use BIP-32/44
// hierarchical derivation. One phrase deterministically derives exactly one
// identity private-key seed via HKDF-SHA256 over the BIP-39 seed, with a
// domain-separation info string scoped to this capability + purpose so the
// same phrase could in principle seed other domain-separated secrets later
// without collision, should that ever be needed. That 32-byte seed is
// turned into an Ed25519 signing keypair by index.ts (the identity root
// key's job is proving who an identity/device is — signing device-binding
// assertions — not confidentiality/key agreement; see
// docs/DECISION_LOG.md, 2026-07-16 "Fix: identity root key must be Ed25519
// (signing-capable), not X25519"). This module only produces the raw seed
// bytes and stays curve-agnostic — it doesn't call getPublicKey itself.
import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
// @scure/bip39 declares an explicit "exports" map in package.json that
// requires the literal ".js" suffix on this subpath (Node enforces this at
// require-time for both CJS and ESM); dropping the suffix resolves fine
// under TypeScript's classic file-probing but throws
// ERR_PACKAGE_PATH_NOT_EXPORTED at runtime, so the extension is required
// here even though it looks redundant next to the extensionless import
// above.
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "./random";

// 256 bits of entropy -> a 24-word BIP-39 mnemonic. This is the root
// identity secret for the lifetime of the account, so we use the strongest
// standard BIP-39 entropy size rather than the more common 128-bit/12-word
// convenience tier.
const RECOVERY_ENTROPY_BYTES = 32;

const IDENTITY_HKDF_INFO = new TextEncoder().encode("ascend-crypto-v1:identity-ed25519");

export function generateRecoveryPhrase(): string {
  const entropy = randomBytes(RECOVERY_ENTROPY_BYTES);
  return entropyToMnemonic(entropy, wordlist);
}

export function isValidRecoveryPhrase(phrase: string): boolean {
  return validateMnemonic(phrase, wordlist);
}

/**
 * Deterministically derives the 32-byte identity private-key seed from a
 * recovery phrase. Same phrase in -> same bytes out, always — this is the
 * property RestoreFromRecoveryPhrase and GenerateIdentityKeyMaterial both
 * depend on, and the property under direct test in
 * __tests__/crypto.test.ts. The caller (index.ts) turns this seed into an
 * Ed25519 signing keypair via `ed25519.getPublicKey`, which performs
 * whatever internal seed expansion/clamping Ed25519 requires — this
 * function itself is curve-agnostic and does no clamping of its own.
 */
export function deriveIdentityPrivateKeyFromPhrase(phrase: string): Uint8Array {
  if (!isValidRecoveryPhrase(phrase)) {
    throw new Error("Invalid recovery phrase: fails BIP-39 wordlist/checksum validation.");
  }
  // BIP-39 seed derivation (PBKDF2-HMAC-SHA512, 2048 rounds, empty
  // passphrase) — standard, deterministic, no external input.
  const seed = mnemonicToSeedSync(phrase);
  // HKDF-SHA256 down to a 32-byte seed, domain-separated so this phrase
  // could in principle seed other purposes later without key reuse across
  // purposes.
  return hkdf(sha256, seed, undefined, IDENTITY_HKDF_INFO, 32);
}
