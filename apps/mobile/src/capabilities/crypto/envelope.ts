// Encrypt/Decrypt: multi-recipient E2E sealed-envelope construction.
//
// `Encrypt` takes N recipient public keys and one plaintext and must
// produce one ciphertext any of those N recipients (and only those N) can
// decrypt with their own private key handle — a "sealed envelope" /
// multi-recipient hybrid encryption scheme (the same idea age and PGP use
// for multiple recipients): a random per-message symmetric content
// encryption key (CEK) encrypts the plaintext once; the CEK itself is then
// wrapped separately for each recipient via X25519 ECDH + HKDF + AEAD using
// a single ephemeral keypair generated for this message.
//
// Wire format (self-contained, versioned — see ExportKeyMaterial's docs in
// index.ts for the export format; this is the on-the-wire ciphertext
// format, a different concern):
//
//   [1 byte]  version (currently 1)
//   [1 byte]  recipientCount N
//   [32 bytes] ephemeral X25519 public key (shared across all N recipients)
//   N times:
//     [16 bytes] recipient id = SHA-256(recipient public key)[0:16]
//     [24 bytes] per-recipient nonce
//     [48 bytes] wrapped CEK (32-byte CEK + 16-byte Poly1305 tag, XChaCha20-Poly1305)
//   [24 bytes] content nonce
//   [remaining] content ciphertext (plaintext length + 16-byte Poly1305 tag, XChaCha20-Poly1305)
//
// The recipient id lets a decrypting party find "their" wrapped-CEK block
// without brute-forcing every entry, without revealing which public keys
// were addressed to a passive observer of the ciphertext (SHA-256 truncated
// hash, not the public key itself).
import { x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, bytesEqual } from "./bytes";
import { randomBytes } from "./random";

const FORMAT_VERSION = 1;
const RECIPIENT_ID_LEN = 16;
const NONCE_LEN = 24;
const WRAPPED_CEK_LEN = 32 + 16; // CEK bytes + Poly1305 tag
const RECIPIENT_BLOCK_LEN = RECIPIENT_ID_LEN + NONCE_LEN + WRAPPED_CEK_LEN;
const WRAP_INFO = new TextEncoder().encode("ascend-crypto-v1:envelope-wrap");

function recipientId(publicKey: Uint8Array): Uint8Array {
  return sha256(publicKey).slice(0, RECIPIENT_ID_LEN);
}

export function encryptEnvelope(recipientPublicKeys: Uint8Array[], plaintext: Uint8Array): Uint8Array {
  if (recipientPublicKeys.length === 0) {
    throw new Error("Encrypt requires at least one recipient public key.");
  }
  if (recipientPublicKeys.length > 255) {
    throw new Error("Encrypt supports at most 255 recipients per envelope.");
  }
  for (const pk of recipientPublicKeys) {
    if (pk.length !== 32) throw new Error("Recipient public key must be 32 bytes (X25519).");
  }

  const ephemeralPrivate = randomBytes(32);
  const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);
  const cek = randomBytes(32);

  const recipientBlocks = recipientPublicKeys.map((recipientPublic) => {
    const dh = x25519.getSharedSecret(ephemeralPrivate, recipientPublic);
    const wrapKey = hkdf(sha256, dh, undefined, WRAP_INFO, 32);
    const nonce = randomBytes(NONCE_LEN);
    const wrapped = xchacha20poly1305(wrapKey, nonce).encrypt(cek);
    return concatBytes(recipientId(recipientPublic), nonce, wrapped);
  });

  const contentNonce = randomBytes(NONCE_LEN);
  const contentCiphertext = xchacha20poly1305(cek, contentNonce).encrypt(plaintext);

  const header = new Uint8Array([FORMAT_VERSION, recipientPublicKeys.length]);
  return concatBytes(header, ephemeralPublic, ...recipientBlocks, contentNonce, contentCiphertext);
}

export function decryptEnvelope(privateKey: Uint8Array, publicKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (ciphertext.length < 2 + 32 + NONCE_LEN) {
    throw new Error("Ciphertext is too short to be a valid envelope.");
  }
  let offset = 0;
  const version = ciphertext[offset];
  offset += 1;
  if (version !== FORMAT_VERSION) {
    throw new Error(`Unsupported envelope format version: ${version}.`);
  }
  const recipientCount = ciphertext[offset];
  offset += 1;
  const ephemeralPublic = ciphertext.slice(offset, offset + 32);
  offset += 32;

  const expectedMinLength = offset + recipientCount * RECIPIENT_BLOCK_LEN + NONCE_LEN;
  if (ciphertext.length < expectedMinLength) {
    throw new Error("Ciphertext is truncated or malformed.");
  }

  const myId = recipientId(publicKey);
  let cek: Uint8Array | null = null;
  for (let i = 0; i < recipientCount; i++) {
    const block = ciphertext.slice(offset, offset + RECIPIENT_BLOCK_LEN);
    offset += RECIPIENT_BLOCK_LEN;
    const id = block.slice(0, RECIPIENT_ID_LEN);
    if (bytesEqual(id, myId)) {
      const nonce = block.slice(RECIPIENT_ID_LEN, RECIPIENT_ID_LEN + NONCE_LEN);
      const wrapped = block.slice(RECIPIENT_ID_LEN + NONCE_LEN);
      const dh = x25519.getSharedSecret(privateKey, ephemeralPublic);
      const wrapKey = hkdf(sha256, dh, undefined, WRAP_INFO, 32);
      cek = xchacha20poly1305(wrapKey, nonce).decrypt(wrapped);
    }
  }
  if (!cek) {
    throw new Error("This private key handle is not an intended recipient of this ciphertext.");
  }

  const contentNonce = ciphertext.slice(offset, offset + NONCE_LEN);
  offset += NONCE_LEN;
  const contentCiphertext = ciphertext.slice(offset);
  return xchacha20poly1305(cek, contentNonce).decrypt(contentCiphertext);
}
