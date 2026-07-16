// Cryptography & Keys — public capability module.
//
// Implements every operation in
// packages/contracts/proto/ascend/crypto/v1/crypto.proto, entirely
// on-device. There is no server component: nothing in this module makes a
// network call, and no function here ever transmits plaintext, private key
// material, or a recovery phrase anywhere.
//
// Constitutional grounding for the whole module (see
// docs/capabilities/cryptography-and-keys.charter.md §4):
//   Art. 1 — private keys are generated and remain on-device.
//   Art. 7 — no server-side key escrow is possible; there is no server path.
//   Art. 8 — zero fields collected by a server; nothing here is transmitted.
//   Art. 9 — ExportKeyMaterial guarantees the user is never locked out of
//            their own cryptographic identity by the platform.
import { x25519 } from "@noble/curves/ed25519.js";
import * as keyRegistry from "./keyRegistry";
import * as mnemonic from "./mnemonic";
import { encryptEnvelope, decryptEnvelope } from "./envelope";
import { initRatchetSession } from "./ratchet";
import { secureLocalStore as storeSecureLocal, secureLocalRetrieve as retrieveSecureLocal } from "./secureStore";
import { logAuditEvent } from "./audit";
import { bytesToBase64 } from "./bytes";
import { randomBytes } from "./random";
import { auditFingerprint as fingerprint } from "./auditHash";
import type {
  GenerateIdentityKeyMaterialRequest,
  GenerateIdentityKeyMaterialResponse,
  GenerateKeyPairRequest,
  GenerateKeyPairResponse,
  EncryptRequest,
  EncryptResponse,
  DecryptRequest,
  DecryptResponse,
  DeriveSharedSecretRequest,
  DeriveSharedSecretResponse,
  SecureLocalStoreRequest,
  SecureLocalStoreResponse,
  SecureLocalRetrieveRequest,
  SecureLocalRetrieveResponse,
  RestoreFromRecoveryPhraseRequest,
  RestoreFromRecoveryPhraseResponse,
  ExportKeyMaterialRequest,
  ExportKeyMaterialResponse,
  KeyHandle,
} from "./types";

export * from "./types";

// `fingerprint` (aliased from auditHash.ts's `auditFingerprint`) is the
// shared short, non-reversible identifier used everywhere in this module
// that audit metadata needs to reference a public key or other sensitive
// value without exposing it — see auditHash.ts.

// ---------------------------------------------------------------------------
// GenerateIdentityKeyMaterial
// ---------------------------------------------------------------------------

export function generateIdentityKeyMaterial(
  _request: GenerateIdentityKeyMaterialRequest = {},
): GenerateIdentityKeyMaterialResponse {
  const recoveryPhrase = mnemonic.generateRecoveryPhrase();
  const privateKey = mnemonic.deriveIdentityPrivateKeyFromPhrase(recoveryPhrase);
  const publicKey = x25519.getPublicKey(privateKey);
  const privateKeyHandle = keyRegistry.registerPrivateKey("identity", privateKey, publicKey);

  logAuditEvent("identity_key_generated", {
    handle: privateKeyHandle.handle,
    publicKeyFingerprint: fingerprint(publicKey),
  });

  // recoveryPhrase is returned to the caller and never stored, logged, or
  // otherwise retained by this module beyond this return value.
  return { publicKey, privateKeyHandle, recoveryPhrase };
}

// ---------------------------------------------------------------------------
// GenerateKeyPair
// ---------------------------------------------------------------------------

export function generateKeyPair(request: GenerateKeyPairRequest): GenerateKeyPairResponse {
  if (!request.purpose) {
    logAuditEvent("key_pair_generation_rejected", { reason: "empty_purpose" });
    throw new Error("GenerateKeyPair requires a non-empty purpose.");
  }
  // Non-recovery-bearing key (charter §3): fresh CSPRNG output only, never
  // derived from a phrase, unlike the identity key above.
  const privateKey = randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);
  const privateKeyHandle = keyRegistry.registerPrivateKey(request.purpose, privateKey, publicKey);

  logAuditEvent("key_pair_generated", {
    handle: privateKeyHandle.handle,
    purpose: request.purpose,
    publicKeyFingerprint: fingerprint(publicKey),
  });

  return { publicKey, privateKeyHandle };
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

export function encrypt(request: EncryptRequest): EncryptResponse {
  const ciphertext = encryptEnvelope(request.recipientPublicKeys, request.plaintext);
  return { ciphertext };
}

export function decrypt(request: DecryptRequest): DecryptResponse {
  const entry = keyRegistry.getPrivateKeyEntry(request.privateKeyHandle);
  const plaintext = decryptEnvelope(entry.privateKey, entry.publicKey, request.ciphertext);
  return { plaintext };
}

// ---------------------------------------------------------------------------
// DeriveSharedSecret
// ---------------------------------------------------------------------------

export function deriveSharedSecret(request: DeriveSharedSecretRequest): DeriveSharedSecretResponse {
  const entry = keyRegistry.getPrivateKeyEntry(request.privateKeyHandle);
  if (request.remotePublicKey.length !== 32) {
    throw new Error("Remote public key must be 32 bytes (X25519).");
  }
  // initRatchetSession mixes a fresh ephemeral contribution alongside the
  // static-static DH (X3DH-style) — see ratchet.ts for the forward-secrecy
  // rationale. It takes the raw static keys directly rather than a
  // pre-computed shared secret so it can perform both DH computations
  // itself.
  const ratchetState = initRatchetSession(entry.privateKey, request.remotePublicKey);
  const sharedSecretHandle = keyRegistry.registerRatchetSession(ratchetState);

  logAuditEvent("shared_secret_derived", {
    localHandle: request.privateKeyHandle.handle,
    sharedSecretHandle: sharedSecretHandle.handle,
    remotePublicKeyFingerprint: fingerprint(request.remotePublicKey),
  });

  return { sharedSecretHandle };
}

// ---------------------------------------------------------------------------
// SecureLocalStore / SecureLocalRetrieve
// ---------------------------------------------------------------------------

export async function secureLocalStore(request: SecureLocalStoreRequest): Promise<SecureLocalStoreResponse> {
  await storeSecureLocal(request.key, request.value);
  return {};
}

export async function secureLocalRetrieve(
  request: SecureLocalRetrieveRequest,
): Promise<SecureLocalRetrieveResponse> {
  const value = await retrieveSecureLocal(request.key);
  return { value };
}

// ---------------------------------------------------------------------------
// RestoreFromRecoveryPhrase
// ---------------------------------------------------------------------------

export function restoreFromRecoveryPhrase(
  request: RestoreFromRecoveryPhraseRequest,
): RestoreFromRecoveryPhraseResponse {
  // Validated explicitly here (rather than only relying on
  // mnemonic.deriveIdentityPrivateKeyFromPhrase's own internal check) so a
  // rejected attempt is audited at this operation's boundary before any
  // exception unwinds — consistent with audit.ts's own stated obligation to
  // log an operation "succeeding/failing," not just succeeding.
  if (!mnemonic.isValidRecoveryPhrase(request.recoveryPhrase)) {
    logAuditEvent("identity_key_restore_failed", { reason: "invalid_recovery_phrase" });
    throw new Error("Invalid recovery phrase: fails BIP-39 wordlist/checksum validation.");
  }
  const privateKey = mnemonic.deriveIdentityPrivateKeyFromPhrase(request.recoveryPhrase);
  const publicKey = x25519.getPublicKey(privateKey);
  const privateKeyHandle = keyRegistry.registerPrivateKey("identity", privateKey, publicKey);

  logAuditEvent("identity_key_restored", {
    handle: privateKeyHandle.handle,
    publicKeyFingerprint: fingerprint(publicKey),
  });

  return { privateKeyHandle, publicKey };
}

// ---------------------------------------------------------------------------
// ExportKeyMaterial
// ---------------------------------------------------------------------------

/**
 * Export blob format, version "ascend-crypto-export-v1" (Art. 9 — this is
 * the documented, portable format the charter requires):
 *
 * UTF-8 JSON, shape:
 * {
 *   "formatVersion": "ascend-crypto-export-v1",
 *   "exportedAt": "<ISO 8601 timestamp>",
 *   "keys": [
 *     {
 *       "handle": "<opaque handle string, informational only>",
 *       "purpose": "<'identity' | caller-supplied purpose string>",
 *       "publicKey": "<base64, 32 bytes, X25519>",
 *       "privateKey": "<base64, 32 bytes, X25519 scalar>"
 *     },
 *     ...
 *   ]
 * }
 *
 * Every currently-registered private key handle in this process (identity
 * key plus any session/device keys generated via GenerateKeyPair) is
 * included. A `purpose: "identity"` entry's `privateKey`, run through the
 * same X25519 derivation this module uses, is sufficient on its own to
 * restore the identity keypair on another implementation — the recovery
 * phrase is NOT included in the export blob (it is shown once by the
 * caller elsewhere and never persisted by this module in any form, per the
 * charter's threat model).
 */
const EXPORT_FORMAT_VERSION = "ascend-crypto-export-v1";

export function exportKeyMaterial(request: ExportKeyMaterialRequest): ExportKeyMaterialResponse {
  if (!request.userConfirmation) {
    logAuditEvent("key_material_export_refused", { reason: "missing_user_confirmation" });
    throw new Error("ExportKeyMaterial requires explicit user_confirmation; refusing a silent export.");
  }

  const entries = keyRegistry.debugListPrivateKeyEntries().map((e) => ({
    handle: e.handle,
    purpose: e.purpose,
    publicKey: bytesToBase64(e.publicKey),
    privateKey: bytesToBase64(e.privateKey),
  }));

  const payload = {
    formatVersion: EXPORT_FORMAT_VERSION,
    exportedAt: new Date().toISOString(),
    keys: entries,
  };

  const exportBlob = new TextEncoder().encode(JSON.stringify(payload, null, 2));

  logAuditEvent("key_material_exported", { keyCount: String(entries.length) });

  return { exportBlob, formatVersion: EXPORT_FORMAT_VERSION };
}

export type { KeyHandle };
