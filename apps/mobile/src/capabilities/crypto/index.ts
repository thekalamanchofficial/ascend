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
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import * as keyRegistry from "./keyRegistry";
import * as mnemonic from "./mnemonic";
import { encryptEnvelope, decryptEnvelope } from "./envelope";
import { initRatchetSession } from "./ratchet";
import { secureLocalStore as storeSecureLocal, secureLocalRetrieve as retrieveSecureLocal } from "./secureStore";
import { logAuditEvent } from "./audit";
import { bytesToBase64 } from "./bytes";
import { randomBytes } from "./random";
import { auditFingerprint as fingerprint } from "./auditHash";
import { isSigningPurpose, SIGNING_PURPOSE_PREFIX } from "./keyPurpose";
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
  SignRequest,
  SignResponse,
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

// The identity root key's job is proving *who* a device/identity is —
// signing device-binding assertions (Identity's `BindDevice`) — not
// confidentiality or key agreement. Nothing in this module or its consumers
// calls Encrypt/Decrypt/DeriveSharedSecret with the identity key
// specifically (those operate on separately-generated device/session
// keys). It is therefore registered under the reserved signing-capable
// purpose `"sign:identity"` (Ed25519), not a bare `"identity"` purpose that
// would (per keyPurpose.ts's convention) make it DH-capable X25519 and
// therefore unable to back a real signature — see docs/DECISION_LOG.md,
// 2026-07-16 "Fix: identity root key must be Ed25519 (signing-capable),
// not X25519" for the regression this closes: as originally built, the
// recovery-derived self-signed device-binding assertion could never
// actually be produced, because Sign() correctly refuses non-signing
// handles.
const IDENTITY_KEY_PURPOSE = "sign:identity";

// ascend:mutates
export function generateIdentityKeyMaterial(
  _request: GenerateIdentityKeyMaterialRequest = {},
): GenerateIdentityKeyMaterialResponse {
  const recoveryPhrase = mnemonic.generateRecoveryPhrase();
  const privateKey = mnemonic.deriveIdentityPrivateKeyFromPhrase(recoveryPhrase);
  const publicKey = ed25519.getPublicKey(privateKey);
  const privateKeyHandle = keyRegistry.registerPrivateKey(IDENTITY_KEY_PURPOSE, privateKey, publicKey);

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

// ascend:mutates
export function generateKeyPair(request: GenerateKeyPairRequest): GenerateKeyPairResponse {
  if (!request.purpose) {
    logAuditEvent("key_pair_generation_rejected", { reason: "empty_purpose" });
    throw new Error("GenerateKeyPair requires a non-empty purpose.");
  }
  // Non-recovery-bearing key (charter §3): fresh CSPRNG output only, never
  // derived from a phrase, unlike the identity key above.
  //
  // Key type is selected by purpose-string convention (see keyPurpose.ts):
  // a "sign:"-prefixed purpose produces a signing-capable Ed25519 keypair;
  // every other purpose produces the existing DH-capable X25519 keypair.
  // Ed25519 and X25519 derive completely different, unrelated public keys
  // from the same raw private-key bytes, so this branch is a correctness
  // requirement, not a style choice — see Sign, below, and
  // docs/DECISION_LOG.md, 2026-07-16 "Sign RPC: Ed25519, purpose-namespaced
  // key-type convention".
  const signing = isSigningPurpose(request.purpose);
  const privateKey = randomBytes(32);
  const publicKey = signing ? ed25519.getPublicKey(privateKey) : x25519.getPublicKey(privateKey);
  const privateKeyHandle = keyRegistry.registerPrivateKey(request.purpose, privateKey, publicKey);

  logAuditEvent("key_pair_generated", {
    handle: privateKeyHandle.handle,
    purpose: request.purpose,
    keyType: signing ? "ed25519" : "x25519",
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
  if (isSigningPurpose(entry.purpose)) {
    throw new Error(
      `Decrypt requires a DH-capable (X25519) key handle; "${entry.purpose}" is a signing-only Ed25519 key.`,
    );
  }
  const plaintext = decryptEnvelope(entry.privateKey, entry.publicKey, request.ciphertext);
  return { plaintext };
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

/**
 * Signs `message` with an Ed25519 signing-capable private key handle,
 * producing a standard 64-byte Ed25519 signature. Added for Identity's
 * `BindDevice` (an already-bound device must cryptographically prove
 * authorization for a new device) — see docs/DECISION_LOG.md, 2026-07-16
 * "Crypto & Keys contract gains Sign; signature verification is not 'own
 * crypto'" and "Sign RPC: Ed25519, purpose-namespaced key-type convention".
 *
 * Deliberately no companion `Verify` here: verification needs only the
 * already-public key and an unmodified standard algorithm, no private
 * material, so it is implemented directly wherever a signature needs
 * checking (e.g. Identity, server-side) rather than round-tripping through
 * this on-device-only module.
 *
 * Only handles registered under a `"sign:"`-prefixed purpose (see
 * keyPurpose.ts) are accepted — a DH-capable (X25519) handle is rejected
 * rather than silently signed with, because doing so would produce a
 * signature that verifies under a DIFFERENT public key than the one
 * GenerateKeyPair returned for that handle (Ed25519 and X25519 derive
 * unrelated public keys from the same raw bytes). The identity root key
 * (purpose `"sign:identity"`, from GenerateIdentityKeyMaterial /
 * RestoreFromRecoveryPhrase) IS signing-capable and IS accepted here — that
 * is the whole point of it being Ed25519: it is how Identity's
 * `BindDevice` produces a real device-binding signature, including from a
 * recovery-phrase-restored identity after total device loss.
 */
// ascend:mutates
export function sign(request: SignRequest): SignResponse {
  const entry = keyRegistry.getPrivateKeyEntry(request.privateKeyHandle);
  if (!isSigningPurpose(entry.purpose)) {
    logAuditEvent("sign_rejected", {
      handle: request.privateKeyHandle.handle,
      reason: "not_a_signing_purpose_key",
    });
    throw new Error(
      `Sign requires a signing-capable key handle (purpose must start with "${SIGNING_PURPOSE_PREFIX}"); got purpose "${entry.purpose}".`,
    );
  }

  const signature = ed25519.sign(request.message, entry.privateKey);

  logAuditEvent("message_signed", {
    handle: request.privateKeyHandle.handle,
    purpose: entry.purpose,
  });

  return { signature };
}

// ---------------------------------------------------------------------------
// DeriveSharedSecret
// ---------------------------------------------------------------------------

// ascend:mutates
export function deriveSharedSecret(request: DeriveSharedSecretRequest): DeriveSharedSecretResponse {
  const entry = keyRegistry.getPrivateKeyEntry(request.privateKeyHandle);
  if (isSigningPurpose(entry.purpose)) {
    throw new Error(
      `DeriveSharedSecret requires a DH-capable (X25519) key handle; "${entry.purpose}" is a signing-only Ed25519 key.`,
    );
  }
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

// ascend:mutates
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
  // Same deterministic derivation as GenerateIdentityKeyMaterial, same
  // curve (Ed25519, signing-capable) and same reserved purpose — this must
  // stay in lockstep with generateIdentityKeyMaterial above or a restored
  // identity's public key would silently stop matching the originally
  // generated one.
  const publicKey = ed25519.getPublicKey(privateKey);
  const privateKeyHandle = keyRegistry.registerPrivateKey(IDENTITY_KEY_PURPOSE, privateKey, publicKey);

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
 *       "purpose": "<'sign:identity' | caller-supplied purpose string>",
 *       "publicKey": "<base64, 32 bytes>",
 *       "privateKey": "<base64, 32 bytes>"
 *     },
 *     ...
 *   ]
 * }
 *
 * `publicKey`/`privateKey` are always 32 raw bytes, but the CURVE they
 * belong to depends on `purpose`, per the same convention Sign/GenerateKeyPair
 * use (see keyPurpose.ts): a `purpose` starting with `"sign:"` — including
 * the reserved `"sign:identity"` purpose the identity root key is always
 * registered under — is Ed25519 (signing-capable); every other purpose is
 * X25519 (DH-capable). A consumer of this export must branch on `purpose`
 * the same way this module does — the two curves are NOT interchangeable
 * even though the byte length is identical.
 *
 * Every currently-registered private key handle in this process (the
 * identity key plus any session/device/signing keys generated via
 * GenerateKeyPair) is included. The `purpose: "sign:identity"` entry's
 * `privateKey`, run through the same Ed25519 derivation this module uses,
 * is sufficient on its own to restore the identity keypair — including its
 * signing capability — on another implementation. The recovery phrase
 * itself is NOT included in the export blob (it is shown once by the
 * caller elsewhere and never persisted by this module in any form, per the
 * charter's threat model).
 */
const EXPORT_FORMAT_VERSION = "ascend-crypto-export-v1";

// ascend:mutates
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
