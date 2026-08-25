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
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import * as keyRegistry from "./keyRegistry";
import * as mnemonic from "./mnemonic";
import * as prekeyStore from "./prekeyStore";
import { encryptEnvelope, decryptEnvelope } from "./envelope";
import { encodeMessageEnvelope, decodeMessageEnvelope } from "./messageEnvelope";
import {
  deriveInitiatorHandshake,
  deriveResponderSharedSecret,
  deriveNextMessageKey,
  deriveNextReceivingMessageKey,
} from "./ratchet";
import { deriveDhPublicKey } from "./dhKey";
import { secureLocalStore as storeSecureLocal, secureLocalRetrieve as retrieveSecureLocal } from "./secureStore";
import { logAuditEvent } from "./audit";
import { bytesToBase64, bytesToHex } from "./bytes";
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
  CompleteSharedSecretRequest,
  CompleteSharedSecretResponse,
  GeneratePrekeyBundleRequest,
  GeneratePrekeyBundleResponse,
  OneTimePrekeyPublic,
  EncryptMessageRequest,
  EncryptMessageResponse,
  DecryptMessageRequest,
  DecryptMessageResponse,
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

// The identity root key's primary job is proving *who* a device/identity
// is — signing device-binding assertions (Identity's `BindDevice`), the
// signed prekey, and (as of the 2026-08-21 key-separation fix)
// `identity_dh_public_key` itself. It is registered under the reserved
// signing-capable purpose `"sign:identity"` (Ed25519), not a bare
// `"identity"` purpose that would (per keyPurpose.ts's convention) make it
// DH-capable X25519 and therefore unable to back a real signature — see
// docs/DECISION_LOG.md, 2026-07-16 "Fix: identity root key must be Ed25519
// (signing-capable), not X25519" for the regression this closes: as
// originally built, the recovery-derived self-signed device-binding
// assertion could never actually be produced, because Sign() correctly
// refuses non-signing handles.
//
// `deriveSharedSecret`/`completeSharedSecret` DO require this identity key
// handle specifically (see below) — but, per the 2026-08-21 key-separation
// fix, they never use its Ed25519 signing bytes directly for DH. They
// derive a genuinely separate DH-capable scalar from the SAME underlying
// seed via `dhKey.ts`'s domain-separated KDF — see keyPurpose.ts and
// dhKey.ts for the full construction and the design defect this corrects.
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
// DeriveSharedSecret — the INITIATING party's half of X3DH.
//
// AMENDED 2026-08-20 (responder-side prekey completion —
// docs/capabilities/cryptography-and-keys.charter.md §3/§6/§7, gated
// 2026-08-19): signature changed from a bare `remote_public_key` to
// `their_prekey_bundle`. This EXPLICITLY SUPERSEDES the pre-amendment
// two-term construction, not a reparameterization of it — see ratchet.ts's
// module header for the full rationale, including why `private_key_handle`
// here must now be this process's identity key handle (purpose
// "sign:identity"), the exact opposite of the pre-amendment check this
// function used to perform.
//
// CORRECTED 2026-08-21 (key-separation fix, docs/DECISION_LOG.md's
// "Key-separation fix" series; charter §3): `theirIdentityPublicKey` renamed
// to `theirIdentitySigningPublicKey` — this is the Ed25519 verification
// anchor, NOT DH-capable. The DH-capable key now lives inside
// `theirPrekeyBundle.identityDhPublicKey`, itself signed and requiring its
// own verification (identityDhPublicKeySignature) before use — a SECOND
// hard-abort signature check, alongside the pre-existing signedPrekey one,
// both required before any DH term is computed. Neither `entry.privateKey`
// (this process's identity seed) nor `theirPrekeyBundle.identityDhPublicKey`
// is ever treated as an Ed25519 key here or fed through a birational
// conversion — see dhKey.ts/ratchet.ts.
// ---------------------------------------------------------------------------

// ascend:mutates
export async function deriveSharedSecret(request: DeriveSharedSecretRequest): Promise<DeriveSharedSecretResponse> {
  const entry = keyRegistry.getPrivateKeyEntry(request.privateKeyHandle);
  if (entry.purpose !== IDENTITY_KEY_PURPOSE) {
    logAuditEvent("derive_shared_secret_rejected", {
      handle: request.privateKeyHandle.handle,
      reason: "not_identity_key",
    });
    throw new Error(
      `DeriveSharedSecret requires the caller's own identity key handle (purpose "${IDENTITY_KEY_PURPOSE}"); got purpose "${entry.purpose}".`,
    );
  }
  if (request.theirIdentitySigningPublicKey.length !== 32) {
    logAuditEvent("derive_shared_secret_rejected", { reason: "invalid_their_identity_signing_public_key_length" });
    throw new Error("their_identity_signing_public_key must be 32 bytes (Ed25519).");
  }
  const { identityDhPublicKey, identityDhPublicKeySignature, signedPrekey, oneTimePrekey } = request.theirPrekeyBundle;
  if (identityDhPublicKey.length !== 32) {
    logAuditEvent("derive_shared_secret_rejected", { reason: "invalid_identity_dh_public_key_length" });
    throw new Error("their_prekey_bundle.identity_dh_public_key must be 32 bytes (X25519).");
  }
  if (signedPrekey.publicKey.length !== 32) {
    logAuditEvent("derive_shared_secret_rejected", {
      reason: "invalid_signed_prekey_public_key_length",
      prekeyId: signedPrekey.prekeyId,
    });
    throw new Error("their_prekey_bundle.signed_prekey.public_key must be 32 bytes (X25519).");
  }

  // Charter §6 "Signed-prekey substitution": a compromised/malicious server
  // must not be able to substitute a different signed prekey. Verification
  // is a HARD ABORT on failure — no partial derivation, never a silent
  // fallback — and happens BEFORE any DH term is computed from
  // signedPrekey.publicKey, not merely before this function returns.
  const signedPrekeySignatureValid = ed25519.verify(
    signedPrekey.signature,
    signedPrekey.publicKey,
    request.theirIdentitySigningPublicKey,
  );
  if (!signedPrekeySignatureValid) {
    logAuditEvent("signed_prekey_signature_invalid", {
      prekeyId: signedPrekey.prekeyId,
      theirIdentitySigningPublicKeyFingerprint: fingerprint(request.theirIdentitySigningPublicKey),
    });
    throw new Error(
      `DeriveSharedSecret refuses to proceed: signed prekey "${signedPrekey.prekeyId}" signature does not verify against the claimed identity signing public key.`,
    );
  }

  // Charter §6 "identity_dh_public_key substitution" (added 2026-08-21, the
  // key-separation fix's own field): identity_dh_public_key is
  // server-published/-fetched material exactly like signed_prekey, and so
  // inherits the identical substitution risk and the identical fix. HARD
  // ABORT on failure, BEFORE any DH term uses identityDhPublicKey — never a
  // silent fallback. Reuses signed_prekey_signature_invalid (same failure
  // class — a required signature over server-published material didn't
  // verify — not a distinct event name, per this codebase's established
  // convention).
  const identityDhKeySignatureValid = ed25519.verify(
    identityDhPublicKeySignature,
    identityDhPublicKey,
    request.theirIdentitySigningPublicKey,
  );
  if (!identityDhKeySignatureValid) {
    logAuditEvent("signed_prekey_signature_invalid", {
      reason: "identity_dh_public_key_signature_invalid",
      theirIdentitySigningPublicKeyFingerprint: fingerprint(request.theirIdentitySigningPublicKey),
      theirIdentityDhPublicKeyFingerprint: fingerprint(identityDhPublicKey),
    });
    throw new Error(
      "DeriveSharedSecret refuses to proceed: their_prekey_bundle.identity_dh_public_key_signature does not verify against the claimed identity signing public key.",
    );
  }

  const { ratchetState, myEphemeralPublic } = deriveInitiatorHandshake(
    entry.privateKey,
    identityDhPublicKey,
    signedPrekey.publicKey,
    oneTimePrekey?.publicKey ?? null,
  );
  // registerRatchetSession is async (SecureLocalStore-backed persistence
  // fix, charter §3 round 2) — the disclosed, required consequence that
  // makes THIS function itself async now (see keyRegistry.ts's module
  // header for the full rationale).
  const sharedSecretHandle = await keyRegistry.registerRatchetSession(ratchetState);

  logAuditEvent("shared_secret_derived", {
    localHandle: request.privateKeyHandle.handle,
    sharedSecretHandle: sharedSecretHandle.handle,
    theirIdentitySigningPublicKeyFingerprint: fingerprint(request.theirIdentitySigningPublicKey),
    theirIdentityDhPublicKeyFingerprint: fingerprint(identityDhPublicKey),
    signedPrekeyId: signedPrekey.prekeyId,
    usedOneTimePrekey: String(Boolean(oneTimePrekey)),
  });

  return { sharedSecretHandle, myEphemeralPublicKey: myEphemeralPublic };
}

// ---------------------------------------------------------------------------
// CompleteSharedSecret — the RESPONDING party's half of X3DH. Added
// 2026-08-20, structurally absent before this amendment (charter §3/§6/§7).
//
// CORRECTED 2026-08-21/22 (key-separation fix round 4, docs/DECISION_LOG.md's
// "Key-separation fix" series; charter §6 "identity impersonation via
// wholesale key fabrication"): `theirIdentityPublicKey` renamed to
// `theirIdentityDhPublicKey` (it was never the Ed25519 signing key — this
// rename only fixes the field name, not the semantics, which were always
// DH-capable). Two NEW required fields, `theirIdentitySigningPublicKey` and
// `theirIdentityDhPublicKeySignature`, add a SECOND hard-abort verification
// (alongside the pre-existing local self-consistency check below): an
// attacker who fabricates both `theirIdentityDhPublicKey` and
// `theirEphemeralPublicKey` wholesale — no genuine private key from any real
// party needed — can otherwise derive a fully working shared secret this
// responder would accept as belonging to whatever identity is claimed. This
// verification happens BEFORE any DH term is computed and, deliberately,
// before the one-time prekey is consumed (a request that fails this check
// must not burn a scarce, forward-secrecy-critical one-time prekey).
// ---------------------------------------------------------------------------

// ascend:mutates
export async function completeSharedSecret(
  request: CompleteSharedSecretRequest,
): Promise<CompleteSharedSecretResponse> {
  const entry = keyRegistry.getPrivateKeyEntry(request.privateKeyHandle);
  if (entry.purpose !== IDENTITY_KEY_PURPOSE) {
    logAuditEvent("complete_shared_secret_rejected", {
      reason: "not_identity_key",
      handle: request.privateKeyHandle.handle,
    });
    throw new Error(
      `CompleteSharedSecret requires the caller's own identity key handle (purpose "${IDENTITY_KEY_PURPOSE}"); got purpose "${entry.purpose}".`,
    );
  }
  if (request.theirIdentityDhPublicKey.length !== 32) {
    logAuditEvent("complete_shared_secret_rejected", { reason: "invalid_their_identity_dh_public_key_length" });
    throw new Error("their_identity_dh_public_key must be 32 bytes (X25519).");
  }
  if (request.theirEphemeralPublicKey.length !== 32) {
    logAuditEvent("complete_shared_secret_rejected", { reason: "invalid_their_ephemeral_public_key_length" });
    throw new Error("their_ephemeral_public_key must be 32 bytes (X25519).");
  }
  if (request.theirIdentitySigningPublicKey.length !== 32) {
    logAuditEvent("complete_shared_secret_rejected", { reason: "invalid_their_identity_signing_public_key_length" });
    throw new Error("their_identity_signing_public_key must be 32 bytes (Ed25519).");
  }

  // Charter §6 "identity impersonation via wholesale key fabrication" (round
  // 4): the initiator's own their_identity_dh_public_key is
  // caller-transport-mediated material (carried in Conversations'
  // session_establishment_payload), not necessarily authenticated by
  // anything else this function checks — verify it against the claimed
  // sender's Ed25519 signing key BEFORE it (or their_ephemeral_public_key,
  // which travels alongside it in the same untrusted payload) is used in any
  // DH term. HARD ABORT on failure, reusing signed_prekey_signature_invalid
  // (same failure class: a required signature over claimed-sender-published
  // material didn't verify), never a silent fallback.
  const theirIdentityDhKeySignatureValid = ed25519.verify(
    request.theirIdentityDhPublicKeySignature,
    request.theirIdentityDhPublicKey,
    request.theirIdentitySigningPublicKey,
  );
  if (!theirIdentityDhKeySignatureValid) {
    logAuditEvent("signed_prekey_signature_invalid", {
      reason: "their_identity_dh_public_key_signature_invalid",
      theirIdentitySigningPublicKeyFingerprint: fingerprint(request.theirIdentitySigningPublicKey),
      theirIdentityDhPublicKeyFingerprint: fingerprint(request.theirIdentityDhPublicKey),
    });
    throw new Error(
      "CompleteSharedSecret refuses to proceed: their_identity_dh_public_key_signature does not verify against the claimed sender's identity signing public key.",
    );
  }

  let signedPrekeyRecord: prekeyStore.StoredSignedPrekeyRecord;
  try {
    signedPrekeyRecord = await prekeyStore.retrieveSignedPrekey(request.mySignedPrekeyId);
  } catch (err) {
    logAuditEvent("complete_shared_secret_rejected", {
      reason: "unknown_signed_prekey_id",
      signedPrekeyId: request.mySignedPrekeyId,
    });
    throw err;
  }

  // Defense-in-depth self-consistency check. Charter §6's actual
  // MITM-facing signature verification lives in DeriveSharedSecret above,
  // against a NETWORK-supplied bundle — CompleteSharedSecretRequest carries
  // no signature field at all, because this device's own locally stored
  // signed-prekey record was never transmitted by anyone untrusted. This
  // check instead re-verifies that the record still self-consistently
  // validates against the identity public key it was signed under at
  // GeneratePrekeyBundle time — catching local storage corruption or a
  // generation-time bug with the identical hard-abort + audit discipline,
  // since a corrupted signed prekey is just as unsafe to derive DH terms
  // from as a substituted one (see docs/DECISION_LOG.md, 2026-08-20).
  const selfConsistent = ed25519.verify(
    signedPrekeyRecord.signature,
    signedPrekeyRecord.publicKey,
    signedPrekeyRecord.identityPublicKey,
  );
  if (!selfConsistent) {
    logAuditEvent("signed_prekey_signature_invalid", {
      prekeyId: request.mySignedPrekeyId,
      reason: "local_record_self_verification_failed",
    });
    throw new Error(
      `CompleteSharedSecret refuses to proceed: locally stored signed prekey "${request.mySignedPrekeyId}" failed self-verification (corrupted or mismatched record).`,
    );
  }

  let oneTimePrekeyPrivate: Uint8Array | null = null;
  if (request.myOneTimePrekeyId) {
    try {
      // Atomic per-prekey_id lookup+delete (charter §6's single most
      // load-bearing requirement of this whole amendment) — see
      // prekeyStore.ts's withOneTimePrekeyLock. A losing concurrent call
      // for the same prekey_id fails here with PrekeyAlreadyConsumedError,
      // never silently succeeding, hanging, or falling back unannounced.
      const record = await prekeyStore.consumeOneTimePrekey(request.myOneTimePrekeyId);
      oneTimePrekeyPrivate = record.privateKey;
    } catch (err) {
      logAuditEvent("one_time_prekey_consumption_failed", {
        oneTimePrekeyId: request.myOneTimePrekeyId,
        reason: err instanceof prekeyStore.PrekeyAlreadyConsumedError ? "already_consumed" : "unknown_error",
      });
      throw err;
    }
  }

  const ratchetState = deriveResponderSharedSecret(
    entry.privateKey,
    request.theirIdentityDhPublicKey,
    request.theirEphemeralPublicKey,
    signedPrekeyRecord.privateKey,
    oneTimePrekeyPrivate,
  );
  // registerRatchetSession is async (SecureLocalStore-backed persistence
  // fix, charter §3 round 2) — completeSharedSecret was already async, so
  // this is just the one new `await` that fix requires here.
  const sharedSecretHandle = await keyRegistry.registerRatchetSession(ratchetState);

  // Charter §6/§5: the exhaustion-fallback case (no one-time prekey
  // available) is a stated, disclosed WEAKER guarantee, never silently
  // folded into the routine case — must be both audited (this event, so
  // it's empirically detectable, not just narratively disclosed) AND
  // eventually surfaced to the user via the passive changed-key-badge
  // indicator's second trigger condition (charter §5). No Conversations UI
  // exists yet to wire that indicator into (checked directly — this
  // codebase has no conversation/messaging screens as of this amendment),
  // so this event is the hook: whoever builds that UI should subscribe to
  // `session_established_signed_prekey_only` (once this stub is replaced by
  // the real Audit client) the same way it will already subscribe to the
  // existing key-rotation event for the first trigger condition. TODO(
  // Conversations UI): wire this event into the shared changed-key-badge
  // indicator as its second trigger condition, per charter §5 — do not
  // invent a second indicator.
  if (!request.myOneTimePrekeyId) {
    logAuditEvent("session_established_signed_prekey_only", {
      localHandle: request.privateKeyHandle.handle,
      sharedSecretHandle: sharedSecretHandle.handle,
      signedPrekeyId: request.mySignedPrekeyId,
      theirIdentityDhPublicKeyFingerprint: fingerprint(request.theirIdentityDhPublicKey),
    });
  } else {
    logAuditEvent("shared_secret_completed_with_otp", {
      localHandle: request.privateKeyHandle.handle,
      sharedSecretHandle: sharedSecretHandle.handle,
      signedPrekeyId: request.mySignedPrekeyId,
      oneTimePrekeyId: request.myOneTimePrekeyId,
      theirIdentityDhPublicKeyFingerprint: fingerprint(request.theirIdentityDhPublicKey),
    });
  }

  return { sharedSecretHandle };
}

// ---------------------------------------------------------------------------
// GeneratePrekeyBundle — added 2026-08-20 (charter §3/§5). Fully invisible,
// automatic background maintenance (rotation for the signed prekey,
// replenishment for one-time prekeys) — no user action, no user awareness
// required for the routine case.
// ---------------------------------------------------------------------------

const PREKEY_ID_BYTE_LENGTH = 16;

function newPrekeyId(): string {
  return bytesToHex(randomBytes(PREKEY_ID_BYTE_LENGTH));
}

// ascend:mutates
export async function generatePrekeyBundle(
  request: GeneratePrekeyBundleRequest,
): Promise<GeneratePrekeyBundleResponse> {
  if (request.oneTimePrekeyCount < 0) {
    logAuditEvent("prekey_bundle_generation_rejected", { reason: "invalid_one_time_prekey_count" });
    throw new Error("one_time_prekey_count must be >= 0.");
  }

  // GeneratePrekeyBundleRequest deliberately carries no key handle (frozen
  // contract) — this RPC locates this process's own identity key itself
  // rather than have one handed to it. See
  // keyRegistry.findPrivateKeyEntryByPurpose's own doc comment and
  // docs/DECISION_LOG.md, 2026-08-20, for the full reasoning and the
  // residual limitation this inherits (the identity key must already be
  // registered in this process — e.g. via GenerateIdentityKeyMaterial or
  // RestoreFromRecoveryPhrase earlier in the same session).
  const identityEntry = keyRegistry.findPrivateKeyEntryByPurpose(IDENTITY_KEY_PURPOSE);
  if (!identityEntry) {
    logAuditEvent("prekey_bundle_generation_rejected", { reason: "no_identity_key_registered" });
    throw new Error(
      "GeneratePrekeyBundle requires this process's identity key to already be registered " +
        "(call GenerateIdentityKeyMaterial or RestoreFromRecoveryPhrase first).",
    );
  }

  const signedPrekeyPrivate = randomBytes(32);
  const signedPrekeyPublic = x25519.getPublicKey(signedPrekeyPrivate);
  // Sign the signed prekey's public key with the identity's long-term
  // Ed25519 signing key via the existing Sign RPC (charter §3) — not a new,
  // separate signing path.
  const { signature } = sign({
    privateKeyHandle: { handle: identityEntry.handle },
    message: signedPrekeyPublic,
  });
  const signedPrekeyId = newPrekeyId();
  const createdAtUnix = Math.floor(Date.now() / 1000);

  await prekeyStore.storeSignedPrekey(signedPrekeyId, {
    privateKey: signedPrekeyPrivate,
    publicKey: signedPrekeyPublic,
    signature,
    identityPublicKey: identityEntry.publicKey,
    createdAtUnix,
  });

  const oneTimePrekeys: OneTimePrekeyPublic[] = [];
  for (let i = 0; i < request.oneTimePrekeyCount; i++) {
    const oneTimePrivate = randomBytes(32);
    const oneTimePublic = x25519.getPublicKey(oneTimePrivate);
    const oneTimeId = newPrekeyId();
    await prekeyStore.storeOneTimePrekey(oneTimeId, { privateKey: oneTimePrivate, publicKey: oneTimePublic });
    oneTimePrekeys.push({ prekeyId: oneTimeId, publicKey: oneTimePublic });
  }

  // identity_dh_public_key — the key-separation fix's own field (charter
  // §3, added 2026-08-21): the genuinely separate, DH-only X25519 public
  // key derived from the SAME identity seed via dhKey.ts's domain-separated
  // KDF — never the Ed25519 signing public key (identityEntry.publicKey)
  // and never a birational conversion of it. Signed with the SAME identity
  // signing key that signs signedPrekeyPublic above, in this same call
  // (charter §3/§6 "identity_dh_public_key substitution") — an unsigned
  // identity_dh_public_key would be a substitution surface a compromised
  // publish/fetch path could exploit.
  const identityDhPublicKey = deriveDhPublicKey(identityEntry.privateKey);
  const { signature: identityDhPublicKeySignature } = sign({
    privateKeyHandle: { handle: identityEntry.handle },
    message: identityDhPublicKey,
  });

  logAuditEvent("prekey_bundle_generated", {
    identityHandle: identityEntry.handle,
    signedPrekeyId,
    oneTimePrekeyCount: String(oneTimePrekeys.length),
    identityDhPublicKeyFingerprint: fingerprint(identityDhPublicKey),
  });

  return {
    identityDhPublicKey,
    signedPrekey: { prekeyId: signedPrekeyId, publicKey: signedPrekeyPublic, signature, createdAtUnix },
    oneTimePrekeys,
    identityDhPublicKeySignature,
  };
}

// ---------------------------------------------------------------------------
// EncryptMessage / DecryptMessage — added 2026-08-23, "the ongoing-ratchet
// exposure gap" amendment (charter §3/§6/§7). The first functions in this
// capability's public contract to actually consume a `shared_secret_handle`
// for real message content — `deriveSharedSecret`/`completeSharedSecret`
// above only ever established a session before this amendment.
//
// Deliberately NOT marked `// ascend:mutates` and NEVER call
// `logAuditEvent` directly (charter §3/§6, Constitution Warden gate round
// 2's explicit audit-posture decision): at per-message call volume, a
// per-message audit event would either flood the audit trail into a
// detailed messaging-cadence log (Art. 8 tension) or be silently
// rate-limited in a way that undermines Art. 5 for the entries that DO
// land — the identical reasoning already established for `Encrypt`/
// `Decrypt` above. Session establishment (`shared_secret_derived`,
// `session_established_signed_prekey_only`, etc.) remains the audited
// lifecycle event; using an already-established session to move data is
// not itself a capability-lifecycle event the way establishing key
// material is. (Note: `keyRegistry.getRatchetSession`/`updateRatchetSession`
// internally call `secureLocalRetrieve`/`secureLocalStore` — the latter
// DOES already emit its own `secure_local_store_write` audit event with
// only a hashed key fingerprint, exactly like every other SecureLocalStore
// write in this module. That is pre-existing, already-audited plumbing,
// not a new, second, undocumented collection surface this amendment adds.)
// ---------------------------------------------------------------------------

export async function encryptMessage(request: EncryptMessageRequest): Promise<EncryptMessageResponse> {
  return keyRegistry.withRatchetSessionLock(request.sharedSecretHandle.handle, async () => {
    const state = await keyRegistry.getRatchetSession(request.sharedSecretHandle);
    const { messageKey, nextState } = deriveNextMessageKey(state);

    // Freshly, randomly generated for EVERY call — required, never derived
    // from sendMessageNumber or any other reused/predictable state (charter
    // §3: a deterministic nonce here would reintroduce a variant of this
    // amendment's own core defect if a crash/retry ever re-derives the same,
    // not-yet-persisted chain position twice).
    const nonce = randomBytes(24);
    const ciphertext = xchacha20poly1305(messageKey, nonce).encrypt(request.plaintext);
    const envelope = encodeMessageEnvelope(nonce, state.sendMessageNumber, ciphertext);

    // Persist the ADVANCED state only after the AEAD encryption itself has
    // already succeeded (it cannot meaningfully fail here, but this keeps
    // the same "derive, use, THEN persist" ordering DecryptMessage below
    // relies on for its own success-only-persistence requirement).
    await keyRegistry.updateRatchetSession(request.sharedSecretHandle, nextState);

    return { ciphertext: envelope };
  });
}

export async function decryptMessage(request: DecryptMessageRequest): Promise<DecryptMessageResponse> {
  return keyRegistry.withRatchetSessionLock(request.sharedSecretHandle.handle, async () => {
    const state = await keyRegistry.getRatchetSession(request.sharedSecretHandle);
    const { nonce, ciphertext } = decodeMessageEnvelope(request.ciphertext);
    const { messageKey, nextState } = deriveNextReceivingMessageKey(state);

    // A failed decrypt (AEAD tag mismatch) must NOT advance
    // receivingChainKey — charter §3/§6, an explicit requirement, not an
    // oversight. xchacha20poly1305(...).decrypt(...) THROWS on tag
    // mismatch, which propagates straight out of this function and skips
    // the updateRatchetSession call below entirely — persistence only
    // happens on the success path, never partially.
    const plaintext = xchacha20poly1305(messageKey, nonce).decrypt(ciphertext);

    await keyRegistry.updateRatchetSession(request.sharedSecretHandle, nextState);

    return { plaintext };
  });
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
