// Cryptography & Keys — TypeScript request/response shapes.
//
// These mirror packages/contracts/proto/ascend/crypto/v1/crypto.proto
// message-for-message (camelCase field names per TS convention, semantics
// unchanged). Field names and shapes here are load-bearing: if the frozen
// contract changes, that is a charter amendment routed back through the
// Chief Architect, not a change made unilaterally in this module.

/** Opaque reference to key material held inside this module. Never raw key bytes. */
export interface KeyHandle {
  handle: string;
}

export interface GenerateIdentityKeyMaterialRequest {}

export interface GenerateIdentityKeyMaterialResponse {
  publicKey: Uint8Array;
  privateKeyHandle: KeyHandle;
  /** Shown once by the caller. Never persisted or logged by this module. */
  recoveryPhrase: string;
}

export interface GenerateKeyPairRequest {
  purpose: string;
}

export interface GenerateKeyPairResponse {
  publicKey: Uint8Array;
  privateKeyHandle: KeyHandle;
}

export interface EncryptRequest {
  recipientPublicKeys: Uint8Array[];
  plaintext: Uint8Array;
}

export interface EncryptResponse {
  ciphertext: Uint8Array;
}

export interface DecryptRequest {
  privateKeyHandle: KeyHandle;
  ciphertext: Uint8Array;
}

export interface DecryptResponse {
  plaintext: Uint8Array;
}

// A responder's published medium-term prekey, signed by the identity's
// long-term signing key (charter §6 "Signed-prekey substitution" —
// verification of this signature before use is required, not optional; see
// index.ts's deriveSharedSecret).
export interface SignedPrekey {
  prekeyId: string;
  publicKey: Uint8Array;
  signature: Uint8Array;
  createdAtUnix: number;
}

// A responder's published single-use prekey. Consuming one (via
// CompleteSharedSecret) permanently deletes its private half — this is the
// term that provides responder-side forward secrecy (charter §6).
export interface OneTimePrekeyPublic {
  prekeyId: string;
  publicKey: Uint8Array;
}

// What an initiator fetches (from wherever it's published — Identity's own
// companion amendment, not this capability) before calling
// DeriveSharedSecret. oneTimePrekey absent means the exhaustion-fallback
// case (charter §6) — DeriveSharedSecret must still succeed, with the
// stated weaker guarantee.
//
// identityDhPublicKey/its signature live INSIDE this bundle, 2026-08-21
// key-separation fix (Security Steward implementation-gate finding, round
// 2): the responder's DH-capable identity key is server-published/-fetched
// material, exactly like signedPrekey, and so needs the identical
// signature-verification discipline — it must not be trusted as a bare,
// unsigned value a compromised server could substitute.
export interface PrekeyBundle {
  /**
   * The responder's X25519 DH-capable identity public key (charter §3's
   * "IK_A/IK_B MUST be a genuinely separate, DH-only key" requirement) —
   * NEVER the Ed25519 signing key. Verified against
   * DeriveSharedSecretRequest.theirIdentitySigningPublicKey via
   * identityDhPublicKeySignature before use in any DH term — hard abort on
   * failure, the same discipline signedPrekey's own signature already
   * requires.
   */
  identityDhPublicKey: Uint8Array;
  identityDhPublicKeySignature: Uint8Array;
  signedPrekey: SignedPrekey;
  oneTimePrekey?: OneTimePrekeyPublic;
}

export interface DeriveSharedSecretRequest {
  privateKeyHandle: KeyHandle;
  /**
   * The responder's Ed25519 SIGNING public key — NOT DH-capable, and
   * genuinely distinct from theirPrekeyBundle.identityDhPublicKey. This is
   * the trusted verification anchor for BOTH
   * theirPrekeyBundle.signedPrekey.signature AND
   * theirPrekeyBundle.identityDhPublicKeySignature. Sourced from Identity's
   * ResolveIdentity — the same value that RPC has always returned,
   * unchanged by the 2026-08-21 key-separation fix. Corrected 2026-08-21:
   * an earlier pass named this field theirIdentityDhPublicKey, which broke
   * signature verification — the verification anchor and the DH-capable
   * key are two different keys and must never be the same wire field
   * again.
   */
  theirIdentitySigningPublicKey: Uint8Array;
  theirPrekeyBundle: PrekeyBundle;
}

export interface DeriveSharedSecretResponse {
  sharedSecretHandle: KeyHandle;
  /** The caller's own freshly generated, single-use ephemeral public key. */
  myEphemeralPublicKey: Uint8Array;
}

export interface CompleteSharedSecretRequest {
  privateKeyHandle: KeyHandle;
  /**
   * The INITIATOR's X25519 DH-capable identity key — carried in
   * Conversations' session_establishment_payload (charter §7 item 4). MUST
   * be verified against theirIdentitySigningPublicKey via
   * theirIdentityDhPublicKeySignature before use in any DH term — required,
   * added 2026-08-21, round 4 (Security Steward gate finding: a distinct
   * threat DH-term-isolation does NOT cover — an attacker who fabricates
   * BOTH theirIdentityDhPublicKey and theirEphemeralPublicKey wholesale
   * holds 100% of the private material every DH term needs and can derive
   * a fully working shared secret the responder will accept as belonging
   * to whatever identity the fabricated key is presented as — "minting a
   * valid key on a user's behalf" under a compromised relay, not merely a
   * derivation mismatch).
   */
  theirIdentityDhPublicKey: Uint8Array;
  theirEphemeralPublicKey: Uint8Array;
  mySignedPrekeyId: string;
  /** Absent means the exhaustion-fallback case (charter §6). */
  myOneTimePrekeyId?: string;
  /**
   * Added 2026-08-21, round 4, same finding. The claimed sender's Ed25519
   * signing public key — sourced by the caller via Identity's
   * ResolveIdentity(sender_identity_ref). The trusted verification anchor
   * for theirIdentityDhPublicKeySignature below.
   */
  theirIdentitySigningPublicKey: Uint8Array;
  /**
   * The initiator's own signature over theirIdentityDhPublicKey (their own
   * GeneratePrekeyBundleResponse.identityDhPublicKeySignature, cached
   * locally and included directly in session_establishment_payload).
   * Verified against theirIdentitySigningPublicKey; hard abort on failure
   * (reusing signed_prekey_signature_invalid, charter §6), never a silent
   * fallback.
   */
  theirIdentityDhPublicKeySignature: Uint8Array;
}

export interface CompleteSharedSecretResponse {
  sharedSecretHandle: KeyHandle;
}

export interface GeneratePrekeyBundleRequest {
  oneTimePrekeyCount: number;
}

export interface GeneratePrekeyBundleResponse {
  /**
   * The device's X25519 DH-capable identity public key, deterministically
   * derived from the same recovery-phrase seed as the Ed25519 signing key
   * via a domain-separated KDF (charter §3) — genuinely different bytes
   * from GenerateIdentityKeyMaterialResponse.publicKey.
   */
  identityDhPublicKey: Uint8Array;
  signedPrekey: SignedPrekey;
  oneTimePrekeys: OneTimePrekeyPublic[];
  /**
   * Signed with the SAME Ed25519 identity signing key that signs
   * signedPrekey.signature, generated in this same call — required,
   * 2026-08-21 (Security Steward finding: an unsigned identityDhPublicKey
   * is a substitution surface a compromised publish/fetch path could
   * exploit).
   */
  identityDhPublicKeySignature: Uint8Array;
}

export interface SecureLocalStoreRequest {
  key: string;
  value: Uint8Array;
}

export interface SecureLocalStoreResponse {}

export interface SecureLocalRetrieveRequest {
  key: string;
}

export interface SecureLocalRetrieveResponse {
  value: Uint8Array;
}

export interface RestoreFromRecoveryPhraseRequest {
  recoveryPhrase: string;
}

export interface RestoreFromRecoveryPhraseResponse {
  privateKeyHandle: KeyHandle;
  publicKey: Uint8Array;
}

export interface ExportKeyMaterialRequest {
  userConfirmation: boolean;
}

export interface ExportKeyMaterialResponse {
  exportBlob: Uint8Array;
  formatVersion: string;
}

export interface SignRequest {
  privateKeyHandle: KeyHandle;
  message: Uint8Array;
}

export interface SignResponse {
  signature: Uint8Array;
}

// ---------------------------------------------------------------------------
// EncryptMessage / DecryptMessage — added 2026-08-23, "the ongoing-ratchet
// exposure gap" amendment (charter §3/§6/§7). The first RPCs in this
// capability's public contract to actually consume a sharedSecretHandle for
// real message content — DeriveSharedSecret/CompleteSharedSecret only ever
// established a session before this amendment. `plaintext`/`ciphertext`
// never cross this capability's own boundary in the other direction
// (plaintext never leaves the device; `ciphertext` is a single,
// self-describing, versioned opaque byte string a caller relays and never
// interprets — see messageEnvelope.ts).
// ---------------------------------------------------------------------------

export interface EncryptMessageRequest {
  sharedSecretHandle: KeyHandle;
  plaintext: Uint8Array;
}

export interface EncryptMessageResponse {
  ciphertext: Uint8Array;
}

export interface DecryptMessageRequest {
  sharedSecretHandle: KeyHandle;
  ciphertext: Uint8Array;
}

export interface DecryptMessageResponse {
  plaintext: Uint8Array;
}
