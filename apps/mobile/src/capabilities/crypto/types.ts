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

export interface DeriveSharedSecretRequest {
  privateKeyHandle: KeyHandle;
  remotePublicKey: Uint8Array;
}

export interface DeriveSharedSecretResponse {
  sharedSecretHandle: KeyHandle;
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
