// Identity — TypeScript request/response shapes.
//
// Hand-mirrored from the real, frozen Go wire types
// (services/api/internal/identity/types.go), not generated —
// packages/contracts/gen/ts is stale/incomplete for this capability (see
// docs/DECISION_LOG.md, 2026-08-17, "UI integration readiness
// verification"), and every backend capability implemented so far,
// including Identity itself, already hand-mirrors its own frozen .proto
// shapes rather than importing generated code (see
// services/api/internal/identity/types.go's own package doc comment). This
// module follows that same, established, guardian-accepted precedent —
// mirroring Cryptography & Keys' apps/mobile/src/capabilities/crypto/types.ts
// pattern on the client side of the boundary.
//
// Field names are camelCase to match the real JSON the Go handlers already
// emit (protojson-shaped tags, see types.go's header comment) — this is the
// actual verified wire shape, not an assumption.
//
// IMPORTANT — []byte fields on the wire are base64-encoded JSON strings,
// not raw byte arrays (every Go `[]byte` with a `json:"..."` tag encodes
// this way by default). The types below represent the in-memory,
// already-decoded shape this module's callers work with (Uint8Array, same
// convention Cryptography & Keys uses) — index.ts is the boundary that
// base64-encodes on the way out and base64-decodes on the way in. A field
// name ending in a plain "PublicKey"/"Proof"/"Blob" here is always a
// Uint8Array; nothing in this file's public surface is a base64 string.
//
// If the frozen contract changes, that is a charter amendment routed back
// through the Chief Architect — not a change made unilaterally here.

/**
 * Mirrors identity.Device — a single bound device's public record.
 *
 * unconsumedOneTimePrekeyCount (proto field 6, added 2026-08-20, prekey
 * bundle publish/fetch amendment) is a derived, self-only, count-only
 * passive signal (charter §4/§6's "Prekey exhaustion as an abuse vector"
 * mitigation) — a device's own owner can use it to notice abnormal
 * depletion, the same "security signal" purpose already established for
 * lastSeenUnix. It is never per-fetch/per-fetcher data.
 */
export interface Device {
  deviceId: string;
  name: string;
  publicKey: Uint8Array;
  addedAtUnix: number;
  lastSeenUnix: number;
  unconsumedOneTimePrekeyCount: number;
}

/**
 * Mirrors identity.PublicIdentity. `epoch` (identity.proto field 5) is the
 * device-topology version counter every BindDevice authorizationProof must
 * be signed against — see index.ts's signBindDeviceMessage doc comment and
 * services/api/internal/identity/sign.go's buildDeviceBindingMessage.
 */
export interface PublicIdentity {
  identityRef: string;
  displayName: string;
  publicKey: Uint8Array;
  deviceCount: number;
  epoch: number;
}

// --- Request/response DTOs, one per RPC in identity.proto ---

export interface CreateIdentityRequest {
  displayName: string;
  publicKey: Uint8Array;
  firstDevicePublicKey: Uint8Array;
  firstDeviceName: string;
}

export interface CreateIdentityResponse {
  publicIdentity: PublicIdentity;
  firstDevice: Device;
}

/**
 * `identityRef` is carried in the URL path by the real RPC (POST
 * /v1/identity/{identityRef}/devices), not the JSON body — see
 * services/api/internal/identity/http.go, which overwrites/drops whatever
 * the body sends for that field with the path param. Included here anyway
 * so callers building the signed message (which DOES need identityRef, per
 * sign.go's buildDeviceBindingMessage) have it in one place; index.ts's
 * bindDevice() does not send it as a JSON field.
 */
export interface BindDeviceRequest {
  identityRef: string;
  devicePublicKey: Uint8Array;
  deviceName: string;
  authorizationProof: Uint8Array;
}

export interface BindDeviceResponse {
  device: Device;
  /** The identity's epoch *after* this bind (already advanced). */
  epoch: number;
}

export interface RevokeDeviceRequest {
  identityRef: string;
  deviceId: string;
}

export interface RevokeDeviceResponse {
  /** The identity's epoch *after* this revoke (already advanced). */
  epoch: number;
}

export interface ResolveIdentityRequest {
  identityRef: string;
}

export interface ResolveIdentityResponse {
  publicIdentity: PublicIdentity;
}

export interface ListDevicesRequest {
  identityRef: string;
}

export interface ListDevicesResponse {
  devices: Device[];
}

export interface ExportIdentityRequest {
  identityRef: string;
}

export interface ExportIdentityResponse {
  exportBlob: Uint8Array;
  formatVersion: string;
}

// ---------------------------------------------------------------------------
// Prekey bundle publish/fetch (charter §3/§4/§6, amendment gated
// 2026-08-20; identity.proto AMENDED 2026-08-20). Pure storage/relay for
// public prekey material Cryptography & Keys' own `generatePrekeyBundle`
// already generated and signed — this module never generates, signs, or
// touches private key material.
//
// SignedPrekey/OneTimePrekeyPublic below are DUPLICATED from
// apps/mobile/src/capabilities/crypto/types.ts's identically-shaped
// interfaces of the same name, not imported — mirrors
// services/api/internal/identity/types.go's own identical choice on the Go
// side (see identity.proto's comment on why: "this service has no
// dependency on Cryptography & Keys' package, only on the shape of public
// bytes handed to it as plain RPC input"). Applying that same modularity
// boundary here: this capability's mobile client stays free of an import
// dependency on Cryptography & Keys' module, consuming only plain
// already-signed bytes a caller (the onboarding/vault composition layer)
// hands it — Art. 10.
// ---------------------------------------------------------------------------

/** Mirrors identity.SignedPrekey. */
export interface SignedPrekey {
  prekeyId: string;
  publicKey: Uint8Array;
  signature: Uint8Array;
  createdAtUnix: number;
}

/** Mirrors identity.OneTimePrekeyPublic. */
export interface OneTimePrekeyPublic {
  prekeyId: string;
  publicKey: Uint8Array;
}

/**
 * Mirrors the `PrekeyBundleStatus` proto enum — encoded as its declared
 * string name on the wire (protojson's default enum encoding), matching
 * services/api/internal/identity/types.go's own PrekeyBundleStatus choice
 * (see that file's doc comment).
 */
export type PrekeyBundleStatus =
  | "PREKEY_BUNDLE_STATUS_UNSPECIFIED"
  | "PREKEY_BUNDLE_STATUS_AVAILABLE"
  // Covers BOTH "no bundle ever published for this device" AND "device_id
  // not bound to identity_ref" — deliberately the same value, deliberately
  // indistinguishable to the caller (charter §3/§6, closing the device-ID
  // enumeration oracle).
  | "PREKEY_BUNDLE_STATUS_NOT_PUBLISHED";

/**
 * identityRef/deviceId are carried in the URL path by the real RPC (POST
 * /v1/identity/{identityRef}/devices/{deviceId}/prekeys — see
 * index.ts's publishPrekeyBundle), not the JSON body — same precedent as
 * BindDeviceRequest above.
 *
 * identityDhPublicKey/identityDhPublicKeySignature (added 2026-08-21, the
 * key-separation fix — identity.proto's own comment on
 * PublishPrekeyBundleRequest fields 5/6) are the device's genuinely
 * separate, DH-only X25519 key and its Ed25519 signature over that key —
 * sourced directly from Cryptography & Keys' own `generatePrekeyBundle()`
 * response (identically-named fields, see
 * apps/mobile/src/capabilities/crypto/types.ts's
 * GeneratePrekeyBundleResponse), never derived here. Stable, non-rotating
 * per device, but republished on every call anyway — this module has no
 * way to derive them independently.
 */
export interface PublishPrekeyBundleRequest {
  identityRef: string;
  deviceId: string;
  signedPrekey: SignedPrekey;
  oneTimePrekeys: OneTimePrekeyPublic[];
  identityDhPublicKey: Uint8Array;
  identityDhPublicKeySignature: Uint8Array;
}

export interface PublishPrekeyBundleResponse {
  /**
   * The number of oneTimePrekeys entries genuinely newly stored by this
   * call — re-publishing an already-known prekeyId is a no-op, not
   * counted again. The signed prekey rotation itself is not counted here.
   */
  publishedCount: number;
}

export interface FetchPrekeyBundleRequest {
  identityRef: string;
  /** Omitted resolves to the identity's most-recently-active bound device. */
  deviceId?: string;
}

/**
 * Fields below `status` are populated only when
 * status === "PREKEY_BUNDLE_STATUS_AVAILABLE"; every other field is
 * absent/zero-value otherwise, so a NOT_PUBLISHED response is
 * byte-for-byte identical regardless of which NOT_PUBLISHED case produced
 * it (charter §3/§6).
 *
 * identityDhPublicKey (renamed from identityPublicKey, 2026-08-21
 * key-separation fix) is the target DEVICE's stored X25519 DH-capable
 * key — NEVER the identity's Ed25519 signing key. identitySigningPublicKey
 * (NEW) and identityDhPublicKeySignature (NEW) were added by the same
 * fix — see each field's own doc comment below. This shape matches
 * Cryptography & Keys' `PrekeyBundle` (apps/mobile/src/capabilities/crypto/types.ts)
 * field-for-field; a caller assembling a `PrekeyBundle` to pass into
 * `crypto.deriveSharedSecret` reads directly from this response.
 */
export interface FetchPrekeyBundleResponse {
  status: PrekeyBundleStatus;
  identityDhPublicKey: Uint8Array;
  deviceId: string;
  signedPrekey: SignedPrekey;
  /**
   * Absent when the target device's one-time-prekey pool is exhausted —
   * the exhaustion-fallback case (Cryptography & Keys charter §6),
   * distinct from PREKEY_BUNDLE_STATUS_NOT_PUBLISHED and only meaningful
   * when status is AVAILABLE.
   */
  oneTimePrekey?: OneTimePrekeyPublic;
  /**
   * The identity's Ed25519 SIGNING public key (NEW, 2026-08-21) —
   * sourced from the identity record itself, the same value
   * `resolveIdentity` returns, NOT from the prekey table. Genuinely
   * distinct from identityDhPublicKey above — the trusted verification
   * anchor for BOTH signedPrekey.signature and
   * identityDhPublicKeySignature (see
   * crypto.DeriveSharedSecretRequest.theirIdentitySigningPublicKey).
   */
  identitySigningPublicKey: Uint8Array;
  /**
   * The target device's stored Ed25519 signature over identityDhPublicKey
   * (NEW, 2026-08-21) — verify against identitySigningPublicKey BEFORE
   * using identityDhPublicKey in any DH computation; hard abort on
   * failure, never a silent fallback (Cryptography & Keys charter §6).
   */
  identityDhPublicKeySignature: Uint8Array;
}
