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

/** Mirrors identity.Device — a single bound device's public record. */
export interface Device {
  deviceId: string;
  name: string;
  publicKey: Uint8Array;
  addedAtUnix: number;
  lastSeenUnix: number;
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
