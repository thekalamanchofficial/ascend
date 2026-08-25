// Identity — thin HTTP client for the eight real, network-wired RPCs at
// /v1/identity (services/api/internal/identity/http.go). Per
// apps/mobile/README.md's capability boundary, this module holds no
// capability logic of its own — it only shapes requests/responses and
// calls the real backend. It never decides *whether* a device binding is
// authorized; that is services/api/internal/identity's job (verified
// server-side against the signed authorizationProof).
//
// Wire contract verified live against the real running server (not just
// read from source) — see docs/DECISION_LOG.md, 2026-08-17, "Identity +
// Session/Request Authentication mobile client integration" for how.
import { apiRequest } from "../../api/httpClient";
import { bytesToBase64, base64ToBytes } from "../crypto/bytes";
import { logAuditEvent } from "./audit";
import type {
  CreateIdentityRequest,
  CreateIdentityResponse,
  BindDeviceRequest,
  BindDeviceResponse,
  RevokeDeviceRequest,
  RevokeDeviceResponse,
  ResolveIdentityRequest,
  ResolveIdentityResponse,
  ListDevicesRequest,
  ListDevicesResponse,
  ExportIdentityRequest,
  ExportIdentityResponse,
  Device,
  PublicIdentity,
  PublishPrekeyBundleRequest,
  PublishPrekeyBundleResponse,
  FetchPrekeyBundleRequest,
  FetchPrekeyBundleResponse,
  SignedPrekey,
  OneTimePrekeyPublic,
  PrekeyBundleStatus,
} from "./types";

export * from "./types";

// --- Wire DTOs (base64-string []byte fields), local to this file only.
// Never exported — callers only ever see the Uint8Array-shaped types from
// ./types; these exist purely to describe what actually goes over HTTP. ---

interface WireDevice {
  deviceId: string;
  name: string;
  publicKey: string;
  addedAtUnix: number;
  lastSeenUnix: number;
  unconsumedOneTimePrekeyCount: number;
}

interface WirePublicIdentity {
  identityRef: string;
  displayName: string;
  publicKey: string;
  deviceCount: number;
  epoch: number;
}

function deviceFromWire(w: WireDevice): Device {
  return { ...w, publicKey: base64ToBytes(w.publicKey) };
}

function publicIdentityFromWire(w: WirePublicIdentity): PublicIdentity {
  return { ...w, publicKey: base64ToBytes(w.publicKey) };
}

// ---------------------------------------------------------------------------
// signBindDeviceMessage — the exact canonical byte sequence a BindDevice
// authorizationProof must be an Ed25519 signature over (via crypto's
// sign()), per services/api/internal/identity/sign.go's
// buildDeviceBindingMessage, verified byte-for-byte against the real running
// server:
//
//   "ascend.identity.v1.BindDevice" || 0x00 ||
//   identityRef || 0x00 ||
//   base64(devicePublicKey) || 0x00 ||
//   deviceName || 0x00 ||
//   decimal(epoch)
//
// `epoch` must be the identity's CURRENT epoch *at signing time* — i.e. the
// value from the most recent CreateIdentity/BindDevice/RevokeDevice
// response the signer has observed for this identity, not a value fetched
// fresh from any RPC (identity.proto's frozen response shapes are the only
// place epoch is discoverable at all — see sign.go's own doc comment on
// this limitation). A caller with a stale local epoch fails closed
// (server returns 401 ErrInvalidSignature) rather than silently succeeding
// against the wrong value — this is a deliberate anti-replay property, not
// a bug to route around.
// ---------------------------------------------------------------------------
export function buildBindDeviceMessage(
  identityRef: string,
  devicePublicKey: Uint8Array,
  deviceName: string,
  epoch: number,
): Uint8Array {
  const parts = [
    "ascend.identity.v1.BindDevice",
    identityRef,
    bytesToBase64(devicePublicKey),
    deviceName,
    String(epoch),
  ];
  const encoder = new TextEncoder();
  const encoded = parts.map((p) => encoder.encode(p));
  const NUL = new Uint8Array([0]);
  const total = encoded.reduce((sum, e) => sum + e.length, 0) + NUL.length * (encoded.length - 1);
  const out = new Uint8Array(total);
  let offset = 0;
  encoded.forEach((chunk, i) => {
    out.set(chunk, offset);
    offset += chunk.length;
    if (i < encoded.length - 1) {
      out.set(NUL, offset);
      offset += NUL.length;
    }
  });
  return out;
}

// ---------------------------------------------------------------------------
// CreateIdentity
// ---------------------------------------------------------------------------

// ascend:mutates
export async function createIdentity(request: CreateIdentityRequest): Promise<CreateIdentityResponse> {
  const resp = await apiRequest<{ publicIdentity: WirePublicIdentity; firstDevice: WireDevice }>("/v1/identity/", {
    method: "POST",
    bearerToken: null, // bootstrapping route, intentionally unauthenticated
    body: {
      displayName: request.displayName,
      publicKey: bytesToBase64(request.publicKey),
      firstDevicePublicKey: bytesToBase64(request.firstDevicePublicKey),
      firstDeviceName: request.firstDeviceName,
    },
  });

  logAuditEvent("identity_created", { identityRef: resp.publicIdentity.identityRef });

  return {
    publicIdentity: publicIdentityFromWire(resp.publicIdentity),
    firstDevice: deviceFromWire(resp.firstDevice),
  };
}

// ---------------------------------------------------------------------------
// BindDevice
// ---------------------------------------------------------------------------

// ascend:mutates
export async function bindDevice(request: BindDeviceRequest): Promise<BindDeviceResponse> {
  const resp = await apiRequest<{ device: WireDevice; epoch: number }>(
    `/v1/identity/${encodeURIComponent(request.identityRef)}/devices`,
    {
      method: "POST",
      // Unauthenticated route by design (services/api/internal/identity/http.go
      // — authorization is the signed authorizationProof itself, verified
      // server-side, not a bearer session). identityRef is dropped from the
      // body here since the real handler takes it from the URL path only.
      bearerToken: null,
      body: {
        devicePublicKey: bytesToBase64(request.devicePublicKey),
        deviceName: request.deviceName,
        authorizationProof: bytesToBase64(request.authorizationProof),
      },
    },
  );

  logAuditEvent("device_bind_requested", {
    identityRef: request.identityRef,
    deviceId: resp.device.deviceId,
    epochAfter: String(resp.epoch),
  });

  return { device: deviceFromWire(resp.device), epoch: resp.epoch };
}

// ---------------------------------------------------------------------------
// RevokeDevice
// ---------------------------------------------------------------------------

/**
 * `sessionToken` authorizes this call (gated route — the caller's verified
 * identity must match `request.identityRef`, enforced server-side by
 * requireCallerMatchesIdentity middleware). Pass the current session's
 * token, obtained from Session/Request Authentication's issueSession.
 *
 * This revokes only the Identity binding — it does NOT by itself revoke
 * the device's active sessions. That used to be a real, unclosed gap (see
 * docs/DECISION_LOG.md, 2026-08-17, "UI integration readiness verification"
 * and "Identity + Session/Request Authentication mobile client
 * integration"), closed the same day via a charter amendment adding
 * sessionauth's `revokeSessionsForDevice` RPC. Callers of this function
 * MUST also call `sessionauth.revokeSessionsForDevice`, in that order (this
 * call first), to complete a real device removal — see
 * `onboarding.ts`'s `removeDevice`, the one real call site, which does
 * exactly that per the charter's §5 composition-ordering requirement. This
 * function on its own remains a legitimate, narrower operation (unbind a
 * device without necessarily touching its live sessions) for any future
 * caller that genuinely wants only that.
 */
// ascend:mutates
export async function revokeDevice(request: RevokeDeviceRequest, sessionToken: string): Promise<RevokeDeviceResponse> {
  const resp = await apiRequest<{ epoch: number }>(
    `/v1/identity/${encodeURIComponent(request.identityRef)}/devices/${encodeURIComponent(request.deviceId)}`,
    { method: "DELETE", bearerToken: sessionToken },
  );

  logAuditEvent("device_revoke_requested", {
    identityRef: request.identityRef,
    deviceId: request.deviceId,
    epochAfter: String(resp.epoch),
  });

  return { epoch: resp.epoch };
}

// ---------------------------------------------------------------------------
// ResolveIdentity — public, unauthenticated lookup, read-only.
// ---------------------------------------------------------------------------

export async function resolveIdentity(request: ResolveIdentityRequest): Promise<ResolveIdentityResponse> {
  const resp = await apiRequest<{ publicIdentity: WirePublicIdentity }>(
    `/v1/identity/${encodeURIComponent(request.identityRef)}`,
    { method: "GET", bearerToken: null },
  );
  return { publicIdentity: publicIdentityFromWire(resp.publicIdentity) };
}

// ---------------------------------------------------------------------------
// ListDevices — gated, read-only.
// ---------------------------------------------------------------------------

export async function listDevices(request: ListDevicesRequest, sessionToken: string): Promise<ListDevicesResponse> {
  const resp = await apiRequest<{ devices: WireDevice[] }>(
    `/v1/identity/${encodeURIComponent(request.identityRef)}/devices`,
    { method: "GET", bearerToken: sessionToken },
  );
  return { devices: resp.devices.map(deviceFromWire) };
}

// ---------------------------------------------------------------------------
// ExportIdentity — gated (Art. 9: always-available, not a support ticket).
// ---------------------------------------------------------------------------

// ascend:mutates
export async function exportIdentity(
  request: ExportIdentityRequest,
  sessionToken: string,
): Promise<ExportIdentityResponse> {
  const resp = await apiRequest<{ exportBlob: string; formatVersion: string }>(
    `/v1/identity/${encodeURIComponent(request.identityRef)}/export`,
    { method: "GET", bearerToken: sessionToken },
  );

  logAuditEvent("identity_exported", { identityRef: request.identityRef, formatVersion: resp.formatVersion });

  return { exportBlob: base64ToBytes(resp.exportBlob), formatVersion: resp.formatVersion };
}

// ---------------------------------------------------------------------------
// Prekey bundle publish/fetch (charter §3/§4/§6, amendment gated
// 2026-08-20). Fully invisible, automatic machinery per charter §5
// (amended) — no dedicated screen: publishPrekeyBundle is called by the
// onboarding composition layer immediately after bindDevice succeeds
// (charter §7's recommended client-orchestration mitigation for the
// brand-new-identity edge case), and fetchPrekeyBundle is called by
// Conversations' own lazy CreateConversation flow, not from a UI action
// here.
// ---------------------------------------------------------------------------

// base64ToBytesOrEmpty guards against the real wire shape's `null`/absent
// []byte fields — FetchPrekeyBundleResponse's fields below `status` are
// left at Go zero-value when status is NOT_PUBLISHED (identity.proto's own
// comment on FetchPrekeyBundleResponse), and Go's encoding/json marshals a
// nil []byte with no `omitempty` (e.g. SignedPrekey.publicKey/signature)
// as JSON `null`, not an empty string — base64ToBytes itself has no
// null-guard (it assumes a real base64 string), so this wrapper is what
// actually makes decoding a NOT_PUBLISHED response safe rather than
// throwing.
function base64ToBytesOrEmpty(value: string | null | undefined): Uint8Array {
  if (!value) return new Uint8Array(0);
  return base64ToBytes(value);
}

interface WireSignedPrekey {
  prekeyId: string;
  publicKey: string | null;
  signature: string | null;
  createdAtUnix: number;
}

interface WireOneTimePrekeyPublic {
  prekeyId: string;
  publicKey: string;
}

function signedPrekeyFromWire(w: WireSignedPrekey): SignedPrekey {
  return {
    prekeyId: w.prekeyId,
    publicKey: base64ToBytesOrEmpty(w.publicKey),
    signature: base64ToBytesOrEmpty(w.signature),
    createdAtUnix: w.createdAtUnix,
  };
}

function signedPrekeyToWire(s: SignedPrekey): WireSignedPrekey {
  return {
    prekeyId: s.prekeyId,
    publicKey: bytesToBase64(s.publicKey),
    signature: bytesToBase64(s.signature),
    createdAtUnix: s.createdAtUnix,
  };
}

function oneTimePrekeyFromWire(w: WireOneTimePrekeyPublic): OneTimePrekeyPublic {
  return { prekeyId: w.prekeyId, publicKey: base64ToBytes(w.publicKey) };
}

function oneTimePrekeyToWire(o: OneTimePrekeyPublic): WireOneTimePrekeyPublic {
  return { prekeyId: o.prekeyId, publicKey: bytesToBase64(o.publicKey) };
}

/**
 * PublishPrekeyBundle — replaces the caller's own device's current signed
 * prekey (rotation) and additively appends oneTimePrekeys to that device's
 * pool. Gated: the caller's sessionToken must authorize BOTH
 * request.identityRef AND request.deviceId as the verified caller's own
 * (server-enforced device-level check — see
 * services/api/wiring.go's requireCallerMatchesIdentityAndDevice). Every
 * value here is already-public, already-signed bytes Cryptography & Keys'
 * generatePrekeyBundle produced — this function never generates, signs, or
 * inspects private key material.
 */
// ascend:mutates
export async function publishPrekeyBundle(
  request: PublishPrekeyBundleRequest,
  sessionToken: string,
): Promise<PublishPrekeyBundleResponse> {
  const resp = await apiRequest<{ publishedCount: number }>(
    `/v1/identity/${encodeURIComponent(request.identityRef)}/devices/${encodeURIComponent(request.deviceId)}/prekeys`,
    {
      method: "POST",
      bearerToken: sessionToken,
      body: {
        signedPrekey: signedPrekeyToWire(request.signedPrekey),
        oneTimePrekeys: request.oneTimePrekeys.map(oneTimePrekeyToWire),
        // identityDhPublicKey/identityDhPublicKeySignature (key-separation
        // fix, charter §3) — stable, non-rotating per device, but sent on
        // every call anyway; this module never generates or verifies
        // them, only relays crypto.generatePrekeyBundle's own output.
        identityDhPublicKey: bytesToBase64(request.identityDhPublicKey),
        identityDhPublicKeySignature: bytesToBase64(request.identityDhPublicKeySignature),
      },
    },
  );

  logAuditEvent("prekey_bundle_published", {
    identityRef: request.identityRef,
    deviceId: request.deviceId,
    publishedCount: String(resp.publishedCount),
  });

  return { publishedCount: resp.publishedCount };
}

/**
 * FetchPrekeyBundle — the one deliberately open, non-self-scoped read this
 * capability exposes (charter §3/§6): any authenticated caller may fetch
 * any identity's bundle, gated only by sessionToken identifying SOME valid
 * session (never checked against request.identityRef). Atomically consumes
 * one available one-time prekey from the target device's pool on every
 * successful (AVAILABLE-status) call — marked ascend:mutates for that
 * reason (mirroring services/api/internal/identity/service.go's own
 * FetchPrekeyBundle marking) even though it is framed as a "fetch"/read,
 * exactly the same "open-to-any-caller read with a real, resource-
 * depleting write side effect" reasoning charter §6 states explicitly.
 */
// ascend:mutates
export async function fetchPrekeyBundle(
  request: FetchPrekeyBundleRequest,
  sessionToken: string,
): Promise<FetchPrekeyBundleResponse> {
  const query = request.deviceId ? `?deviceId=${encodeURIComponent(request.deviceId)}` : "";
  const resp = await apiRequest<{
    status: PrekeyBundleStatus;
    identityDhPublicKey?: string | null;
    deviceId?: string;
    signedPrekey: WireSignedPrekey;
    oneTimePrekey?: WireOneTimePrekeyPublic | null;
    identitySigningPublicKey?: string | null;
    identityDhPublicKeySignature?: string | null;
  }>(`/v1/identity/${encodeURIComponent(request.identityRef)}/prekey-bundle${query}`, {
    method: "GET",
    bearerToken: sessionToken,
  });

  logAuditEvent("prekey_bundle_fetched", { identityRef: request.identityRef, status: resp.status });

  return {
    status: resp.status,
    identityDhPublicKey: base64ToBytesOrEmpty(resp.identityDhPublicKey),
    deviceId: resp.deviceId ?? "",
    signedPrekey: signedPrekeyFromWire(resp.signedPrekey),
    oneTimePrekey: resp.oneTimePrekey ? oneTimePrekeyFromWire(resp.oneTimePrekey) : undefined,
    identitySigningPublicKey: base64ToBytesOrEmpty(resp.identitySigningPublicKey),
    identityDhPublicKeySignature: base64ToBytesOrEmpty(resp.identityDhPublicKeySignature),
  };
}
