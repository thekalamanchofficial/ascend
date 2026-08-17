// Identity — thin HTTP client for the six real, network-wired RPCs at
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
 * KNOWN GAP (do not silently paper over — see
 * docs/DECISION_LOG.md, 2026-08-17, "UI integration readiness verification"
 * and this pass's own entry): removing a device here revokes its Identity
 * binding ONLY. It does NOT also revoke that device's currently-active
 * sessions. Session/Request Authentication's ListActiveSessions returns no
 * session_token per session (by design — see sessionauth's charter §3), so
 * this client has no way to look up and RevokeSession the specific
 * sessions belonging to `request.deviceId`. RevokeAllSessions is scoped to
 * ALL of the *caller's own* sessions across every device, not one target
 * device, so calling it here would be over-broad and silently change the
 * promised "remove this device" UX without authorization. ValidateSession
 * also does not re-check device-bound status, so a removed device's
 * already-issued sessions remain valid until natural expiry. This is a
 * cross-capability contract gap, routed back to the Chief Architect, not
 * resolved unilaterally here.
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
