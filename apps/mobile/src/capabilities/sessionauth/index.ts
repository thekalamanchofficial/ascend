// Session / Request Authentication — thin HTTP client for the seven real,
// network-wired RPCs at /v1/sessionauth
// (services/api/internal/sessionauth/http.go). Per apps/mobile/README.md's
// capability boundary, this module holds no capability logic of its own —
// it never decides whether a session is valid or who's allowed to revoke
// what; that is services/api/internal/sessionauth's job.
//
// Wire contract verified live against the real running server — see
// docs/DECISION_LOG.md, 2026-08-17, this pass's decision-log entry.
//
// You do not need to call validateSession yourself in normal client code —
// that RPC exists for the server's own middleware to resolve a caller from
// a bearer token; it's included here only for this module's completeness
// as a full capability client, mirroring every other RPC's coverage.
import { apiRequest, apiRequestRaw } from "../../api/httpClient";
import { bytesToBase64 } from "../crypto/bytes";
import { logAuditEvent } from "./audit";
import type {
  GetSessionChallengeRequest,
  GetSessionChallengeResponse,
  IssueSessionRequest,
  IssueSessionResponse,
  RevokeSessionRequest,
  RevokeSessionResponse,
  RevokeAllSessionsRequest,
  RevokeAllSessionsResponse,
  ListActiveSessionsResponse,
  ExportSessionsResponse,
} from "./types";

export * from "./types";

// ---------------------------------------------------------------------------
// buildIssueSessionMessage — the exact canonical byte sequence an
// IssueSession `proof` must be an Ed25519 signature over (via crypto's
// sign()), per services/api/internal/sessionauth/sign.go's
// buildIssueSessionMessage, verified byte-for-byte against the real running
// server:
//
//   "ascend.session.v1.IssueSession" || 0x00 ||
//   identityRef || 0x00 ||
//   deviceId || 0x00 ||
//   challengeNonce
//
// Signed with the SAME device key that was bound to this deviceId via
// Identity's BindDevice/CreateIdentity (see
// apps/mobile/src/features/onboarding — the "sign:device-binding"-purpose
// key), never the identity root key, since ValidateSession/IssueSession
// resolve the device's own public key via Identity, not the identity's
// root key.
// ---------------------------------------------------------------------------
export function buildIssueSessionMessage(identityRef: string, deviceId: string, challengeNonce: string): Uint8Array {
  const parts = ["ascend.session.v1.IssueSession", identityRef, deviceId, challengeNonce];
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
// GetSessionChallenge — unauthenticated (no session exists yet).
// ---------------------------------------------------------------------------

export async function getSessionChallenge(
  request: GetSessionChallengeRequest,
): Promise<GetSessionChallengeResponse> {
  return apiRequest<GetSessionChallengeResponse>("/v1/sessionauth/challenge", {
    method: "POST",
    bearerToken: null,
    body: { identityRef: request.identityRef, deviceId: request.deviceId },
  });
}

// ---------------------------------------------------------------------------
// IssueSession — unauthenticated (this call IS how a session is obtained).
// ---------------------------------------------------------------------------

// ascend:mutates
export async function issueSession(request: IssueSessionRequest): Promise<IssueSessionResponse> {
  const resp = await apiRequest<IssueSessionResponse>("/v1/sessionauth/sessions", {
    method: "POST",
    bearerToken: null,
    body: {
      identityRef: request.identityRef,
      deviceId: request.deviceId,
      challengeNonce: request.challengeNonce,
      proof: bytesToBase64(request.proof),
    },
  });

  // Never log the session token itself — only that issuance happened, for
  // which identity/device, and when it expires (see audit.ts's hard rule).
  logAuditEvent("session_issued", {
    identityRef: request.identityRef,
    deviceId: request.deviceId,
    expiresAtUnix: String(resp.expiresAtUnix),
  });

  return resp;
}

// ---------------------------------------------------------------------------
// ValidateSession — included for client completeness; not needed in normal
// app code (server-side middleware concern; see this file's header).
// ---------------------------------------------------------------------------

export async function validateSession(
  sessionToken: string,
): Promise<{ identityRef: string; deviceId: string; valid: boolean }> {
  return apiRequest<{ identityRef: string; deviceId: string; valid: boolean }>("/v1/sessionauth/sessions/validate", {
    method: "POST",
    bearerToken: null,
    body: { sessionToken },
  });
}

// ---------------------------------------------------------------------------
// RevokeSession — "sign out this device/session." The token itself is the
// bearer credential authorizing this call (charter §3) — sent as a body
// field, not an Authorization header, matching the real route's shape.
// ---------------------------------------------------------------------------

// ascend:mutates
export async function revokeSession(request: RevokeSessionRequest): Promise<RevokeSessionResponse> {
  const resp = await apiRequest<RevokeSessionResponse>("/v1/sessionauth/sessions/revoke", {
    method: "POST",
    bearerToken: null,
    body: { sessionToken: request.sessionToken },
  });

  logAuditEvent("session_revoke_requested", {});

  return resp;
}

// ---------------------------------------------------------------------------
// RevokeAllSessions — "sign out everywhere." Fully implementable per this
// capability's charter (no gap like RevokeDevice's cascade below): scoped
// to the caller's own identity, resolved from callerSessionToken itself.
// ---------------------------------------------------------------------------

// ascend:mutates
export async function revokeAllSessions(request: RevokeAllSessionsRequest): Promise<RevokeAllSessionsResponse> {
  const resp = await apiRequest<RevokeAllSessionsResponse>("/v1/sessionauth/sessions/revoke-all", {
    method: "POST",
    bearerToken: null,
    body: { callerSessionToken: request.callerSessionToken },
  });

  logAuditEvent("all_sessions_revoked", { sessionsRevoked: String(resp.sessionsRevoked) });

  return resp;
}

// ---------------------------------------------------------------------------
// ListActiveSessions — gated, read-only, no request body (bearer token
// only). Deliberately returns no session_token per session (charter §3) —
// this is what makes RevokeDevice's session cascade impossible client-side;
// see identity/index.ts's revokeDevice doc comment for the full gap.
// ---------------------------------------------------------------------------

export async function listActiveSessions(callerSessionToken: string): Promise<ListActiveSessionsResponse> {
  return apiRequest<ListActiveSessionsResponse>("/v1/sessionauth/sessions/active", {
    method: "GET",
    bearerToken: callerSessionToken,
  });
}

// ---------------------------------------------------------------------------
// ExportSessions — gated, raw byte body + X-Ascend-Format-Version header,
// not a JSON envelope (see services/api/internal/sessionauth/http.go's
// handleExportSessions). session_token is deliberately never included in
// the export (charter §3/§4) — a live bearer credential is not archival
// data.
// ---------------------------------------------------------------------------

// ascend:mutates
export async function exportSessions(callerSessionToken: string): Promise<ExportSessionsResponse> {
  const { bytes, formatVersion } = await apiRequestRaw("/v1/sessionauth/sessions/export", {
    method: "GET",
    bearerToken: callerSessionToken,
  });

  logAuditEvent("sessions_exported", { formatVersion: formatVersion ?? "unknown" });

  return { exportBlob: bytes, formatVersion: formatVersion ?? "unknown" };
}
