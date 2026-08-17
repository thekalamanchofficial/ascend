// Session / Request Authentication — TypeScript request/response shapes.
//
// Hand-mirrored from the real, frozen Go wire types
// (services/api/internal/sessionauth/types.go), not generated — same
// established precedent as Identity/Cryptography & Keys' client modules;
// see docs/DECISION_LOG.md, 2026-08-17, "UI integration readiness
// verification" and this pass's own decision-log entry.
//
// `proof`/export blob []byte fields are base64-encoded strings on the
// wire; the shapes below are the in-memory, already-decoded form
// (Uint8Array) this module's callers work with — index.ts is the boundary
// that converts. `sessionToken`/`challengeNonce` are plain opaque strings
// on the wire (server-generated CSPRNG output, base64url-encoded by the
// server — see services/api/internal/sessionauth/token.go — but this
// module treats them as opaque strings throughout, never decoding them,
// since nothing on the client ever needs their raw bytes).
//
// If the frozen contract changes, that is a charter amendment routed back
// through the Chief Architect — not a change made unilaterally here.

/**
 * Mirrors sessionauth.SessionSummary — the transparency-view projection
 * ListActiveSessions returns. Deliberately carries no `sessionToken`
 * field (not in the frozen contract) — see charter §3 and the "device
 * removal gap" documented in index.ts's revokeDeviceGapNote.
 */
export interface SessionSummary {
  deviceId: string;
  issuedAtUnix: number;
  expiresAtUnix: number;
  lastUsedAtUnix: number;
}

// --- Request/response DTOs, one per RPC in sessionauth.proto ---

export interface GetSessionChallengeRequest {
  identityRef: string;
  deviceId: string;
}

export interface GetSessionChallengeResponse {
  challengeNonce: string;
  challengeExpiresAtUnix: number;
}

export interface IssueSessionRequest {
  identityRef: string;
  deviceId: string;
  challengeNonce: string;
  proof: Uint8Array;
}

export interface IssueSessionResponse {
  sessionToken: string;
  expiresAtUnix: number;
}

export interface RevokeSessionRequest {
  sessionToken: string;
}

export interface RevokeSessionResponse {}

export interface RevokeAllSessionsRequest {
  callerSessionToken: string;
}

export interface RevokeAllSessionsResponse {
  sessionsRevoked: number;
}

export interface ListActiveSessionsResponse {
  sessions: SessionSummary[];
}

export interface ExportSessionsResponse {
  exportBlob: Uint8Array;
  formatVersion: string;
}
