// Client-side audit stub for the Session/Request Authentication capability's
// mobile wrapper.
//
// This is NOT this capability's Art. 5 audit trail of record. The real one
// already exists and already fires server-side: IssueSession, RevokeSession,
// and RevokeAllSessions each call their own AuditEmitter.Emit(...) in
// services/api/internal/sessionauth/service.go, scoped to the
// server-verified caller. This stub exists for the same two narrower
// reasons as apps/mobile/src/capabilities/identity/audit.ts: local dev
// visibility, and satisfying scripts/constitution/check-audit-events-ts.sh's
// convention (established by Cryptography & Keys, applied consistently
// here rather than carved out as an exception).
//
// Same hard rule as crypto/audit.ts and identity/audit.ts: `metadata` may
// only ever contain operation names, already-safe-to-log identifiers
// (identityRef/deviceId — opaque server-issued IDs, not secrets), counts,
// and outcomes — never a signature/proof, a session_token, or a challenge
// nonce (session_token in particular is a live bearer credential; logging
// it, even to a local dev console, is the exact anti-pattern
// sessionauth's own server-side anomaly tracking hashes before logging —
// see services/api/internal/sessionauth/DATA_MANIFEST.md's note on
// tokenFingerprint. This module never passes a raw session_token to
// logAuditEvent).
export function logAuditEvent(action: string, metadata: Record<string, string> = {}): void {
  // eslint-disable-next-line no-undef
  const isDev = typeof __DEV__ !== "undefined" ? __DEV__ : process.env.NODE_ENV !== "production";
  if (isDev) {
    // eslint-disable-next-line no-console
    console.log(`[audit:sessionauth] ${action}`, metadata);
  }
}
