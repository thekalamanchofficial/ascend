// Client-side audit stub for the Identity capability's mobile wrapper.
//
// This is NOT this capability's Art. 5 audit trail of record. The real one
// already exists and already fires: every mutating RPC in
// services/api/internal/identity/service.go (CreateIdentity, BindDevice,
// RevokeDevice, ExportIdentity) calls its own AuditEmitter.Emit(...)
// server-side, scoped to the server-verified caller — see that package's
// service.go/audit.go. This stub exists for two narrower reasons:
//
//   1. Local dev visibility into what this client module just did, before
//      the corresponding network response (or its failure) comes back.
//   2. Satisfying scripts/constitution/check-audit-events-ts.sh, the
//      mechanical Art. 5 check that requires every exported function marked
//      "// ascend:mutates" under apps/mobile/src/capabilities/** to call
//      logAuditEvent(...) — the same convention Cryptography & Keys
//      established (see apps/mobile/src/capabilities/crypto/audit.ts),
//      applied consistently here rather than carved out as an exception.
//
// Same hard rule as crypto/audit.ts: `metadata` may only ever contain
// operation names, identifiers already safe to log (identityRef/deviceId
// are opaque server-issued IDs, not secrets), counts, and outcomes — never
// a public key, a signature/proof, or export blob bytes.
export function logAuditEvent(action: string, metadata: Record<string, string> = {}): void {
  // eslint-disable-next-line no-undef
  const isDev = typeof __DEV__ !== "undefined" ? __DEV__ : process.env.NODE_ENV !== "production";
  if (isDev) {
    // eslint-disable-next-line no-console
    console.log(`[audit:identity] ${action}`, metadata);
  }
}
