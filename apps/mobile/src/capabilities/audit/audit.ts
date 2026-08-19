// Client-side audit stub for the Audit / Explainability capability's OWN
// mobile wrapper.
//
// This is NOT a second audit trail of record — Audit IS the audit trail of
// record (services/api/internal/audit), and every RPC this module wraps
// either reads that trail (Query, Explain) or discloses it (ExportAuditTrail).
// Reads are not themselves state mutations, so per this codebase's
// established convention (see identity/audit.ts, permissions/audit.ts,
// fileobjects/audit.ts) this stub exists for exactly the same two narrower
// reasons every sibling capability's audit.ts states:
//
//   1. Local dev visibility into what this client module just did, before
//      the corresponding network response (or its failure) comes back.
//   2. Satisfying scripts/constitution/check-audit-events-ts.sh, the
//      mechanical Art. 5 check that requires every exported function
//      marked "// ascend:mutates" under apps/mobile/src/capabilities/** to
//      call logAuditEvent(...). `exportAuditTrail` is marked
//      ascend:mutates for this reason, mirroring identity's exportIdentity,
//      permissions' exportPermissions, and sessionauth's exportSessions
//      (none are real state mutations, but all are significant-disclosure
//      operations this codebase's convention treats the same way — a
//      user's full activity history leaving the device is worth a local
//      trace even though nothing server-side changed as a result).
//      `query` and `explain` are plain reads, like `listGrantsForSubject`/
//      `listFileObjects`, and are NOT so marked.
//
// Deliberately NOT wired to services/api/internal/audit's own Emit RPC —
// this module has no legitimate reason to emit an audit event about
// reading/exporting the audit trail itself back into the audit trail (that
// would be circular, and is not what this stub is for). Same hard rule as
// every sibling capability's audit.ts: `metadata` may only ever contain
// operation names, already-safe-to-log identifiers (identityRef/
// formatVersion/eventId are opaque/non-secret), counts, and outcomes —
// never an event's full metadata contents beyond what's already safe to
// log, and never the export bundle's bytes.
export function logAuditEvent(action: string, metadata: Record<string, string> = {}): void {
  // eslint-disable-next-line no-undef
  const isDev = typeof __DEV__ !== "undefined" ? __DEV__ : process.env.NODE_ENV !== "production";
  if (isDev) {
    // eslint-disable-next-line no-console
    console.log(`[audit:audit] ${action}`, metadata);
  }
}
