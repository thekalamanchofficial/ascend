// Client-side audit stub for the Permissions capability's mobile wrapper.
//
// This is NOT this capability's Art. 5 audit trail of record. The real one
// already exists and already fires server-side:
// services/api/internal/permissions/export.go's `ExportPermissions` calls
// its own `AuditEmitter.Emit(...)`, scoped to the server-verified caller,
// even though disclosing a user's own permission history isn't itself a
// state mutation (see that file's own doc comment: "disclosing a user's
// complete permission history is an important, sensitive action in its own
// right"). This stub exists for the same two narrower reasons as every
// sibling capability's audit.ts (identity/audit.ts, fileobjects/audit.ts):
//
//   1. Local dev visibility into what this client module just did, before
//      the corresponding network response (or its failure) comes back.
//   2. Satisfying scripts/constitution/check-audit-events-ts.sh, the
//      mechanical Art. 5 check that requires every exported function
//      marked "// ascend:mutates" under apps/mobile/src/capabilities/** to
//      call logAuditEvent(...) — established by Cryptography & Keys,
//      applied consistently here. `exportPermissions` is marked
//      ascend:mutates for this reason, mirroring identity's exportIdentity
//      and fileobjects' exportFile (both likewise not real state mutations,
//      but significant-disclosure operations this codebase's convention
//      treats the same way). `listGrantsForSubject` is a plain read, like
//      listFileObjects/listDevices, and is NOT so marked.
//
// Same hard rule as every sibling capability's audit.ts: `metadata` may
// only ever contain operation names, already-safe-to-log identifiers
// (identityRef/formatVersion are opaque/non-secret), counts, and outcomes —
// never a grant's full contents beyond what's already safe to log, and
// never the export blob's bytes.
export function logAuditEvent(action: string, metadata: Record<string, string> = {}): void {
  // eslint-disable-next-line no-undef
  const isDev = typeof __DEV__ !== "undefined" ? __DEV__ : process.env.NODE_ENV !== "production";
  if (isDev) {
    // eslint-disable-next-line no-console
    console.log(`[audit:permissions] ${action}`, metadata);
  }
}
