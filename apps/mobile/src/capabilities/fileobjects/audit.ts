// Client-side audit stub for the File Objects capability's mobile wrapper.
//
// This is NOT this capability's Art. 5 audit trail of record. The real one
// already exists and already fires server-side: every mutating RPC
// (CreateFileObject, CreateVersion, SetFilePermissions, SetFileMetadata,
// DeleteFileObject) calls its own AuditEmitter.Emit(...) in
// services/api/internal/fileobjects/service.go, scoped to the
// server-verified caller, and read denials funnel through the single
// shared checkRead()/auditListDenied() call sites documented there (see
// docs/capabilities/file-objects.charter.md §4). This stub exists for the
// same two narrower reasons as identity/audit.ts and sessionauth/audit.ts:
//
//   1. Local dev visibility into what this client module just did, before
//      the corresponding network response (or its failure) comes back.
//   2. Satisfying scripts/constitution/check-audit-events-ts.sh, the
//      mechanical Art. 5 check that requires every exported function
//      marked "// ascend:mutates" under apps/mobile/src/capabilities/** to
//      call logAuditEvent(...) — established by Cryptography & Keys,
//      applied consistently here.
//
// Same hard rule as every sibling capability's audit.ts: `metadata` may
// only ever contain operation names, already-safe-to-log identifiers
// (fileObjectId/versionRef/eventId are opaque server-issued IDs, not
// secrets), counts, and outcomes — never raw file content, an export blob,
// or anything that could embed a blob_ref (charter §6 point 8 — this
// module never even sees a blob_ref, since File Objects' own frozen
// contract never returns one, but the discipline is stated here
// explicitly for the same reason it's stated in the server-side charter).
export function logAuditEvent(action: string, metadata: Record<string, string> = {}): void {
  // eslint-disable-next-line no-undef
  const isDev = typeof __DEV__ !== "undefined" ? __DEV__ : process.env.NODE_ENV !== "production";
  if (isDev) {
    // eslint-disable-next-line no-console
    console.log(`[audit:fileobjects] ${action}`, metadata);
  }
}
