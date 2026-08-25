// Client-side audit stub for the Conversations capability's mobile wrapper.
//
// This is NOT this capability's Art. 5 audit trail of record. The real one
// already exists and already fires server-side: CreateConversation and
// SendMessage both call AuditEmitter.Emit(...) in
// services/api/internal/conversations/service.go, scoped to the
// server-verified caller, per charter §4 — content-free (actor, action,
// conversation_id, timestamp; NEVER ciphertext, NEVER
// session_establishment_payload). Denials of GetConversation/ListMessages/
// ExportConversation/SendMessage for a non-participant are audited too, via
// the shared checkAccess()/auditAccessDenied() call sites documented there.
// This stub exists for the same two narrower reasons as every sibling
// capability's audit.ts (see fileobjects/audit.ts's header comment):
//
//   1. Local dev visibility into what this client module just did, before
//      the corresponding network response (or its failure) comes back.
//   2. Satisfying scripts/constitution/check-audit-events-ts.sh, the
//      mechanical Art. 5 check that requires every exported function
//      marked "// ascend:mutates" under apps/mobile/src/capabilities/** to
//      call logAuditEvent(...).
//
// Same hard rule as every sibling capability's audit.ts: `metadata` may
// only ever contain operation names, already-safe-to-log identifiers
// (conversationId/messageId are opaque server-issued IDs, not secrets;
// otherParticipant/sender/creator/requestingSubject are opaque identity_refs,
// the same already-established non-secret category every other capability's
// client-side audit stub treats them as), counts, and outcomes — NEVER
// ciphertext, a session_establishment_payload, an export blob, or any
// plaintext this app's feature-composition layer may have decrypted
// (apps/mobile/src/features/conversations/ — a strictly different module,
// never imported here).
export function logAuditEvent(action: string, metadata: Record<string, string> = {}): void {
  // eslint-disable-next-line no-undef
  const isDev = typeof __DEV__ !== "undefined" ? __DEV__ : process.env.NODE_ENV !== "production";
  if (isDev) {
    // eslint-disable-next-line no-console
    console.log(`[audit:conversations] ${action}`, metadata);
  }
}
