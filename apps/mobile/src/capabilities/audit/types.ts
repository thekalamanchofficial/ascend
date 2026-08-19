// Audit / Explainability — TypeScript request/response shapes.
//
// Hand-mirrored from the real, frozen Go wire types
// (services/api/internal/audit/types.go, http.go, export.go), not
// generated — same established precedent as every other capability client
// in this codebase (see identity/types.ts's own header comment for the full
// rationale).
//
// *** WIRE-FORMAT NOTE, VERIFIED AGAINST REAL GO SOURCE, NOT ASSUMED. ***
//
// Unlike Permissions (mixed PascalCase wrapper / snake_case Grant) or
// Identity/SessionAuth (fully camelCase), Audit's HTTP DTOs
// (services/api/internal/audit/http.go's queryResponseDTO/
// explainResponseDTO/emitResponseDTO) carry explicit snake_case `json`
// tags throughout, matching the frozen `AuditEvent` struct
// (services/api/internal/audit/types.go) exactly:
//   { "events": [ { "event_id": "...", "actor": "...", "action": "...",
//                    "resource": { "resource_type": "...", "resource_id": "..." },
//                    "rule_reference": "...", "metadata": { ... },
//                    "occurred_at_unix": 123 } ] }
// index.ts's `Wire*` interfaces below encode exactly this shape.
//
// ExportAuditTrail does NOT follow Identity's/Permissions' "JSON envelope
// with a base64 `exportBlob` field" pattern — it follows SessionAuth's
// ExportSessions pattern instead: a raw (non-enveloped) JSON body (the
// export bundle itself, services/api/internal/audit/export.go's
// `ExportBundle`) plus an `X-Ascend-Format-Version` response header
// (verified against http.go's `handleExport`, byte-for-byte identical
// shape to sessionauth/http.go's `handleExportSessions`). index.ts calls
// `apiRequestRaw` (not `apiRequest`) for this reason, exactly like
// sessionauth's `exportSessions`.
//
// If the frozen contract (packages/contracts/proto/ascend/audit/v1/audit.proto)
// changes, that is a charter amendment routed back through the Chief
// Architect — not a change made unilaterally here.

/** Mirrors audit.ResourceRef — an opaque reference to the resource an event is about. Audit never interprets resource_type/resource_id beyond treating them as opaque strings, same as Permissions' identical-shaped ResourceRef. */
export interface ResourceRef {
  resourceType: string;
  resourceId: string;
}

/**
 * Mirrors audit.AuditEvent — one durable, append-only record of an
 * explainable action (charter §3/§6). `metadata` may only ever describe
 * *that* an action happened (never sensitive content — e.g. record that a
 * file was decrypted and by whom, never the plaintext); this module does
 * not enforce that (the server does), it only displays whatever comes
 * back.
 */
export interface AuditEvent {
  eventId: string;
  actor: string;
  action: string;
  resource: ResourceRef;
  ruleReference: string;
  metadata: Record<string, string>;
  occurredAtUnix: number;
}

// --- Request/response DTOs, for the three RPCs this module exposes
// (charter §3's Query/Explain/ExportAuditTrail — Emit is deliberately not
// wrapped here: it is the internal, capability-to-capability call other
// backend capabilities make in-process; mobile has no legitimate reason to
// call it directly. See index.ts's header.) ---

/**
 * A subject's own audit trail (charter §3), queryable by resource, time
 * range, or action type (audit.proto's QueryRequest fields). `subject`
 * MUST be the caller's own identityRef — the server enforces this
 * independently for any cross-subject query (fail-closed
 * PermissionChecker, services/api/internal/audit/service.go's `Query`),
 * same 403-on-mismatch discipline as every other self-scoped RPC in this
 * codebase. All filter fields are optional (server treats a zero value as
 * "no filter" — see http.go's `parseUnixOrZero` and QueryFilter's
 * zero-valued string fields).
 */
export interface QueryRequest {
  subject: string;
  resourceTypeFilter?: string;
  resourceIdFilter?: string;
  actionFilter?: string;
  sinceUnix?: number;
  untilUnix?: number;
}

export interface QueryResponse {
  events: AuditEvent[];
}

/** Turns a raw event into a plain-language rationale (charter §3). Subject to the same self-or-permitted visibility rule as Query, evaluated server-side against the event's own actor. */
export interface ExplainRequest {
  eventId: string;
}

export interface ExplainResponse {
  humanReadableRationale: string;
}

/**
 * A user's full audit trail, exportable (Art. 9). `identityRef` MUST be
 * the caller's own identityRef — the server enforces this independently
 * (same self-or-permitted visibility rule as Query/Explain).
 */
export interface ExportAuditTrailRequest {
  identityRef: string;
}

export interface ExportAuditTrailResponse {
  exportBlob: Uint8Array;
  formatVersion: string;
}
