// Permissions — TypeScript request/response shapes.
//
// Hand-mirrored from the real, frozen Go wire types
// (services/api/internal/permissions/types.go), not generated — same
// established precedent as every other capability client in this codebase
// (see identity/types.ts's own header comment for the full rationale).
//
// *** WIRE-FORMAT NOTE, VERIFIED AGAINST REAL GO SOURCE, NOT ASSUMED. ***
//
// Unlike File Objects (fully PascalCase, no tags anywhere) or Identity/
// SessionAuth (fully camelCase via protojson-shaped tags), Permissions'
// real Go types are a MIX (see types.go):
//   - Request/response wrapper structs (`ListGrantsForSubjectRequest`,
//     `ListGrantsForSubjectResponse`, `ExportPermissionsRequest`,
//     `ExportPermissionsResponse`) carry NO `json` tags at all, so their
//     field names are PascalCase on the wire exactly as written in Go
//     (`Grants`, `ExportBlob`, `FormatVersion`).
//   - The `Grant` struct (and its nested `ResourceRef`) DOES carry explicit
//     snake_case `json` tags (`grantor`, `subject`, `action`, `resource`,
//     `scope`, `granted_at_unix`, `resource_type`, `resource_id`) — see
//     types.go's `Grant`/`ResourceRef` definitions.
// So a `ListGrantsForSubjectResponse` on the wire looks like:
//   { "Grants": [ { "grantor": "...", "subject": "...", "action": "...",
//                    "resource": { "resource_type": "...", "resource_id": "..." },
//                    "scope": "...", "granted_at_unix": 123 } ] }
// index.ts's `Wire*` interfaces below encode exactly this mix — do not
// "fix" either half to match the other; both are the real, verified wire
// shape (services/api/internal/permissions/http_test.go's own JSON
// round-trip tests confirm this exact mixed casing).
//
// []byte fields (`ExportBlob`) are base64-encoded JSON strings on the wire,
// same as every other Go []byte field in this codebase. The shape below is
// the in-memory, already-decoded form (Uint8Array) this module's callers
// work with — index.ts's `exportPermissions` is the boundary that decodes.
//
// If the frozen contract changes, that is a charter amendment routed back
// through the Chief Architect — not a change made unilaterally here.

/** Mirrors permissions.ResourceRef — an opaque reference to a resource owned by whichever capability defines that resource type (e.g. "file_object"). Permissions never interprets resource_type/resource_id beyond treating them as opaque strings. */
export interface ResourceRef {
  resourceType: string;
  resourceId: string;
}

/**
 * Mirrors permissions.Grant exactly — the currently-effective access record
 * for one (subject, action, resource) tuple. This is Permissions' own
 * generic view: it carries no display-ready name for the resource (e.g. a
 * file's `name`) because Permissions has no knowledge of what a
 * `file_object` even is beyond an opaque resource_type string — hydrating
 * that is explicitly out of scope for this module (permissions.charter.md
 * §3; same reasoning file-objects.charter.md §3 already applied to its own
 * "shared with me" exclusion).
 */
export interface Grant {
  grantor: string;
  subject: string;
  action: string;
  resource: ResourceRef;
  scope: string;
  grantedAtUnix: number;
}

// --- Request/response DTOs, for the two RPCs this module exposes
// (charter §3's ListGrantsForSubject / ExportPermissions — CheckPermission/
// GrantPermission/RevokePermission are deliberately not wrapped here: mobile
// already reaches those indirectly through File Objects' own
// SetFilePermissions, and exposing a second, parallel grant/revoke path
// here would violate Art. 16 consistency). ---

/**
 * "What can I access" (charter §5) — self-only. `subject` MUST be the
 * caller's own identityRef; the server enforces this independently
 * (services/api/internal/permissions/http.go's `handleListGrantsForSubject`
 * rejects any other value with a 403, same enumeration-prevention reasoning
 * as CheckPermission's own subject check).
 */
export interface ListGrantsForSubjectRequest {
  subject: string;
}

export interface ListGrantsForSubjectResponse {
  grants: Grant[];
}

/**
 * A user's full grant/revoke history and current effective permissions
 * (Art. 9). `identityRef` MUST be the caller's own identityRef — the
 * server enforces this independently (same 403-on-mismatch pattern as
 * every other export RPC in this codebase).
 */
export interface ExportPermissionsRequest {
  identityRef: string;
}

export interface ExportPermissionsResponse {
  exportBlob: Uint8Array;
  formatVersion: string;
}
