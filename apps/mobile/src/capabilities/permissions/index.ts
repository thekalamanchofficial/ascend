// Permissions — thin HTTP client for the two RPCs this pass wires up on
// mobile, at /v1/permissions (services/api/internal/permissions/http.go):
// `GET /v1/permissions/grants/subject` (ListGrantsForSubject) and
// `GET /v1/permissions/export` (ExportPermissions). Per
// apps/mobile/README.md's capability boundary, this module holds no
// capability logic of its own — it never decides who can access what; that
// is services/api/internal/permissions's job.
//
// Deliberately does NOT wrap CheckPermission/GrantPermission/
// RevokePermission — mobile already reaches those indirectly through File
// Objects' own SetFilePermissions (apps/mobile/src/capabilities/fileobjects
// `setFilePermissions`), and a second, parallel grant/revoke path here
// would give mobile two different ways to do the same thing (Art. 16
// consistency). See docs/DECISION_LOG.md for this scoping decision.
//
// See types.ts's header for the wire-format mix this file's Wire*
// interfaces encode: PascalCase request/response wrapper field names, but
// snake_case Grant/ResourceRef field names — both real, both verified
// against services/api/internal/permissions/types.go and http_test.go, not
// assumed.
//
// Every route this module calls is gated (bearer session token required)
// AND independently checks the caller-identified field (`subject` /
// `identity_ref`) against the network-verified caller server-side
// (http.go's ErrCallerMismatch checks) — so both functions below require
// the caller to pass their own known identityRef; there is no ambient-
// identity path, and this module cannot be used to list or export anyone
// else's permissions.
import { apiRequest } from "../../api/httpClient";
import { base64ToBytes } from "../crypto/bytes";
import { logAuditEvent } from "./audit";
import type {
  Grant,
  ResourceRef,
  ListGrantsForSubjectRequest,
  ListGrantsForSubjectResponse,
  ExportPermissionsRequest,
  ExportPermissionsResponse,
} from "./types";

export * from "./types";

// --- Wire DTOs, local to this file only. Never exported — callers only
// ever see the camelCase, Uint8Array-shaped types from ./types; these exist
// purely to describe what actually goes over HTTP (see types.ts's header
// comment for the PascalCase-wrapper / snake_case-Grant mix). ---

interface WireResourceRef {
  resource_type: string;
  resource_id: string;
}

interface WireGrant {
  grantor: string;
  subject: string;
  action: string;
  resource: WireResourceRef;
  scope: string;
  granted_at_unix: number;
}

function grantFromWire(w: WireGrant): Grant {
  return {
    grantor: w.grantor,
    subject: w.subject,
    action: w.action,
    resource: resourceRefFromWire(w.resource),
    scope: w.scope,
    grantedAtUnix: w.granted_at_unix,
  };
}

function resourceRefFromWire(w: WireResourceRef): ResourceRef {
  return { resourceType: w.resource_type, resourceId: w.resource_id };
}

// ---------------------------------------------------------------------------
// ListGrantsForSubject — "what can I access" (charter §5), self-only, read-
// only. Deliberately not marked ascend:mutates — a read, like
// listFileObjects/listDevices elsewhere in this codebase.
// ---------------------------------------------------------------------------
export async function listGrantsForSubject(
  request: ListGrantsForSubjectRequest,
  sessionToken: string,
): Promise<ListGrantsForSubjectResponse> {
  const resp = await apiRequest<{ Grants: WireGrant[] | null }>(
    `/v1/permissions/grants/subject?subject=${encodeURIComponent(request.subject)}`,
    { method: "GET", bearerToken: sessionToken },
  );

  return { grants: (resp.Grants ?? []).map(grantFromWire) };
}

// ---------------------------------------------------------------------------
// ExportPermissions — gated (Art. 9: always-available, not a support
// ticket). Bundles this identity's full grant/revoke history and currently
// active grants into one portable, versioned document.
// ---------------------------------------------------------------------------

// ascend:mutates
export async function exportPermissions(
  request: ExportPermissionsRequest,
  sessionToken: string,
): Promise<ExportPermissionsResponse> {
  const resp = await apiRequest<{ ExportBlob: string; FormatVersion: string }>(
    `/v1/permissions/export?identity_ref=${encodeURIComponent(request.identityRef)}`,
    { method: "GET", bearerToken: sessionToken },
  );

  logAuditEvent("permissions_exported", { identityRef: request.identityRef, formatVersion: resp.FormatVersion });

  return { exportBlob: base64ToBytes(resp.ExportBlob), formatVersion: resp.FormatVersion };
}
