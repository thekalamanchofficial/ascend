// Audit / Explainability — thin HTTP client for three of the four real,
// network-wired RPCs at /v1/audit (services/api/internal/audit/http.go):
// `GET /v1/audit/events` (Query), `GET /v1/audit/events/{eventID}/explain`
// (Explain), `GET /v1/audit/export` (ExportAuditTrail). Per
// apps/mobile/README.md's capability boundary, this module holds no
// capability logic of its own — it never decides what counts as an
// explainable action or who may see whose trail; that is
// services/api/internal/audit's job (fail-closed PermissionChecker,
// verified server-side).
//
// Deliberately does NOT wrap Emit (`POST /v1/audit/events`) — per
// audit.proto's own header comment and this capability's charter §3, Emit
// is the internal, capability-to-capability call every OTHER backend
// capability's state-mutating operation makes in-process (`audit.Emit(...)`);
// it is reachable over the network only because Cryptography & Keys runs
// entirely on-device and has no other way to reach it (a documented,
// still-unwired placeholder — apps/mobile/src/capabilities/crypto/audit.ts).
// This module is the *read-facing* client — mobile has no legitimate
// reason to construct and emit an arbitrary audit event about some other
// capability's action, so that network route is intentionally left
// unwrapped here.
//
// Every route this module calls is gated (bearer session token required,
// services/api/wiring.go's requireVerifiedCaller middleware — deletes and
// overwrites the caller-identity header server-side, so a caller cannot
// forge it) AND independently checks the caller-identified field
// (`subject` / `identityRef`, or an event's own `actor`) against the
// network-verified caller server-side, failing closed for any cross-subject
// access (services/api/internal/audit/service.go's `denyAllChecker`
// default) — so every function below that's scoped to "my own trail"
// requires the caller to pass their own known identityRef; there is no
// ambient-identity path, and this module cannot be used to read or export
// anyone else's audit trail.
//
// See types.ts's header for the wire-format this file's Wire* interfaces
// encode (snake_case throughout, verified against
// services/api/internal/audit/http.go and types.go) and for why
// exportAuditTrail uses apiRequestRaw (raw body + X-Ascend-Format-Version
// header), not apiRequest.
import { apiRequest, apiRequestRaw } from "../../api/httpClient";
import { logAuditEvent } from "./audit";
import type {
  ResourceRef,
  AuditEvent,
  QueryRequest,
  QueryResponse,
  ExplainRequest,
  ExplainResponse,
  ExportAuditTrailRequest,
  ExportAuditTrailResponse,
} from "./types";

export * from "./types";

// --- Wire DTOs, local to this file only. Never exported — callers only
// ever see the camelCase-shaped types from ./types; these exist purely to
// describe what actually goes over HTTP (see types.ts's header comment). ---

interface WireResourceRef {
  resource_type: string;
  resource_id: string;
}

interface WireAuditEvent {
  event_id: string;
  actor: string;
  action: string;
  resource: WireResourceRef;
  rule_reference: string;
  metadata: Record<string, string> | null;
  occurred_at_unix: number;
}

function resourceRefFromWire(w: WireResourceRef): ResourceRef {
  return { resourceType: w.resource_type, resourceId: w.resource_id };
}

function eventFromWire(w: WireAuditEvent): AuditEvent {
  return {
    eventId: w.event_id,
    actor: w.actor,
    action: w.action,
    resource: resourceRefFromWire(w.resource),
    ruleReference: w.rule_reference,
    metadata: w.metadata ?? {},
    occurredAtUnix: w.occurred_at_unix,
  };
}

// ---------------------------------------------------------------------------
// Query — "my own audit trail" (charter §3), read-only, reverse-chronological
// (services/api/internal/audit/postgres_store.go's `ORDER BY
// occurred_at_unix DESC` — this module does not re-sort). Deliberately not
// marked ascend:mutates — a read, like listGrantsForSubject/
// listFileObjects elsewhere in this codebase.
// ---------------------------------------------------------------------------
export async function query(request: QueryRequest, sessionToken: string): Promise<QueryResponse> {
  const params = new URLSearchParams();
  if (request.subject) params.set("subject", request.subject);
  if (request.resourceTypeFilter) params.set("resource_type", request.resourceTypeFilter);
  if (request.resourceIdFilter) params.set("resource_id", request.resourceIdFilter);
  if (request.actionFilter) params.set("action", request.actionFilter);
  if (request.sinceUnix) params.set("since", String(request.sinceUnix));
  if (request.untilUnix) params.set("until", String(request.untilUnix));
  const qs = params.toString();

  const resp = await apiRequest<{ events: WireAuditEvent[] | null }>(`/v1/audit/events${qs ? `?${qs}` : ""}`, {
    method: "GET",
    bearerToken: sessionToken,
  });

  return { events: (resp.events ?? []).map(eventFromWire) };
}

// ---------------------------------------------------------------------------
// Explain — turns one raw event into a plain-language rationale (charter
// §3). Read-only, not marked ascend:mutates.
// ---------------------------------------------------------------------------
export async function explain(request: ExplainRequest, sessionToken: string): Promise<ExplainResponse> {
  const resp = await apiRequest<{ human_readable_rationale: string }>(
    `/v1/audit/events/${encodeURIComponent(request.eventId)}/explain`,
    { method: "GET", bearerToken: sessionToken },
  );

  return { humanReadableRationale: resp.human_readable_rationale };
}

// ---------------------------------------------------------------------------
// ExportAuditTrail — gated (Art. 9: always-available, not a support
// ticket). Bundles this identity's full, hash-chained activity history into
// one portable, versioned, independently-verifiable document.
// ---------------------------------------------------------------------------

// ascend:mutates
export async function exportAuditTrail(
  request: ExportAuditTrailRequest,
  sessionToken: string,
): Promise<ExportAuditTrailResponse> {
  const { bytes, formatVersion } = await apiRequestRaw(
    `/v1/audit/export?identity_ref=${encodeURIComponent(request.identityRef)}`,
    { method: "GET", bearerToken: sessionToken },
  );

  logAuditEvent("audit_trail_exported", { identityRef: request.identityRef, formatVersion: formatVersion ?? "unknown" });

  return { exportBlob: bytes, formatVersion: formatVersion ?? "unknown" };
}
