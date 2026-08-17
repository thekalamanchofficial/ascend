// File Objects — thin HTTP client for the eleven real, network-wired RPCs
// at /file-objects (services/api/internal/fileobjects/http.go — note NO
// /v1 prefix, unlike Identity/SessionAuth; confirmed against http.go's own
// Mount(), which wires r.Route("/file-objects", ...) directly onto the
// root router, not under a /v1 group). Per apps/mobile/README.md's
// capability boundary, this module holds no capability logic of its own —
// it never decides who may read/write/share/delete a file; that is
// services/api/internal/fileobjects's job (Permissions-delegated, per
// charter §6). This module never calls Storage directly — File Objects'
// own CreateFileObject/CreateVersion/GetFileContent/ExportFile already
// carry file bytes in their own request/response bodies.
//
// See types.ts's header for the wire-format divergence this file's Wire*
// interfaces encode: PascalCase field names (no json struct tags on the
// real Go types), not Identity/SessionAuth's camelCase.
//
// Every route is gated (bearer session token required) AND independently
// checks `requestingSubject` (and, on CreateFileObject, `owner`) against
// the network-verified caller server-side (http.go's ErrCallerMismatch
// checks) — so every function below requires the caller to pass their own
// known identityRef in those fields; there is no ambient-identity path.
import { apiRequest } from "../../api/httpClient";
import { bytesToBase64, base64ToBytes } from "../crypto/bytes";
import { logAuditEvent } from "./audit";
import type {
  FileObject,
  FileEvent,
  VersionSummary,
  CreateFileObjectRequest,
  CreateFileObjectResponse,
  ListFileObjectsRequest,
  ListFileObjectsResponse,
  CreateVersionRequest,
  CreateVersionResponse,
  GetFileContentRequest,
  GetFileContentResponse,
  ListVersionsRequest,
  ListVersionsResponse,
  GetFileHistoryRequest,
  GetFileHistoryResponse,
  SetFilePermissionsRequest,
  SetFilePermissionsResponse,
  GetFileMetadataRequest,
  GetFileMetadataResponse,
  SetFileMetadataRequest,
  SetFileMetadataResponse,
  ExportFileRequest,
  ExportFileResponse,
  DeleteFileObjectRequest,
  DeleteFileObjectResponse,
} from "./types";

export * from "./types";

// --- Wire DTOs (PascalCase, base64-string []byte fields), local to this
// file only. Never exported — callers only ever see the camelCase,
// Uint8Array-shaped types from ./types; these exist purely to describe
// what actually goes over HTTP (see types.ts's header comment). ---

interface WireFileObject {
  FileObjectID: string;
  Owner: string;
  CurrentVersionRef: string;
  Name: string;
  MimeType: string;
  Tags: string[] | null;
  SizeBytes: number;
  CreatedAtUnix: number;
}

interface WireVersionSummary {
  VersionRef: string;
  CreatedAtUnix: number;
  CreatedBy: string;
  SizeBytes: number;
}

interface WireFileEvent {
  EventID: string;
  Action: string;
  Actor: string;
  OccurredAtUnix: number;
  Metadata: Record<string, string> | null;
}

function fileObjectFromWire(w: WireFileObject): FileObject {
  return {
    fileObjectId: w.FileObjectID,
    owner: w.Owner,
    currentVersionRef: w.CurrentVersionRef,
    name: w.Name,
    mimeType: w.MimeType,
    tags: w.Tags ?? [],
    sizeBytes: w.SizeBytes,
    createdAtUnix: w.CreatedAtUnix,
  };
}

function versionSummaryFromWire(w: WireVersionSummary): VersionSummary {
  return {
    versionRef: w.VersionRef,
    createdAtUnix: w.CreatedAtUnix,
    createdBy: w.CreatedBy,
    sizeBytes: w.SizeBytes,
  };
}

function fileEventFromWire(w: WireFileEvent): FileEvent {
  return {
    eventId: w.EventID,
    action: w.Action,
    actor: w.Actor,
    occurredAtUnix: w.OccurredAtUnix,
    metadata: w.Metadata ?? {},
  };
}

// ---------------------------------------------------------------------------
// CreateFileObject — establishes identity, owner, and version 1 in one
// call. `owner` and `requestingSubject` must both equal the caller's own
// identityRef (http.go rejects otherwise, ErrCallerMismatch, 403).
// ---------------------------------------------------------------------------

// ascend:mutates
export async function createFileObject(
  request: CreateFileObjectRequest,
  sessionToken: string,
): Promise<CreateFileObjectResponse> {
  const resp = await apiRequest<{ FileObject: WireFileObject }>("/file-objects/", {
    method: "POST",
    bearerToken: sessionToken,
    body: {
      Owner: request.owner,
      RequestingSubject: request.requestingSubject,
      InitialContent: bytesToBase64(request.initialContent),
      Name: request.name,
      MimeType: request.mimeType,
    },
  });

  const fileObject = fileObjectFromWire(resp.FileObject);
  logAuditEvent("file_object_created", { fileObjectId: fileObject.fileObjectId, name: fileObject.name });

  return { fileObject };
}

// ---------------------------------------------------------------------------
// ListFileObjects — self-only "my files" inventory (charter §3, added
// 2026-08-18). `owner` MUST be the caller's own identityRef — the server
// enforces this at TWO independent layers (service-level
// requestingSubject==owner, and HTTP-level requestingSubject==the verified
// bearer-token caller); this module does not attempt to work around either.
// Deliberately not marked ascend:mutates — a read, like listDevices/
// listActiveSessions elsewhere in this codebase.
// ---------------------------------------------------------------------------
export async function listFileObjects(
  request: ListFileObjectsRequest,
  sessionToken: string,
): Promise<ListFileObjectsResponse> {
  const resp = await apiRequest<{ FileObjects: WireFileObject[] }>("/file-objects/list", {
    method: "POST",
    bearerToken: sessionToken,
    body: { Owner: request.owner, RequestingSubject: request.requestingSubject },
  });

  return { fileObjects: resp.FileObjects.map(fileObjectFromWire) };
}

// ---------------------------------------------------------------------------
// CreateVersion — every edit is a new version, never an overwrite.
// ---------------------------------------------------------------------------

// ascend:mutates
export async function createVersion(
  request: CreateVersionRequest,
  sessionToken: string,
): Promise<CreateVersionResponse> {
  const resp = await apiRequest<{ VersionRef: string }>("/file-objects/versions", {
    method: "POST",
    bearerToken: sessionToken,
    body: {
      FileObjectID: request.fileObjectId,
      RequestingSubject: request.requestingSubject,
      Content: bytesToBase64(request.content),
    },
  });

  logAuditEvent("file_version_created", { fileObjectId: request.fileObjectId, versionRef: resp.VersionRef });

  return { versionRef: resp.VersionRef };
}

// ---------------------------------------------------------------------------
// GetFileContent — omitting versionRef returns the current version
// (charter §5's zero-config default). Read-only, not audited client-side
// beyond dev visibility (server-side denial auditing is the real Art. 5
// obligation here, via the shared checkRead() call site).
// ---------------------------------------------------------------------------
export async function getFileContent(
  request: GetFileContentRequest,
  sessionToken: string,
): Promise<GetFileContentResponse> {
  const resp = await apiRequest<{ Content: string }>("/file-objects/content", {
    method: "POST",
    bearerToken: sessionToken,
    body: {
      FileObjectID: request.fileObjectId,
      RequestingSubject: request.requestingSubject,
      VersionRef: request.versionRef ?? "",
    },
  });

  return { content: base64ToBytes(resp.Content) };
}

// ---------------------------------------------------------------------------
// ListVersions — read-only.
// ---------------------------------------------------------------------------
export async function listVersions(
  request: ListVersionsRequest,
  sessionToken: string,
): Promise<ListVersionsResponse> {
  const resp = await apiRequest<{ Versions: WireVersionSummary[] }>("/file-objects/versions/list", {
    method: "POST",
    bearerToken: sessionToken,
    body: { FileObjectID: request.fileObjectId, RequestingSubject: request.requestingSubject },
  });

  return { versions: resp.Versions.map(versionSummaryFromWire) };
}

// ---------------------------------------------------------------------------
// GetFileHistory — read-only. Feeds the merged history/version timeline
// (charter §5) together with ListVersions — see
// apps/mobile/src/features/vault/screens/FileDetailScreen.tsx.
// ---------------------------------------------------------------------------
export async function getFileHistory(
  request: GetFileHistoryRequest,
  sessionToken: string,
): Promise<GetFileHistoryResponse> {
  const resp = await apiRequest<{ Events: WireFileEvent[] }>("/file-objects/history", {
    method: "POST",
    bearerToken: sessionToken,
    body: { FileObjectID: request.fileObjectId, RequestingSubject: request.requestingSubject },
  });

  return { events: resp.Events.map(fileEventFromWire) };
}

// ---------------------------------------------------------------------------
// SetFilePermissions — grant or revoke `subject`'s access. `action` is
// exactly "fileobjects.read" or "fileobjects.write" (charter §6 point 1).
// ---------------------------------------------------------------------------

// ascend:mutates
export async function setFilePermissions(
  request: SetFilePermissionsRequest,
  sessionToken: string,
): Promise<SetFilePermissionsResponse> {
  await apiRequest<Record<string, never>>("/file-objects/permissions", {
    method: "POST",
    bearerToken: sessionToken,
    body: {
      FileObjectID: request.fileObjectId,
      RequestingSubject: request.requestingSubject,
      Grant: request.grant,
      Subject: request.subject,
      Action: request.action,
      Scope: request.scope,
    },
  });

  // Never log a stray value for `subject` beyond the identity ref itself —
  // it's already an opaque, non-secret identifier, same class as
  // fileObjectId (see DATA_MANIFEST.md).
  logAuditEvent(request.grant ? "file_permission_granted" : "file_permission_revoked", {
    fileObjectId: request.fileObjectId,
    subject: request.subject,
    action: request.action,
  });

  return {};
}

// ---------------------------------------------------------------------------
// GetFileMetadata — read-only, fixed field set (name/mimeType/tags/size).
// ---------------------------------------------------------------------------
export async function getFileMetadata(
  request: GetFileMetadataRequest,
  sessionToken: string,
): Promise<GetFileMetadataResponse> {
  const resp = await apiRequest<{ Name: string; MimeType: string; Tags: string[] | null; SizeBytes: number }>(
    "/file-objects/metadata/get",
    {
      method: "POST",
      bearerToken: sessionToken,
      body: { FileObjectID: request.fileObjectId, RequestingSubject: request.requestingSubject },
    },
  );

  return { name: resp.Name, mimeType: resp.MimeType, tags: resp.Tags ?? [], sizeBytes: resp.SizeBytes };
}

// ---------------------------------------------------------------------------
// SetFileMetadata — partial update: only fields present in `request` are
// sent as non-null (Go pointer fields = partial update semantics). `size`
// is never caller-settable (charter §3) and has no field here at all.
// ---------------------------------------------------------------------------

// ascend:mutates
export async function setFileMetadata(
  request: SetFileMetadataRequest,
  sessionToken: string,
): Promise<SetFileMetadataResponse> {
  await apiRequest<Record<string, never>>("/file-objects/metadata/set", {
    method: "POST",
    bearerToken: sessionToken,
    body: {
      FileObjectID: request.fileObjectId,
      RequestingSubject: request.requestingSubject,
      Name: request.name ?? null,
      MimeType: request.mimeType ?? null,
      Tags: request.tags ?? null,
    },
  });

  logAuditEvent("file_metadata_updated", {
    fileObjectId: request.fileObjectId,
    fieldsChanged: [
      request.name !== undefined ? "name" : null,
      request.mimeType !== undefined ? "mimeType" : null,
      request.tags !== undefined ? "tags" : null,
    ]
      .filter((f): f is string => f !== null)
      .join(","),
  });

  return {};
}

// ---------------------------------------------------------------------------
// ExportFile — gated (Art. 9: always-available, not a support ticket).
// Bundles content (all versions), metadata, and File Objects' own emitted
// history into one portable, versioned document.
// ---------------------------------------------------------------------------

// ascend:mutates
export async function exportFile(request: ExportFileRequest, sessionToken: string): Promise<ExportFileResponse> {
  const resp = await apiRequest<{ ExportBlob: string; FormatVersion: string }>("/file-objects/export", {
    method: "POST",
    bearerToken: sessionToken,
    body: { FileObjectID: request.fileObjectId, RequestingSubject: request.requestingSubject },
  });

  logAuditEvent("file_exported", { fileObjectId: request.fileObjectId, formatVersion: resp.FormatVersion });

  return { exportBlob: base64ToBytes(resp.ExportBlob), formatVersion: resp.FormatVersion };
}

// ---------------------------------------------------------------------------
// DeleteFileObject — lifecycle termination. Content becomes unreachable
// (Storage DeleteBlob/crypto-shred); the file object's identity/history
// remain resolvable in the audit trail (charter §3), but GetFileContent on
// a deleted file object fails (ErrFileObjectDeleted / ErrContentUnavailable
// depending on which path is hit).
// ---------------------------------------------------------------------------

// ascend:mutates
export async function deleteFileObject(
  request: DeleteFileObjectRequest,
  sessionToken: string,
): Promise<DeleteFileObjectResponse> {
  await apiRequest<Record<string, never>>("/file-objects/delete", {
    method: "POST",
    bearerToken: sessionToken,
    body: { FileObjectID: request.fileObjectId, RequestingSubject: request.requestingSubject },
  });

  logAuditEvent("file_deleted", { fileObjectId: request.fileObjectId });

  return {};
}
