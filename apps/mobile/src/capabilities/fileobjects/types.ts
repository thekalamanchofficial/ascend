// File Objects — TypeScript request/response shapes.
//
// Hand-mirrored from the real, frozen Go wire types
// (services/api/internal/fileobjects/types.go), not generated — same
// established precedent as Identity/Session-Auth/Cryptography & Keys'
// client modules (see identity/types.ts's own header comment).
//
// *** WIRE-FORMAT DIVERGENCE, VERIFIED AGAINST REAL GO SOURCE, NOT
// ASSUMED — read this before touching index.ts. ***
//
// Unlike Identity/SessionAuth (whose Go request/response structs carry
// protojson-shaped `json:"camelCase"` tags), File Objects' Go types in
// services/api/internal/fileobjects/types.go carry NO `json` struct tags
// at all. Go's encoding/json falls back to the exported field name
// verbatim when no tag is present — so the wire format for every File
// Objects RPC is PascalCase, matching the Go struct field names exactly:
// `CreateFileObjectRequest` is `{"Owner":"...","RequestingSubject":"...",
// "InitialContent":"<base64>","Name":"...","MimeType":"..."}` on the wire,
// NOT `{"owner":...}`. This is intentional and confirmed by reading
// types.go directly (see its own header comment: "TEMPORARY MIRROR... The
// types below are a hand-written mirror of the frozen .proto messages,
// field-for-field" — no tag-adding pass has happened for this capability).
// Do not "fix" this to camelCase to match Identity's convention — that
// would silently break every request against the real server.
//
// The public types below (the ones this directory's callers use) are
// still camelCase, for consistency with every other capability client in
// this codebase (identity, sessionauth) — index.ts's `Wire*` interfaces
// (PascalCase, local to that file, never exported) are the boundary that
// converts in both directions. Storage is never called directly by this
// module — File Objects' own CreateFileObject/CreateVersion accept raw
// file bytes in their own request body and store them via Storage
// internally, server-side; `blob_ref` is never exposed to any client (see
// docs/capabilities/file-objects.charter.md §6 point 8).
//
// []byte Go fields (InitialContent, Content, ExportBlob) are
// base64-encoded JSON strings on the wire, same as every other Go []byte
// field in this codebase (encoding/json's default for []byte regardless of
// tag presence). The shapes below are the in-memory, already-decoded form
// (Uint8Array) this module's callers work with — index.ts's `*FromWire`
// converters/`bytesToBase64` calls are the boundary.
//
// If the frozen contract changes, that is a charter amendment routed back
// through the Chief Architect — not a change made unilaterally here.

/** Mirrors fileobjects.FileObject. Never carries a blob_ref field (charter §6 point 8, mechanically closed — see index.ts). */
export interface FileObject {
  fileObjectId: string;
  owner: string;
  currentVersionRef: string;
  name: string;
  mimeType: string;
  tags: string[];
  sizeBytes: number;
  createdAtUnix: number;
}

/** Mirrors fileobjects.VersionSummary — never carries a blob_ref (charter §6 point 8). */
export interface VersionSummary {
  versionRef: string;
  createdAtUnix: number;
  createdBy: string;
  sizeBytes: number;
}

/**
 * Mirrors fileobjects.FileEvent — one of File Objects' own emitted audit
 * events (never a raw aggregation of Permissions'/Storage's own audit
 * trails, charter §6 point 8a). `action` is one of
 * "fileobjects.create_file_object" / "fileobjects.create_version" /
 * "fileobjects.permission_granted" / "fileobjects.permission_revoked" /
 * "fileobjects.set_file_metadata" / "fileobjects.delete_file_object" —
 * not a closed TS union here, since the server is the sole source of
 * truth for this vocabulary and a new value must never fail client-side
 * parsing (Art. 12: the client stays understandable/forward-compatible
 * rather than brittle).
 */
export interface FileEvent {
  eventId: string;
  action: string;
  actor: string;
  occurredAtUnix: number;
  metadata: Record<string, string>;
}

/** The only two values `SetFilePermissionsRequest.action` may take (charter §6 point 1). */
export type FileObjectsPermissionAction = "fileobjects.read" | "fileobjects.write";

// --- Request/response DTOs, one per RPC in fileobjects.proto ---

export interface CreateFileObjectRequest {
  owner: string;
  requestingSubject: string;
  initialContent: Uint8Array;
  name: string;
  mimeType: string;
}

export interface CreateFileObjectResponse {
  fileObject: FileObject;
}

/**
 * Self-only "what do I own" inventory listing (charter §3, added
 * 2026-08-18) — deliberately not CheckPermission-gated, mirroring
 * Storage's ExportAllBlobs precedent. `owner` MUST equal the caller's own
 * identityRef; the server independently verifies this against both the
 * request's own requestingSubject field and the verified bearer-token
 * caller (two-layer check, see index.ts's listFileObjects doc comment) —
 * this module never attempts to list another identity's files.
 */
export interface ListFileObjectsRequest {
  owner: string;
  requestingSubject: string;
}

export interface ListFileObjectsResponse {
  fileObjects: FileObject[];
}

export interface CreateVersionRequest {
  fileObjectId: string;
  requestingSubject: string;
  content: Uint8Array;
}

export interface CreateVersionResponse {
  versionRef: string;
}

/**
 * `versionRef` omitted (or empty string) returns the current (latest)
 * version — charter §5's zero-config default; never required for the
 * common "open this file" flow.
 */
export interface GetFileContentRequest {
  fileObjectId: string;
  requestingSubject: string;
  versionRef?: string;
}

export interface GetFileContentResponse {
  content: Uint8Array;
}

export interface ListVersionsRequest {
  fileObjectId: string;
  requestingSubject: string;
}

export interface ListVersionsResponse {
  versions: VersionSummary[];
}

export interface GetFileHistoryRequest {
  fileObjectId: string;
  requestingSubject: string;
}

export interface GetFileHistoryResponse {
  events: FileEvent[];
}

export interface SetFilePermissionsRequest {
  fileObjectId: string;
  requestingSubject: string;
  /** true = grant, false = revoke. */
  grant: boolean;
  subject: string;
  action: FileObjectsPermissionAction;
  scope: string;
}

export type SetFilePermissionsResponse = Record<string, never>;

export interface GetFileMetadataRequest {
  fileObjectId: string;
  requestingSubject: string;
}

export interface GetFileMetadataResponse {
  name: string;
  mimeType: string;
  tags: string[];
  sizeBytes: number;
}

/** Pointer-shaped fields on the wire (`*string`) = partial update; omit a field here to leave it unchanged. `size` is never caller-settable (charter §3) — there is no sizeBytes field on this request. */
export interface SetFileMetadataRequest {
  fileObjectId: string;
  requestingSubject: string;
  name?: string;
  mimeType?: string;
  tags?: string[];
}

export type SetFileMetadataResponse = Record<string, never>;

export interface ExportFileRequest {
  fileObjectId: string;
  requestingSubject: string;
}

export interface ExportFileResponse {
  exportBlob: Uint8Array;
  formatVersion: string;
}

export interface DeleteFileObjectRequest {
  fileObjectId: string;
  requestingSubject: string;
}

export type DeleteFileObjectResponse = Record<string, never>;
