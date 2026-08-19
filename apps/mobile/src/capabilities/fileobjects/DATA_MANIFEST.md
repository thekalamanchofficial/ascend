# Data Manifest — File Objects (mobile client)

Per `docs/CONSTITUTION.md` Art. 8 (privacy is the default; minimum data,
documented purpose) and `docs/capabilities/file-objects.charter.md` §4
("`name` — purpose: user-facing identification; `mime_type` — purpose:
correct rendering/handling; `tags` — purpose: user-driven organization
(Art. 11); `size` — purpose: display and storage-policy decisions. No
other fields.").

This directory (`apps/mobile/src/capabilities/fileobjects/`) is a thin
HTTP client for the real File Objects capability implemented in
`services/api/internal/fileobjects` — the authoritative manifest for what
is *collected and stored server-side* is that package's own
`DATA_MANIFEST.md`. This client-side manifest documents the narrower
question that one doesn't cover: what does *this module* transmit, and
why — every field below is already documented, with the same purpose, on
the server side; nothing here is new collection.

## Fields

- `owner` / `requestingSubject` / `subject`
  Purpose: server-issued opaque identity-reference strings (Identity's
  format), sent so the server knows which identity is acting and, for
  `subject`, who a permission grant/revoke targets. Not generated,
  resolved, or interpreted by this module — it is always caller-supplied
  (the current identity's own `identityRef`, or, for `setFilePermissions`,
  an identity_ref the user types in — see the Share dialog's own
  documented no-discovery limitation in `apps/mobile/src/features/vault/`).

- `fileObjectId` / `versionRef` / `eventId`
  Purpose: server-issued opaque identifiers, echoed back to the server on
  subsequent calls so a gated request knows which file/version/event it
  concerns. Not generated or interpreted by this module.

- `initialContent` / `content`
  Purpose: the actual file bytes being uploaded (`createFileObject`) or
  versioned (`createVersion`) — read from a user-picked file via
  `expo-document-picker`/`expo-file-system` (see
  `apps/mobile/src/features/vault/screens/FilesListScreen.tsx`'s upload
  flow) and base64-encoded for transmission. This module never inspects,
  transforms, or retains file content beyond the single request/response
  round trip that sends or receives it.

- `name` / `mimeType` / `tags`
  Purpose: user-facing identification, correct rendering/handling, and
  user-driven organization, respectively — the exact three purposes the
  server-side charter's own Art. 8 manifest states (§4, quoted above).
  `name`/`mimeType` are set at upload time or via `setFileMetadata`'s
  rename/retag actions; `tags` are entirely user-authored.

- `sizeBytes`
  Purpose: display only. This module never sends `sizeBytes` on a write —
  it is always server-derived and only ever read back (charter §3: "size
  is derived... never caller-settable via SetFileMetadata" — `types.ts`'s
  `SetFileMetadataRequest` has no `sizeBytes` field at all, mechanically
  precluding this module from attempting to set it).

- `action` (on `setFilePermissions`) / `scope` / `grant`
  Purpose: the specific permission being changed. `action` is constrained
  by `FileObjectsPermissionAction` (types.ts) to exactly
  `"fileobjects.read"` / `"fileobjects.write"` — the two values the server
  charter defines (§6 point 1) — so this module cannot construct a request
  naming any other action string.

- `grantedAtUnix` (received only, via `listFileAccess` — charter §3, added
  2026-08-18)
  Purpose: display only — lets the owner-only "who has access" view
  (`FileDetailScreen.tsx`) show when each grant was made. Never sent by
  this module (there is no request field for it); always echoed back
  from the server's own `Permissions.Grant.GrantedAtUnix`, which this
  module neither generates nor interprets beyond formatting for display.

## Fields held locally by this module

None. This module is stateless — it shapes a request, calls the real
backend, and returns a parsed response; it does not itself persist
anything to `SecureLocalStore` or any other store. Any local caching of
`FileObject`/version/history data for UI purposes (loading state, list
display) is owned by the calling screen layer
(`apps/mobile/src/features/vault/`), not this module.

## Explicitly out of scope (not collected)

- No `blobRef` of any kind ever passes through this module — the
  server-side charter (§6 point 8) guarantees `blob_ref` is never returned
  by any File Objects RPC response, and this module's `types.ts`
  mechanically has no field to carry one even if the server ever leaked
  one by accident.
- No file content is cached or duplicated client-side beyond the single
  request/response that transmits it (mirrors the server-side charter's
  own "no shadow plaintext copies" threat-model commitment, §6).
- No device/hardware fingerprint, IP address, or geolocation.
- No search/discovery data — this pass ships no query capability over
  file names/tags/content; `listFileObjects` returns a caller's own full
  inventory only (see index.ts's own doc comment).

## Notes

- The client-side `logAuditEvent` calls in `audit.ts`/`index.ts` are a
  local dev-visibility and mechanical-CI-convention stub, not this
  capability's Art. 5 audit trail of record — see `audit.ts`'s header
  comment. The real audit trail is emitted server-side by
  `services/api/internal/fileobjects/service.go` for every mutating RPC
  and for every denied read/list attempt (the shared `checkRead()` /
  `auditListDenied()` / `auditAccessListDenied()` call sites), scoped to
  the server-verified caller, independent of anything this client module
  does or fails to do. `listFileAccess` is deliberately NOT marked
  `// ascend:mutates` here (it is a read, like `listFileObjects`/
  `getFileMetadata`) — a denied call (a non-owner attempting to see a
  file's grant list) is denied and audited server-side, but this client
  module never surfaces that denial as an error to the caller (see
  `FileDetailScreen.tsx`'s hide-on-403 handling) — there is nothing for
  this stub to log on that path.
- `logAuditEvent`'s metadata for `setFilePermissions` includes `subject`
  (an identity_ref) — this is the same class of already-opaque,
  non-secret identifier `identityRef`/`deviceId` are treated as elsewhere
  in this codebase's client-side audit stubs (see identity/audit.ts's hard
  rule), never a secret.
