# Data Manifest — Permissions (mobile client)

Per `docs/CONSTITUTION.md` Art. 8 (privacy is the default; minimum data,
documented purpose) and `docs/capabilities/permissions.charter.md` §4.

This directory (`apps/mobile/src/capabilities/permissions/`) is a thin HTTP
client for the real Permissions capability implemented in
`services/api/internal/permissions` — the authoritative manifest for what is
*collected and stored server-side* is
`services/api/internal/permissions/DATA_MANIFEST.md`. This client-side
manifest documents the narrower question that one doesn't cover: what does
*this module* transmit, and why — every field below is already documented,
with the same purpose, on the server side; nothing here is new collection.

This module wraps exactly two of Permissions' six RPCs
(`ListGrantsForSubject`, `ExportPermissions`) — see `index.ts`'s header for
why `CheckPermission`/`GrantPermission`/`RevokePermission` are deliberately
not wrapped here (mobile already reaches those indirectly through File
Objects' `SetFilePermissions`; a second path would violate Art. 16).

## Fields

- `subject` (sent on `listGrantsForSubject`) / `identityRef` (sent on
  `exportPermissions`)
  Purpose: server-issued opaque identity-reference string (Identity's
  format), sent so the server knows whose grants to list or export. Always
  the caller's own `identityRef` — the server independently rejects any
  other value (403). Not generated, resolved, or interpreted by this
  module.

## Fields received (not sent)

- `grantor` / `subject` / `action` / `resource` (`resourceType` +
  `resourceId`) / `scope` / `grantedAtUnix` (via `listGrantsForSubject`'s
  `Grant` rows)
  Purpose: display only — lets the "what can I access" view show exactly
  what the server-side Permissions charter's own Art. 8 manifest documents
  for each field (§4: grantor/subject/action/resource identify who can do
  what to which resource; scope bounds it to less than full access; the
  timestamp is required for the grant history). This module never
  interprets, resolves, or hydrates `resource` beyond displaying its raw
  `resourceType`/`resourceId` strings — Permissions itself has no knowledge
  of, e.g., a `file_object`'s display name, so neither does this module
  (charter §3; the same "shared with me" hydration exclusion File Objects'
  own charter §3 already reasons through).

- `exportBlob` / `formatVersion` (via `exportPermissions`)
  Purpose: the user's full grant/revoke history and current effective
  permissions, as a portable, versioned document (Art. 9). This module
  base64-decodes the blob into bytes and hands it, unmodified, to the
  caller (`features/permissions/screens/AccessScreen.tsx`) — it never
  inspects or transforms the export document's contents.

## Fields held locally by this module

None. This module is stateless — it shapes a request, calls the real
backend, and returns a parsed response; it does not itself persist anything
to `SecureLocalStore` or any other store. Any local caching of `Grant` data
for UI purposes (loading state, list display) is owned by the calling
screen layer (`apps/mobile/src/features/permissions/`), not this module.

## Explicitly out of scope (not collected)

- No display name, resource content, or any capability-specific hydration
  of a `resource_type`/`resource_id` pair — Permissions' own frozen
  contract carries none, and this module does not attempt to enrich it by
  calling another capability out-of-band.
- No device/hardware fingerprint, IP address, or geolocation.
- No raw grant/revoke mutation path — `checkPermission`/`grantPermission`/
  `revokePermission` are not wrapped by this module at all (see `index.ts`'s
  header), so there is no risk of this module collecting or transmitting
  fields specific to those RPCs (e.g. an arbitrary `grantor`/`subject` pair
  a UI author might otherwise be tempted to let a user type in directly).

## Notes

- The client-side `logAuditEvent` call in `audit.ts`/`index.ts` is a local
  dev-visibility and mechanical-CI-convention stub, not this capability's
  Art. 5 audit trail of record — see `audit.ts`'s header comment. The real
  audit trail is emitted server-side by
  `services/api/internal/permissions/export.go` for `ExportPermissions`
  (deliberately audited even though it's not a state mutation — see that
  file's own doc comment), independent of anything this client module does
  or fails to do. `listGrantsForSubject` is a plain read with no
  server-side audit event of its own (matching `ListFileObjects`'/
  `listDevices`' precedent) and is not marked `// ascend:mutates` here.
