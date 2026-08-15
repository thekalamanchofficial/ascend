# Data Manifest — File Objects

Per `docs/CONSTITUTION.md` Art. 8 (privacy is the default; minimum data
necessary, every collected field has a documented purpose) and the File
Objects charter §4/§3. This is the exhaustive list of fields this
capability collects and stores, on `FileObjectRecord` (`types.go`, marked
`// ascend:file-object`) beyond the identity/ownership/versioning/history
fields Art. 2 itself requires (`file_object_id`, `owner`,
`current_version_ref`, `created_at_unix`, `last_history_event_id` — those
are structural, not user-descriptive data, and are not re-documented here
as a Fields entry; they are covered by Art. 2's own obligation, not Art. 8's
"why was this collected" question).

File Objects never collects, stores, or observes actual file **content** as
a field of any persisted record — content is opaque bytes handed to
Storage via `StoreBlob`/read back via `RetrieveBlob`; this capability only
ever holds a `blob_ref` (an opaque handle, itself never exposed through any
File Objects RPC response, audit event, or error message — charter §6
point 8) pointing at Storage's own independently-governed data.

## Fields

- `name`
  Purpose: user-facing identification — the field a person actually reads
  to recognize which file this is, independent of whatever conversation or
  context it was shared in (charter §3).

- `mime_type`
  Purpose: correct rendering/handling — what a client uses to decide how to
  display or open the file's content, without needing to inspect the bytes
  themselves.

- `tags`
  Purpose: user-driven organization (Art. 11) — a caller-controlled,
  freeform set of labels; File Objects never infers or auto-assigns tags on
  a user's behalf, it only stores what `SetFileMetadata` was explicitly
  given.

- `size` (`size_bytes` on `FileObjectRecord`/`VersionRecord`)
  Purpose: display and storage-policy decisions ("how much data do I have")
  without requiring a caller to re-read content just to learn its size.
  Always derived from the current version's stored blob length — never
  caller-settable via `SetFileMetadata` (charter §3).

## Not collected / not a data field

- No file content is ever collected as a field of any persisted record —
  see the note above this table. `StoreBlob`/`RetrieveBlob`'s `data`
  parameter passes straight through to Storage; File Objects never retains
  a copy of it outside of what a single in-flight RPC call needs (charter
  §6 threat model: "File Objects must not cache or duplicate content
  outside what Storage returns").
- `blob_ref` (Storage's own opaque handle) is stored internally on
  `VersionRecord` purely as a cross-reference to Storage, but is
  deliberately excluded from every export, response, audit event, and error
  message this capability produces (charter §6 point 8) — see
  `export.go`'s `exportedVersionSummary` and `errors.go`'s
  `ErrContentUnavailable`.
- No display name, contact information, or other personal-identity
  attribute beyond `owner`/`requesting_subject`/grant `subject` is
  collected — these are opaque identity-reference strings (Identity's
  format, by convention) this package never resolves against Identity (see
  `docs/DECISION_LOG.md`, "File Objects: no runtime Identity dependency").
- No access-pattern telemetry beyond the `fileobjects.*` audit events this
  package emits via the injected `AuditEmitter` (not stored twice — see
  `store.go`'s `events` map, which mirrors exactly what was emitted, never
  anything additional).

## Retention

A `FileObjectRecord`/`VersionRecord` (including its tombstone form after
`DeleteFileObject`) is retained for as long as its owner's account exists,
mirroring Storage's/Permissions'/Session-Auth's own retention precedent.
**Known gap, not yet wired**, identical in shape to the one already flagged
by every sibling capability: no account-deletion signal exists yet from any
capability for this package to subscribe to, so full-owner purge on account
deletion is not yet implemented. Tracked as a follow-up integration point —
see `docs/DECISION_LOG.md`.
