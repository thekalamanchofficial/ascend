-- 0005_fileobjects: File Objects' durable file-object/version/event store.
--
-- Every column maps 1:1 onto a field this capability already persists on
-- FileObjectRecord/VersionRecord/FileEvent (types.go) and onto
-- internal/fileobjects/DATA_MANIFEST.md's documented fields (Art. 8) —
-- name, mime_type, tags, size_bytes are the manifest's own "Fields" entries;
-- file_object_id/owner/current_version_ref/created_at_unix/
-- last_history_event_id are Art. 2's own structural identity/owner/history
-- fields, not re-documented in the manifest per its own note.
--
-- Three separate tables, not one, because InMemoryStore (store.go) itself
-- keeps three separate maps with genuinely different keys and lifecycles:
-- fileObjects (one row per file object), versions (many rows per file
-- object, creation-ordered), events (many rows per file object,
-- emission-ordered).
--
-- blob_ref (on fileobjects_versions) is stored purely as a cross-reference
-- to Storage's own independently-governed data — it is NEVER exposed
-- through any Store method's return values beyond the raw column itself,
-- and never through any File Objects export/response/audit path (charter
-- §6 point 8, DATA_MANIFEST.md's "Not collected / not a data field").
--
-- seq (fileobjects_versions, fileobjects_events) is a pure internal
-- ordering column, mirroring audit_events'/permissions_history's own seq/id
-- columns — never returned by any Store method, only used in ORDER BY, to
-- reproduce InMemoryStore's slice-append (creation/emission) order exactly.
--
-- See docs/DECISION_LOG.md, "File Objects: Store interface introduced,
-- PostgresStore added" for the full design rationale.

CREATE TABLE IF NOT EXISTS fileobjects_records (
    file_object_id         TEXT NOT NULL PRIMARY KEY,
    owner                   TEXT NOT NULL,
    current_version_ref     TEXT NOT NULL,
    name                    TEXT NOT NULL,
    mime_type                TEXT NOT NULL,
    tags                     JSONB NOT NULL DEFAULT '[]',
    size_bytes               BIGINT NOT NULL,
    created_at_unix          BIGINT NOT NULL,
    deleted                  BOOLEAN NOT NULL DEFAULT false,
    deleted_at_unix          BIGINT NOT NULL DEFAULT 0,
    last_history_event_id    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS fileobjects_versions (
    version_ref      TEXT NOT NULL PRIMARY KEY,
    file_object_id   TEXT NOT NULL,
    blob_ref         TEXT NOT NULL,
    created_at_unix  BIGINT NOT NULL,
    created_by       TEXT NOT NULL,
    size_bytes       BIGINT NOT NULL,
    seq              BIGSERIAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fileobjects_versions_fileobject ON fileobjects_versions (file_object_id, seq);

CREATE TABLE IF NOT EXISTS fileobjects_events (
    event_id          TEXT NOT NULL PRIMARY KEY,
    file_object_id     TEXT NOT NULL,
    action              TEXT NOT NULL,
    actor               TEXT NOT NULL,
    occurred_at_unix     BIGINT NOT NULL,
    metadata             JSONB NOT NULL DEFAULT '{}',
    seq                  BIGSERIAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fileobjects_events_fileobject ON fileobjects_events (file_object_id, seq);

-- Least-privilege runtime role. Like 0003_permissions, this migration does
-- NOT create ascend_app — it already exists, created idempotently by
-- migration 0001. Full DELETE is intentionally granted on all three tables
-- here (unlike audit_events'/permissions_history's append-only discipline):
-- deleteFileObjectRecord's atomic teardown of a file object + all its
-- versions + all its events is genuine, designed application behavior
-- (DeleteFileObject's charter §3 content-unreachability guarantee), not
-- something to prevent.
GRANT SELECT, INSERT, UPDATE, DELETE ON fileobjects_records TO ascend_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON fileobjects_versions TO ascend_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON fileobjects_events TO ascend_app;
GRANT USAGE, SELECT ON SEQUENCE fileobjects_versions_seq_seq TO ascend_app;
GRANT USAGE, SELECT ON SEQUENCE fileobjects_events_seq_seq TO ascend_app;
