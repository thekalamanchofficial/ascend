-- 0004_storage: Storage's durable blob-metadata and wrapping-key store.
--
-- Every column on storage_blobs maps 1:1 onto a documented field in
-- services/api/internal/storage/DATA_MANIFEST.md (Art. 8) — owner,
-- blob_ref, policy_id, size_bytes, created_at_unix, location, deleted,
-- deleted_at_unix, deletion_mechanism (BlobRecord). storage_wrapping_keys
-- holds Storage's own operational outer-wrapping-key material (wrap.go) —
-- explicitly NOT part of the data manifest, NEVER exported, kept in a
-- separate table for the same reason InMemoryStore keeps it in a separate
-- map (store.go): a deliberate structural safeguard against a future change
-- accidentally leaking it through an export path.
--
-- Two tables, not one, mirroring InMemoryStore's own two maps (records,
-- wrappingKeys) exactly — see store.go's package doc comment.
--
-- Unlike 0001_audit_events/0003_permissions' append-only history tables,
-- neither table here gets a REVOKE: both legitimate business-logic paths
-- (crypto-shred destroying a wrapping key, physical delete removing a
-- blob's record, tombstoning a deleted blob's record in place) genuinely
-- need UPDATE/DELETE on these tables — this is not a tamper-evidence log.
--
-- See docs/DECISION_LOG.md, "Storage: Store interface introduced,
-- PostgresStore added" for the full design rationale, in particular the
-- lockBlob cross-call advisory-lock design (which does not depend on any
-- schema here — it locks on a hash of blob_ref, not a row).

CREATE TABLE IF NOT EXISTS storage_blobs (
    blob_ref            TEXT NOT NULL PRIMARY KEY,
    owner                TEXT NOT NULL,
    policy_id            TEXT NOT NULL,
    size_bytes           BIGINT NOT NULL,
    created_at_unix      BIGINT NOT NULL,
    location             TEXT NOT NULL,
    deleted              BOOLEAN NOT NULL DEFAULT false,
    deleted_at_unix      BIGINT NOT NULL DEFAULT 0,
    deletion_mechanism   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_storage_blobs_owner ON storage_blobs (owner);

CREATE TABLE IF NOT EXISTS storage_wrapping_keys (
    blob_ref   TEXT NOT NULL PRIMARY KEY,
    key_bytes  BYTEA NOT NULL
);

-- Least-privilege runtime role. Like 0003_permissions, this migration does
-- NOT create ascend_app — it already exists, created idempotently by
-- migration 0001. This migration only grants it what these two tables
-- need.
GRANT SELECT, INSERT, UPDATE, DELETE ON storage_blobs TO ascend_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON storage_wrapping_keys TO ascend_app;
