-- Reverses 0004_storage.up.sql. Does not DROP ROLE ascend_app: that role is
-- owned by migration 0001 (which created it) and may still be depended on
-- by other tables' grants — dropping it here would break, not help, a
-- rollback. Revoking this migration's own grants on its two tables
-- specifically is sufficient to undo what this migration added.
REVOKE ALL ON storage_blobs FROM ascend_app;
REVOKE ALL ON storage_wrapping_keys FROM ascend_app;

DROP INDEX IF EXISTS idx_storage_blobs_owner;

DROP TABLE IF EXISTS storage_wrapping_keys;
DROP TABLE IF EXISTS storage_blobs;
