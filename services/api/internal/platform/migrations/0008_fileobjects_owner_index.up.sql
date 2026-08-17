-- 0008_fileobjects_owner_index: indexes fileobjects_records.owner, backing
-- ListFileObjects (docs/capabilities/file-objects.charter.md §3, amendment
-- 2026-08-18) — PostgresStore.listFileObjectsByOwner (postgres_store.go)
-- queries WHERE owner = $1, unindexed on this column before this migration
-- (fileobjects_records' only prior index is its own primary key,
-- file_object_id). No new table/column: ListFileObjects introduces no new
-- persisted field (charter §3: "this amendment introduces no new field"),
-- so this migration is purely a query-performance index, not a schema
-- change.

CREATE INDEX IF NOT EXISTS idx_fileobjects_records_owner ON fileobjects_records (owner);
