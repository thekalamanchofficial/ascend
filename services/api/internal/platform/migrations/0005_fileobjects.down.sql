-- Reverses 0005_fileobjects.up.sql. Does not DROP ROLE ascend_app: that role
-- is owned by migration 0001 (which created it) and may still be depended
-- on by other tables' grants — dropping it here would break, not help, a
-- rollback. Revoking this migration's own grants on its three tables
-- specifically is sufficient to undo what this migration added.
REVOKE ALL ON fileobjects_records FROM ascend_app;
REVOKE ALL ON fileobjects_versions FROM ascend_app;
REVOKE ALL ON fileobjects_events FROM ascend_app;

DROP INDEX IF EXISTS idx_fileobjects_events_fileobject;
DROP INDEX IF EXISTS idx_fileobjects_versions_fileobject;

DROP TABLE IF EXISTS fileobjects_events;
DROP TABLE IF EXISTS fileobjects_versions;
DROP TABLE IF EXISTS fileobjects_records;
