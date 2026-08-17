-- Reverses 0002_identities.up.sql. Does not DROP ROLE ascend_app: that role
-- is owned by migration 0001 (which created it) and may still be depended
-- on by other tables' grants (this migration's own included) — dropping it
-- here would break, not help, a rollback. Revoking this migration's own
-- grants on `identities` specifically is sufficient to undo what this
-- migration added.
REVOKE ALL ON identities FROM ascend_app;

DROP TABLE IF EXISTS identities;
