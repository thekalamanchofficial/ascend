-- Reverses 0006_sessionauth_sessions.up.sql. Does not DROP ROLE
-- ascend_app: that role is owned by migration 0001 (which created it) and
-- may still be depended on by other tables' grants — dropping it here
-- would break, not help, a rollback. Revoking this migration's own grant
-- on its one table is sufficient to undo what this migration added.
REVOKE ALL ON sessionauth_sessions FROM ascend_app;

DROP INDEX IF EXISTS idx_sessionauth_sessions_identity;

DROP TABLE IF EXISTS sessionauth_sessions;
