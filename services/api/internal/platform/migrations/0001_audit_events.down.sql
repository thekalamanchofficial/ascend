-- Reverses 0001_audit_events.up.sql. Does not DROP ROLE ascend_app: future
-- migrations (0002+, for other capabilities) may already depend on that
-- role owning grants on their own tables — dropping a role a later
-- migration still references would break, not help, a rollback. Revoking
-- this migration's own grants on audit_events specifically is sufficient
-- to undo what this migration added.
REVOKE ALL ON audit_events FROM ascend_app;

DROP INDEX IF EXISTS idx_audit_events_occurred_at;
DROP INDEX IF EXISTS idx_audit_events_action;
DROP INDEX IF EXISTS idx_audit_events_resource;
DROP INDEX IF EXISTS idx_audit_events_actor;

DROP TABLE IF EXISTS audit_events;
