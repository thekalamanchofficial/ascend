-- Reverses 0003_permissions.up.sql. Does not DROP ROLE ascend_app: that role
-- is owned by migration 0001 (which created it) and may still be depended
-- on by other tables' grants (0002_identities' included) — dropping it here
-- would break, not help, a rollback. Revoking this migration's own grants on
-- its four tables specifically is sufficient to undo what this migration
-- added.
REVOKE ALL ON permissions_grants FROM ascend_app;
REVOKE ALL ON permissions_owners FROM ascend_app;
REVOKE ALL ON permissions_policies FROM ascend_app;
REVOKE ALL ON permissions_history FROM ascend_app;

DROP INDEX IF EXISTS idx_permissions_history_grantor;
DROP INDEX IF EXISTS idx_permissions_history_subject;
DROP INDEX IF EXISTS idx_permissions_grants_subject;
DROP INDEX IF EXISTS idx_permissions_grants_resource;

DROP TABLE IF EXISTS permissions_history;
DROP TABLE IF EXISTS permissions_policies;
DROP TABLE IF EXISTS permissions_owners;
DROP TABLE IF EXISTS permissions_grants;
