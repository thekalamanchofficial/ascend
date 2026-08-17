-- 0003_permissions: Permissions' durable grant/owner/policy/history store.
--
-- Every column maps 1:1 onto a documented field in
-- services/api/internal/permissions/DATA_MANIFEST.md (Art. 8) — grantor,
-- subject, action, resource_type/resource_id, scope, granted_at_unix (Grant)
-- and event_type, outcome, denial_reason, at_unix (HistoryEntry). `Policy`
-- is intentionally excluded from the manifest (platform config, not
-- personal data per the manifest's own "Not collected"/exclusion note) but
-- still gets a table here, since it is genuinely persisted state this
-- capability owns.
--
-- Four separate tables, not one, because InMemoryStore (store.go) itself
-- keeps four separate maps/slices with genuinely different keys and
-- lifecycles — see internal/permissions/postgres_store.go's doc comment,
-- and in particular the comment on putGrant there, for why
-- permissions_owners is NOT derivable from permissions_grants's earliest
-- row: an owner recorded on a resource's first-ever grant is never
-- overwritten even after that original grant is later revoked, so
-- ownership can outlive every grant that ever established it.
--
-- (resource_type, resource_id) is used as the real composite key
-- throughout, rather than InMemoryStore's synthetic
-- ResourceRef.key() string-concatenation (types.go) — a real relational
-- schema doesn't need a synthetic key just to make a Go map lookup work.
--
-- See docs/DECISION_LOG.md, "Permissions: Store interface introduced,
-- PostgresStore added" for the full design rationale.

CREATE TABLE IF NOT EXISTS permissions_grants (
    grantor          TEXT NOT NULL,
    subject          TEXT NOT NULL,
    action           TEXT NOT NULL,
    resource_type    TEXT NOT NULL,
    resource_id      TEXT NOT NULL,
    scope            TEXT NOT NULL,
    granted_at_unix  BIGINT NOT NULL,
    PRIMARY KEY (subject, action, resource_type, resource_id)
);
CREATE INDEX IF NOT EXISTS idx_permissions_grants_resource ON permissions_grants (resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_permissions_grants_subject ON permissions_grants (subject);

CREATE TABLE IF NOT EXISTS permissions_owners (
    resource_type  TEXT NOT NULL,
    resource_id    TEXT NOT NULL,
    owner_subject  TEXT NOT NULL,
    PRIMARY KEY (resource_type, resource_id)
);

CREATE TABLE IF NOT EXISTS permissions_policies (
    resource_type    TEXT NOT NULL PRIMARY KEY,
    default_rules    TEXT NOT NULL,
    defined_at_unix  BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions_history (
    id               BIGSERIAL NOT NULL PRIMARY KEY,
    event_type       TEXT NOT NULL,
    grantor          TEXT NOT NULL,
    subject          TEXT NOT NULL,
    action           TEXT NOT NULL,
    resource_type    TEXT NOT NULL,
    resource_id      TEXT NOT NULL,
    scope            TEXT NOT NULL DEFAULT '',
    at_unix          BIGINT NOT NULL,
    outcome          TEXT NOT NULL,
    denial_reason    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_permissions_history_subject ON permissions_history (subject);
CREATE INDEX IF NOT EXISTS idx_permissions_history_grantor ON permissions_history (grantor);

-- Least-privilege runtime role. Unlike 0001_audit_events, this migration
-- does NOT create ascend_app — it already exists, created idempotently by
-- migration 0001. This migration only grants it what these four tables
-- need.
GRANT SELECT, INSERT, UPDATE, DELETE ON permissions_grants TO ascend_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON permissions_owners TO ascend_app;
GRANT SELECT, INSERT, UPDATE ON permissions_policies TO ascend_app;
GRANT SELECT, INSERT ON permissions_history TO ascend_app;
GRANT USAGE, SELECT ON SEQUENCE permissions_history_id_seq TO ascend_app;

-- permissions_history is an append-only record backing ExportPermissions/
-- Art. 5 explainability, same discipline as audit_events (migration 0001):
-- explicit REVOKE, not merely "never GRANTed". Same scope caveat as
-- audit_events' own REVOKE (0001_audit_events.up.sql): this binds
-- ascend_app/PUBLIC only, not the migration-admin role that owns this
-- table — see that file's comment for the full disclosure, which applies
-- identically here.
REVOKE UPDATE, DELETE ON permissions_history FROM ascend_app;
REVOKE UPDATE, DELETE ON permissions_history FROM PUBLIC;
