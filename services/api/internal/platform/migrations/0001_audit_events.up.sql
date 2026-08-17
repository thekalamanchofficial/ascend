-- 0001_audit_events: Audit / Explainability's durable event log.
--
-- Every column maps 1:1 onto a documented field in
-- services/api/internal/audit/DATA_MANIFEST.md (Art. 8) — event_id, actor,
-- action, resource.resource_type/resource_id, rule_reference, metadata,
-- occurred_at_unix, prev_hash. `seq` is the one Postgres-only addition, an
-- internal ordering column never exposed through the Store interface (see
-- postgres_store.go) — it exists only to give Query's "most-recent-first"
-- and All's "oldest-first, append order" an unambiguous tiebreaker distinct
-- from occurred_at_unix, which is not guaranteed strictly monotonic under
-- concurrent inserts within the same wall-clock second.
--
-- See docs/DECISION_LOG.md, "Database setup: shared platform foundation +
-- Audit on real Postgres" for the full design rationale, including why the
-- hash-chain (prev_hash/event_id) integrity guarantee is enforced in Go
-- (internal/audit/postgres_store.go, via a Postgres advisory lock), not in
-- SQL/PL-pgSQL.

CREATE TABLE IF NOT EXISTS audit_events (
    event_id          TEXT NOT NULL PRIMARY KEY,
    prev_hash         TEXT NOT NULL,
    actor             TEXT NOT NULL,
    action            TEXT NOT NULL,
    resource_type     TEXT NOT NULL DEFAULT '',
    resource_id       TEXT NOT NULL DEFAULT '',
    rule_reference    TEXT NOT NULL DEFAULT '',
    metadata          JSONB NOT NULL DEFAULT '{}',
    occurred_at_unix  BIGINT NOT NULL,
    seq               BIGSERIAL NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor);
CREATE INDEX IF NOT EXISTS idx_audit_events_resource ON audit_events (resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events (action);
CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at ON audit_events (occurred_at_unix);

-- Least-privilege runtime role (docs/DECISION_LOG.md, same entry as above).
-- Created with NO password here — a migration file is committed to git, so
-- a real secret must never be embedded in one. The password is set
-- immediately after migrations run, by platform.ProvisionAppRolePassword
-- (Go code, sourced from the ASCEND_APP_DB_PASSWORD environment variable),
-- never by this file.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ascend_app') THEN
        CREATE ROLE ascend_app LOGIN;
    END IF;
END
$$;

GRANT SELECT, INSERT ON audit_events TO ascend_app;
GRANT USAGE, SELECT ON SEQUENCE audit_events_seq_seq TO ascend_app;

-- Append-only enforcement at the DB level, per Store's own doc comment
-- (internal/audit/store.go) and the capability's charter §6. Explicit
-- REVOKE, not merely "never GRANTed" — makes the guarantee inspectable and
-- holds even if a future migration accidentally GRANTs something broader
-- to PUBLIC.
--
-- SCOPE, disclosed honestly (charter §6 amendment, 2026-08-17, Security
-- Steward merge-gate finding — docs/DECISION_LOG.md, "Database setup:
-- Security Steward block and fix"): this REVOKE binds ascend_app (the
-- running application's own runtime credential) and PUBLIC (every other
-- role with no explicit grant) — it does NOT and CANNOT bind ascend_admin,
-- the role that owns this table (it ran this CREATE TABLE). Postgres table
-- ownership carries an implicit, un-revokable right to DELETE/UPDATE/ALTER/
-- DROP the object and to re-grant itself any privilege — REVOKE has no
-- power over an owner. Real protection against that specific credential
-- would require decoupling the owning role from the migration-runner role
-- entirely (tracked in docs/CAPABILITY_REGISTRY.md), not a stronger REVOKE
-- here. Never describe this REVOKE, on its own, as satisfying the charter's
-- "including platform operators" language — it does not.
REVOKE UPDATE, DELETE ON audit_events FROM ascend_app;
REVOKE UPDATE, DELETE ON audit_events FROM PUBLIC;
