-- 0002_identities: Identity's durable identity/device store.
--
-- Every column maps 1:1 onto a documented field in
-- services/api/internal/identity/DATA_MANIFEST.md (Art. 8) — display_name,
-- public_key, created_at_unix, epoch, and each device's device_id/name/
-- public_key/added_at/last_seen (the latter five packed inside the
-- `devices` JSONB array, not a separate table — see
-- internal/identity/postgres_store.go's doc comment and
-- docs/DECISION_LOG.md, "Identity: PostgresStore, a real Postgres-backed
-- implementation of Store", for why a single JSONB column faithfully
-- preserves InMemoryStore's existing whole-record-replace semantics with
-- the least complexity). `identity_ref` is the primary key: this
-- capability's Store interface (Create/Get/Replace) only ever looks up a
-- record by that single value — no other index is needed.

CREATE TABLE IF NOT EXISTS identities (
    identity_ref     TEXT NOT NULL PRIMARY KEY,
    display_name     TEXT NOT NULL,
    public_key       BYTEA NOT NULL,
    created_at_unix  BIGINT NOT NULL,
    epoch            BIGINT NOT NULL DEFAULT 0,
    devices          JSONB NOT NULL DEFAULT '[]'
);

-- Least-privilege runtime role. Unlike 0001_audit_events, this migration
-- does NOT create ascend_app — it already exists, created idempotently by
-- migration 0001. This migration only grants it what the `identities`
-- table needs.
--
-- No DELETE grant: Store's interface (Create/Get/Replace) has no delete
-- method — RevokeDevice (service.go) calls Replace with a shrunk Devices
-- list, it never removes an identity row. Unlike audit_events, there is no
-- append-only/tamper-evidence clause in this capability's charter, so
-- UPDATE is granted plainly (no REVOKE needed here, and none added).
GRANT SELECT, INSERT, UPDATE ON identities TO ascend_app;
