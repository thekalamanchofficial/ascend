-- 0009_identity_prekeys: Identity's prekey bundle publish/fetch amendment
-- (docs/capabilities/identity.charter.md §3/§4/§6, amendment gated
-- 2026-08-20). Two tables, not one:
--
--   * identity_signed_prekeys -- one row per (identity_ref, device_id): the
--     device's CURRENT signed prekey. Rotatable -- PublishPrekeyBundle
--     replaces this row's contents in place (an UPSERT keyed on the
--     primary key), it never accumulates history. Primary key is
--     (identity_ref, device_id), matching charter §3's "replaces the
--     device's current signed prekey (rotation)".
--
--   * identity_one_time_prekeys -- a pool table, many rows per
--     (identity_ref, device_id), one row per still-available one-time
--     prekey. PublishPrekeyBundle only ever INSERTs (additive, charter
--     §3); FetchPrekeyBundle's atomic claim is the only thing that ever
--     DELETEs a row (charter §6's atomic claim-and-delete requirement --
--     see postgres_prekey_store.go's ClaimOneOneTimePrekey for the exact
--     single-statement construction). prekey_id is globally unique
--     (primary key) -- Cryptography & Keys' own charter generates these
--     as fresh random identifiers per bundle; a caller re-publishing the
--     same prekey_id twice is treated as an idempotent no-op, not an
--     error (see postgres_prekey_store.go's PublishBundle doc comment).
--
-- Neither table is part of DATA_MANIFEST.md's Art. 9-export-required set:
-- charter §4 explicitly and deliberately excludes prekey state from
-- ExportIdentity's output (ephemeral, auto-regenerating routing
-- infrastructure -- "a device that rejoins or a fresh device that binds
-- simply regenerates and republishes on next launch"), so these two
-- tables carry no ascend:persisted/Export obligation the way `identities`
-- does (see identity/types.go's SignedPrekey/OneTimePrekeyPublic doc
-- comments for where this is made explicit in code, not just here). Both
-- are still fully documented in DATA_MANIFEST.md's field list per Art. 8
-- (every collected field needs a documented purpose; export status is a
-- separate, explicitly-argued question).
--
-- identity_ref/device_id are NOT foreign keys into a `devices` table,
-- because no such table exists -- Identity's existing schema
-- (0002_identities.up.sql) stores each identity's devices inside a single
-- JSONB column on the `identities` row, not a normalized devices table
-- (see that migration's own doc comment). Binding validity (is this
-- device_id really bound to this identity_ref?) is therefore checked in
-- Go, against IdentityRecord.Devices, exactly the same way every other
-- device-scoped operation in this package (RevokeDevice, and now
-- PublishPrekeyBundle/FetchPrekeyBundle) already does -- not enforced at
-- the database layer here, consistent with the rest of this schema.

CREATE TABLE IF NOT EXISTS identity_signed_prekeys (
    identity_ref     TEXT NOT NULL,
    device_id        TEXT NOT NULL,
    prekey_id        TEXT NOT NULL,
    public_key       BYTEA NOT NULL,
    signature        BYTEA NOT NULL,
    created_at_unix  BIGINT NOT NULL,
    PRIMARY KEY (identity_ref, device_id)
);

CREATE TABLE IF NOT EXISTS identity_one_time_prekeys (
    prekey_id     TEXT NOT NULL PRIMARY KEY,
    identity_ref  TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    public_key    BYTEA NOT NULL
);

-- Backs both ClaimOneOneTimePrekey's atomic claim (WHERE identity_ref = $1
-- AND device_id = $2 ... FOR UPDATE SKIP LOCKED LIMIT 1) and
-- CountUnconsumedOneTimePrekeys -- both scoped to one (identity_ref,
-- device_id) pair; without this index either query degrades to a full
-- table scan as the pool grows across every identity.
CREATE INDEX IF NOT EXISTS identity_one_time_prekeys_device_idx
    ON identity_one_time_prekeys (identity_ref, device_id);

-- Least-privilege runtime role, same pattern as every prior migration in
-- this series (does NOT create ascend_app -- it already exists, created
-- idempotently by migration 0001). DELETE is granted on
-- identity_one_time_prekeys (the atomic claim genuinely deletes rows --
-- charter §6 / Art. 8's anti-retention requirement, "consumed one-time
-- prekeys are deleted, not retained with a marker") -- identity_signed_prekeys
-- has no DELETE grant, matching `identities`' own precedent (rotation is
-- an UPSERT/UPDATE, never a delete; Store's interface for the `identities`
-- table has no delete method either).
--
-- UPDATE is ALSO granted on identity_one_time_prekeys, even though no
-- statement in this package ever issues a literal UPDATE against it
-- (ClaimOneOneTimePrekey's `SELECT ... FOR UPDATE SKIP LOCKED` is a
-- claim-and-delete, never a claim-and-mark, per Art. 8 above) -- this is
-- a real Postgres privilege-model requirement, not a design choice:
-- `SELECT ... FOR UPDATE` itself requires the UPDATE privilege on the
-- table it locks rows in, in addition to SELECT (confirmed live: a first
-- pass of this migration granting only SELECT/INSERT/DELETE produced a
-- genuine `permission denied for table identity_one_time_prekeys`
-- (SQLSTATE 42501) when ClaimOneOneTimePrekey ran against the real
-- ascend_app role -- caught by this capability's own live-Postgres
-- concurrency test, not assumed correct from reading the SQL alone; see
-- docs/DECISION_LOG.md). Granting this privilege does not reopen the
-- anti-retention commitment -- it is a permission grant, not a statement
-- this package ever actually executes.
GRANT SELECT, INSERT, UPDATE ON identity_signed_prekeys TO ascend_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_one_time_prekeys TO ascend_app;
