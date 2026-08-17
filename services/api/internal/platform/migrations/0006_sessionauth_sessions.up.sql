-- 0006_sessionauth_sessions: Session/Request Authentication's durable
-- session store.
--
-- Every column maps 1:1 onto a documented field in
-- services/api/internal/sessionauth/DATA_MANIFEST.md (Art. 8) —
-- session_token, identity_ref, device_id, issued_at_unix, expires_at_unix,
-- last_used_at_unix (Session). Challenge nonces (the other half of this
-- capability's storage) are NOT here — they live in Redis
-- (redis_nonce_store.go), not Postgres, per a documented decision
-- (docs/DECISION_LOG.md, "Batch C (Session/Request Authentication)
-- design"): pure ephemeral, single-use state with no durability/export
-- requirement.
--
-- Unlike 0001_audit_events/0003_permissions' append-only history tables,
-- this table gets full CRUD, including a real DELETE: session revocation
-- is a legitimate, real, immediate action (Art. 7 — see
-- sessionauth/store.go's own "revocation is real and immediate" doc
-- comment on delete). This is not a tamper-evidence log.
--
-- No WHERE-clause-level expiry filtering is baked into this schema on
-- purpose: `get` must return a row regardless of whether
-- expires_at_unix has passed (Service's own ValidateSession/resolveCaller
-- check expiry themselves; ExportSessions specifically wants
-- expired-but-not-revoked sessions).

CREATE TABLE IF NOT EXISTS sessionauth_sessions (
    session_token       TEXT NOT NULL PRIMARY KEY,
    identity_ref         TEXT NOT NULL,
    device_id             TEXT NOT NULL,
    issued_at_unix        BIGINT NOT NULL,
    expires_at_unix       BIGINT NOT NULL,
    last_used_at_unix     BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessionauth_sessions_identity ON sessionauth_sessions (identity_ref);

-- Least-privilege runtime role. Like 0003_permissions/0004_storage/
-- 0005_fileobjects, this migration does NOT create ascend_app — it already
-- exists, created idempotently by migration 0001. This migration only
-- grants it what this one table needs.
GRANT SELECT, INSERT, UPDATE, DELETE ON sessionauth_sessions TO ascend_app;
