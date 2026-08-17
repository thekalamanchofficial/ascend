-- 0007_sessionauth_device_generations: durable per-(identity_ref, device_id)
-- generation counter backing RevokeSessionsForDevice's atomicity guarantee
-- (docs/capabilities/session-authentication.charter.md §3, amendment
-- 2026-08-17: "sessions_revoked is a completion guarantee, not a
-- point-in-time snapshot count... the implementer must close the race via
-- a per-device serialization point... or a revoked-at watermark for the
-- device that IssueSession checks as part of its own commit").
--
-- Mirrors Identity's own `epoch` counter (0002_identities.up.sql) in
-- spirit — a monotonically increasing, server-held generation value that
-- an in-flight operation's commit is checked against, so a commit whose
-- view of the world has gone stale fails closed rather than silently
-- succeeding. See sessionauth/postgres_session_store.go's
-- putIfDeviceGenerationUnchanged/revokeAllForDevice for the exact
-- transactional mechanics (SELECT ... FOR UPDATE row lock, held for the
-- duration of one short transaction — the "per-device serialization
-- point" itself).
--
-- Not part of DATA_MANIFEST.md's Art. 8 field list: like Identity's epoch,
-- this is not user-supplied or user-visible data, it is internal
-- anti-race protocol state with no export requirement — see
-- sessionauth/DATA_MANIFEST.md's existing "Note on the failure-tracking
-- counter" precedent for the same reasoning applied to a different
-- internal-only counter in this same package.

CREATE TABLE IF NOT EXISTS sessionauth_device_generations (
    identity_ref TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    generation   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (identity_ref, device_id)
);

-- Least-privilege runtime role. Like every prior migration in this series,
-- this does NOT create ascend_app — it already exists, created idempotently
-- by migration 0001. This migration only grants it what this one table
-- needs.
GRANT SELECT, INSERT, UPDATE, DELETE ON sessionauth_device_generations TO ascend_app;
