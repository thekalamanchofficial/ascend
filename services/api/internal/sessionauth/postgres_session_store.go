package sessionauth

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresSessionStore is a Postgres-backed implementation of SessionStore,
// persisting Session rows into the sessionauth_sessions table (see
// internal/platform/migrations/0006_sessionauth_sessions.up.sql). It
// replicates InMemorySessionStore's observable behavior exactly — most
// importantly, get returns a row regardless of whether it has expired (no
// store-level filtering), and touchLastUsed/delete are safe no-ops for an
// unknown token — Service (service.go) is written against the SessionStore
// interface and does not know or care which implementation actually backs
// it.
//
// # Error-handling design decision
//
// SessionStore's seven methods (store.go) were introduced in this same
// change, matching InMemorySessionStore's own pre-existing,
// error-return-free method set exactly, for the identical reason Permissions'
// PostgresStore documents (internal/permissions/postgres_store.go): adding
// error returns to SessionStore would be an interface change Service was
// never meant to absorb as part of this migration. So, mirroring that same
// package's resolution:
//
//   - get: a genuine query failure folds into (Session{}, false) — the same
//     shape as a legitimate miss. Every caller (ValidateSession,
//     resolveCaller, RevokeSession) already treats ok=false as "this
//     session is not valid" — fail closed, never a false "yes this session
//     is good" from a DB hiccup.
//   - listActiveForIdentity / listAllForIdentity: a genuine query failure
//     folds into a nil slice, matching Audit's/Permissions' identical
//     precedent for read-only list/export paths (ListActiveSessions,
//     ExportSessions) — an empty result during an outage is
//     indistinguishable from a genuinely empty result, an accepted
//     limitation shared with every prior batch's Postgres store.
//   - put / touchLastUsed / delete / deleteAllForIdentity: these four are
//     mutations with no error-return channel to fold a genuine failure
//     into — deleteAllForIdentity even has a *plausible-looking* zero value
//     (its int count) that a swallowed error could silently return,
//     exactly the "RevokeAllSessions reports N sessions revoked when the
//     DELETE never actually ran" silent-success hazard Art. 5 forbids
//     (session revocation is a real, immediate, Art. 7-obligated action —
//     see store.go's delete doc comment — a caller who believes they
//     revoked every session when they didn't is a genuine security-relevant
//     lie, not just a stale read). So, matching Permissions'
//     PostgresStore's identical resolution for its own four void-return
//     mutation methods, all four panic on a genuine query/exec failure
//     rather than silently no-oping or returning a misleadingly-normal-
//     looking zero value. A panic inside an HTTP handler goroutine is
//     recovered per-request by Go's own net/http server (logs the stack
//     trace, closes that one connection, writes no 200-with-lies response)
//     — no other in-flight request is affected. touchLastUsed/delete's own
//     DOCUMENTED "safe no-op for an unknown token" behavior is preserved
//     exactly: a DELETE/UPDATE matching zero rows is not a Postgres error,
//     so it never reaches the panic path — only a genuine connectivity/
//     query failure does.
type PostgresSessionStore struct {
	pool *pgxpool.Pool
}

// NewPostgresSessionStore constructs a PostgresSessionStore against an
// already-connected pool. Callers are responsible for having already run
// this package's migration (0006_sessionauth_sessions.up.sql) against the
// same database — this constructor does not run migrations itself (that is
// platform.New's job, at server startup).
func NewPostgresSessionStore(pool *pgxpool.Pool) *PostgresSessionStore {
	return &PostgresSessionStore{pool: pool}
}

// sessionStoreFailure panics with a message identifying which void-return
// mutation method failed and why. See PostgresSessionStore's doc comment
// above for the full reasoning.
func sessionStoreFailure(op string, err error) {
	panic(fmt.Sprintf("sessionauth: postgres session store %s: %v", op, err))
}

// put upserts sess, keyed by its session_token.
func (s *PostgresSessionStore) put(sess Session) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessionauth_sessions
			(session_token, identity_ref, device_id, issued_at_unix, expires_at_unix, last_used_at_unix)
		VALUES
			($1, $2, $3, $4, $5, $6)
		ON CONFLICT (session_token)
		DO UPDATE SET identity_ref = EXCLUDED.identity_ref,
		              device_id = EXCLUDED.device_id,
		              issued_at_unix = EXCLUDED.issued_at_unix,
		              expires_at_unix = EXCLUDED.expires_at_unix,
		              last_used_at_unix = EXCLUDED.last_used_at_unix
	`,
		sess.SessionToken, sess.IdentityRef, sess.DeviceID,
		sess.IssuedAtUnix, sess.ExpiresAtUnix, sess.LastUsedAtUnix,
	)
	if err != nil {
		sessionStoreFailure("put", err)
	}
}

// get returns the session record for token, if any exists — REGARDLESS of
// whether expires_at_unix has passed (no WHERE expires_at_unix >= now
// filter; this is a hard requirement, see PostgresSessionStore's doc
// comment and store.go's InMemorySessionStore.get doc comment for why).
func (s *PostgresSessionStore) get(token string) (Session, bool) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, `
		SELECT session_token, identity_ref, device_id, issued_at_unix, expires_at_unix, last_used_at_unix
		FROM sessionauth_sessions
		WHERE session_token = $1
	`, token)

	sess, err := scanSession(row)
	if err != nil {
		return Session{}, false
	}
	return sess, true
}

// touchLastUsed updates last_used_at_unix for an existing session. A safe
// no-op if the token is unknown (an UPDATE matching zero rows is not a
// Postgres error), matching InMemorySessionStore.touchLastUsed's documented
// behavior exactly.
func (s *PostgresSessionStore) touchLastUsed(token string, nowUnix int64) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		UPDATE sessionauth_sessions SET last_used_at_unix = $1 WHERE session_token = $2
	`, nowUnix, token)
	if err != nil {
		sessionStoreFailure("touch_last_used", err)
	}
}

// delete removes a session outright — revocation is real and immediate
// (Art. 7): once deleted, no subsequent get can ever resolve this token
// again. A safe no-op if the token is already unknown (a DELETE matching
// zero rows is not a Postgres error).
func (s *PostgresSessionStore) delete(token string) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `DELETE FROM sessionauth_sessions WHERE session_token = $1`, token)
	if err != nil {
		sessionStoreFailure("delete", err)
	}
}

// deleteAllForIdentity removes every session belonging to identityRef and
// reports how many were removed — backs RevokeAllSessions. See
// PostgresSessionStore's doc comment for why a genuine query failure here
// panics rather than returning a misleadingly-normal-looking 0.
func (s *PostgresSessionStore) deleteAllForIdentity(identityRef string) int {
	ctx := context.Background()
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessionauth_sessions WHERE identity_ref = $1`, identityRef)
	if err != nil {
		sessionStoreFailure("delete_all_for_identity", err)
	}
	return int(tag.RowsAffected())
}

// listActiveForIdentity returns every currently-unexpired session for
// identityRef — backs ListActiveSessions. See PostgresSessionStore's doc
// comment for why a genuine query failure folds into a nil slice.
func (s *PostgresSessionStore) listActiveForIdentity(identityRef string, nowUnix int64) []Session {
	return s.querySessions(`
		SELECT session_token, identity_ref, device_id, issued_at_unix, expires_at_unix, last_used_at_unix
		FROM sessionauth_sessions
		WHERE identity_ref = $1 AND expires_at_unix >= $2
	`, identityRef, nowUnix)
}

// listAllForIdentity returns every session record this store currently
// holds for identityRef, active or expired (but not yet revoked/deleted) —
// backs ExportSessions. See PostgresSessionStore's doc comment for why a
// genuine query failure folds into a nil slice.
func (s *PostgresSessionStore) listAllForIdentity(identityRef string) []Session {
	return s.querySessions(`
		SELECT session_token, identity_ref, device_id, issued_at_unix, expires_at_unix, last_used_at_unix
		FROM sessionauth_sessions
		WHERE identity_ref = $1
	`, identityRef)
}

// deviceGenerationLockTimeout bounds how long a single
// putIfDeviceGenerationUnchanged/revokeAllForDevice call will wait to open
// its transaction and take the SELECT ... FOR UPDATE row lock on the
// device's generation row, before giving up and failing loudly rather than
// blocking forever — the same "no unbounded context.Background() wait"
// discipline Storage's lockBlob applies after its own live-proven incident
// (docs/DECISION_LOG.md, "Storage: lockBlob bounded-timeout fix (Security
// Steward block)"), applied here from the start rather than added after
// one. 5 seconds for the identical reasoning lockAcquireTimeout there
// uses: generous relative to this package's real critical-section cost (a
// handful of parameterized queries, no filesystem I/O, no call beyond
// Postgres itself), short enough that a genuinely stuck caller fails
// within a reasonable patience window. Unlike lockBlob, this critical
// section is ONE self-contained transaction (pool.Begin/Commit/Rollback,
// releasing its connection back to the pool automatically either way),
// never a connection held open across a multi-call, cross-method service-
// level sequence with filesystem I/O in between — so the blast radius of
// contention here is inherently smaller by construction, but the same
// bound is applied anyway rather than assumed safe without it.
const deviceGenerationLockTimeout = 5 * time.Second

// currentDeviceGeneration performs a plain, non-transactional read — see
// SessionStore's doc comment (store.go) for why this read does not itself
// need to be atomic; the correctness guarantee lives entirely in
// putIfDeviceGenerationUnchanged's own re-check under lock, not here.
// Returns 0 (never an error) both for a device with no row yet (a device
// that has never had RevokeSessionsForDevice called for it — the common
// case) and for a genuine query failure, matching this package's
// established "a real failure on a read-only path folds into the safe/
// empty result" precedent (see get/listActiveForIdentity/listAllForIdentity
// above) — this read is advisory only, never the atomicity-critical step.
func (s *PostgresSessionStore) currentDeviceGeneration(identityRef, deviceID string) int64 {
	ctx := context.Background()
	var generation int64
	err := s.pool.QueryRow(ctx,
		`SELECT generation FROM sessionauth_device_generations WHERE identity_ref = $1 AND device_id = $2`,
		identityRef, deviceID,
	).Scan(&generation)
	if err != nil {
		return 0
	}
	return generation
}

// putIfDeviceGenerationUnchanged is IssueSession's atomic commit gate — see
// SessionStore's doc comment (store.go) for the full design. Implemented
// as a single Postgres transaction: SELECT ... FOR UPDATE takes a
// row-level lock on (or, via the upsert immediately before it, creates
// then locks) the device's generation row, held until this transaction
// commits or rolls back — this IS the "per-device serialization point"
// the charter's atomicity requirement calls for, mutually exclusive
// against revokeAllForDevice's own identical lock-taking below for the
// same (identity_ref, device_id): whichever transaction's SELECT ... FOR
// UPDATE runs first for a given device blocks the other's until it
// commits or rolls back.
func (s *PostgresSessionStore) putIfDeviceGenerationUnchanged(sess Session, expectedGeneration int64) bool {
	ctx, cancel := context.WithTimeout(context.Background(), deviceGenerationLockTimeout)
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		sessionStoreFailure("put_if_device_generation_unchanged: begin tx (possibly timed out after "+deviceGenerationLockTimeout.String()+")", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit has succeeded

	// Upsert-to-zero-then-lock: a device with no prior revocation history
	// has no row yet. ON CONFLICT DO NOTHING makes this safe to run
	// unconditionally on every call without a separate existence check.
	if _, err := tx.Exec(ctx, `
		INSERT INTO sessionauth_device_generations (identity_ref, device_id, generation)
		VALUES ($1, $2, 0)
		ON CONFLICT (identity_ref, device_id) DO NOTHING
	`, sess.IdentityRef, sess.DeviceID); err != nil {
		sessionStoreFailure("put_if_device_generation_unchanged: upsert generation row", err)
	}

	var current int64
	if err := tx.QueryRow(ctx, `
		SELECT generation FROM sessionauth_device_generations
		WHERE identity_ref = $1 AND device_id = $2
		FOR UPDATE
	`, sess.IdentityRef, sess.DeviceID).Scan(&current); err != nil {
		sessionStoreFailure("put_if_device_generation_unchanged: lock generation row", err)
	}

	if current != expectedGeneration {
		// Deliberately NOT sessionStoreFailure — this is the expected,
		// correct rejection path (the charter's atomicity requirement
		// working as designed: a RevokeSessionsForDevice call for this
		// device committed since expectedGeneration was captured), not a
		// store failure. Explicit rollback here (also covered by the
		// deferred one, kept for clarity that this path intentionally
		// discards the transaction) before reporting rejection.
		_ = tx.Rollback(ctx)
		return false
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO sessionauth_sessions
			(session_token, identity_ref, device_id, issued_at_unix, expires_at_unix, last_used_at_unix)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (session_token)
		DO UPDATE SET identity_ref = EXCLUDED.identity_ref,
		              device_id = EXCLUDED.device_id,
		              issued_at_unix = EXCLUDED.issued_at_unix,
		              expires_at_unix = EXCLUDED.expires_at_unix,
		              last_used_at_unix = EXCLUDED.last_used_at_unix
	`,
		sess.SessionToken, sess.IdentityRef, sess.DeviceID,
		sess.IssuedAtUnix, sess.ExpiresAtUnix, sess.LastUsedAtUnix,
	); err != nil {
		sessionStoreFailure("put_if_device_generation_unchanged: insert session", err)
	}

	if err := tx.Commit(ctx); err != nil {
		sessionStoreFailure("put_if_device_generation_unchanged: commit", err)
	}
	return true
}

// revokeAllForDevice atomically bumps (identityRef, deviceID)'s generation
// and deletes every session currently stored for that exact pair, as one
// transaction — see SessionStore's doc comment (store.go) and
// putIfDeviceGenerationUnchanged above for the full mutual-exclusion
// design; both take the SAME row-level lock, so whichever call's
// transaction begins first for a given device fully commits (or rolls
// back) before the other's SELECT ... FOR UPDATE can proceed.
func (s *PostgresSessionStore) revokeAllForDevice(identityRef, deviceID string) int {
	ctx, cancel := context.WithTimeout(context.Background(), deviceGenerationLockTimeout)
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		sessionStoreFailure("revoke_all_for_device: begin tx (possibly timed out after "+deviceGenerationLockTimeout.String()+")", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO sessionauth_device_generations (identity_ref, device_id, generation)
		VALUES ($1, $2, 0)
		ON CONFLICT (identity_ref, device_id) DO NOTHING
	`, identityRef, deviceID); err != nil {
		sessionStoreFailure("revoke_all_for_device: upsert generation row", err)
	}

	// SELECT ... FOR UPDATE first (taking the lock) is not strictly
	// required for a single subsequent UPDATE statement — Postgres's own
	// row-level locking on UPDATE would already serialize two concurrent
	// UPDATEs to the same row — but taking the lock explicitly, the same
	// way putIfDeviceGenerationUnchanged does, keeps both methods'
	// locking behavior visibly identical rather than relying on two
	// different implicit mechanisms to coincidentally agree.
	var current int64
	if err := tx.QueryRow(ctx, `
		SELECT generation FROM sessionauth_device_generations
		WHERE identity_ref = $1 AND device_id = $2
		FOR UPDATE
	`, identityRef, deviceID).Scan(&current); err != nil {
		sessionStoreFailure("revoke_all_for_device: lock generation row", err)
	}
	_ = current // read only to hold the lock consistently with putIfDeviceGenerationUnchanged; the value itself isn't needed here

	if _, err := tx.Exec(ctx, `
		UPDATE sessionauth_device_generations SET generation = generation + 1
		WHERE identity_ref = $1 AND device_id = $2
	`, identityRef, deviceID); err != nil {
		sessionStoreFailure("revoke_all_for_device: bump generation", err)
	}

	tag, err := tx.Exec(ctx, `
		DELETE FROM sessionauth_sessions WHERE identity_ref = $1 AND device_id = $2
	`, identityRef, deviceID)
	if err != nil {
		sessionStoreFailure("revoke_all_for_device: delete sessions", err)
	}

	if err := tx.Commit(ctx); err != nil {
		sessionStoreFailure("revoke_all_for_device: commit", err)
	}
	return int(tag.RowsAffected())
}

func (s *PostgresSessionStore) querySessions(query string, args ...any) []Session {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil
		}
		out = append(out, sess)
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// rowScanner is the common subset of pgx.Row and pgx.Rows this package
// needs (just Scan), matching Audit's/Permissions' own equivalent seam.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanSession scans a Session row. The caller (get: pgx.ErrNoRows; querySessions:
// any other failure) doesn't need to distinguish "no rows" from "genuine
// error" here — both simply fold into ok=false / an empty result, per
// PostgresSessionStore's doc comment.
func scanSession(row rowScanner) (Session, error) {
	var sess Session
	err := row.Scan(
		&sess.SessionToken,
		&sess.IdentityRef,
		&sess.DeviceID,
		&sess.IssuedAtUnix,
		&sess.ExpiresAtUnix,
		&sess.LastUsedAtUnix,
	)
	if err != nil {
		return Session{}, err
	}
	return sess, nil
}
