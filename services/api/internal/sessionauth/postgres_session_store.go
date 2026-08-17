package sessionauth

import (
	"context"
	"fmt"

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
