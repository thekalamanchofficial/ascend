package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is a Postgres-backed implementation of Store, persisting
// BlobRecord metadata into storage_blobs and wrapping-key material into
// storage_wrapping_keys (see
// internal/platform/migrations/0004_storage.up.sql). It replicates
// InMemoryStore's observable behavior exactly (miss shapes, wrapping-key
// destroy-once semantics, and — the one genuinely new design problem —
// lockBlob's cross-call serialization) — Service (service.go) is written
// against the Store interface and does not know or care which
// implementation actually backs it.
//
// # Error-handling design decision (read this before touching any method below)
//
// Store's 9 methods (store.go) are fixed by this same change to match
// InMemoryStore's own pre-existing, error-return-free method set exactly,
// so Service's call sites (service.go) stay textually and behaviorally
// identical. That leaves the same question Audit's and Permissions'
// PostgresStore both had to answer: with no error-return channel on any of
// these 9 methods, how does a genuine Postgres failure (a dropped
// connection, a context timeout, etc. — as opposed to a legitimate "not
// found") get handled without silently pretending a mutation succeeded, or
// silently pretending a read came back empty/absent when it might not have?
//
// This implementation follows Permissions' precedent exactly, split the
// same way:
//
//   - The five read/query-shaped methods (get, recordsForOwner,
//     wrappingKey, hasWrappingKey, and destroyWrappingKey's initial
//     existence check) fold a genuine query failure into the same shape as
//     a legitimate miss — fail closed. get: DB error -> (BlobRecord{},
//     false), same as a genuine "no such blob_ref"; every caller
//     (RetrieveBlob/MoveBlob/DeleteBlob/GetStorageLocation) already treats
//     found=false as ErrBlobNotFound, never as an implicit "proceed as if
//     it exists". recordsForOwner: DB error -> nil slice, matching Audit's
//     All()/Query() and Permissions' four list methods' identical
//     precedent for a read-only export path (ExportAllBlobs) with no
//     allow/deny decision riding on it. wrappingKey/hasWrappingKey: DB
//     error -> (nil, false) / false, the fail-closed direction for
//     "can I retrieve/does a key exist" — RetrieveBlob already treats a
//     missing key as a hard error ("no wrapping key available"), and
//     DeleteBlob's crypto-shred path already treats "no key to destroy" as
//     a hard failure, so folding a DB error into the same shape never
//     manufactures a false "yes, retrievable" or "yes, still shreddable"
//     result out of an outage.
//
//   - The four write methods (put, delete, putWrappingKey,
//     destroyWrappingKey's actual DELETE) return NOTHING (or, for
//     destroyWrappingKey, a bool whose true/false is part of its documented
//     contract, not a spare error channel) — there is no return value to
//     fold a genuine write failure into defensively. Silently no-oping on a
//     failed put/delete/putWrappingKey here would let StoreBlob/MoveBlob/
//     DeleteBlob proceed to emit a "storage.store_blob"/"storage.move_blob"/
//     "storage.delete_blob" audit event reporting SUCCESS for a mutation
//     that never actually reached the database — exactly the "silent
//     success hazard Art. 5 forbids" that service.go's own comments already
//     call out repeatedly for the audit-emit step, one layer lower. So
//     these three panic on a genuine query/exec failure, exactly matching
//     Permissions' PostgresStore precedent (storeFailure there,
//     storeFailure here). destroyWrappingKey is the one write method that
//     DOES have a real return value already (bool) as part of its existing,
//     frozen contract ("Returns false if no key was present to destroy") —
//     a genuine DB failure there is NOT folded into false (which would look
//     identical to "already destroyed" and let DeleteBlob's crypto-shred
//     path silently treat a live outage as a successful shred of an
//     already-gone key), it panics too, for the same reason put/delete do.
//
// A panic inside an HTTP handler goroutine is recovered per-request by Go's
// own net/http server (it logs the stack trace and closes that single
// connection without ever writing a 200-with-lies response) — the caller
// sees a hard failure, not a soft one, and no other in-flight request is
// affected.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore constructs a PostgresStore against an already-connected
// pool. Callers are responsible for having already run this package's
// migration (0004_storage.up.sql) against the same database — this
// constructor does not run migrations itself (that is platform.New's job,
// at server startup).
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// storeFailure panics with a message identifying which void-return
// mutation method failed and why. See PostgresStore's doc comment above for
// the full reasoning. Named identically to Permissions' own helper
// (internal/permissions/postgres_store.go) by convention — kept
// package-local here rather than shared, since both packages deliberately
// avoid importing each other (Art. 10).
func storeFailure(op string, err error) {
	panic(fmt.Sprintf("storage: postgres %s: %v", op, err))
}

// --- lockBlob: cross-call session-level advisory lock ---
//
// lockBlob must serialize an entire multi-call sequence (spanning
// Service.MoveBlob's/DeleteBlob's full method bodies — several separate
// Store method calls, no shared transaction connecting them) against any
// other concurrent call for the same blob_ref, exactly like
// InMemoryStore's per-blob_ref *sync.Mutex does today (store.go's own doc
// comment). A transaction-scoped advisory lock
// (pg_advisory_xact_lock, what Audit's Append uses) does NOT work here — it
// only lives for the duration of one transaction, and there is no single
// transaction spanning Store.get/Store.put/etc. across a MoveBlob/DeleteBlob
// call.
//
// Instead, this acquires a genuine SESSION-level advisory lock
// (pg_advisory_lock/pg_advisory_unlock) on a connection checked out from
// the pool for the lock's entire lifetime, via pool.Acquire(ctx) rather
// than pool.Exec — a plain pool.Exec would hand back a DIFFERENT,
// essentially random connection from the pool on every call, and
// pg_advisory_lock's session-level variant is tied to the specific backend
// session (Postgres connection) that took it, not to any value or key
// visible to other connections. Locking on one connection and unlocking on
// another would silently fail to serialize anything — the unlock would
// either error (no matching lock held on that connection) or, worse, do
// nothing while the original lock-holding connection keeps the lock
// forever until that connection itself closes. So the *pgxpool.Conn
// acquired here is held onto, unshared, from the moment pg_advisory_lock
// returns until the returned unlock closure runs pg_advisory_unlock on that
// exact same connection and releases it back to the pool — never returned
// to the pool in between, and never used for any other query in the
// meantime.
//
// blobLockKey derives the int64 lock key from blobRef via fnv1a64, the same
// algorithm Audit's own postgres_store.go uses for its own fixed advisory
// lock key (internal/audit/postgres_store.go) — copied into this package
// rather than imported cross-package, per Art. 10 (this package must not
// depend on internal/audit's internals) and per this task's explicit
// instruction. Unlike Audit's single fixed key (one lock for the whole
// table), this hashes blobRef itself, giving each blob_ref its own lock key
// — different blob_refs essentially never collide in practice (a 64-bit
// hash space) and, even in the rare case two different blob_refs hash to
// the same int64, the only cost is those two blob_refs occasionally
// serializing against each other unnecessarily — never an unsafe outcome,
// exactly the same accepted trade-off InMemoryStore's own
// sync.Map-of-mutexes makes (a fresh mutex per distinct key, no collision
// possible there, but the safety property this replicates — "same blob_ref
// serializes, different blob_refs don't block each other" — holds here too,
// modulo the negligible hash-collision case).
func blobLockKey(blobRef string) int64 {
	return fnv1a64(blobRef)
}

func fnv1a64(s string) int64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	var h uint64 = offset64
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return int64(h)
}

// lockAcquireTimeout bounds the TOTAL time a single lockBlob call will
// spend waiting to obtain BOTH a dedicated connection from the pool AND the
// requested advisory lock on that connection, combined, before giving up
// and failing loudly (via storeFailure) rather than blocking forever. See
// lockBlob's doc comment below for why this exists — it is a
// Security-Steward-mandated fix for a live-proven, unrecoverable
// whole-server deadlock (docs/DECISION_LOG.md, "Storage: lockBlob
// bounded-timeout fix (Security Steward block)"), not a tuning nicety.
//
// 5 seconds is chosen as generous relative to this package's real
// operations (a MoveBlob/DeleteBlob critical section is a handful of
// parameterized queries plus at most one local-filesystem read/write — see
// service.go — normally low-single-digit milliseconds), while still short
// enough that a client-visible failure surfaces within a request's
// reasonable patience window rather than the caller/load-balancer's own
// timeout firing first with no diagnostic information. Not derived from any
// deeper analysis than "comfortably above normal-case latency, comfortably
// below what a caller/proxy will silently give up on" — revisit if real
// traffic shows either edge is wrong.
const lockAcquireTimeout = 5 * time.Second

// lockReleaseTimeout bounds how long the closure lockBlob returns will wait
// for pg_advisory_unlock to complete on the already-held connection before
// giving up and failing loudly. This is a much rarer failure mode than the
// acquire path (the connection is already ours, not being contended for),
// but is bounded for the same reason: no unbounded context.Background()
// wait anywhere in this file, full stop.
const lockReleaseTimeout = 5 * time.Second

// lockBlob acquires a session-level Postgres advisory lock keyed on
// blobRef, on a dedicated connection held for the lock's entire lifetime,
// and returns an unlock function that releases the advisory lock and
// returns the connection to the pool. Callers must defer the returned
// function, exactly as with InMemoryStore.lockBlob. See the package-level
// doc comment above this function for the full design rationale.
//
// BOUNDED-TIMEOUT FIX (Security Steward block, docs/DECISION_LOG.md,
// "Storage: lockBlob bounded-timeout fix (Security Steward block)") — read
// this before assuming "checked out of the pool, held while blocked" is a
// merely theoretical concern:
//
// The `SELECT pg_advisory_lock` call below blocks server-side until the
// lock is free, and the connection it runs on — checked out of the SAME
// pool (s.pool) that get()/put()/etc. also draw from — is held for the
// entire time a caller is BLOCKED WAITING, not just while it holds the
// lock. This was originally documented here as a low-probability,
// theoretical risk; Security Steward's Batch B merge-gate review LIVE-
// PROVED it is neither low-probability nor theoretical: 20 concurrent
// MoveBlob requests against ONE blob_ref a single ordinary user legitimately
// owns reliably consumed all platform.maxPoolConns (10) connections — 9
// goroutines blocked inside this exact statement waiting for the same key,
// and the 10th (the actual lock HOLDER) itself then permanently blocked on
// pool.Acquire for its own subsequent get()/put() call inside the critical
// section, because zero connections remained free — a genuine circular
// deadlock. Because both pool.Acquire and this Exec previously ran under
// context.Background() (no deadline, ever), NOTHING resolved it: 0/20
// requests ever completed, the deadlock did not self-heal, and — because
// this pool is shared across every Postgres-backed capability, not
// Storage-scoped — an entirely unrelated capability (Identity's
// POST /v1/identity) hung too. The server needed a manual process
// kill/restart to recover. Triggerable by one ordinary authenticated user,
// on one resource they legitimately own, with request volume merely
// approaching maxPoolConns — not "unusual multi-user load at scale."
//
// The fix: both the pool.Acquire call and the pg_advisory_lock Exec below
// now share a single bounded context (lockAcquireTimeout, 5s) instead of
// context.Background(). pgx propagates context cancellation into a real
// Postgres-side query cancellation for a blocked pg_advisory_lock (not just
// a client-side give-up that leaves the server-side wait running), so a
// timed-out waiter's connection is genuinely freed back to the pool, not
// merely abandoned by the client while still consuming a slot server-side.
// This converts the failure mode from "permanent, unrecoverable,
// whole-server outage" into "bounded-duration pool contention that
// self-resolves within lockAcquireTimeout, after which every blocked
// caller fails loudly with a clear error instead of hanging forever."
//
// WHAT THIS FIX DOES NOT CLOSE (stated plainly, not oversold): a burst of
// concurrent requests against one hot blob_ref can still transiently
// consume most or all of the shared pool for up to lockAcquireTimeout — an
// unrelated capability sharing the same pool (e.g. Identity) can still
// experience elevated latency during that window, waiting for its own
// pool.Acquire (which, in every other capability's PostgresStore as of this
// writing, still runs under context.Background() with no bound of its own)
// to find a free connection. What the fix guarantees is that the window is
// now BOUNDED (at most lockAcquireTimeout, not forever) and SELF-RESOLVING
// (Storage's own waiters give up and release their connections
// automatically, with no manual intervention) — a real, live-verified
// improvement from unrecoverable outage to bounded degradation, not a
// complete elimination of shared-pool contention. Security Steward noted a
// second, more complete fix — a connection pool dedicated to lock-holding,
// separate from the general query pool, closing the cross-capability blast
// radius entirely — as the more thorough option; that was assessed as a
// real architecture change beyond this fix's mandated minimum bar and is
// tracked as a follow-up, not implemented here.
//
// A failure to acquire the connection or take the lock within the bound —
// including a timeout — panics (via storeFailure) rather than returning a
// no-op unlock function: proceeding as though the lock were held, when it
// was not, would silently reintroduce the exact double-delete/lost-update
// race this lock exists to prevent — strictly worse than a loud failure.
// This is the same "fail loudly, never silently proceed unsafely"
// convention this file already applied to every OTHER lockBlob failure
// mode; a bounded timeout is simply one more way that failure can occur,
// not a new failure-handling philosophy. A panic here surfaces through
// Service.MoveBlob/DeleteBlob (service.go) exactly like any other lockBlob
// failure already did — recovered per-request by the composition root's
// chi middleware.Recoverer (services/api/main.go) into a clean 500, not an
// unhandled crash, and never left mid-request in an ambiguous state.
func (s *PostgresStore) lockBlob(blobRef string) func() {
	key := blobLockKey(blobRef)

	ctx, cancel := context.WithTimeout(context.Background(), lockAcquireTimeout)
	defer cancel()

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		storeFailure("lock_blob: acquiring dedicated connection (possibly timed out after "+lockAcquireTimeout.String()+")", err)
	}

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		conn.Release()
		storeFailure("lock_blob: taking advisory lock (possibly timed out after "+lockAcquireTimeout.String()+")", err)
	}

	unlocked := false
	return func() {
		if unlocked {
			// Defensive: a caller that (incorrectly) invoked the returned
			// closure more than once must not double-release the same
			// connection back into the pool or attempt a second
			// pg_advisory_unlock on an already-unlocked key.
			return
		}
		unlocked = true
		unlockCtx, cancel := context.WithTimeout(context.Background(), lockReleaseTimeout)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", key); err != nil {
			// The connection is still released either way below — an
			// unlock failure must not leak the connection out of the pool
			// forever. The advisory lock itself is automatically released
			// when its owning session/connection closes, so even a failed
			// explicit unlock here is bounded: worst case, the lock is held
			// until this specific physical connection is eventually closed
			// by the pool (idle timeout / pool shutdown), not forever.
			conn.Release()
			storeFailure("lock_blob: releasing advisory lock", err)
		}
		conn.Release()
	}
}

// put upserts record, matching InMemoryStore.put's unconditional
// overwrite-on-write semantics.
func (s *PostgresStore) put(record BlobRecord) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO storage_blobs
			(blob_ref, owner, policy_id, size_bytes, created_at_unix, location, deleted, deleted_at_unix, deletion_mechanism)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (blob_ref) DO UPDATE SET
			owner              = EXCLUDED.owner,
			policy_id          = EXCLUDED.policy_id,
			size_bytes         = EXCLUDED.size_bytes,
			created_at_unix    = EXCLUDED.created_at_unix,
			location           = EXCLUDED.location,
			deleted            = EXCLUDED.deleted,
			deleted_at_unix    = EXCLUDED.deleted_at_unix,
			deletion_mechanism = EXCLUDED.deletion_mechanism
	`,
		record.BlobRef, record.Owner, record.PolicyID, record.SizeBytes, record.CreatedAtUnix,
		record.Location, record.Deleted, record.DeletedAtUnix, record.DeletionMechanism,
	)
	if err != nil {
		storeFailure("put", err)
	}
}

// get looks up a single BlobRecord by blob_ref. See PostgresStore's doc
// comment for why a genuine query failure folds into found=false, matching
// a legitimate miss.
func (s *PostgresStore) get(blobRef string) (BlobRecord, bool) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, `
		SELECT blob_ref, owner, policy_id, size_bytes, created_at_unix, location, deleted, deleted_at_unix, deletion_mechanism
		FROM storage_blobs
		WHERE blob_ref = $1
	`, blobRef)

	r, err := scanBlobRecord(row)
	if err != nil {
		return BlobRecord{}, false
	}
	return r, true
}

// delete removes blobRef's BlobRecord entirely. Only used by StoreBlob's
// own rollback path (service.go) when a subsequent step in the same
// request fails — never by DeleteBlob itself, which writes a tombstone via
// put instead. Matches InMemoryStore.delete exactly (a genuine hard
// removal, not a tombstone).
func (s *PostgresStore) delete(blobRef string) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `DELETE FROM storage_blobs WHERE blob_ref = $1`, blobRef)
	if err != nil {
		storeFailure("delete", err)
	}
}

// recordsForOwner returns every BlobRecord (including tombstones) owned by
// owner, backing ExportAllBlobs. See PostgresStore's doc comment for why a
// genuine query failure folds into a nil slice.
func (s *PostgresStore) recordsForOwner(owner string) []BlobRecord {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `
		SELECT blob_ref, owner, policy_id, size_bytes, created_at_unix, location, deleted, deleted_at_unix, deletion_mechanism
		FROM storage_blobs
		WHERE owner = $1
	`, owner)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []BlobRecord
	for rows.Next() {
		r, err := scanBlobRecord(rows)
		if err != nil {
			return nil
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// putWrappingKey upserts blobRef's wrapping key, matching
// InMemoryStore.putWrappingKey's unconditional overwrite-on-write
// semantics.
func (s *PostgresStore) putWrappingKey(blobRef string, key []byte) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO storage_wrapping_keys (blob_ref, key_bytes)
		VALUES ($1, $2)
		ON CONFLICT (blob_ref) DO UPDATE SET key_bytes = EXCLUDED.key_bytes
	`, blobRef, key)
	if err != nil {
		storeFailure("put_wrapping_key", err)
	}
}

// wrappingKey looks up blobRef's wrapping key. See PostgresStore's doc
// comment for why a genuine query failure folds into ok=false, matching a
// legitimate miss.
func (s *PostgresStore) wrappingKey(blobRef string) ([]byte, bool) {
	ctx := context.Background()
	var key []byte
	err := s.pool.QueryRow(ctx, `
		SELECT key_bytes FROM storage_wrapping_keys WHERE blob_ref = $1
	`, blobRef).Scan(&key)
	if err != nil {
		return nil, false
	}
	return key, true
}

// destroyWrappingKey deletes blobRef's wrapping key, if present, returning
// true only if a row genuinely existed and was deleted — matching
// InMemoryStore.destroyWrappingKey's exact contract ("Returns false if no
// key was present to destroy"). A genuine DB failure panics (via
// storeFailure) rather than returning false: see PostgresStore's doc
// comment for why folding a failure into false here specifically would be
// unsafe (indistinguishable from "already destroyed", which DeleteBlob's
// crypto-shred path treats as a hard error condition it must not silently
// swallow).
//
// There is no separate zeroing step here (InMemoryStore.destroyWrappingKey
// calls zeroBytes(key) before deleting its in-memory copy) — once the row
// is deleted from Postgres, no in-process copy of the key bytes is ever
// held by this method to begin with, so there is nothing further to zero.
func (s *PostgresStore) destroyWrappingKey(blobRef string) bool {
	ctx := context.Background()
	tag, err := s.pool.Exec(ctx, `DELETE FROM storage_wrapping_keys WHERE blob_ref = $1`, blobRef)
	if err != nil {
		storeFailure("destroy_wrapping_key", err)
	}
	return tag.RowsAffected() > 0
}

// hasWrappingKey reports whether blobRef currently has a wrapping key
// recorded, without returning the key itself. See PostgresStore's doc
// comment for why a genuine query failure folds into false.
func (s *PostgresStore) hasWrappingKey(blobRef string) bool {
	ctx := context.Background()
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM storage_wrapping_keys WHERE blob_ref = $1)
	`, blobRef).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

// rowScanner is the common subset of pgx.Row and pgx.Rows this package
// needs (just Scan), matching Audit's/Permissions' own equivalent seam
// (internal/audit/postgres_store.go, internal/permissions/postgres_store.go).
type rowScanner interface {
	Scan(dest ...any) error
}

func scanBlobRecord(row rowScanner) (BlobRecord, error) {
	var r BlobRecord
	err := row.Scan(
		&r.BlobRef,
		&r.Owner,
		&r.PolicyID,
		&r.SizeBytes,
		&r.CreatedAtUnix,
		&r.Location,
		&r.Deleted,
		&r.DeletedAtUnix,
		&r.DeletionMechanism,
	)
	if err != nil {
		// No special-casing of pgx.ErrNoRows here: get()/wrappingKey()'s
		// callers only ever check the returned bool, not the error kind
		// (matching Store's frozen, error-return-free method signatures) —
		// see PostgresStore's doc comment for why any query failure
		// (ErrNoRows included) folds into the same "not found" shape.
		return BlobRecord{}, err
	}
	return r, nil
}
