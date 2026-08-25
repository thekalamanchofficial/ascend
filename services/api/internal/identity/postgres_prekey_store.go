package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// claimQueryTimeout bounds every query this file issues, including the
// single-statement atomic claim (ClaimOneOneTimePrekey). Charter §6/§7
// requires "whatever row-level or advisory lock the atomic claim above
// uses must be bounded by a timeout, never held indefinitely" — citing
// Storage's lockBlob incident (services/api/internal/storage/postgres_store.go)
// by name as the precedent this exists to prevent recurring.
//
// Stated plainly, because it matters for understanding why this
// implementation is NOT simply "the same fix lockBlob needed, applied
// here too": lockBlob's incident was a session-level advisory lock that
// could BLOCK WAITING on another connection indefinitely, exhausting the
// shared pool while every waiter sat parked inside a blocking call.
// ClaimOneOneTimePrekey below cannot reproduce that failure mode by
// construction — it is ONE statement (`DELETE ... WHERE prekey_id = (SELECT
// ... FOR UPDATE SKIP LOCKED LIMIT 1) ... RETURNING`), not a multi-call
// sequence wrapped in an acquired-and-held lock, and SKIP LOCKED means the
// inner SELECT never blocks waiting for a row another transaction is
// currently holding — it simply skips that row and looks for the next
// available one, so two concurrent claims against a device with a single
// remaining prekey resolve immediately: one gets it, the other correctly
// sees no rows available. This context timeout is real defense-in-depth
// against a slow/hung connection or network partition, not a mitigation
// for a lock-wait hazard that this construction doesn't have in the first
// place — see this file's package doc comment below for the full
// reasoning, since charter §7 requires that reasoning to be explicit, not
// assumed.
const claimQueryTimeout = 5 * time.Second

// PostgresPrekeyStore is a Postgres-backed implementation of PrekeyStore,
// persisting into the identity_signed_prekeys / identity_one_time_prekeys
// tables (internal/platform/migrations/0009_identity_prekeys.up.sql).
//
// # Why this is not lockBlob, restated at the file level (charter §7's
// explicit "must not be assumed to fall out of reusing existing
// middleware/patterns" instruction, applied here to the SQL construction
// itself, not just the HTTP-layer caller-binding)
//
// Storage's lockBlob (internal/storage/postgres_store.go) exists to
// serialize a MULTI-STATEMENT, non-transactional sequence spanning
// several separate Store calls (MoveBlob/DeleteBlob's full method
// bodies) — there is no single SQL statement that could express what it
// protects, so it reaches for a session-level advisory lock held across
// that whole sequence. ClaimOneOneTimePrekey below has no such multi-call
// sequence to protect: "find an available prekey and remove it" is
// expressible, and is expressed, as exactly one SQL statement. Postgres
// itself wraps any single statement in an implicit transaction — no
// explicit pool.Begin/Commit is needed or used here, and there is
// therefore no separate "acquire a lock, do other work, release the
// lock" window for a bug to reopen the check-then-act race this
// capability's charter exists to close. This is the single most
// load-bearing design decision in this file — see
// docs/DECISION_LOG.md's entry for this amendment's implementation for
// why it was chosen over any lock-based alternative.
type PostgresPrekeyStore struct {
	pool *pgxpool.Pool
}

func NewPostgresPrekeyStore(pool *pgxpool.Pool) *PostgresPrekeyStore {
	return &PostgresPrekeyStore{pool: pool}
}

// PublishBundle upserts the device's signed prekey (rotation, keyed on the
// (identity_ref, device_id) primary key) and additively inserts oneTime,
// all inside one transaction — not required by charter §6's atomicity
// language (which is specifically about the CLAIM operation), but a
// reasonable, low-cost choice here too: a publish call that half-applies
// (new signed prekey stored, one_time_prekeys insert fails, or vice
// versa) would leave a device's bundle in a state neither the old nor the
// new caller intended, purely as an implementation-quality choice, logged
// in docs/DECISION_LOG.md as non-charter-mandated but sensible.
//
// Duplicate prekey_id handling: `ON CONFLICT (prekey_id) DO NOTHING`
// treats a re-published prekey_id as an idempotent no-op, not an error —
// Cryptography & Keys' own charter generates these as fresh random
// identifiers per bundle, so a genuine collision should never happen in
// practice; this choice exists to make a client's safe retry-after-
// uncertain-network-response idempotent rather than to paper over a real
// application bug. publishedCount reflects only rows genuinely newly
// inserted (via CommandTag.RowsAffected(), not len(oneTime)), so a caller
// can tell a retried, already-applied publish apart from a fresh one.
func (s *PostgresPrekeyStore) PublishBundle(identityRef, deviceID string, signedPrekey SignedPrekey, identityDhPublicKey, identityDhPublicKeySignature []byte, oneTime []OneTimePrekeyPublic) (int32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), claimQueryTimeout)
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("identity: publish prekey bundle: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit succeeds

	// identity_dh_public_key/identity_dh_public_key_signature (added
	// 2026-08-21, key-separation fix — 0010_identity_prekeys_dh_key.up.sql)
	// are stable, non-rotating per-device values but are upserted alongside
	// the rotatable signed-prekey fields on EVERY call regardless — this
	// package has no way to derive them independently (identity.proto's
	// own comment on PublishPrekeyBundleRequest field 5).
	if _, err := tx.Exec(ctx, `
		INSERT INTO identity_signed_prekeys
			(identity_ref, device_id, prekey_id, public_key, signature, created_at_unix,
			 identity_dh_public_key, identity_dh_public_key_signature)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (identity_ref, device_id) DO UPDATE SET
			prekey_id                        = EXCLUDED.prekey_id,
			public_key                       = EXCLUDED.public_key,
			signature                        = EXCLUDED.signature,
			created_at_unix                  = EXCLUDED.created_at_unix,
			identity_dh_public_key           = EXCLUDED.identity_dh_public_key,
			identity_dh_public_key_signature = EXCLUDED.identity_dh_public_key_signature
	`,
		identityRef, deviceID,
		signedPrekey.PrekeyID, signedPrekey.PublicKey, signedPrekey.Signature, signedPrekey.CreatedAtUnix,
		identityDhPublicKey, identityDhPublicKeySignature,
	); err != nil {
		return 0, fmt.Errorf("identity: publish prekey bundle: upsert signed prekey: %w", err)
	}

	var published int32
	for _, otp := range oneTime {
		tag, err := tx.Exec(ctx, `
			INSERT INTO identity_one_time_prekeys (prekey_id, identity_ref, device_id, public_key)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (prekey_id) DO NOTHING
		`, otp.PrekeyID, identityRef, deviceID, otp.PublicKey)
		if err != nil {
			return 0, fmt.Errorf("identity: publish prekey bundle: insert one-time prekey %q: %w", otp.PrekeyID, err)
		}
		published += int32(tag.RowsAffected())
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("identity: publish prekey bundle: commit: %w", err)
	}
	return published, nil
}

// GetSignedPrekey returns found=false (not an error) when no row exists —
// the brand-new-identity edge case (charter §3/§7), a legitimate state,
// not a failure. Also returns found=false, fail-closed (charter §3/§6), if
// either identity_dh_public_key or identity_dh_public_key_signature comes
// back empty — defense-in-depth beyond the NOT NULL constraint
// (0010_identity_prekeys_dh_key.up.sql's own doc comment on why the schema
// alone cannot produce this state today, but this check does not assume
// that invariant holds forever).
func (s *PostgresPrekeyStore) GetSignedPrekey(identityRef, deviceID string) (SignedPrekey, []byte, []byte, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), claimQueryTimeout)
	defer cancel()

	var prekey SignedPrekey
	var identityDhPublicKey, identityDhPublicKeySignature []byte
	err := s.pool.QueryRow(ctx, `
		SELECT prekey_id, public_key, signature, created_at_unix,
		       identity_dh_public_key, identity_dh_public_key_signature
		FROM identity_signed_prekeys
		WHERE identity_ref = $1 AND device_id = $2
	`, identityRef, deviceID).Scan(
		&prekey.PrekeyID, &prekey.PublicKey, &prekey.Signature, &prekey.CreatedAtUnix,
		&identityDhPublicKey, &identityDhPublicKeySignature,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SignedPrekey{}, nil, nil, false, nil
		}
		return SignedPrekey{}, nil, nil, false, fmt.Errorf("identity: get signed prekey: %w", err)
	}
	if len(identityDhPublicKey) == 0 || len(identityDhPublicKeySignature) == 0 {
		return SignedPrekey{}, nil, nil, false, nil
	}
	return prekey, identityDhPublicKey, identityDhPublicKeySignature, true, nil
}

// ClaimOneOneTimePrekey is the single most load-bearing method in this
// file — see this file's package-level doc comment for why its shape
// (one statement, no explicit lock) is what charter §6/§7 actually
// requires, not merely one acceptable option among several.
//
// The WHERE clause's subquery does the real work: `SELECT prekey_id ...
// FOR UPDATE SKIP LOCKED LIMIT 1` takes a row-level lock on (at most) one
// candidate row and, critically, SKIPS any row a concurrent transaction
// has already locked rather than blocking on it — so two simultaneous
// calls against a device with exactly one remaining prekey never both
// wait for the same row; whichever transaction's subquery runs first
// locks and returns that row, the second transaction's subquery finds no
// unlocked rows to skip to and returns zero, correctly producing
// found=false rather than either blocking or double-issuing the same
// prekey_id. The outer DELETE then removes the exact row the subquery
// selected in the same statement — permanently, satisfying Art. 8's
// anti-retention requirement (no "consumed" marker is ever written,
// matching charter §4's explicit correction of an earlier draft that
// would have retained one).
func (s *PostgresPrekeyStore) ClaimOneOneTimePrekey(identityRef, deviceID string) (OneTimePrekeyPublic, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), claimQueryTimeout)
	defer cancel()

	var claimed OneTimePrekeyPublic
	err := s.pool.QueryRow(ctx, `
		DELETE FROM identity_one_time_prekeys
		WHERE prekey_id = (
			SELECT prekey_id FROM identity_one_time_prekeys
			WHERE identity_ref = $1 AND device_id = $2
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		RETURNING prekey_id, public_key
	`, identityRef, deviceID).Scan(&claimed.PrekeyID, &claimed.PublicKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OneTimePrekeyPublic{}, false, nil // exhaustion-fallback case, charter §3 — not an error
		}
		return OneTimePrekeyPublic{}, false, fmt.Errorf("identity: claim one-time prekey (possibly timed out after "+claimQueryTimeout.String()+"): %w", err)
	}
	return claimed, true, nil
}

// CountUnconsumedOneTimePrekeys backs ListDevices'
// unconsumed_one_time_prekey_count (charter §4 — a derived count computed
// fresh on every read, never itself persisted).
func (s *PostgresPrekeyStore) CountUnconsumedOneTimePrekeys(identityRef, deviceID string) (int32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), claimQueryTimeout)
	defer cancel()

	var count int32
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM identity_one_time_prekeys
		WHERE identity_ref = $1 AND device_id = $2
	`, identityRef, deviceID).Scan(&count); err != nil {
		return 0, fmt.Errorf("identity: count unconsumed one-time prekeys: %w", err)
	}
	return count, nil
}
