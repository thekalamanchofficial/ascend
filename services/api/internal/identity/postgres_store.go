package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgUniqueViolation is the Postgres error code for a unique-constraint
// violation (23505) — https://www.postgresql.org/docs/current/errcodes-appendix.html.
// Used to distinguish "this identity_ref already exists" (ErrInvalidArgument,
// matching InMemoryStore.Create's exact behavior) from any other, genuine
// insert failure (a dropped connection, a constraint this schema doesn't
// even have yet, etc.), which is propagated as a real wrapped error instead
// of being folded into a sentinel.
const pgUniqueViolation = "23505"

// PostgresStore is a Postgres-backed implementation of Store, persisting
// IdentityRecord rows into the identities table (see
// internal/platform/migrations/0002_identities.up.sql). It replicates
// InMemoryStore's observable behavior exactly (error shapes for duplicate
// Create / missing Get / missing Replace) — Service (service.go) is written
// against the Store interface and does not know or care which
// implementation actually backs it.
//
// Devices are stored as a single JSONB array column, not a separate
// relational table: Replace overwrites the entire record (including
// devices) atomically in the current in-memory design, and nothing
// anywhere queries "list all devices across all identities" as a
// cross-cutting operation, so a JSONB column faithfully preserves existing
// semantics with the least complexity (Art. 12/13) — see
// docs/DECISION_LOG.md, "Identity: PostgresStore, a real Postgres-backed
// implementation of Store".
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore constructs a PostgresStore against an already-connected
// pool. Callers are responsible for having already run this package's
// migration (0002_identities.up.sql) against the same database — this
// constructor does not run migrations itself (that is platform.New's job,
// at server startup).
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Create inserts a brand-new record. Returns ErrInvalidArgument if
// record.IdentityRef already exists, matching InMemoryStore.Create's exact
// behavior — detected via the unique-constraint violation Postgres itself
// reports on the identity_ref primary key, not a separate pre-check SELECT
// (which would be race-prone between two concurrent Creates of the same
// ref). Any other insert failure is a genuine, wrapped error.
func (s *PostgresStore) Create(record IdentityRecord) error {
	ctx := context.Background()

	devicesJSON, err := json.Marshal(record.Devices)
	if err != nil {
		return fmt.Errorf("identity: postgres create: marshaling devices: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO identities
			(identity_ref, display_name, public_key, created_at_unix, epoch, devices)
		VALUES
			($1, $2, $3, $4, $5, $6)
	`,
		record.IdentityRef,
		record.DisplayName,
		record.PublicKey,
		record.CreatedAtUnix,
		record.Epoch,
		devicesJSON,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return ErrInvalidArgument
		}
		return fmt.Errorf("identity: postgres create: inserting record: %w", err)
	}
	return nil
}

// Get returns the record for identityRef, or ErrIdentityNotFound. Any other
// query failure is a genuine, wrapped error.
func (s *PostgresStore) Get(identityRef string) (IdentityRecord, error) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, `
		SELECT identity_ref, display_name, public_key, created_at_unix, epoch, devices
		FROM identities
		WHERE identity_ref = $1
	`, identityRef)

	rec, err := scanIdentityRecord(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return IdentityRecord{}, ErrIdentityNotFound
		}
		return IdentityRecord{}, fmt.Errorf("identity: postgres get: %w", err)
	}
	return rec, nil
}

// Replace overwrites the stored record for record.IdentityRef in place
// (used after appending/removing a device). Returns ErrIdentityNotFound if
// no record exists yet for that ref, matching InMemoryStore.Replace's exact
// behavior — detected via RowsAffected() rather than a separate existence
// check, avoiding a check-then-act race between two concurrent Replace
// calls for the same ref.
func (s *PostgresStore) Replace(record IdentityRecord) error {
	ctx := context.Background()

	devicesJSON, err := json.Marshal(record.Devices)
	if err != nil {
		return fmt.Errorf("identity: postgres replace: marshaling devices: %w", err)
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE identities
		SET display_name = $2,
		    public_key = $3,
		    created_at_unix = $4,
		    epoch = $5,
		    devices = $6
		WHERE identity_ref = $1
	`,
		record.IdentityRef,
		record.DisplayName,
		record.PublicKey,
		record.CreatedAtUnix,
		record.Epoch,
		devicesJSON,
	)
	if err != nil {
		return fmt.Errorf("identity: postgres replace: updating record: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrIdentityNotFound
	}
	return nil
}

// rowScanner is the common subset of pgx.Row this package needs (just
// Scan), matching the audit package's own equivalent seam
// (internal/audit/postgres_store.go) — kept here even though only Get uses
// it today, so a future multi-row read (should one ever be added) can share
// scanIdentityRecord without duplicating the column list.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanIdentityRecord(row rowScanner) (IdentityRecord, error) {
	var (
		rec         IdentityRecord
		devicesJSON []byte
	)
	err := row.Scan(
		&rec.IdentityRef,
		&rec.DisplayName,
		&rec.PublicKey,
		&rec.CreatedAtUnix,
		&rec.Epoch,
		&devicesJSON,
	)
	if err != nil {
		return IdentityRecord{}, err
	}
	rec.Devices = make([]Device, 0)
	if len(devicesJSON) > 0 {
		if err := json.Unmarshal(devicesJSON, &rec.Devices); err != nil {
			return IdentityRecord{}, fmt.Errorf("unmarshaling devices: %w", err)
		}
	}
	return rec, nil
}
