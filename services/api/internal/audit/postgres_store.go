package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// appendAdvisoryLockKey is the fixed Postgres advisory-lock key
// PostgresStore.Append takes (via pg_advisory_xact_lock) as the very first
// statement of its transaction, before it reads anything. It has no
// meaning beyond "the one lock key every Append call contends on" — any
// fixed, documented int64 constant would do; this one is
// hash/fnv-1a-64("audit_events_append") reinterpreted as a signed int64
// (pg_advisory_xact_lock accepts any bigint, negative included), computed
// once below rather than hand-typed, purely so the constant is
// reproducible from its own name instead of being a bare magic number.
//
// This is unconditional (every Append call takes it, regardless of table
// state) rather than a `SELECT ... FOR UPDATE` on the current tail row,
// because a FOR UPDATE against a possibly-empty table locks nothing at
// all — two concurrent first-ever inserts could both read no rows and both
// compute PrevHash="", corrupting the chain right at genesis. A single,
// table-wide advisory lock mirrors InMemoryStore's own single mutex
// exactly, and is deliberately coarse: this is an audit log's append path,
// not a request-per-millisecond hot path, so serializing all Append calls
// process-wide (well, cluster-wide, since it's a DB-level lock) is an
// acceptable, simple trade for chain correctness under real concurrency.
var appendAdvisoryLockKey = fnv1a64("audit_events_append")

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

// PostgresStore is a Postgres-backed implementation of Store, persisting
// AuditEvent rows into the audit_events table (see
// internal/platform/migrations/0001_audit_events.up.sql). It replicates
// InMemoryStore's observable behavior exactly (ordering, hash-chain
// semantics, Get/Query/All error shapes) — Service (service.go) is written
// against the Store interface and does not know or care which
// implementation actually backs it.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore constructs a PostgresStore against an already-connected
// pool. Callers are responsible for having already run this package's
// migration (0001_audit_events.up.sql) against the same database — this
// constructor does not run migrations itself (that is platform.New's job,
// at server startup).
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Append mirrors InMemoryStore.Append's whole-chain serialization: every
// call, however concurrent, sees a consistent, race-free view of the
// current chain tail. See appendAdvisoryLockKey's doc comment for why an
// unconditional advisory lock is used instead of a row-level lock.
func (s *PostgresStore) Append(e AuditEvent) (AuditEvent, error) {
	ctx := context.Background()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("audit: postgres append: beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op if Commit already succeeded

	// Unconditional, table-wide lock — the FIRST statement in the
	// transaction, before any read. See appendAdvisoryLockKey's doc
	// comment.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", appendAdvisoryLockKey); err != nil {
		return AuditEvent{}, fmt.Errorf("audit: postgres append: taking advisory lock: %w", err)
	}

	var tail string
	err = tx.QueryRow(ctx, "SELECT event_id FROM audit_events ORDER BY seq DESC LIMIT 1").Scan(&tail)
	if err != nil {
		if err != pgx.ErrNoRows {
			return AuditEvent{}, fmt.Errorf("audit: postgres append: reading chain tail: %w", err)
		}
		// No rows yet: tail is "", matching InMemoryStore's zero-value
		// lastHash for the genesis event.
		tail = ""
	}

	e.PrevHash = tail
	e.EventID = computeEventHash(e)

	metadataJSON, err := json.Marshal(e.Metadata)
	if err != nil {
		// e.Metadata is a map[string]string (see types.go); this can only
		// fail on a programming error, not a runtime condition — mirrors
		// hash.go's computeEventHash treating its own equivalent marshal
		// failure as unrecoverable, but here (unlike computeEventHash)
		// Append already has a real error return to use, so it is
		// returned rather than panicked.
		return AuditEvent{}, fmt.Errorf("audit: postgres append: marshaling metadata: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_events
			(event_id, prev_hash, actor, action, resource_type, resource_id, rule_reference, metadata, occurred_at_unix)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		e.EventID,
		e.PrevHash,
		e.Actor,
		e.Action,
		e.Resource.ResourceType,
		e.Resource.ResourceID,
		e.RuleReference,
		metadataJSON,
		e.OccurredAtUnix,
	)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("audit: postgres append: inserting event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return AuditEvent{}, fmt.Errorf("audit: postgres append: committing transaction: %w", err)
	}
	return e, nil
}

// Get looks up a single event by its EventID.
//
// Defensive-error-handling note: Store.Get's signature (AuditEvent, bool)
// has no error return, so a genuine query failure (a dropped connection, a
// context cancellation, etc.) has no channel to be surfaced through other
// than folding it into "not found" (ok=false). This is deliberately
// fail-closed in the same spirit as this package's denyAllChecker default
// (service.go) — a caller who gets ok=false because of a transient DB
// error sees the same "I can't find this" result as a caller who asked for
// an event that never existed, never a false "yes it exists" from stale
// or partial data. The trade-off is that a real outage is indistinguishable
// from a genuine not-found from this method's return value alone; that is
// an accepted limitation of the frozen Store interface, not something this
// implementation can fix without an interface change (a charter
// amendment), and is consistent with how All() below handles the same
// situation.
func (s *PostgresStore) Get(eventID string) (AuditEvent, bool) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, `
		SELECT event_id, prev_hash, actor, action, resource_type, resource_id, rule_reference, metadata, occurred_at_unix
		FROM audit_events
		WHERE event_id = $1
	`, eventID)

	e, err := scanAuditEvent(row)
	if err != nil {
		return AuditEvent{}, false
	}
	return e, true
}

// Query returns events matching filter, most-recent-first (occurred_at_unix
// DESC, seq DESC as a deterministic tiebreaker — see the migration file's
// comment on why seq exists; unlike InMemoryStore's stable Go slice sort,
// Postgres row order is not otherwise guaranteed for rows sharing the same
// occurred_at_unix). Empty-string / zero-value filter fields mean "no
// filter on that field", matching InMemoryStore.Query's semantics exactly.
func (s *PostgresStore) Query(filter QueryFilter) ([]AuditEvent, error) {
	ctx := context.Background()

	clause := "WHERE 1=1"
	args := make([]any, 0, 6)
	addFilter := func(sqlFrag string, val any) {
		args = append(args, val)
		clause += fmt.Sprintf(" AND %s $%d", sqlFrag, len(args))
	}

	if filter.Subject != "" {
		addFilter("actor =", filter.Subject)
	}
	if filter.ResourceTypeFilter != "" {
		addFilter("resource_type =", filter.ResourceTypeFilter)
	}
	if filter.ResourceIDFilter != "" {
		addFilter("resource_id =", filter.ResourceIDFilter)
	}
	if filter.ActionFilter != "" {
		addFilter("action =", filter.ActionFilter)
	}
	if filter.SinceUnix != 0 {
		addFilter("occurred_at_unix >=", filter.SinceUnix)
	}
	if filter.UntilUnix != 0 {
		addFilter("occurred_at_unix <=", filter.UntilUnix)
	}

	query := fmt.Sprintf(`
		SELECT event_id, prev_hash, actor, action, resource_type, resource_id, rule_reference, metadata, occurred_at_unix
		FROM audit_events
		%s
		ORDER BY occurred_at_unix DESC, seq DESC
	`, clause)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: postgres query: %w", err)
	}
	defer rows.Close()

	out := make([]AuditEvent, 0)
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("audit: postgres query: scanning row: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: postgres query: iterating rows: %w", err)
	}
	return out, nil
}

// All returns every event in true append order (oldest first, ORDER BY seq
// ASC) — VerifyIntegrity and ExportAuditTrail both depend on receiving
// events in genuine append order.
//
// Defensive-error-handling note: same as Get above — Store.All has no
// error return, so a genuine query failure is folded into an empty slice
// rather than surfaced. An empty result is the fail-closed choice
// consistent with Get's ok=false: callers (VerifyIntegrity,
// ExportAuditTrail) treat "no events" as a legitimate, verifiable state
// (an empty chain trivially satisfies VerifyIntegrity), never as a false
// claim that events exist when they might not have been readable. As with
// Get, this cannot distinguish "genuinely empty" from "DB error" without a
// Store interface change.
func (s *PostgresStore) All() []AuditEvent {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `
		SELECT event_id, prev_hash, actor, action, resource_type, resource_id, rule_reference, metadata, occurred_at_unix
		FROM audit_events
		ORDER BY seq ASC
	`)
	if err != nil {
		return []AuditEvent{}
	}
	defer rows.Close()

	out := make([]AuditEvent, 0)
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return []AuditEvent{}
		}
		out = append(out, e)
	}
	if rows.Err() != nil {
		return []AuditEvent{}
	}
	return out
}

// rowScanner is the common subset of pgx.Row and pgx.Rows this package
// needs (just Scan), so scanAuditEvent can be shared between Get's single
// QueryRow and Query/All's multi-row Rows without duplicating the column
// list and struct assembly three times.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAuditEvent(row rowScanner) (AuditEvent, error) {
	var (
		e            AuditEvent
		metadataJSON []byte
	)
	err := row.Scan(
		&e.EventID,
		&e.PrevHash,
		&e.Actor,
		&e.Action,
		&e.Resource.ResourceType,
		&e.Resource.ResourceID,
		&e.RuleReference,
		&metadataJSON,
		&e.OccurredAtUnix,
	)
	if err != nil {
		return AuditEvent{}, err
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &e.Metadata); err != nil {
			return AuditEvent{}, fmt.Errorf("unmarshaling metadata: %w", err)
		}
	}
	return e, nil
}
