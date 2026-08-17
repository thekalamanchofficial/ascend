package fileobjects

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is a Postgres-backed implementation of Store, persisting
// FileObjectRecord/VersionRecord/FileEvent rows into the
// fileobjects_records, fileobjects_versions, and fileobjects_events tables
// (see internal/platform/migrations/0005_fileobjects.up.sql). It replicates
// InMemoryStore's observable behavior exactly (creation-order version
// listing, emission-order event listing, deleteFileObjectRecord's atomic
// three-table teardown) — Service (service.go) is written against the Store
// interface and does not know or care which implementation actually backs
// it.
//
// NewPostgresStore constructs a PostgresStore against an already-connected
// pool. Callers are responsible for having already run this package's
// migration (0005_fileobjects.up.sql) against the same database — this
// constructor does not run migrations itself (that is platform.New's job,
// at server startup).
//
// # Error-handling design decision (read this before touching any method below)
//
// Store's 8 methods (store.go) were introduced in this same change,
// alongside this implementation, but their signatures are fixed by that
// introduction to match InMemoryStore's own pre-existing, error-return-free
// method set exactly, so Service's call sites (service.go) stay textually
// and behaviorally identical. That leaves the same design question Audit's
// and Permissions' own PostgresStore implementations faced: with no
// error-return channel on any of these 8 methods, how does a genuine
// Postgres failure (a dropped connection, a context timeout, etc. — as
// opposed to a legitimate "not found") get handled without silently
// pretending a mutation succeeded, or silently pretending a read came back
// empty when it didn't?
//
// This package's 8 methods split cleanly into the same two groups Audit and
// Permissions used, with NEITHER of Permissions' extra wrinkles applying
// here:
//
//   - getFileObject / getVersion (bool "found" return) and listVersions /
//     eventsForFileObject (slice return) are the four read methods. A
//     genuine query failure folds into the same shape as a legitimate miss
//     — (FileObjectRecord{}, false), (VersionRecord{}, false), or an empty
//     slice — mirroring Audit's Get/All and Permissions' activeGrant/
//     grantsForResource precedent exactly. Every caller in service.go
//     already treats a miss as ErrFileObjectNotFound/ErrVersionNotFound or
//     "nothing to show", never as an implicit allow or an implicit
//     success — unlike Permissions' ownerOf, no method here gates a
//     bootstrap-owner or other privilege-escalation decision on the
//     difference between "genuinely not found" and "DB error", so no
//     special ("", true)-style exception is needed anywhere in this file.
//   - putFileObject / deleteFileObjectRecord / addVersion / addEvent (no
//     return value at all) are the four mutation methods. Silently
//     no-oping on a genuine write failure would let Service proceed to
//     audit-log and report success for a mutation that never reached the
//     database — the same "silent success hazard Art. 5 forbids" Audit's
//     and Permissions' own postgres stores already call out. These four
//     panic on a genuine failure via the shared storeFailure helper below,
//     identical in spirit and mechanism to Permissions'
//     postgres_store.go's storeFailure: a panic inside an HTTP handler
//     goroutine is recovered per-request by Go's own net/http server (logs
//     the stack trace, closes that one connection, never writes a
//     200-with-lies response) — a hard, visible failure, not a soft one.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore constructs a PostgresStore against an already-connected
// pool. See the package-level PostgresStore doc comment for the migration
// this implementation depends on.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// storeFailure panics with a message identifying which void-return
// mutation method failed and why. See PostgresStore's doc comment above for
// the full reasoning.
func storeFailure(op string, err error) {
	panic(fmt.Sprintf("fileobjects: postgres %s: %v", op, err))
}

// putFileObject upserts r into fileobjects_records, keyed by file_object_id
// — matching InMemoryStore.putFileObject's unconditional
// `s.fileObjects[r.FileObjectID] = r` overwrite-in-place semantics.
func (s *PostgresStore) putFileObject(r FileObjectRecord) {
	ctx := context.Background()

	tagsJSON, err := json.Marshal(r.Tags)
	if err != nil {
		// r.Tags is a []string (types.go); this can only fail on a
		// programming error, not a runtime condition.
		storeFailure("put_file_object: marshaling tags", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO fileobjects_records
			(file_object_id, owner, current_version_ref, name, mime_type, tags, size_bytes, created_at_unix, deleted, deleted_at_unix, last_history_event_id)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (file_object_id)
		DO UPDATE SET owner = EXCLUDED.owner,
		              current_version_ref = EXCLUDED.current_version_ref,
		              name = EXCLUDED.name,
		              mime_type = EXCLUDED.mime_type,
		              tags = EXCLUDED.tags,
		              size_bytes = EXCLUDED.size_bytes,
		              created_at_unix = EXCLUDED.created_at_unix,
		              deleted = EXCLUDED.deleted,
		              deleted_at_unix = EXCLUDED.deleted_at_unix,
		              last_history_event_id = EXCLUDED.last_history_event_id
	`,
		r.FileObjectID, r.Owner, r.CurrentVersionRef, r.Name, r.MimeType, tagsJSON, r.SizeBytes,
		r.CreatedAtUnix, r.Deleted, r.DeletedAtUnix, r.LastHistoryEventID,
	)
	if err != nil {
		storeFailure("put_file_object: upserting record", err)
	}
}

// getFileObject looks up id's FileObjectRecord. See PostgresStore's doc
// comment for why a genuine query failure folds into ok=false, matching a
// legitimate miss.
func (s *PostgresStore) getFileObject(id string) (FileObjectRecord, bool) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, `
		SELECT file_object_id, owner, current_version_ref, name, mime_type, tags, size_bytes, created_at_unix, deleted, deleted_at_unix, last_history_event_id
		FROM fileobjects_records
		WHERE file_object_id = $1
	`, id)

	r, err := scanFileObjectRecord(row)
	if err != nil {
		return FileObjectRecord{}, false
	}
	return r, true
}

// deleteFileObjectRecord deletes id's file object AND all its versions AND
// all its events, atomically, in one transaction — matching
// InMemoryStore.deleteFileObjectRecord's single-critical-section teardown
// exactly. This is the one method in this file where a partial failure
// (e.g. the record deleted but versions/events left orphaned) would be a
// real Art. 15 hidden-state hazard; wrapping all three DELETEs in a single
// transaction (committed only if all three succeed) is what prevents that
// — see postgres_store_test.go's atomicity test for the live proof.
func (s *PostgresStore) deleteFileObjectRecord(id string) {
	ctx := context.Background()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		storeFailure("delete_file_object_record: beginning transaction", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op if Commit already succeeded

	if _, err := tx.Exec(ctx, "DELETE FROM fileobjects_events WHERE file_object_id = $1", id); err != nil {
		storeFailure("delete_file_object_record: deleting events", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM fileobjects_versions WHERE file_object_id = $1", id); err != nil {
		storeFailure("delete_file_object_record: deleting versions", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM fileobjects_records WHERE file_object_id = $1", id); err != nil {
		storeFailure("delete_file_object_record: deleting record", err)
	}

	if err := tx.Commit(ctx); err != nil {
		storeFailure("delete_file_object_record: committing transaction", err)
	}
}

// addVersion inserts v as a new row in fileobjects_versions, keyed by its
// own version_ref (never overwritten — CreateVersion never reuses a
// version_ref). seq (BIGSERIAL) records true insertion order for
// listVersions' ORDER BY below.
func (s *PostgresStore) addVersion(fileObjectID string, v VersionRecord) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO fileobjects_versions
			(version_ref, file_object_id, blob_ref, created_at_unix, created_by, size_bytes)
		VALUES
			($1, $2, $3, $4, $5, $6)
	`, v.VersionRef, fileObjectID, v.BlobRef, v.CreatedAtUnix, v.CreatedBy, v.SizeBytes)
	if err != nil {
		storeFailure("add_version", err)
	}
}

// listVersions returns fileObjectID's versions in creation order (ORDER BY
// seq ASC, matching InMemoryStore's append-ordered slice). See
// PostgresStore's doc comment for why a genuine query failure folds into an
// empty slice.
func (s *PostgresStore) listVersions(fileObjectID string) []VersionRecord {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `
		SELECT version_ref, file_object_id, blob_ref, created_at_unix, created_by, size_bytes
		FROM fileobjects_versions
		WHERE file_object_id = $1
		ORDER BY seq ASC
	`, fileObjectID)
	if err != nil {
		return []VersionRecord{}
	}
	defer rows.Close()

	out := make([]VersionRecord, 0)
	for rows.Next() {
		v, err := scanVersionRecord(rows)
		if err != nil {
			return []VersionRecord{}
		}
		out = append(out, v)
	}
	if rows.Err() != nil {
		return []VersionRecord{}
	}
	return out
}

// getVersion looks up a single version by (fileObjectID, versionRef). See
// PostgresStore's doc comment for why a genuine query failure folds into
// ok=false, matching a legitimate miss.
func (s *PostgresStore) getVersion(fileObjectID, versionRef string) (VersionRecord, bool) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, `
		SELECT version_ref, file_object_id, blob_ref, created_at_unix, created_by, size_bytes
		FROM fileobjects_versions
		WHERE file_object_id = $1 AND version_ref = $2
	`, fileObjectID, versionRef)

	v, err := scanVersionRecord(row)
	if err != nil {
		return VersionRecord{}, false
	}
	return v, true
}

// addEvent inserts e as a new row in fileobjects_events, keyed by its own
// event_id. seq (BIGSERIAL) records true insertion (emission) order for
// eventsForFileObject's ORDER BY below.
func (s *PostgresStore) addEvent(fileObjectID string, e FileEvent) {
	ctx := context.Background()

	metadataJSON, err := json.Marshal(e.Metadata)
	if err != nil {
		// e.Metadata is a map[string]string (types.go); this can only fail
		// on a programming error, not a runtime condition.
		storeFailure("add_event: marshaling metadata", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO fileobjects_events
			(event_id, file_object_id, action, actor, occurred_at_unix, metadata)
		VALUES
			($1, $2, $3, $4, $5, $6)
	`, e.EventID, fileObjectID, e.Action, e.Actor, e.OccurredAtUnix, metadataJSON)
	if err != nil {
		storeFailure("add_event", err)
	}
}

// eventsForFileObject returns fileObjectID's own File-Objects-emitted event
// log in emission order (ORDER BY seq ASC, matching InMemoryStore's
// append-ordered slice). See PostgresStore's doc comment for why a genuine
// query failure folds into an empty slice.
func (s *PostgresStore) eventsForFileObject(fileObjectID string) []FileEvent {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `
		SELECT event_id, action, actor, occurred_at_unix, metadata
		FROM fileobjects_events
		WHERE file_object_id = $1
		ORDER BY seq ASC
	`, fileObjectID)
	if err != nil {
		return []FileEvent{}
	}
	defer rows.Close()

	out := make([]FileEvent, 0)
	for rows.Next() {
		e, err := scanFileEvent(rows)
		if err != nil {
			return []FileEvent{}
		}
		out = append(out, e)
	}
	if rows.Err() != nil {
		return []FileEvent{}
	}
	return out
}

// listFileObjectsByOwner returns every FileObjectRecord (including
// tombstones) owned by owner, backing ListFileObjects (charter §3, added
// 2026-08-18). Queries fileobjects_records.owner, indexed by
// 0008_fileobjects_owner_index.up.sql. See PostgresStore's doc comment for
// why a genuine query failure folds into an empty slice, matching
// listVersions/eventsForFileObject's existing precedent exactly.
func (s *PostgresStore) listFileObjectsByOwner(owner string) []FileObjectRecord {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `
		SELECT file_object_id, owner, current_version_ref, name, mime_type, tags, size_bytes, created_at_unix, deleted, deleted_at_unix, last_history_event_id
		FROM fileobjects_records
		WHERE owner = $1
	`, owner)
	if err != nil {
		return []FileObjectRecord{}
	}
	defer rows.Close()

	out := make([]FileObjectRecord, 0)
	for rows.Next() {
		r, err := scanFileObjectRecord(rows)
		if err != nil {
			return []FileObjectRecord{}
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return []FileObjectRecord{}
	}
	return out
}

// rowScanner is the common subset of pgx.Row and pgx.Rows this package
// needs (just Scan), matching Audit's/Permissions' own equivalent seam
// (internal/audit/postgres_store.go, internal/permissions/postgres_store.go).
type rowScanner interface {
	Scan(dest ...any) error
}

func scanFileObjectRecord(row rowScanner) (FileObjectRecord, error) {
	var (
		r        FileObjectRecord
		tagsJSON []byte
	)
	err := row.Scan(
		&r.FileObjectID,
		&r.Owner,
		&r.CurrentVersionRef,
		&r.Name,
		&r.MimeType,
		&tagsJSON,
		&r.SizeBytes,
		&r.CreatedAtUnix,
		&r.Deleted,
		&r.DeletedAtUnix,
		&r.LastHistoryEventID,
	)
	if err != nil {
		return FileObjectRecord{}, err
	}
	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &r.Tags); err != nil {
			return FileObjectRecord{}, fmt.Errorf("unmarshaling tags: %w", err)
		}
	}
	return r, nil
}

func scanVersionRecord(row rowScanner) (VersionRecord, error) {
	var v VersionRecord
	err := row.Scan(
		&v.VersionRef,
		&v.FileObjectID,
		&v.BlobRef,
		&v.CreatedAtUnix,
		&v.CreatedBy,
		&v.SizeBytes,
	)
	if err != nil {
		return VersionRecord{}, err
	}
	return v, nil
}

func scanFileEvent(row rowScanner) (FileEvent, error) {
	var (
		e            FileEvent
		metadataJSON []byte
	)
	err := row.Scan(
		&e.EventID,
		&e.Action,
		&e.Actor,
		&e.OccurredAtUnix,
		&metadataJSON,
	)
	if err != nil {
		return FileEvent{}, err
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &e.Metadata); err != nil {
			return FileEvent{}, fmt.Errorf("unmarshaling metadata: %w", err)
		}
	}
	return e, nil
}
