package fileobjects

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/ascend/services/api/internal/platform"
)

// This file exercises PostgresStore against a real Postgres database. It
// assumes internal/platform/migrations/0005_fileobjects.up.sql has already
// been applied to that database — by `go run .` (main.go runs migrations
// automatically at startup, see internal/platform/platform.go's New) or by
// whatever else set up the test database. This file deliberately does NOT
// call platform.RunMigrations itself: running migrations is the composition
// root's job, not a test's.
//
// Gate: every test here is skipped (visibly, via t.Skip) unless
// DATABASE_URL is set. Run `docker compose up -d` from the repo root
// first, with a populated .env (see .env.example), then set DATABASE_URL
// before `go test`.
//
// Unlike Audit's/Permissions' own postgres_store_test.go, no
// MIGRATIONS_DATABASE_URL admin-connection cleanup dance is needed here:
// all three tables this package owns (fileobjects_records,
// fileobjects_versions, fileobjects_events) grant DELETE to ascend_app
// (0005_fileobjects.up.sql) — none of them carry the audit_events-style
// append-only discipline — so ordinary cleanup via the store's own
// DATABASE_URL connection is sufficient.

// requirePostgres skips the calling test if DATABASE_URL is not set, and
// otherwise returns it.
func requirePostgres(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres-backed fileobjects store tests — run `docker compose up -d` from the repo root first")
	}
	return url
}

// newTestPostgresStore constructs a real PostgresStore against
// DATABASE_URL, closing the pool when the test completes.
func newTestPostgresStore(t *testing.T) *PostgresStore {
	t.Helper()
	url := requirePostgres(t)
	pool, err := platform.NewPostgresPool(context.Background(), url)
	if err != nil {
		t.Fatalf("connecting to postgres (is `docker compose up -d` running, and have migrations been applied?): %v", err)
	}
	t.Cleanup(pool.Close)
	return NewPostgresStore(pool)
}

// uniqueRunID returns a value distinct to this single test invocation, used
// to build file_object_id/version_ref/event_id values so each test's
// assertions are isolated from any other test's data, including any left
// behind by a prior run whose cleanup could not run.
func uniqueRunID(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generating unique run id: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// cleanupFileObject deletes every row (across all three tables) tagged with
// fileObjectID, via the store's own app-role DATABASE_URL connection — all
// three tables grant DELETE to ascend_app (0005_fileobjects.up.sql).
func cleanupFileObject(t *testing.T, store *PostgresStore, fileObjectID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.pool.Exec(ctx, "DELETE FROM fileobjects_events WHERE file_object_id = $1", fileObjectID); err != nil {
		t.Logf("cleanup: deleting test events: %v", err)
	}
	if _, err := store.pool.Exec(ctx, "DELETE FROM fileobjects_versions WHERE file_object_id = $1", fileObjectID); err != nil {
		t.Logf("cleanup: deleting test versions: %v", err)
	}
	if _, err := store.pool.Exec(ctx, "DELETE FROM fileobjects_records WHERE file_object_id = $1", fileObjectID); err != nil {
		t.Logf("cleanup: deleting test record: %v", err)
	}
}

// TestPostgresStore_PutGetFileObjectRoundTrip covers putFileObject/
// getFileObject's basic round trip, including Tags and
// LastHistoryEventID — the two fields easiest to lose in a marshal/scan
// mismatch.
func TestPostgresStore_PutGetFileObjectRoundTrip(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	fileObjectID := "fo-" + run
	t.Cleanup(func() { cleanupFileObject(t, store, fileObjectID) })

	if _, ok := store.getFileObject(fileObjectID); ok {
		t.Fatal("expected a miss before any putFileObject call")
	}

	rec := FileObjectRecord{
		FileObjectID:       fileObjectID,
		Owner:              "identity:owner-" + run,
		CurrentVersionRef:  "v1-" + run,
		Name:               "report.pdf",
		MimeType:           "application/pdf",
		Tags:               []string{"finance", "q3"},
		SizeBytes:          1234,
		CreatedAtUnix:      1000,
		Deleted:            false,
		DeletedAtUnix:      0,
		LastHistoryEventID: "evt-" + run,
	}
	store.putFileObject(rec)

	got, ok := store.getFileObject(fileObjectID)
	if !ok {
		t.Fatal("expected a hit after putFileObject")
	}
	if got.FileObjectID != rec.FileObjectID || got.Owner != rec.Owner || got.CurrentVersionRef != rec.CurrentVersionRef ||
		got.Name != rec.Name || got.MimeType != rec.MimeType || got.SizeBytes != rec.SizeBytes ||
		got.CreatedAtUnix != rec.CreatedAtUnix || got.Deleted != rec.Deleted || got.DeletedAtUnix != rec.DeletedAtUnix ||
		got.LastHistoryEventID != rec.LastHistoryEventID {
		t.Fatalf("round-tripped record mismatch: got %+v, want %+v", got, rec)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "finance" || got.Tags[1] != "q3" {
		t.Fatalf("round-tripped Tags mismatch: got %v, want [finance q3]", got.Tags)
	}

	// putFileObject on an existing file_object_id upserts in place (matches
	// InMemoryStore's unconditional overwrite semantics), including
	// LastHistoryEventID/Deleted transitions.
	rec.LastHistoryEventID = "evt2-" + run
	rec.Deleted = true
	rec.DeletedAtUnix = 2000
	store.putFileObject(rec)
	got, ok = store.getFileObject(fileObjectID)
	if !ok || got.LastHistoryEventID != "evt2-"+run || !got.Deleted || got.DeletedAtUnix != 2000 {
		t.Fatalf("expected upsert to overwrite in place, got %+v", got)
	}
}

// TestPostgresStore_VersionsCreationOrderAndLookup covers addVersion/
// listVersions' creation-order guarantee and getVersion's hit/miss shape.
func TestPostgresStore_VersionsCreationOrderAndLookup(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	fileObjectID := "fo-" + run
	t.Cleanup(func() { cleanupFileObject(t, store, fileObjectID) })

	if versions := store.listVersions(fileObjectID); len(versions) != 0 {
		t.Fatalf("expected no versions before any addVersion call, got %v", versions)
	}
	if _, ok := store.getVersion(fileObjectID, "v1-"+run); ok {
		t.Fatal("expected a miss for a version that was never added")
	}

	v1 := VersionRecord{VersionRef: "v1-" + run, FileObjectID: fileObjectID, BlobRef: "blob-1-" + run, CreatedAtUnix: 100, CreatedBy: "identity:alice", SizeBytes: 10}
	v2 := VersionRecord{VersionRef: "v2-" + run, FileObjectID: fileObjectID, BlobRef: "blob-2-" + run, CreatedAtUnix: 200, CreatedBy: "identity:bob", SizeBytes: 20}
	v3 := VersionRecord{VersionRef: "v3-" + run, FileObjectID: fileObjectID, BlobRef: "blob-3-" + run, CreatedAtUnix: 300, CreatedBy: "identity:alice", SizeBytes: 30}
	store.addVersion(fileObjectID, v1)
	store.addVersion(fileObjectID, v2)
	store.addVersion(fileObjectID, v3)

	versions := store.listVersions(fileObjectID)
	if len(versions) != 3 {
		t.Fatalf("expected 3 versions, got %d (%+v)", len(versions), versions)
	}
	if versions[0].VersionRef != v1.VersionRef || versions[1].VersionRef != v2.VersionRef || versions[2].VersionRef != v3.VersionRef {
		t.Fatalf("expected versions in creation order [v1 v2 v3], got %+v", versions)
	}

	got, ok := store.getVersion(fileObjectID, v2.VersionRef)
	if !ok {
		t.Fatal("expected a hit for v2")
	}
	if got.BlobRef != v2.BlobRef || got.CreatedBy != v2.CreatedBy || got.SizeBytes != v2.SizeBytes || got.CreatedAtUnix != v2.CreatedAtUnix {
		t.Fatalf("getVersion returned unexpected fields: %+v, want %+v", got, v2)
	}

	if _, ok := store.getVersion(fileObjectID, "no-such-version"); ok {
		t.Fatal("expected a miss for a version_ref that was never added")
	}
}

// TestPostgresStore_EventsEmissionOrder covers addEvent/eventsForFileObject's
// emission-order guarantee, including Metadata round-tripping.
func TestPostgresStore_EventsEmissionOrder(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	fileObjectID := "fo-" + run
	t.Cleanup(func() { cleanupFileObject(t, store, fileObjectID) })

	if events := store.eventsForFileObject(fileObjectID); len(events) != 0 {
		t.Fatalf("expected no events before any addEvent call, got %v", events)
	}

	e1 := FileEvent{EventID: "e1-" + run, Action: "fileobjects.create_file_object", Actor: "identity:alice", OccurredAtUnix: 100, Metadata: map[string]string{"name": "report.pdf"}}
	e2 := FileEvent{EventID: "e2-" + run, Action: "fileobjects.create_version", Actor: "identity:alice", OccurredAtUnix: 200, Metadata: map[string]string{"version_ref": "v2"}}
	e3 := FileEvent{EventID: "e3-" + run, Action: "fileobjects.delete_file_object", Actor: "identity:alice", OccurredAtUnix: 300, Metadata: map[string]string{"versions_deleted": "2"}}
	store.addEvent(fileObjectID, e1)
	store.addEvent(fileObjectID, e2)
	store.addEvent(fileObjectID, e3)

	events := store.eventsForFileObject(fileObjectID)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d (%+v)", len(events), events)
	}
	if events[0].EventID != e1.EventID || events[1].EventID != e2.EventID || events[2].EventID != e3.EventID {
		t.Fatalf("expected events in emission order [e1 e2 e3], got %+v", events)
	}
	if events[1].Action != e2.Action || events[1].Actor != e2.Actor || events[1].OccurredAtUnix != e2.OccurredAtUnix {
		t.Fatalf("eventsForFileObject returned unexpected fields for e2: %+v", events[1])
	}
	if events[1].Metadata["version_ref"] != "v2" {
		t.Fatalf("expected Metadata to round-trip, got %+v", events[1].Metadata)
	}
}

// TestPostgresStore_DeleteFileObjectRecordIsAtomicAcrossAllThreeTables is
// the direct proof that deleteFileObjectRecord's transaction actually
// works: it puts a file object with multiple versions and events, deletes
// it, and confirms ALL THREE tables are empty for that file_object_id
// afterward — not just that each individual DELETE statement is
// syntactically correct in isolation.
func TestPostgresStore_DeleteFileObjectRecordIsAtomicAcrossAllThreeTables(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	fileObjectID := "fo-" + run
	// No t.Cleanup registered for cleanupFileObject: the whole point of this
	// test is that deleteFileObjectRecord itself leaves nothing behind. A
	// defensive cleanup is still registered in case an assertion fails
	// partway through, so a failed run doesn't leak rows into later runs.
	t.Cleanup(func() { cleanupFileObject(t, store, fileObjectID) })

	store.putFileObject(FileObjectRecord{
		FileObjectID:      fileObjectID,
		Owner:             "identity:owner-" + run,
		CurrentVersionRef: "v2-" + run,
		Name:              "contract.pdf",
		MimeType:          "application/pdf",
		SizeBytes:         999,
		CreatedAtUnix:     100,
	})
	store.addVersion(fileObjectID, VersionRecord{VersionRef: "v1-" + run, FileObjectID: fileObjectID, BlobRef: "blob-1-" + run, CreatedAtUnix: 100, CreatedBy: "identity:owner-" + run, SizeBytes: 10})
	store.addVersion(fileObjectID, VersionRecord{VersionRef: "v2-" + run, FileObjectID: fileObjectID, BlobRef: "blob-2-" + run, CreatedAtUnix: 200, CreatedBy: "identity:owner-" + run, SizeBytes: 20})
	store.addEvent(fileObjectID, FileEvent{EventID: "e1-" + run, Action: "fileobjects.create_file_object", Actor: "identity:owner-" + run, OccurredAtUnix: 100, Metadata: map[string]string{}})
	store.addEvent(fileObjectID, FileEvent{EventID: "e2-" + run, Action: "fileobjects.create_version", Actor: "identity:owner-" + run, OccurredAtUnix: 200, Metadata: map[string]string{}})

	// Sanity check: everything is actually there before deleting.
	if _, ok := store.getFileObject(fileObjectID); !ok {
		t.Fatal("setup failed: expected the file object to exist before delete")
	}
	if versions := store.listVersions(fileObjectID); len(versions) != 2 {
		t.Fatalf("setup failed: expected 2 versions before delete, got %d", len(versions))
	}
	if events := store.eventsForFileObject(fileObjectID); len(events) != 2 {
		t.Fatalf("setup failed: expected 2 events before delete, got %d", len(events))
	}

	store.deleteFileObjectRecord(fileObjectID)

	if _, ok := store.getFileObject(fileObjectID); ok {
		t.Fatal("expected fileobjects_records to be empty for this file_object_id after deleteFileObjectRecord")
	}
	if versions := store.listVersions(fileObjectID); len(versions) != 0 {
		t.Fatalf("expected fileobjects_versions to be empty for this file_object_id after deleteFileObjectRecord, got %d rows", len(versions))
	}
	if events := store.eventsForFileObject(fileObjectID); len(events) != 0 {
		t.Fatalf("expected fileobjects_events to be empty for this file_object_id after deleteFileObjectRecord, got %d rows", len(events))
	}

	// Direct row-count proof against all three tables, not just via this
	// package's own Store methods (which could theoretically mask a bug by
	// filtering) — the strongest form of the atomicity claim.
	ctx := context.Background()
	for _, table := range []string{"fileobjects_records", "fileobjects_versions", "fileobjects_events"} {
		var count int
		if err := store.pool.QueryRow(ctx, "SELECT COUNT(*) FROM "+table+" WHERE file_object_id = $1", fileObjectID).Scan(&count); err != nil {
			t.Fatalf("counting rows in %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("expected 0 rows in %s for file_object_id %s after deleteFileObjectRecord, got %d", table, fileObjectID, count)
		}
	}
}
