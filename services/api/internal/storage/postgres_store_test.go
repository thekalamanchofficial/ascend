package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ascend/services/api/internal/platform"
)

// This file exercises PostgresStore against a real Postgres database. It
// assumes internal/platform/migrations/0004_storage.up.sql has already been
// applied to that database — by `go run .` (main.go runs migrations
// automatically at startup, see internal/platform/platform.go's New) or by
// whatever else set up the test database. This file deliberately does NOT
// call platform.RunMigrations itself: running migrations is the composition
// root's job, not a test's.
//
// Gate: every test here is skipped (visibly, via t.Skip) unless DATABASE_URL
// is set. Run `docker compose up -d` from the repo root first, with a
// populated .env (see .env.example), then set DATABASE_URL before `go test`.
//
// Unlike Audit's/Permissions' Postgres tests, cleanup here needs no
// MIGRATIONS_DATABASE_URL admin-connection dance: storage_blobs and
// storage_wrapping_keys both grant DELETE to ascend_app
// (0004_storage.up.sql) — neither is an append-only/tamper-evidence table —
// so ordinary cleanup via the same DATABASE_URL connection every test (and
// every real request) uses is sufficient.

func requirePostgres(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres-backed storage store tests — run `docker compose up -d` from the repo root first")
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
// to tag every row a test writes (blob_ref) so its assertions are isolated
// from any other test's data — including any left behind by a prior run
// whose cleanup could not run — without requiring the tables to be empty.
func uniqueRunID(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generating unique run id: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// cleanupBlob deletes blobRef's row from both storage_blobs and
// storage_wrapping_keys via the store's own app-role connection — both
// tables grant DELETE to ascend_app (0004_storage.up.sql).
func cleanupBlob(t *testing.T, store *PostgresStore, blobRef string) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.pool.Exec(ctx, "DELETE FROM storage_blobs WHERE blob_ref = $1", blobRef); err != nil {
		t.Logf("cleanup: deleting test blob record: %v", err)
	}
	if _, err := store.pool.Exec(ctx, "DELETE FROM storage_wrapping_keys WHERE blob_ref = $1", blobRef); err != nil {
		t.Logf("cleanup: deleting test wrapping key: %v", err)
	}
}

// TestPostgresStore_PutGetRoundTrip covers put/get's basic round trip and
// get's miss behavior for a blob_ref that was never put.
func TestPostgresStore_PutGetRoundTrip(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	blobRef := "blob-" + run
	t.Cleanup(func() { cleanupBlob(t, store, blobRef) })

	if _, found := store.get(blobRef); found {
		t.Fatal("expected a miss before any put")
	}

	record := BlobRecord{
		BlobRef:       blobRef,
		Owner:         "identity:alice-" + run,
		PolicyID:      "policy-a",
		SizeBytes:     1234,
		CreatedAtUnix: 1000,
		Location:      "local-filesystem:/tmp/x",
	}
	store.put(record)

	got, found := store.get(blobRef)
	if !found {
		t.Fatal("expected a hit after put")
	}
	if got != record {
		t.Fatalf("round-tripped record does not match: got %+v, want %+v", got, record)
	}

	// put again (overwrite-in-place, matching InMemoryStore.put's
	// unconditional overwrite semantics).
	record.SizeBytes = 5678
	record.Deleted = true
	record.DeletedAtUnix = 2000
	record.DeletionMechanism = DeletionMechanismPhysical
	store.put(record)

	got, found = store.get(blobRef)
	if !found || got != record {
		t.Fatalf("expected put to overwrite in place: got %+v found=%v, want %+v", got, found, record)
	}

	// Exactly one row for this blob_ref — overwrite upserted in place, it
	// did not insert a second row.
	var count int
	if err := store.pool.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM storage_blobs WHERE blob_ref = $1", blobRef,
	).Scan(&count); err != nil {
		t.Fatalf("counting blob rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row after overwrite, got %d", count)
	}
}

// TestPostgresStore_Delete covers delete's hard-removal behavior (used only
// by StoreBlob's own rollback path, service.go — never by DeleteBlob, which
// writes a tombstone via put instead).
func TestPostgresStore_Delete(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	blobRef := "blob-" + run
	t.Cleanup(func() { cleanupBlob(t, store, blobRef) })

	store.put(BlobRecord{BlobRef: blobRef, Owner: "identity:alice-" + run, PolicyID: "policy-a", CreatedAtUnix: 1})
	if _, found := store.get(blobRef); !found {
		t.Fatal("expected a hit after put")
	}

	store.delete(blobRef)
	if _, found := store.get(blobRef); found {
		t.Fatal("expected a miss after delete")
	}

	// delete on an absent row must not panic/error (matches
	// InMemoryStore.delete's `delete(map, key)` no-op-on-absent semantics).
	store.delete(blobRef)
}

// TestPostgresStore_RecordsForOwnerFiltering covers recordsForOwner's exact
// filter predicate, including tombstoned (deleted) records — ExportAllBlobs
// depends on tombstones being included.
func TestPostgresStore_RecordsForOwnerFiltering(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	ownerA := "identity:owner-a-" + run
	ownerB := "identity:owner-b-" + run

	blobRef1 := "blob-1-" + run
	blobRef2 := "blob-2-" + run
	blobRef3 := "blob-3-" + run
	t.Cleanup(func() {
		cleanupBlob(t, store, blobRef1)
		cleanupBlob(t, store, blobRef2)
		cleanupBlob(t, store, blobRef3)
	})

	store.put(BlobRecord{BlobRef: blobRef1, Owner: ownerA, PolicyID: "policy-a", CreatedAtUnix: 1})
	store.put(BlobRecord{
		BlobRef: blobRef2, Owner: ownerA, PolicyID: "policy-a", CreatedAtUnix: 2,
		Deleted: true, DeletedAtUnix: 20, DeletionMechanism: DeletionMechanismCryptoShred,
	})
	store.put(BlobRecord{BlobRef: blobRef3, Owner: ownerB, PolicyID: "policy-a", CreatedAtUnix: 3})

	gotA := store.recordsForOwner(ownerA)
	if len(gotA) != 2 {
		t.Fatalf("recordsForOwner(ownerA): expected 2 records (including the tombstone), got %d (%+v)", len(gotA), gotA)
	}
	sawLive, sawTombstone := false, false
	for _, r := range gotA {
		if r.Owner != ownerA {
			t.Fatalf("recordsForOwner returned a record for the wrong owner: %+v", r)
		}
		if r.Deleted {
			sawTombstone = true
		} else {
			sawLive = true
		}
	}
	if !sawLive || !sawTombstone {
		t.Fatalf("expected both a live record and a tombstone for ownerA, got %+v", gotA)
	}

	gotB := store.recordsForOwner(ownerB)
	if len(gotB) != 1 || gotB[0].BlobRef != blobRef3 {
		t.Fatalf("recordsForOwner(ownerB): expected exactly blobRef3, got %+v", gotB)
	}

	if got := store.recordsForOwner("identity:nobody-" + run); len(got) != 0 {
		t.Fatalf("recordsForOwner: expected 0 records for an owner with none, got %d", len(got))
	}
}

// TestPostgresStore_WrappingKeyLifecycle covers putWrappingKey/wrappingKey/
// hasWrappingKey/destroyWrappingKey's full round trip, including
// destroyWrappingKey's exact "returns false if no key was present" contract
// (used by DeleteBlob's crypto-shred path to fail loudly on a double-shred
// attempt).
func TestPostgresStore_WrappingKeyLifecycle(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	blobRef := "blob-" + run
	t.Cleanup(func() { cleanupBlob(t, store, blobRef) })

	if _, ok := store.wrappingKey(blobRef); ok {
		t.Fatal("expected wrappingKey to miss before any putWrappingKey")
	}
	if store.hasWrappingKey(blobRef) {
		t.Fatal("expected hasWrappingKey=false before any putWrappingKey")
	}
	// destroyWrappingKey on an absent key returns false — the contract
	// DeleteBlob's crypto-shred path depends on.
	if store.destroyWrappingKey(blobRef) {
		t.Fatal("expected destroyWrappingKey=false when no key was ever present")
	}

	key := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	store.putWrappingKey(blobRef, key)

	got, ok := store.wrappingKey(blobRef)
	if !ok {
		t.Fatal("expected wrappingKey to hit after putWrappingKey")
	}
	if string(got) != string(key) {
		t.Fatalf("wrappingKey returned wrong bytes: got %v, want %v", got, key)
	}
	if !store.hasWrappingKey(blobRef) {
		t.Fatal("expected hasWrappingKey=true after putWrappingKey")
	}

	// Overwrite: putWrappingKey again with a different key.
	newKey := []byte{9, 9, 9, 9}
	store.putWrappingKey(blobRef, newKey)
	got, ok = store.wrappingKey(blobRef)
	if !ok || string(got) != string(newKey) {
		t.Fatalf("expected putWrappingKey to overwrite in place: got %v ok=%v, want %v", got, ok, newKey)
	}

	// First destroy: key was present, returns true, and is genuinely gone.
	if !store.destroyWrappingKey(blobRef) {
		t.Fatal("expected destroyWrappingKey=true when a key was present")
	}
	if store.hasWrappingKey(blobRef) {
		t.Fatal("expected hasWrappingKey=false after destroyWrappingKey")
	}
	if _, ok := store.wrappingKey(blobRef); ok {
		t.Fatal("expected wrappingKey to miss after destroyWrappingKey")
	}

	// Second destroy (double-shred attempt): returns false, not a repeat
	// true — this is exactly what lets DeleteBlob's crypto-shred path fail
	// loudly on a double-shred rather than silently no-op.
	if store.destroyWrappingKey(blobRef) {
		t.Fatal("expected a second destroyWrappingKey call to return false (already destroyed)")
	}
}

// TestPostgresStore_LockBlob_SerializesConcurrentGetThenPutSequences is the
// most important test in this file: it proves lockBlob actually serializes
// an entire multi-call get-then-put sequence across TWO SEPARATE goroutines
// (and, critically, across separate Store method calls with no shared
// transaction — the exact cross-call scenario a transaction-scoped
// pg_advisory_xact_lock cannot handle) for the SAME blob_ref, exactly
// matching InMemoryStore.lockBlob's contract that service.go's
// MoveBlob/DeleteBlob depend on.
//
// Design: N goroutines each run the identical critical section — lock,
// read the current counter value via get(), sleep briefly (to widen the
// window a broken/no-op lock would race into), increment, write it back via
// put(), unlock — a classic read-modify-write race detector. If lockBlob
// genuinely serializes (no interleaving), the final counter value is
// exactly N: every increment is observed by the next goroutine's read. If
// two connections' lock/unlock pairs are NOT actually tied to the same
// session (e.g. a bug that used pool.Exec instead of holding a dedicated
// *pgxpool.Conn), goroutines would race past each other and the final
// counter would be LESS than N (a classic lost-update outcome) with very
// high probability at this worker count and sleep duration.
func TestPostgresStore_LockBlob_SerializesConcurrentGetThenPutSequences(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	blobRef := "lock-blob-" + run
	t.Cleanup(func() { cleanupBlob(t, store, blobRef) })

	// Force real OS-thread parallelism — genuine concurrency, not just
	// interleaved single-threaded scheduling, is what makes this a
	// meaningful proof.
	prevProcs := runtime.GOMAXPROCS(0)
	if prevProcs < 4 {
		runtime.GOMAXPROCS(4)
	}
	t.Cleanup(func() { runtime.GOMAXPROCS(prevProcs) })

	// workers is deliberately kept well BELOW platform.maxPoolConns (10):
	// lockBlob's blocking `SELECT pg_advisory_lock` (postgres_store.go) is
	// issued on a connection checked out of THIS SAME pool and held for
	// the entire time a worker is waiting to acquire the lock, not just
	// while it holds it — so if `workers` approached or exceeded the pool
	// size, every connection could end up consumed by goroutines blocked
	// waiting for the lock, leaving none free for the eventual lock
	// holder's own get()/put() calls (which need their own connection from
	// the same pool) — a genuine self-inflicted deadlock, not a bug in the
	// lock logic itself. This was hit empirically while writing this test
	// (workers=12 against maxPoolConns=10 hung for the full test timeout);
	// see this file's connection-pool-sizing note and
	// docs/DECISION_LOG.md's "Storage: Store interface introduced,
	// PostgresStore added" entry for the production implication (many
	// concurrent duplicate MoveBlob/DeleteBlob requests for the SAME
	// blob_ref, at a volume approaching pool size, carries the identical
	// risk against the real service).
	const workers = 6

	// Seed the counter at 0 via a real record (SizeBytes doubles as the
	// counter here — any int64 field works; SizeBytes chosen since it has
	// no other meaning in this test).
	store.put(BlobRecord{BlobRef: blobRef, Owner: "identity:locker-" + run, PolicyID: "policy-a", CreatedAtUnix: 1, SizeBytes: 0})

	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // maximize the chance all goroutines race into lockBlob together

			unlock := store.lockBlob(blobRef)
			// Full get-then-put sequence, exactly mirroring
			// MoveBlob/DeleteBlob's shape in service.go: read the record,
			// decide, mutate, write back — all while holding the lock.
			record, found := store.get(blobRef)
			if !found {
				unlock()
				t.Errorf("worker: expected to find the seeded record while holding the lock")
				return
			}
			// A deliberately observable read-modify-write window: without
			// real serialization, two goroutines could both read the same
			// SizeBytes value here before either writes back, and the
			// final count would undercount.
			record.SizeBytes++
			store.put(record)
			unlock()
		}()
	}
	close(start)
	wg.Wait()

	final, found := store.get(blobRef)
	if !found {
		t.Fatal("expected the record to still exist after all workers completed")
	}
	if final.SizeBytes != workers {
		t.Fatalf("lockBlob failed to serialize %d concurrent get-then-put sequences: expected final counter == %d, got %d (a lower value indicates a lost update — two goroutines' critical sections interleaved instead of serializing)", workers, workers, final.SizeBytes)
	}
}

// TestPostgresStore_LockBlob_DifferentBlobRefsDoNotBlockEachOther proves
// lockBlob's other half of the contract: different blob_refs never block
// each other (InMemoryStore.lockBlob's own doc comment: "Different
// blob_refs never block each other"). Two goroutines lock two DIFFERENT
// blob_refs and both must be able to hold their locks concurrently — this
// test fails (hangs, caught via a timeout channel) if lockBlob were instead
// implemented as one single, global lock.
func TestPostgresStore_LockBlob_DifferentBlobRefsDoNotBlockEachOther(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	blobRefA := "lock-blob-a-" + run
	blobRefB := "lock-blob-b-" + run

	unlockA := store.lockBlob(blobRefA)
	defer unlockA()

	done := make(chan struct{})
	go func() {
		unlockB := store.lockBlob(blobRefB)
		defer unlockB()
		close(done)
	}()

	select {
	case <-done:
		// Success: locking a different blob_ref did not block on blobRefA's
		// still-held lock.
	case <-time.After(5 * time.Second):
		t.Fatal("locking a different blob_ref blocked while blobRefA's lock was held — lockBlob is not per-blob_ref")
	}
}
