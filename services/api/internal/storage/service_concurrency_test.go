package storage

import (
	"errors"
	"runtime"
	"sync"
	"testing"
)

// service_concurrency_test.go proves the concurrency-hardening fix for
// DeleteBlob/MoveBlob required by this capability's threat model
// (docs/capabilities/storage.charter.md §6, "Concurrency hardening
// required, 2026-07-17") and recorded in docs/DECISION_LOG.md, "Storage:
// concurrency-harden DeleteBlob/MoveBlob (per-blob_ref operation lock)".
//
// No C compiler is available in this environment (confirmed: `gcc` is not
// on PATH), so `go test -race` cannot run. Per Security Steward's own
// precedent for Session/Request Authentication's nonce-consumption proof
// (docs/DECISION_LOG.md, 2026-07-17, "Session / Request Authentication
// passes merge gate"), this substitutes two forms of stronger, targeted
// evidence instead of skipping verification:
//
//  1. Each test below runs its two-goroutine race, from scratch, across
//     concurrencyTestIterations (200) independent trials, with
//     GOMAXPROCS forced above 1 — many trials against the REAL,
//     currently-fixed code, all of which must hold the stated invariant
//     every single time.
//  2. A companion mutation-tested proof (run manually, documented in
//     docs/DECISION_LOG.md, not committed here since it requires an
//     isolated, deliberately-broken copy of this package OUTSIDE this
//     repo) confirms these exact tests reliably FAIL against a version of
//     service.go/store.go with the per-blob_ref lock removed — i.e. that
//     these tests would actually catch the bug they exist to catch, not
//     just pass vacuously.
const concurrencyTestIterations = 200

// raceGOMAXPROCS ensures at least 2 OS threads can run goroutines in
// parallel for the duration of a test, restoring the previous value
// afterward. Genuine concurrency (not just interleaved single-threaded
// scheduling) is what makes this a meaningful proof rather than a test
// that could vacuously pass by construction.
func raceGOMAXPROCS(t *testing.T) {
	t.Helper()
	prev := runtime.GOMAXPROCS(0)
	want := prev
	if want < 4 {
		want = 4
	}
	runtime.GOMAXPROCS(want)
	t.Cleanup(func() { runtime.GOMAXPROCS(prev) })
}

// TestDeleteBlob_ConcurrentDuplicateRequests_ExactlyOneSucceeds proves:
// N concurrent DeleteBlob calls for the SAME blob_ref result in exactly
// one successful deletion and (N-1) clean ErrBlobAlreadyDeleted
// rejections — never more than one success (double-free / double
// physical-delete / double-audit-"succeeded"-event) and never zero
// successes (a lost delete). Run across many iterations with real
// goroutine parallelism, per the file-level doc comment above.
//
// Uses 16 concurrent callers per iteration, not 2: with only 2 callers,
// this test was empirically found (during this fix's own mutation-testing
// pass, see docs/DECISION_LOG.md) to sometimes NOT observe the race even
// against the deliberately-broken, lock-removed variant of DeleteBlob —
// the unguarded check-then-act window here is small enough (an in-memory
// map read/decide/write, no I/O) that two goroutines' startup latency
// alone was occasionally enough to accidentally serialize them. 8
// concurrent callers raised the catch rate but still missed the race in
// roughly 1 of 10 full 200-iteration runs against the broken variant; 16
// concurrent callers (120 pairwise races per iteration instead of 1)
// caught it in every one of 10 separate 200-iteration runs (2,000 trials
// total) against the broken variant, while the fixed code passed all
// 2,000 trials at the same worker count — the number this test now uses.
func TestDeleteBlob_ConcurrentDuplicateRequests_ExactlyOneSucceeds(t *testing.T) {
	raceGOMAXPROCS(t)

	const workers = 16

	for i := 0; i < concurrencyTestIterations; i++ {
		backend := newFakeBackend(true /* physical delete */, "fake")
		checker := newFakePermissionChecker(true)
		audit := newFakeAuditEmitter()

		svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, checker, audit)
		if err != nil {
			t.Fatalf("iteration %d: NewService: %v", i, err)
		}
		stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("delete me"), PolicyID: "policy-a"})
		if err != nil {
			t.Fatalf("iteration %d: StoreBlob: %v", i, err)
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, workers)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start // maximize the chance all goroutines race into DeleteBlob together
				_, callErr := svc.DeleteBlob(DeleteBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
				errs[idx] = callErr
			}(w)
		}
		close(start)
		wg.Wait()

		successCount, alreadyDeletedCount, unexpected := 0, 0, 0
		for _, callErr := range errs {
			switch {
			case callErr == nil:
				successCount++
			case errors.Is(callErr, ErrBlobAlreadyDeleted):
				alreadyDeletedCount++
			default:
				unexpected++
				t.Errorf("iteration %d: unexpected error from concurrent DeleteBlob: %v", i, callErr)
			}
		}
		if unexpected > 0 {
			t.FailNow()
		}
		if successCount != 1 || alreadyDeletedCount != workers-1 {
			t.Fatalf("iteration %d: expected exactly 1 success and %d already-deleted rejections out of %d concurrent calls, got %d successes and %d already-deleted (errs=%v)",
				i, workers-1, workers, successCount, alreadyDeletedCount, errs)
		}

		// Never a double-free: the backend's real Delete mechanism must
		// have run exactly once, not repeatedly.
		if got := backend.deleteCallCount(); got != 1 {
			t.Fatalf("iteration %d: expected the backend's physical Delete to be invoked exactly once, got %d calls (double-free)", i, got)
		}

		// Never corrupted/duplicated audit state: exactly one
		// storage.delete_blob (success) event and exactly (workers-1)
		// storage.delete_blob_failed/already_deleted events — never more
		// than one success event.
		successEvents, alreadyDeletedEvents := 0, 0
		for _, c := range audit.calls {
			if c.action == "storage.delete_blob" {
				successEvents++
			}
			if c.action == "storage.delete_blob_failed" && c.ruleReference == "already_deleted" {
				alreadyDeletedEvents++
			}
		}
		if successEvents != 1 {
			t.Fatalf("iteration %d: expected exactly 1 storage.delete_blob audit event, got %d", i, successEvents)
		}
		if alreadyDeletedEvents != workers-1 {
			t.Fatalf("iteration %d: expected exactly %d storage.delete_blob_failed/already_deleted audit events, got %d", i, workers-1, alreadyDeletedEvents)
		}

		// Final state is a single, consistent tombstone, not a
		// corrupted/racily-overwritten record.
		record, found := svc.store.get(stored.BlobRef)
		if !found || !record.Deleted || record.DeletionMechanism != DeletionMechanismPhysical {
			t.Fatalf("iteration %d: expected a single consistent physical-delete tombstone, got record=%+v found=%v", i, record, found)
		}
	}
}

// TestMoveBlob_ConcurrentDuplicateRequests_SafelySerialized proves the
// documented behavior for concurrent MoveBlob calls on the same blob_ref
// targeting the SAME new_policy_id (the realistic "duplicate request"
// case — e.g. a retried network call): the two calls are safely
// SERIALIZED by the per-blob_ref lock, never raced. Exactly one of them
// performs the real relocation (Store to the new backend, Delete from the
// old one); the other, once unblocked, observes the record already
// updated to the target policy and takes the pre-existing "already at
// this policy" no-op branch (service.go) — itself a real, audited event,
// just not a second physical relocation. This capability-engineer chose
// "both succeed, serialized" over "one succeeds, one fails" specifically
// because MoveBlob's own no-op branch already existed for the
// already-at-target-policy case and is the more honest outcome for a
// caller that legitimately retried an ambiguous prior request — it should
// not need to distinguish "my move succeeded" from "someone else's
// concurrent identical move succeeded" to know its data ended up in the
// right place.
//
// The invariant proven, either way: never a dual-copy (both backends hold
// the blob) and never a lost copy (neither does) after both calls
// complete, and the backend's real Store/Delete mechanism runs exactly
// once each, not twice — the second call must genuinely take the no-op
// path, not silently re-run and re-audit a full relocation.
func TestMoveBlob_ConcurrentDuplicateRequests_SafelySerialized(t *testing.T) {
	raceGOMAXPROCS(t)

	// 16 concurrent callers, not 2 — same empirical reasoning as
	// TestDeleteBlob_ConcurrentDuplicateRequests_ExactlyOneSucceeds above
	// (more pairwise races per iteration makes the race reliably
	// reproducible against a deliberately-broken variant, not just
	// occasionally).
	const workers = 16

	for i := 0; i < concurrencyTestIterations; i++ {
		backendA := newFakeBackend(true, "fake-a")
		backendB := newFakeBackend(true, "fake-b")
		checker := newFakePermissionChecker(true)
		audit := newFakeAuditEmitter()

		svc, err := NewService(NewInMemoryStore(), []Policy{
			{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backendA},
			{ID: "policy-b", DisplayName: "B", Description: "d", Backend: backendB},
		}, checker, audit)
		if err != nil {
			t.Fatalf("iteration %d: NewService: %v", i, err)
		}
		stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("move me"), PolicyID: "policy-a"})
		if err != nil {
			t.Fatalf("iteration %d: StoreBlob: %v", i, err)
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, workers)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				_, callErr := svc.MoveBlob(MoveBlobRequest{BlobRef: stored.BlobRef, NewPolicyID: "policy-b", RequestingSubject: "identity:alice"})
				errs[idx] = callErr
			}(w)
		}
		close(start)
		wg.Wait()

		for w, callErr := range errs {
			if callErr != nil {
				t.Fatalf("iteration %d: worker %d: expected all %d concurrent identical MoveBlob calls to succeed (safely serialized, one real move + the rest no-ops), got %v", i, w, workers, callErr)
			}
		}

		// No dual copy, no lost copy, regardless of interleaving.
		if backendA.has(stored.BlobRef) {
			t.Fatalf("iteration %d: expected the old copy (backend A) to be gone after the move", i)
		}
		if !backendB.has(stored.BlobRef) {
			t.Fatalf("iteration %d: expected the new copy (backend B) to exist after the move", i)
		}

		// The real relocation mechanism ran exactly once: one Store into
		// B, one Delete from A. If the lock failed to serialize the
		// calls, more than one could have raced into the real-move branch
		// (not the no-op branch) and each performed its own Store/Delete —
		// still possibly leaving backendB "has" the blob, but via multiple
		// Store calls and multiple Delete-from-A calls, which is exactly
		// the unaccounted-for double-mutation this test exists to catch.
		if got := backendB.storeCallCount(); got != 1 {
			t.Fatalf("iteration %d: expected exactly 1 Store call into the new backend, got %d (indicates more than one of the %d concurrent calls took the real-move branch instead of being serialized)", i, got, workers)
		}
		if got := backendA.deleteCallCount(); got != 1 {
			t.Fatalf("iteration %d: expected exactly 1 Delete call against the old backend, got %d", i, got)
		}

		// Content still correct and retrievable via the same blob_ref.
		got, err := svc.RetrieveBlob(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
		if err != nil {
			t.Fatalf("iteration %d: RetrieveBlob after concurrent moves: %v", i, err)
		}
		if string(got.Data) != "move me" {
			t.Fatalf("iteration %d: data changed across concurrent moves: got %q", i, got.Data)
		}

		// Audit is consistent: exactly one real-move event (no_op absent
		// or "false") and exactly (workers-1) no-op events (no_op ==
		// "true").
		realMoveEvents, noOpEvents := 0, 0
		for _, c := range audit.calls {
			if c.action != "storage.move_blob" {
				continue
			}
			if c.metadata["no_op"] == "true" {
				noOpEvents++
			} else {
				realMoveEvents++
			}
		}
		if realMoveEvents != 1 || noOpEvents != workers-1 {
			t.Fatalf("iteration %d: expected exactly 1 real-move audit event and %d no-op audit events, got %d real + %d no-op", i, workers-1, realMoveEvents, noOpEvents)
		}
	}
}
