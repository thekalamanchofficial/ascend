package storage

import (
	"errors"
	"testing"
)

func newTestService(t *testing.T, allowPerm bool) (*Service, *fakeAuditEmitter, *fakePermissionChecker, *fakeBackend, *fakeBackend) {
	t.Helper()
	backendA := newFakeBackend(true, "fake-a")
	backendB := newFakeBackend(true, "fake-b")
	checker := newFakePermissionChecker(allowPerm)
	audit := newFakeAuditEmitter()

	policies := []Policy{
		{ID: "policy-a", DisplayName: "Policy A", Description: "test policy A", Backend: backendA},
		{ID: "policy-b", DisplayName: "Policy B", Description: "test policy B", Backend: backendB},
	}
	svc, err := NewService(NewInMemoryStore(), policies, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, audit, checker, backendA, backendB
}

// --- StoreBlob ---

func TestStoreBlob_Success(t *testing.T) {
	svc, audit, checker, backendA, _ := newTestService(t, true)

	resp, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("opaque ciphertext"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}
	if resp.BlobRef == "" {
		t.Fatalf("expected a non-empty blob_ref")
	}
	if !backendA.has(resp.BlobRef) {
		t.Fatalf("expected backend to physically hold the (sealed) blob")
	}
	last, ok := audit.lastCall()
	if !ok || last.action != "storage.store_blob" {
		t.Fatalf("expected a storage.store_blob audit event, got %+v (ok=%v)", last, ok)
	}

	// The gap this task closes: StoreBlob must call GrantPermission to
	// bootstrap the blob's owner (see docs/DECISION_LOG.md, "Storage:
	// StoreBlob establishes Permissions ownership via GrantPermission").
	checker.mu.Lock()
	grantCalls := checker.grantCalls
	checker.mu.Unlock()
	if len(grantCalls) != 1 {
		t.Fatalf("expected exactly one GrantPermission call, got %d: %+v", len(grantCalls), grantCalls)
	}
	got := grantCalls[0]
	want := grantCall{
		grantor: "identity:alice", subject: "identity:alice",
		action: ActionRetrieveBlob, resourceType: resourceTypeBlob, resourceID: resp.BlobRef,
		scope: scopeOwnerBootstrap,
	}
	if got != want {
		t.Fatalf("GrantPermission call = %+v, want %+v", got, want)
	}
}

// TestStoreBlob_GrantPermissionFailureRollsBack proves that when
// establishing the blob's owner grant fails, StoreBlob rolls the write
// back rather than leaving an unreachable, ungoverned blob whose true
// owner can never be established (the actual gap this task closes — see
// docs/DECISION_LOG.md).
func TestStoreBlob_GrantPermissionFailureRollsBack(t *testing.T) {
	backendA := newFakeBackend(true, "fake-a")
	checker := newFakePermissionChecker(true)
	checker.grantErr = errors.New("fake: grant failed")
	audit := newFakeAuditEmitter()

	svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backendA}}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	_, err = svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("data"), PolicyID: "policy-a"})
	if err == nil {
		t.Fatalf("expected StoreBlob to fail when establishing the owner grant fails")
	}
	if len(backendA.data) != 0 {
		t.Fatalf("expected the backend write to be rolled back, but backend still holds %d entries", len(backendA.data))
	}
	// The audit emit must never be reached — the mutation never
	// meaningfully happened from the caller's point of view.
	if audit.callCount() != 0 {
		t.Fatalf("expected no audit emit when the owner grant fails, got %d calls", audit.callCount())
	}
}

func TestStoreBlob_UnknownPolicyRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	_, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("x"), PolicyID: "does-not-exist"})
	if !errors.Is(err, ErrUnknownPolicy) {
		t.Fatalf("expected ErrUnknownPolicy, got %v", err)
	}
}

func TestStoreBlob_EmptyDataRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	_, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: nil, PolicyID: "policy-a"})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

// TestStoreBlob_AuditFailureRollsBack proves that when the audit emit
// fails on StoreBlob's success path, the write is rolled back rather than
// left as an orphaned, unreachable blob (the caller never received a
// blob_ref, so an un-rolled-back write would be permanently hidden state).
func TestStoreBlob_AuditFailureRollsBack(t *testing.T) {
	backendA := newFakeBackend(true, "fake-a")
	checker := newFakePermissionChecker(true)
	audit := newFakeAuditEmitter()
	audit.failAll = true

	svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backendA}}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	_, err = svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("data"), PolicyID: "policy-a"})
	if err == nil {
		t.Fatalf("expected StoreBlob to fail when audit emit fails")
	}

	if len(backendA.data) != 0 {
		t.Fatalf("expected the backend write to be rolled back, but backend still holds %d entries", len(backendA.data))
	}

	// The owner grant established just before the failed audit emit must
	// also be revoked — otherwise a rolled-back blob_ref (never returned to
	// any caller) would leave a live, orphaned Permissions grant behind,
	// against this package's "no dual-copy/no orphaned grant" discipline.
	checker.mu.Lock()
	grantCalls, revokeCalls := checker.grantCalls, checker.revokeCalls
	checker.mu.Unlock()
	if len(grantCalls) != 1 {
		t.Fatalf("expected exactly one GrantPermission call before the audit emit failed, got %d", len(grantCalls))
	}
	if len(revokeCalls) != 1 {
		t.Fatalf("expected exactly one RevokePermission call rolling back the grant, got %d", len(revokeCalls))
	}
	g, r := grantCalls[0], revokeCalls[0]
	if r != (revokeCall{grantor: g.grantor, subject: g.subject, action: g.action, resourceType: g.resourceType, resourceID: g.resourceID}) {
		t.Fatalf("RevokePermission call %+v does not match the earlier GrantPermission call %+v", r, g)
	}
}

// --- RetrieveBlob ---

func TestRetrieveBlob_AllowedReturnsOriginalBytes(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	original := []byte("opaque end-to-end ciphertext, storage never sees plaintext")

	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: original, PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}

	got, err := svc.RetrieveBlob(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("RetrieveBlob: %v", err)
	}
	if string(got.Data) != string(original) {
		t.Fatalf("RetrieveBlob returned different bytes: got %q, want %q", got.Data, original)
	}
}

func TestRetrieveBlob_PermissionDenied(t *testing.T) {
	svc, audit, _, _, _ := newTestService(t, true)
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("secret"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}

	// Flip the checker to deny for this call by constructing a second
	// Service that shares the SAME underlying backend (so it sees the
	// blob already stored above) but is wired with a denying
	// PermissionChecker instead.
	denyingChecker := newFakePermissionChecker(false)
	svcDeny, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: mustGetPolicyBackend(t, svc, "policy-a")}}, denyingChecker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	_, err = svcDeny.RetrieveBlob(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:mallory"})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
	last, ok := audit.lastCall()
	if !ok || last.action != "storage.retrieve_blob_denied" {
		t.Fatalf("expected a storage.retrieve_blob_denied audit event, got %+v (ok=%v)", last, ok)
	}
}

func mustGetPolicyBackend(t *testing.T, svc *Service, id string) Backend {
	t.Helper()
	p, ok := svc.policies[id]
	if !ok {
		t.Fatalf("test setup: policy %q not found", id)
	}
	return p.Backend
}

func TestRetrieveBlob_NotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	_, err := svc.RetrieveBlob(RetrieveBlobRequest{BlobRef: "blob_never_existed", RequestingSubject: "identity:alice"})
	if !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("expected ErrBlobNotFound, got %v", err)
	}
}

func TestRetrieveBlob_AuditFailureWithholdsData(t *testing.T) {
	backendA := newFakeBackend(true, "fake-a")
	checker := newFakePermissionChecker(true)
	audit := newFakeAuditEmitter()

	svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backendA}}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("secret data"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}

	audit.failNext = true
	resp, err := svc.RetrieveBlob(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
	if err == nil {
		t.Fatalf("expected RetrieveBlob to fail when audit emit fails")
	}
	if len(resp.Data) != 0 {
		t.Fatalf("expected no data to be returned when audit emit fails, got %d bytes", len(resp.Data))
	}
}

// --- MoveBlob ---

func TestMoveBlob_AtomicNoDualCopy(t *testing.T) {
	svc, audit, _, backendA, backendB := newTestService(t, true)

	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("move me"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}
	if !backendA.has(stored.BlobRef) {
		t.Fatalf("expected blob to exist in backend A before move")
	}
	if backendB.has(stored.BlobRef) {
		t.Fatalf("expected blob to NOT exist in backend B before move")
	}

	moveResp, err := svc.MoveBlob(MoveBlobRequest{BlobRef: stored.BlobRef, NewPolicyID: "policy-b", RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("MoveBlob: %v", err)
	}
	if moveResp.NewLocation == "" {
		t.Fatalf("expected a non-empty new_location")
	}

	// No dual copy: exactly one backend holds the blob after a
	// successful move.
	if backendA.has(stored.BlobRef) {
		t.Fatalf("expected blob to be removed from backend A after move (no residual copy)")
	}
	if !backendB.has(stored.BlobRef) {
		t.Fatalf("expected blob to exist in backend B after move")
	}

	// Still retrievable, same content, via the same blob_ref.
	got, err := svc.RetrieveBlob(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("RetrieveBlob after move: %v", err)
	}
	if string(got.Data) != "move me" {
		t.Fatalf("data changed across move: got %q", got.Data)
	}

	loc, err := svc.GetStorageLocation(GetStorageLocationRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("GetStorageLocation: %v", err)
	}
	if loc.HumanReadableLocation != moveResp.NewLocation {
		t.Fatalf("GetStorageLocation does not reflect the move: got %q, want %q", loc.HumanReadableLocation, moveResp.NewLocation)
	}

	foundMoveEvent := false
	for _, c := range audit.calls {
		if c.action == "storage.move_blob" {
			foundMoveEvent = true
		}
	}
	if !foundMoveEvent {
		t.Fatalf("expected a storage.move_blob audit event")
	}
}

// TestMoveBlob_RollbackWhenOldDeleteFails proves the atomicity guarantee
// in the failure direction: if removing the old copy fails after the new
// copy was already written, MoveBlob must not report success, and must
// roll back the new copy so the old copy remains the SOLE copy — never
// silently leaving two.
func TestMoveBlob_RollbackWhenOldDeleteFails(t *testing.T) {
	backendA := newFakeBackend(true, "fake-a")
	backendA.failDelete = true
	backendB := newFakeBackend(true, "fake-b")
	checker := newFakePermissionChecker(true)
	audit := newFakeAuditEmitter()

	svc, err := NewService(NewInMemoryStore(), []Policy{
		{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backendA},
		{ID: "policy-b", DisplayName: "B", Description: "d", Backend: backendB},
	}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("move me"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}

	_, err = svc.MoveBlob(MoveBlobRequest{BlobRef: stored.BlobRef, NewPolicyID: "policy-b", RequestingSubject: "identity:alice"})
	if err == nil {
		t.Fatalf("expected MoveBlob to report failure when the old copy cannot be removed")
	}

	// The critical invariant: never leave two live copies after this
	// method returns, regardless of whether it reports success or
	// failure.
	if backendA.has(stored.BlobRef) && backendB.has(stored.BlobRef) {
		t.Fatalf("dual copy detected after a failed move: both backend A and backend B hold the blob")
	}
	if !backendA.has(stored.BlobRef) {
		t.Fatalf("expected the old copy (backend A) to remain the sole copy after a rolled-back move")
	}
}

func TestMoveBlob_UnknownNewPolicyRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("x"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}
	_, err = svc.MoveBlob(MoveBlobRequest{BlobRef: stored.BlobRef, NewPolicyID: "does-not-exist", RequestingSubject: "identity:alice"})
	if !errors.Is(err, ErrUnknownPolicy) {
		t.Fatalf("expected ErrUnknownPolicy, got %v", err)
	}
}

// --- DeleteBlob: physical-delete path ---

func TestDeleteBlob_PhysicalDeletePath(t *testing.T) {
	svc, audit, _, backendA, _ := newTestService(t, true)
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("delete me"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}
	if !svc.store.hasWrappingKey(stored.BlobRef) {
		t.Fatalf("test setup: expected a wrapping key to exist before delete")
	}

	_, err = svc.DeleteBlob(DeleteBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("DeleteBlob: %v", err)
	}

	if backendA.has(stored.BlobRef) {
		t.Fatalf("expected the physical-delete path to genuinely remove the bytes from the backend")
	}

	record, found := svc.store.get(stored.BlobRef)
	if !found {
		t.Fatalf("expected a tombstone record to remain after delete")
	}
	if !record.Deleted || record.DeletionMechanism != DeletionMechanismPhysical {
		t.Fatalf("expected DeletionMechanism == %q, got record %+v", DeletionMechanismPhysical, record)
	}

	if _, err := svc.RetrieveBlob(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"}); !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("expected RetrieveBlob to fail with ErrBlobNotFound after physical delete, got %v", err)
	}

	loc, err := svc.GetStorageLocation(GetStorageLocationRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("GetStorageLocation after delete: %v", err)
	}
	if loc.HumanReadableLocation == "" {
		t.Fatalf("expected GetStorageLocation to still answer for a deleted blob (Art. 15 — inspectable, not hidden)")
	}

	foundDeleteEvent := false
	for _, c := range audit.calls {
		if c.action == "storage.delete_blob" && c.metadata["deletion_mechanism"] == DeletionMechanismPhysical {
			foundDeleteEvent = true
		}
	}
	if !foundDeleteEvent {
		t.Fatalf("expected a storage.delete_blob audit event with deletion_mechanism=%q", DeletionMechanismPhysical)
	}
}

// --- DeleteBlob: crypto-shred path ---

// TestDeleteBlob_CryptoShredPath is the load-bearing test for this
// capability's crypto-shred fallback: it proves, independently of any
// "trust me," that (1) the wrapping key genuinely existed and genuinely
// decrypted the stored bytes before deletion, (2) DeleteBlob on a backend
// that cannot guarantee physical erasure destroys that key rather than
// merely hiding it, (3) the sealed bytes remain physically present in the
// backend (this backend cannot erase them — that's the whole premise of
// needing the fallback) yet are permanently unrecoverable without the now-
// destroyed key.
func TestDeleteBlob_CryptoShredPath(t *testing.T) {
	backendNoPhysicalDelete := newFakeBackend(false /* SupportsPhysicalDelete */, "fake-no-erase")
	checker := newFakePermissionChecker(true)
	audit := newFakeAuditEmitter()

	svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backendNoPhysicalDelete}}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	original := []byte("this must become permanently unrecoverable")
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: original, PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}

	// (1) Prove the key/ciphertext relationship is real BEFORE deletion:
	// capture the key via a test-only accessor and independently decrypt
	// the raw sealed bytes sitting in the backend.
	keyBefore, ok := svc.store.wrappingKey(stored.BlobRef)
	if !ok {
		t.Fatalf("test setup: expected a wrapping key to exist before delete")
	}
	keyCopy := append([]byte(nil), keyBefore...)

	rawSealedBefore, ok := backendNoPhysicalDelete.rawBytes(stored.BlobRef)
	if !ok {
		t.Fatalf("test setup: expected sealed bytes to exist in the backend before delete")
	}
	opened, err := openOuterEnvelope(keyCopy, rawSealedBefore)
	if err != nil || string(opened) != string(original) {
		t.Fatalf("test setup: pre-deletion decrypt with the real key must succeed and match original; err=%v got=%q", err, opened)
	}

	// (2) Delete. This backend reports SupportsPhysicalDelete() == false,
	// so the service must take the crypto-shred branch.
	_, err = svc.DeleteBlob(DeleteBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("DeleteBlob: %v", err)
	}

	record, found := svc.store.get(stored.BlobRef)
	if !found || record.DeletionMechanism != DeletionMechanismCryptoShred {
		t.Fatalf("expected DeletionMechanism == %q, got record %+v (found=%v)", DeletionMechanismCryptoShred, record, found)
	}

	// The key is genuinely gone from the running system — not just
	// unreturned by some API, but actually absent from the store.
	if svc.store.hasWrappingKey(stored.BlobRef) {
		t.Fatalf("expected the wrapping key to be destroyed (absent from the store) after crypto-shred delete")
	}

	// The sealed bytes are STILL physically present in this backend —
	// that is the entire premise of needing the crypto-shred fallback
	// (this backend cannot guarantee byte-level erasure). Proving this
	// is what makes the "unrecoverable despite bytes remaining" claim
	// meaningful rather than vacuous.
	rawSealedAfter, stillPresent := backendNoPhysicalDelete.rawBytes(stored.BlobRef)
	if !stillPresent {
		t.Fatalf("expected sealed bytes to remain physically present after crypto-shred (this backend cannot erase them)")
	}
	if string(rawSealedAfter) != string(rawSealedBefore) {
		t.Fatalf("expected the sealed bytes themselves to be unchanged by crypto-shred (only the key is destroyed)")
	}

	// (3) Prove those still-present bytes are genuinely unrecoverable:
	// the correct key is provably gone (assertion above); attempting to
	// open the still-present ciphertext with any key other than the one
	// that is now destroyed fails — including a zeroed key of the same
	// length, standing in for "no correct key is obtainable anymore."
	zeroed := make([]byte, wrappingKeySize)
	if _, err := openOuterEnvelope(zeroed, rawSealedAfter); err == nil {
		t.Fatalf("expected the still-present sealed bytes to be unrecoverable without the destroyed key")
	}

	// The service-level API confirms the same thing end-to-end: no path
	// to the plaintext remains.
	if _, err := svc.RetrieveBlob(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"}); !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("expected RetrieveBlob to fail with ErrBlobNotFound after crypto-shred delete, got %v", err)
	}

	foundDeleteEvent := false
	for _, c := range audit.calls {
		if c.action == "storage.delete_blob" && c.metadata["deletion_mechanism"] == DeletionMechanismCryptoShred {
			foundDeleteEvent = true
		}
	}
	if !foundDeleteEvent {
		t.Fatalf("expected a storage.delete_blob audit event with deletion_mechanism=%q", DeletionMechanismCryptoShred)
	}
}

func TestDeleteBlob_AlreadyDeletedRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("x"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}
	if _, err := svc.DeleteBlob(DeleteBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"}); err != nil {
		t.Fatalf("first DeleteBlob: %v", err)
	}
	_, err = svc.DeleteBlob(DeleteBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
	if !errors.Is(err, ErrBlobAlreadyDeleted) {
		t.Fatalf("expected ErrBlobAlreadyDeleted, got %v", err)
	}
}

func TestDeleteBlob_PermissionDenied(t *testing.T) {
	backendA := newFakeBackend(true, "fake-a")
	allowChecker := newFakePermissionChecker(true)
	audit := newFakeAuditEmitter()
	svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backendA}}, allowChecker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("x"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}

	denyChecker := newFakePermissionChecker(false)
	svcDeny, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backendA}}, denyChecker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	_, err = svcDeny.DeleteBlob(DeleteBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:mallory"})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
	// Blob must remain intact after a denied delete attempt.
	if !backendA.has(stored.BlobRef) {
		t.Fatalf("expected the blob to remain untouched after a denied delete attempt")
	}
}

// --- ListStoragePolicies ---

func TestListStoragePolicies_OnlyAdvertisesConfiguredPolicies(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	resp, err := svc.ListStoragePolicies(ListStoragePoliciesRequest{})
	if err != nil {
		t.Fatalf("ListStoragePolicies: %v", err)
	}
	if len(resp.Policies) != 2 {
		t.Fatalf("expected exactly 2 policies, got %d", len(resp.Policies))
	}
	ids := map[string]bool{}
	for _, p := range resp.Policies {
		ids[p.PolicyID] = true
		if p.DisplayName == "" || p.Description == "" {
			t.Fatalf("expected every advertised policy to have a display name and description: %+v", p)
		}
	}
	if !ids["policy-a"] || !ids["policy-b"] {
		t.Fatalf("expected policy-a and policy-b to be advertised, got %v", ids)
	}
}

func TestNewService_RejectsEmptyPolicySet(t *testing.T) {
	_, err := NewService(NewInMemoryStore(), nil, newFakePermissionChecker(true), newFakeAuditEmitter())
	if err == nil {
		t.Fatalf("expected NewService to reject an empty policy set")
	}
}

// TestNewService_RegistersBlobPolicyOnConstruction proves NewService calls
// PermissionChecker.DefinePolicy for resourceTypeBlob exactly once, at
// construction, before returning — this is what stops a real
// Permissions.CheckPermission from failing closed on "blob" for every
// gated call this package makes (see docs/DECISION_LOG.md, "Storage:
// register 'blob' Permissions policy at construction").
func TestNewService_RegistersBlobPolicyOnConstruction(t *testing.T) {
	checker := newFakePermissionChecker(true)
	backend := newFakeBackend(true, "fake")
	policies := []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}

	if _, err := NewService(NewInMemoryStore(), policies, checker, newFakeAuditEmitter()); err != nil {
		t.Fatalf("NewService: %v", err)
	}

	checker.mu.Lock()
	calls := checker.definePolicyCall
	checker.mu.Unlock()

	if len(calls) != 1 {
		t.Fatalf("expected exactly one DefinePolicy call, got %d: %+v", len(calls), calls)
	}
	if calls[0].resourceType != resourceTypeBlob {
		t.Fatalf("expected DefinePolicy to register resource type %q, got %q", resourceTypeBlob, calls[0].resourceType)
	}
	if calls[0].defaultRules != blobDefaultRules {
		t.Fatalf("expected DefinePolicy to be called with default_rules %q, got %q", blobDefaultRules, calls[0].defaultRules)
	}
}

// TestNewService_PropagatesDefinePolicyFailure proves a failure to
// register the default policy surfaces as a loud construction-time error
// rather than a Service that silently proceeds without ever having
// registered "blob" — the same "fail loudly, not silently" discipline
// this package applies to every other mutation whose audit emit can fail
// (DefinePolicy's own audit emit is what could fail here, per
// permissions.Service.DefinePolicy's doc comment).
func TestNewService_PropagatesDefinePolicyFailure(t *testing.T) {
	checker := newFakePermissionChecker(true)
	checker.definePolicyErr = errors.New("fake: define policy failed")
	backend := newFakeBackend(true, "fake")
	policies := []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}

	if _, err := NewService(NewInMemoryStore(), policies, checker, newFakeAuditEmitter()); err == nil {
		t.Fatalf("expected NewService to propagate a DefinePolicy failure")
	}
}

// --- GetStorageLocation ---

func TestGetStorageLocation_NotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	_, err := svc.GetStorageLocation(GetStorageLocationRequest{BlobRef: "blob_never_existed", RequestingSubject: "identity:alice"})
	if !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("expected ErrBlobNotFound, got %v", err)
	}
}

func TestGetStorageLocation_MissingRequestingSubjectRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("x"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}
	_, err = svc.GetStorageLocation(GetStorageLocationRequest{BlobRef: stored.BlobRef})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

// TestGetStorageLocation_DeniedForNonGrantedSubject/_AllowedForOwner/
// _AllowedForGrantedSubject use realisticPermissionChecker (not the plain
// allow/deny fakePermissionChecker) specifically because they need to
// distinguish owner vs. granted vs. neither for the SAME subject field —
// a blanket allow/deny fake cannot express that distinction. Proves the
// 2026-07-17 gating fix (docs/DECISION_LOG.md, "Storage follow-ups...")
// end to end: GetStorageLocation is gated on the exact same
// ActionRetrieveBlob action/resource RetrieveBlob itself uses.
func TestGetStorageLocation_DeniedForNonGrantedSubject(t *testing.T) {
	checker := newRealisticPermissionChecker()
	backend := newFakeBackend(true, "fake")
	audit := newFakeAuditEmitter()
	svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("x"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}
	checker.establishOwner("identity:alice", resourceTypeBlob, stored.BlobRef)

	_, err = svc.GetStorageLocation(GetStorageLocationRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:mallory"})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for a non-owner, non-granted subject, got %v", err)
	}
	last, ok := audit.lastCall()
	if !ok || last.action != "storage.get_storage_location_denied" {
		t.Fatalf("expected a storage.get_storage_location_denied audit event, got %+v (ok=%v)", last, ok)
	}
}

func TestGetStorageLocation_AllowedForOwner(t *testing.T) {
	checker := newRealisticPermissionChecker()
	backend := newFakeBackend(true, "fake")
	audit := newFakeAuditEmitter()
	svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("x"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}
	checker.establishOwner("identity:alice", resourceTypeBlob, stored.BlobRef)

	loc, err := svc.GetStorageLocation(GetStorageLocationRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("expected the owner to be allowed, got %v", err)
	}
	if loc.HumanReadableLocation == "" {
		t.Fatalf("expected a non-empty human_readable_location")
	}
}

func TestGetStorageLocation_AllowedForGrantedSubject(t *testing.T) {
	checker := newRealisticPermissionChecker()
	backend := newFakeBackend(true, "fake")
	audit := newFakeAuditEmitter()
	svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("x"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}
	checker.establishOwner("identity:alice", resourceTypeBlob, stored.BlobRef)
	checker.grant("identity:bob", ActionRetrieveBlob, resourceTypeBlob, stored.BlobRef)

	loc, err := svc.GetStorageLocation(GetStorageLocationRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:bob"})
	if err != nil {
		t.Fatalf("expected a subject with an active storage.retrieve_blob grant to be allowed, got %v", err)
	}
	if loc.HumanReadableLocation == "" {
		t.Fatalf("expected a non-empty human_readable_location")
	}
}
