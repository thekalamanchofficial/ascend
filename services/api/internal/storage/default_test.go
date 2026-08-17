package storage

import (
	"errors"
	"os"
	"testing"
)

// TestNewFilesystemService_EndToEnd exercises the real, production-shaped
// constructor (two genuine local-filesystem-backed policies, real
// physical delete) end to end: store, retrieve, move between the two real
// policies, and physically delete — proving the whole stack works
// against actual disk I/O, not only fakes.
func TestNewFilesystemService_EndToEnd(t *testing.T) {
	checker := newFakePermissionChecker(true)
	audit := newFakeAuditEmitter()
	svc, err := NewFilesystemService(NewInMemoryStore(), checker, audit)
	if err != nil {
		t.Fatalf("NewFilesystemService: %v", err)
	}
	// Clean up the real .data directories this test creates on disk.
	t.Cleanup(func() {
		_ = os.RemoveAll(DefaultDataDir(PolicyLocalDefault))
		_ = os.RemoveAll(DefaultDataDir(PolicyLocalSecondary))
	})

	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("real disk io"), PolicyID: PolicyLocalDefault})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}

	got, err := svc.RetrieveBlob(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("RetrieveBlob: %v", err)
	}
	if string(got.Data) != "real disk io" {
		t.Fatalf("got %q, want %q", got.Data, "real disk io")
	}

	moveResp, err := svc.MoveBlob(MoveBlobRequest{BlobRef: stored.BlobRef, NewPolicyID: PolicyLocalSecondary, RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("MoveBlob: %v", err)
	}
	if moveResp.NewLocation == "" {
		t.Fatalf("expected a non-empty new_location")
	}

	if _, err := svc.DeleteBlob(DeleteBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"}); err != nil {
		t.Fatalf("DeleteBlob: %v", err)
	}

	if _, err := svc.RetrieveBlob(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"}); !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("expected ErrBlobNotFound after real physical delete, got %v", err)
	}
}
