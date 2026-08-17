package storage

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestExportBlobRecord proves BlobRecord (ascend:persisted) has a working,
// parseable export path, per Art. 9 / scripts/constitution/check-export-paths.sh.
func TestExportBlobRecord(t *testing.T) {
	r := BlobRecord{
		BlobRef:       "blob_abc123",
		Owner:         "identity:alice",
		PolicyID:      "policy-a",
		SizeBytes:     42,
		CreatedAtUnix: 1700000000,
		Location:      "local-filesystem:/tmp/blob_abc123",
	}

	blob, err := ExportBlobRecord(r)
	if err != nil {
		t.Fatalf("ExportBlobRecord returned error: %v", err)
	}

	var roundTripped BlobRecord
	if err := json.Unmarshal(blob, &roundTripped); err != nil {
		t.Fatalf("exported BlobRecord blob did not parse back as JSON: %v", err)
	}
	if roundTripped != r {
		t.Fatalf("round-tripped BlobRecord does not match original: got %+v, want %+v", roundTripped, r)
	}
}

// TestExportBlobRecord_TombstoneRoundtrips proves a deleted blob's
// tombstone form (Deleted/DeletedAtUnix/DeletionMechanism populated) also
// round-trips cleanly — the export path must remain honest for deleted
// blobs, not only live ones.
func TestExportBlobRecord_TombstoneRoundtrips(t *testing.T) {
	r := BlobRecord{
		BlobRef:           "blob_deleted1",
		Owner:             "identity:alice",
		PolicyID:          "policy-a",
		SizeBytes:         10,
		CreatedAtUnix:     1700000000,
		Location:          "local-filesystem:/tmp/blob_deleted1",
		Deleted:           true,
		DeletedAtUnix:     1700000500,
		DeletionMechanism: DeletionMechanismCryptoShred,
	}
	blob, err := ExportBlobRecord(r)
	if err != nil {
		t.Fatalf("ExportBlobRecord returned error: %v", err)
	}
	var roundTripped BlobRecord
	if err := json.Unmarshal(blob, &roundTripped); err != nil {
		t.Fatalf("exported tombstone BlobRecord did not parse back as JSON: %v", err)
	}
	if roundTripped != r {
		t.Fatalf("round-tripped tombstone BlobRecord does not match original: got %+v, want %+v", roundTripped, r)
	}
}

// TestExportAllBlobs_IncludesLiveContentExcludesDeletedContent proves
// ExportAllBlobs (Art. 9) actually bundles usable content for live blobs,
// and is honest (no content, but full tombstone metadata) for deleted
// ones — a genuinely usable, self-describing, versioned export, per this
// capability's spawn brief.
func TestExportAllBlobs_IncludesLiveContentExcludesDeletedContent(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)

	live, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("live content"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob (live): %v", err)
	}
	deleted, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("will be deleted"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob (to-be-deleted): %v", err)
	}
	if _, err := svc.DeleteBlob(DeleteBlobRequest{BlobRef: deleted.BlobRef, RequestingSubject: "identity:alice"}); err != nil {
		t.Fatalf("DeleteBlob: %v", err)
	}

	resp, err := svc.ExportAllBlobs(ExportAllBlobsRequest{Owner: "identity:alice", RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("ExportAllBlobs: %v", err)
	}
	if resp.FormatVersion == "" {
		t.Fatalf("expected a non-empty format_version")
	}

	var doc struct {
		FormatVersion string `json:"formatVersion"`
		Owner         string `json:"owner"`
		Blobs         []struct {
			BlobRef           string `json:"blobRef"`
			Deleted           bool   `json:"deleted"`
			DeletionMechanism string `json:"deletionMechanism"`
			Data              []byte `json:"data"`
		} `json:"blobs"`
	}
	if err := json.Unmarshal(resp.ExportBlob, &doc); err != nil {
		t.Fatalf("export_blob did not parse as JSON independently of this package: %v", err)
	}
	if doc.FormatVersion != resp.FormatVersion {
		t.Fatalf("embedded formatVersion %q does not match response FormatVersion %q", doc.FormatVersion, resp.FormatVersion)
	}
	if doc.Owner != "identity:alice" {
		t.Fatalf("expected owner identity:alice, got %q", doc.Owner)
	}
	if len(doc.Blobs) != 2 {
		t.Fatalf("expected 2 blob entries (1 live, 1 tombstone), got %d", len(doc.Blobs))
	}

	for _, b := range doc.Blobs {
		switch b.BlobRef {
		case live.BlobRef:
			if b.Deleted {
				t.Fatalf("expected the live blob's export entry to have deleted=false")
			}
			if string(b.Data) != "live content" {
				t.Fatalf("expected the live blob's export entry to contain its original bytes, got %q", b.Data)
			}
		case deleted.BlobRef:
			if !b.Deleted || b.DeletionMechanism == "" {
				t.Fatalf("expected the deleted blob's export entry to be a fully-described tombstone, got %+v", b)
			}
			if len(b.Data) != 0 {
				t.Fatalf("expected the deleted blob's export entry to carry NO content, got %d bytes", len(b.Data))
			}
		default:
			t.Fatalf("unexpected blob_ref in export: %s", b.BlobRef)
		}
	}
}

func TestExportAllBlobs_EmptyOwnerRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	_, err := svc.ExportAllBlobs(ExportAllBlobsRequest{Owner: ""})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestExportAllBlobs_MissingRequestingSubjectRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	_, err := svc.ExportAllBlobs(ExportAllBlobsRequest{Owner: "identity:alice", RequestingSubject: ""})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

// TestExportAllBlobs_DeniedForNonOwnerEvenWithFullGrantCoverage is the
// load-bearing proof for the 2026-07-17 gating fix
// (docs/DECISION_LOG.md, "Storage follow-ups..."): ExportAllBlobs is
// rejected for anyone other than the exact owner, even a subject who
// holds a valid, active storage.retrieve_blob grant on EVERY one of the
// owner's blobs — bulk export specifically requires being the owner;
// full per-blob grant coverage is not a substitute. Uses an
// allow-everything PermissionChecker deliberately: if ExportAllBlobs
// mistakenly delegated to CheckPermission (instead of its own direct
// owner-equality check), this test would incorrectly pass, so a failure
// here would prove the implementation regressed to the wrong design.
// Also asserts CheckPermission is never called at all, proving
// ExportAllBlobs's own doc-commented claim that it is not
// CheckPermission-gated per blob.
func TestExportAllBlobs_DeniedForNonOwnerEvenWithFullGrantCoverage(t *testing.T) {
	checker := newFakePermissionChecker(true) // allow-everything, on purpose — see doc comment above
	backend := newFakeBackend(true, "fake")
	audit := newFakeAuditEmitter()
	svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	var blobRefs []string
	for i := 0; i < 3; i++ {
		stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("secret"), PolicyID: "policy-a"})
		if err != nil {
			t.Fatalf("StoreBlob: %v", err)
		}
		blobRefs = append(blobRefs, stored.BlobRef)
	}
	// checker.allow is already true for every subject/action/resource —
	// this stands in for "bob holds an active storage.retrieve_blob grant
	// on every one of alice's blobs."
	_ = blobRefs

	checker.mu.Lock()
	checker.calls = nil // reset: only StoreBlob calls (none, StoreBlob doesn't check permission) may have landed above
	checker.mu.Unlock()

	_, err = svc.ExportAllBlobs(ExportAllBlobsRequest{Owner: "identity:alice", RequestingSubject: "identity:bob"})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for a non-owner subject despite full per-blob grant coverage, got %v", err)
	}

	checker.mu.Lock()
	callCount := len(checker.calls)
	checker.mu.Unlock()
	if callCount != 0 {
		t.Fatalf("expected ExportAllBlobs to never call CheckPermission at all (bulk export is owner-only, not per-blob gated), but it was called %d time(s)", callCount)
	}

	last, ok := audit.lastCall()
	if !ok || last.action != "storage.export_all_blobs_denied" {
		t.Fatalf("expected a storage.export_all_blobs_denied audit event, got %+v (ok=%v)", last, ok)
	}
}

func TestExportAllBlobs_AllowedForExactOwner(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, true)
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("x"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}
	resp, err := svc.ExportAllBlobs(ExportAllBlobsRequest{Owner: "identity:alice", RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("expected the exact owner to be allowed, got %v", err)
	}
	if resp.FormatVersion == "" {
		t.Fatalf("expected a non-empty format_version")
	}
	_ = stored
}
