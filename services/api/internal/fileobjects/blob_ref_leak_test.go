package fileobjects

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// This file holds the three tests charter §6 point 8 explicitly requires
// at implementation time — "required, test-backed" for each of (a), (b),
// and (c). blob_ref must never be returned through any File Objects RPC
// response, audit event, or error message; these tests prove each of the
// three concrete leak paths Security Steward traced at charter-freeze
// review is actually closed by this implementation, not just asserted in
// prose.

// (a) GetFileHistory/ExportFile return ONLY File Objects' own emitted
// events — never a raw aggregation of the Permissions/Storage calls this
// package makes internally (whose blob-level mirror events legitimately
// carry blob_ref, per Permissions'/Storage's own Art. 8 data manifests).
func TestPoint8a_HistoryAndExportContainOnlyFileObjectsOwnEventsNoBlobRef(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2")}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionRead, Scope: "read",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	name := "renamed.pdf"
	if _, err := svc.SetFileMetadata(SetFileMetadataRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Name: &name}); err != nil {
		t.Fatalf("SetFileMetadata: %v", err)
	}

	// Collect every blob_ref that actually exists, so we know exactly what
	// a leak would look like.
	var blobRefs []string
	for _, v := range storeVersionsFor(t, svc, fo.FileObjectID) {
		blobRefs = append(blobRefs, v.BlobRef)
	}
	if len(blobRefs) != 2 {
		t.Fatalf("expected 2 blob refs, got %d", len(blobRefs))
	}

	hist, err := svc.GetFileHistory(GetFileHistoryRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("GetFileHistory: %v", err)
	}

	// Exactly File Objects' own 4 mutation events so far — create,
	// create_version, permission_granted, set_file_metadata. Nothing about
	// the blob-level mirror GrantPermission call File Objects itself made
	// internally.
	wantActions := map[string]bool{
		"fileobjects.create_file_object": true,
		"fileobjects.create_version":     true,
		"fileobjects.permission_granted": true,
		"fileobjects.set_file_metadata":  true,
	}
	if len(hist.Events) != len(wantActions) {
		t.Fatalf("expected exactly %d events, got %d: %+v", len(wantActions), len(hist.Events), hist.Events)
	}
	for _, e := range hist.Events {
		if !wantActions[e.Action] {
			t.Fatalf("unexpected event action %q — GetFileHistory must return ONLY File Objects' own emitted events", e.Action)
		}
		assertNoBlobRefSubstring(t, "GetFileHistory event", e.Action, blobRefs)
		assertNoBlobRefSubstring(t, "GetFileHistory event actor", e.Actor, blobRefs)
		for k, v := range e.Metadata {
			assertNoBlobRefSubstring(t, "GetFileHistory event metadata["+k+"]", v, blobRefs)
		}
	}

	exp, err := svc.ExportFile(ExportFileRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("ExportFile: %v", err)
	}
	exportText := string(exp.ExportBlob)
	for _, ref := range blobRefs {
		if strings.Contains(exportText, ref) {
			t.Fatalf("ExportFile's export bundle contains a blob_ref (%q) — charter §6 point 8 violation", ref)
		}
	}
}

func assertNoBlobRefSubstring(t *testing.T, label, value string, blobRefs []string) {
	t.Helper()
	for _, ref := range blobRefs {
		if ref != "" && strings.Contains(value, ref) {
			t.Fatalf("%s (%q) contains a blob_ref (%q) — charter §6 point 8 violation", label, value, ref)
		}
	}
}

// (b) GetFileContent/ExportFile must catch and re-wrap ANY error from
// Storage.RetrieveBlob into a File-Objects-level error — never propagate
// Storage's raw error text verbatim, since it could embed a blob_ref.
func TestPoint8b_StorageErrorsAreReWrappedNeverPropagatedVerbatim(t *testing.T) {
	svc, storage, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	versions := storeVersionsFor(t, svc, fo.FileObjectID)
	blobRef := versions[0].BlobRef

	secretLeak := "super-secret-internal-path/" + blobRef + "/wrapping-key-material-xyz789"
	storage.retrieveErrFor[blobRef] = fmt.Errorf("storage: backend retrieve failed for blob %s at %s: permission denied", blobRef, secretLeak)

	_, err := svc.GetFileContent(GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err == nil {
		t.Fatalf("expected GetFileContent to fail")
	}
	if !errors.Is(err, ErrContentUnavailable) {
		t.Fatalf("expected ErrContentUnavailable, got %v", err)
	}
	if strings.Contains(err.Error(), blobRef) || strings.Contains(err.Error(), secretLeak) {
		t.Fatalf("GetFileContent propagated Storage's raw error text verbatim — blob_ref/secret leaked: %v", err)
	}

	_, err = svc.ExportFile(ExportFileRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err == nil {
		t.Fatalf("expected ExportFile to fail")
	}
	if !errors.Is(err, ErrContentUnavailable) {
		t.Fatalf("expected ErrContentUnavailable, got %v", err)
	}
	if strings.Contains(err.Error(), blobRef) || strings.Contains(err.Error(), secretLeak) {
		t.Fatalf("ExportFile propagated Storage's raw error text verbatim — blob_ref/secret leaked: %v", err)
	}
}

// (c) A subject who is granted, then revoked, fileobjects.read access must
// never be able to discover a blob_ref via ANY File Objects RPC — before
// the revoke they legitimately never receive one (blob_ref is never
// returned through any response, per (a)/(b) above and the RPC surface
// itself), and after the revoke they are denied outright. This test
// exercises every RPC the revoked subject could call, as that subject,
// confirming each is either denied or — for the two RPCs whose full
// bundles were captured while access was still valid — never contained a
// blob_ref to begin with.
func TestPoint8c_GrantedThenRevokedSubjectCannotDiscoverBlobRef(t *testing.T) {
	svc, _, perms, audit := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	versions := storeVersionsFor(t, svc, fo.FileObjectID)
	blobRef := versions[0].BlobRef

	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionRead, Scope: "read",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	// While access is valid, prove none of the granted subject's
	// legitimate reads ever surface blob_ref either (the RPC contract
	// itself structurally never returns one, but confirm concretely).
	if content, err := svc.GetFileContent(GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: collaborator}); err != nil || strings.Contains(string(content.Content), blobRef) {
		t.Fatalf("unexpected: GetFileContent err=%v content=%q", err, content.Content)
	}
	if lv, err := svc.ListVersions(ListVersionsRequest{FileObjectID: fo.FileObjectID, RequestingSubject: collaborator}); err != nil {
		t.Fatalf("ListVersions: %v", err)
	} else {
		for _, v := range lv.Versions {
			// VersionSummary structurally has no blob_ref field at all —
			// nothing to assert beyond "it compiles", but confirm the
			// version_ref itself isn't secretly the blob_ref.
			if v.VersionRef == blobRef {
				t.Fatalf("version_ref must never equal blob_ref")
			}
		}
	}

	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: false,
		Subject: collaborator, Action: ActionRead,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Charter §6 point 8's closing reasoning: the mirrored Grant/Revoke
	// calls' actor is the file's OWNER (grantor), never the
	// granted/revoked subject — so File Objects' own audit trail never
	// attributes a blob-bearing action to the revoked subject either. This
	// is exactly what would make Audit's own fail-closed cross-subject
	// Query default protect the revoked subject even if they could query
	// Audit directly (a separate capability this package doesn't own —
	// reasoned through in the charter, verified here against File Objects'
	// own emitted calls specifically).
	for _, c := range audit.allCalls() {
		if c.actor == collaborator {
			assertNoBlobRefSubstring(t, "audit call actor="+collaborator, c.action, []string{blobRef})
			for _, v := range c.metadata {
				assertNoBlobRefSubstring(t, "audit call actor="+collaborator+" metadata", v, []string{blobRef})
			}
		}
	}
	if perms.hasActiveGrant(collaborator, storageRetrieveBlobAction, resourceTypeBlob, blobRef) {
		t.Fatalf("expected collaborator's blob-level grant to be gone after revoke")
	}

	// After revoke: every read RPC denies the (former) collaborator
	// outright — no path to even attempt discovering a blob_ref.
	if _, err := svc.GetFileContent(GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: collaborator}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("GetFileContent: expected ErrPermissionDenied post-revoke, got %v", err)
	}
	if _, err := svc.ListVersions(ListVersionsRequest{FileObjectID: fo.FileObjectID, RequestingSubject: collaborator}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("ListVersions: expected ErrPermissionDenied post-revoke, got %v", err)
	}
	if _, err := svc.GetFileHistory(GetFileHistoryRequest{FileObjectID: fo.FileObjectID, RequestingSubject: collaborator}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("GetFileHistory: expected ErrPermissionDenied post-revoke, got %v", err)
	}
	if _, err := svc.GetFileMetadata(GetFileMetadataRequest{FileObjectID: fo.FileObjectID, RequestingSubject: collaborator}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("GetFileMetadata: expected ErrPermissionDenied post-revoke, got %v", err)
	}
	if _, err := svc.ExportFile(ExportFileRequest{FileObjectID: fo.FileObjectID, RequestingSubject: collaborator}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("ExportFile: expected ErrPermissionDenied post-revoke, got %v", err)
	}
}
