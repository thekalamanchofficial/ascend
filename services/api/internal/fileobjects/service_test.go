package fileobjects

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	owner        = "identity:alice"
	collaborator = "identity:bob"
	stranger     = "identity:mallory"
)

func createTestFileObject(t *testing.T, svc *Service, ownerRef string, content []byte) FileObject {
	t.Helper()
	resp, err := svc.CreateFileObject(CreateFileObjectRequest{
		Owner:             ownerRef,
		RequestingSubject: ownerRef,
		InitialContent:    content,
		Name:              "report.pdf",
		MimeType:          "application/pdf",
	})
	if err != nil {
		t.Fatalf("CreateFileObject: %v", err)
	}
	return resp.FileObject
}

// --- construction / policy registration -----------------------------

func TestNewService_RegistersFileObjectPolicyOnConstruction(t *testing.T) {
	_, _, perms, _ := newTestService(t)
	if len(perms.definePolicyCalls) != 1 || perms.definePolicyCalls[0] != resourceTypeFileObject {
		t.Fatalf("expected exactly one DefinePolicy call for %q, got %v", resourceTypeFileObject, perms.definePolicyCalls)
	}
	// Must NOT register "blob" — that is Storage's own construction-time
	// responsibility (charter §6 point 0).
	for _, rt := range perms.definePolicyCalls {
		if rt == resourceTypeBlob {
			t.Fatalf("fileobjects.NewService must not register %q's policy — that is Storage's responsibility", resourceTypeBlob)
		}
	}
}

func TestNewService_PropagatesDefinePolicyFailure(t *testing.T) {
	perms := newMemPermissions()
	perms.definePolicyErr = errors.New("boom")
	_, err := NewService(newInMemoryStore(), newFakeStorageClient(), perms, newFakeAuditEmitter())
	if err == nil {
		t.Fatalf("expected NewService to propagate a DefinePolicy failure as a construction-time error")
	}
}

// --- CreateFileObject --------------------------------------------------

func TestCreateFileObject_HappyPath(t *testing.T) {
	svc, storage, perms, audit := newTestService(t)

	fo := createTestFileObject(t, svc, owner, []byte("hello world"))

	if fo.FileObjectID == "" || fo.CurrentVersionRef == "" {
		t.Fatalf("expected non-empty file_object_id/current_version_ref, got %+v", fo)
	}
	if fo.SizeBytes != int64(len("hello world")) {
		t.Fatalf("size_bytes = %d, want %d", fo.SizeBytes, len("hello world"))
	}

	// Bootstrap grants established (charter §6 point 2).
	if !perms.hasActiveGrant(owner, ActionRead, resourceTypeFileObject, fo.FileObjectID) {
		t.Fatalf("expected owner to hold fileobjects.read on the new file object")
	}
	if !perms.hasActiveGrant(owner, ActionWrite, resourceTypeFileObject, fo.FileObjectID) {
		t.Fatalf("expected owner to hold fileobjects.write on the new file object")
	}
	if o, ok := perms.ownerOf(resourceTypeFileObject, fo.FileObjectID); !ok || o != owner {
		t.Fatalf("expected %q to be the implicit Permissions owner of the file object, got %q (found=%v)", owner, o, ok)
	}

	versions := storeVersionsFor(t, svc, fo.FileObjectID)
	if len(versions) != 1 {
		t.Fatalf("expected exactly one version after CreateFileObject, got %d", len(versions))
	}
	if !perms.hasActiveGrant(owner, storageRetrieveBlobAction, resourceTypeBlob, versions[0].BlobRef) {
		t.Fatalf("expected owner to hold storage.retrieve_blob on version 1's blob")
	}
	if !storage.has(versions[0].BlobRef) {
		t.Fatalf("expected version 1's blob to actually be stored")
	}

	if audit.callCount() != 1 {
		t.Fatalf("expected exactly one audit event for CreateFileObject, got %d", audit.callCount())
	}
	last, _ := audit.lastCall()
	if last.action != "fileobjects.create_file_object" {
		t.Fatalf("audit action = %q", last.action)
	}
}

// storeVersionsFor is a small test-only helper reaching into Service's
// store — acceptable white-box access from within this package's own test
// suite.
func storeVersionsFor(t *testing.T, svc *Service, fileObjectID string) []VersionRecord {
	t.Helper()
	return svc.store.listVersions(fileObjectID)
}

func TestCreateFileObject_RejectsEmptyContent(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	_, err := svc.CreateFileObject(CreateFileObjectRequest{Owner: owner, RequestingSubject: owner, InitialContent: nil})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

// --- CreateVersion -------------------------------------------------------

func TestCreateVersion_HappyPath_UpdatesCurrentVersionAndSize(t *testing.T) {
	svc, _, _, audit := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))

	resp, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("version two content")})
	if err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	if resp.VersionRef == "" || resp.VersionRef == fo.CurrentVersionRef {
		t.Fatalf("expected a fresh, distinct version_ref, got %q (v1 was %q)", resp.VersionRef, fo.CurrentVersionRef)
	}

	meta, err := svc.GetFileMetadata(GetFileMetadataRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("GetFileMetadata: %v", err)
	}
	if meta.SizeBytes != int64(len("version two content")) {
		t.Fatalf("size_bytes after CreateVersion = %d, want %d", meta.SizeBytes, len("version two content"))
	}

	versions := storeVersionsFor(t, svc, fo.FileObjectID)
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}

	if audit.callCount() != 2 { // create_file_object + create_version
		t.Fatalf("expected 2 audit events, got %d", audit.callCount())
	}
}

// TestCreateVersion_OwnerGrantedFirst_NonOwnerCollaboratorNeverBecomesBlobOwner
// is THE critical correctness test this charter's third guardian re-gate
// round exists to prove (charter §6 point 3): a non-owner collaborator who
// holds only fileobjects.write must never become the new version's blob's
// permanent Permissions-owner, even though they are the one who physically
// calls CreateVersion. It relies on memPermissions' faithful reimplementation
// of Permissions' real bootstrap_owner semantics (first-ever GrantPermission
// call on a resource sets its permanent owner) — a fake that only records
// calls and returns a fixed allow/deny could never catch this class of bug.
func TestCreateVersion_OwnerGrantedFirst_NonOwnerCollaboratorNeverBecomesBlobOwner(t *testing.T) {
	svc, _, perms, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))

	// Owner grants collaborator write-only access — no read grant, so the
	// mirror loop (which only mirrors ActionRead grantees) has nothing to
	// mirror; this isolates the test to point 3's owner-first requirement
	// specifically.
	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionWrite, Scope: "full",
	}); err != nil {
		t.Fatalf("SetFilePermissions (grant write to collaborator): %v", err)
	}

	// The collaborator — not the owner — calls CreateVersion.
	resp, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: collaborator, Content: []byte("collaborator's edit")})
	if err != nil {
		t.Fatalf("CreateVersion (by collaborator): %v", err)
	}

	v, found := svc.store.getVersion(fo.FileObjectID, resp.VersionRef)
	if !found {
		t.Fatalf("new version not found in store")
	}

	gotOwner, ok := perms.ownerOf(resourceTypeBlob, v.BlobRef)
	if !ok {
		t.Fatalf("expected the new blob to have an established Permissions owner")
	}
	if gotOwner != owner {
		t.Fatalf("SECURITY REGRESSION: new blob's permanent Permissions-owner is %q, want the file object's real owner %q — a non-owner collaborator calling CreateVersion must never become a blob's permanent owner (charter §6 point 3)", gotOwner, owner)
	}
	if !perms.hasActiveGrant(owner, storageRetrieveBlobAction, resourceTypeBlob, v.BlobRef) {
		t.Fatalf("expected the file's real owner to hold storage.retrieve_blob on the new blob")
	}
}

func TestCreateVersion_MirrorsReadAccessToExistingGrantees(t *testing.T) {
	svc, _, perms, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))

	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionRead, Scope: "read",
	}); err != nil {
		t.Fatalf("SetFilePermissions (grant read): %v", err)
	}

	resp, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2")})
	if err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	v, _ := svc.store.getVersion(fo.FileObjectID, resp.VersionRef)

	if !perms.hasActiveGrant(collaborator, storageRetrieveBlobAction, resourceTypeBlob, v.BlobRef) {
		t.Fatalf("expected collaborator's existing fileobjects.read grant to be mirrored onto the new version's blob")
	}

	// And functionally: the collaborator can now read the new version's
	// content through the real RPC surface.
	content, err := svc.GetFileContent(GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: collaborator, VersionRef: resp.VersionRef})
	if err != nil {
		t.Fatalf("GetFileContent by mirrored collaborator: %v", err)
	}
	if string(content.Content) != "v2" {
		t.Fatalf("content = %q, want %q", content.Content, "v2")
	}
}

func TestCreateVersion_DeniedWithoutWriteGrant(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))

	_, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger, Content: []byte("v2")})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

// --- GetFileContent / ListVersions / GetFileMetadata / GetFileHistory ---

func TestGetFileContent_DefaultsToCurrentVersion(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("first"))
	if _, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("second")}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}

	resp, err := svc.GetFileContent(GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("GetFileContent: %v", err)
	}
	if string(resp.Content) != "second" {
		t.Fatalf("content = %q, want current version %q", resp.Content, "second")
	}
}

func TestGetFileContent_SpecificOldVersion(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("first"))
	if _, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("second")}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}

	resp, err := svc.GetFileContent(GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, VersionRef: fo.CurrentVersionRef})
	if err != nil {
		t.Fatalf("GetFileContent (old version): %v", err)
	}
	if string(resp.Content) != "first" {
		t.Fatalf("content = %q, want old version %q", resp.Content, "first")
	}
}

func TestGetFileContent_DeniedForStranger(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("secret"))
	_, err := svc.GetFileContent(GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestListVersions_DeniedForStranger(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	_, err := svc.ListVersions(ListVersionsRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestListVersions_ReturnsAllVersionsInOrder(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2")}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}

	resp, err := svc.ListVersions(ListVersionsRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(resp.Versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(resp.Versions))
	}
	if resp.Versions[0].VersionRef != fo.CurrentVersionRef {
		t.Fatalf("expected version 1 first (creation order)")
	}
}

func TestGetFileMetadata_DeniedForStranger(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	_, err := svc.GetFileMetadata(GetFileMetadataRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestGetFileHistory_DeniedForStranger(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	_, err := svc.GetFileHistory(GetFileHistoryRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestGetFileHistory_ReturnsFileObjectsOwnEvents(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2")}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}

	resp, err := svc.GetFileHistory(GetFileHistoryRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("GetFileHistory: %v", err)
	}
	if len(resp.Events) != 2 {
		t.Fatalf("expected 2 events (create_file_object, create_version), got %d: %+v", len(resp.Events), resp.Events)
	}
	if resp.Events[0].Action != "fileobjects.create_file_object" || resp.Events[1].Action != "fileobjects.create_version" {
		t.Fatalf("unexpected event actions: %+v", resp.Events)
	}
}

// --- §4 Art. 5: single shared read-denial audit call site ---------------

func TestCheckRead_DeniedEmitsSharedAuditEvent(t *testing.T) {
	svc, _, _, audit := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))

	rpcCalls := []struct {
		name string
		call func() error
	}{
		{"GetFileContent", func() error {
			_, err := svc.GetFileContent(GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
			return err
		}},
		{"ListVersions", func() error {
			_, err := svc.ListVersions(ListVersionsRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
			return err
		}},
		{"GetFileMetadata", func() error {
			_, err := svc.GetFileMetadata(GetFileMetadataRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
			return err
		}},
		{"GetFileHistory", func() error {
			_, err := svc.GetFileHistory(GetFileHistoryRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
			return err
		}},
		{"ExportFile", func() error {
			_, err := svc.ExportFile(ExportFileRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
			return err
		}},
	}

	for _, rpc := range rpcCalls {
		before := audit.callCount()
		if err := rpc.call(); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s: expected ErrPermissionDenied, got %v", rpc.name, err)
		}
		last, ok := audit.lastCall()
		if !ok || audit.callCount() != before+1 {
			t.Fatalf("%s: expected exactly one new audit event on denial", rpc.name)
		}
		if last.action != "fileobjects.access_denied" {
			t.Fatalf("%s: audit action = %q, want fileobjects.access_denied", rpc.name, last.action)
		}
		if last.metadata["rpc"] != rpc.name {
			t.Fatalf("%s: audit metadata[rpc] = %q, want %q", rpc.name, last.metadata["rpc"], rpc.name)
		}
		if last.actor != stranger {
			t.Fatalf("%s: audit actor = %q, want %q", rpc.name, last.actor, stranger)
		}
	}
}

// --- SetFilePermissions --------------------------------------------------

func TestSetFilePermissions_RejectsInvalidAction(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	_, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: "fileobjects.admin", Scope: "full",
	})
	if !errors.Is(err, ErrInvalidPermissionAction) {
		t.Fatalf("expected ErrInvalidPermissionAction, got %v", err)
	}
}

func TestSetFilePermissions_GrantRead_MirrorsToAllVersions(t *testing.T) {
	svc, _, perms, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2")}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}

	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionRead, Scope: "read",
	}); err != nil {
		t.Fatalf("SetFilePermissions: %v", err)
	}

	if !perms.hasActiveGrant(collaborator, ActionRead, resourceTypeFileObject, fo.FileObjectID) {
		t.Fatalf("expected file-object-level read grant")
	}
	for _, v := range storeVersionsFor(t, svc, fo.FileObjectID) {
		if !perms.hasActiveGrant(collaborator, storageRetrieveBlobAction, resourceTypeBlob, v.BlobRef) {
			t.Fatalf("expected read grant mirrored onto version %s's blob", v.VersionRef)
		}
	}
}

func TestSetFilePermissions_RevokeRead_MirrorsToAllVersions(t *testing.T) {
	svc, _, perms, _ := newTestService(t)
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

	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: false,
		Subject: collaborator, Action: ActionRead,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if perms.hasActiveGrant(collaborator, ActionRead, resourceTypeFileObject, fo.FileObjectID) {
		t.Fatalf("expected file-object-level read grant to be revoked")
	}
	for _, v := range storeVersionsFor(t, svc, fo.FileObjectID) {
		if perms.hasActiveGrant(collaborator, storageRetrieveBlobAction, resourceTypeBlob, v.BlobRef) {
			t.Fatalf("expected revoke mirrored onto version %s's blob", v.VersionRef)
		}
	}

	// Functional proof: the revoked collaborator can no longer read
	// content through the real RPC surface, for ANY version.
	if _, err := svc.GetFileContent(GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: collaborator, VersionRef: fo.CurrentVersionRef}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected revoked collaborator to be denied on the old version too, got %v", err)
	}
}

func TestSetFilePermissions_WriteGrant_DoesNotMirrorToBlobs(t *testing.T) {
	svc, _, perms, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))

	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionWrite, Scope: "full",
	}); err != nil {
		t.Fatalf("SetFilePermissions: %v", err)
	}
	for _, v := range storeVersionsFor(t, svc, fo.FileObjectID) {
		if perms.hasActiveGrant(collaborator, storageRetrieveBlobAction, resourceTypeBlob, v.BlobRef) {
			t.Fatalf("fileobjects.write grants must never mirror onto blob-level grants (charter §6 point 4)")
		}
	}
}

// TestSetFilePermissions_PartialMirrorFailure_FailsLoudly proves the
// second most safety-critical invariant in this charter (§6 point 4): if
// mirroring a revoke onto one of several versions' blobs fails partway
// through, SetFilePermissions must return a loud error naming the
// affected version(s) rather than ever reporting success — a silent
// partial failure would leave a since-revoked subject still able to read
// specific old versions directly via Storage.RetrieveBlob.
func TestSetFilePermissions_PartialMirrorFailure_FailsLoudly(t *testing.T) {
	svc, _, perms, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2")}); err != nil {
		t.Fatalf("CreateVersion 2: %v", err)
	}
	if _, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v3")}); err != nil {
		t.Fatalf("CreateVersion 3: %v", err)
	}
	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionRead, Scope: "read",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	versions := storeVersionsFor(t, svc, fo.FileObjectID)
	if len(versions) != 3 {
		t.Fatalf("expected 3 versions, got %d", len(versions))
	}
	// Force the mirror-revoke to fail for the SECOND version's blob only —
	// a genuine partial failure, not "everything fails" or "nothing fails".
	failingVersion := versions[1]
	perms.revokeFailFor[callKey(collaborator, storageRetrieveBlobAction, resourceTypeBlob, failingVersion.BlobRef)] = errors.New("simulated mirror failure")

	_, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: false,
		Subject: collaborator, Action: ActionRead,
	})
	if err == nil {
		t.Fatalf("expected SetFilePermissions to fail loudly on a partial mirror failure, got nil error")
	}
	if !strings.Contains(err.Error(), failingVersion.VersionRef) {
		t.Fatalf("expected the error to name the specific version that failed to mirror (%s), got: %v", failingVersion.VersionRef, err)
	}

	// The other two versions' mirrors must still have gone through — a
	// partial failure must not roll back the parts that succeeded, only
	// be reported loudly.
	for i, v := range versions {
		if i == 1 {
			continue
		}
		if perms.hasActiveGrant(collaborator, storageRetrieveBlobAction, resourceTypeBlob, v.BlobRef) {
			t.Fatalf("expected version %d's mirror-revoke to have succeeded despite version 1's failure", i)
		}
	}
	// And the file-object-level revoke itself must have gone through —
	// only the version-mirroring loop is what's flagged as failed.
	if perms.hasActiveGrant(collaborator, ActionRead, resourceTypeFileObject, fo.FileObjectID) {
		t.Fatalf("expected the file-object-level revoke to have succeeded even though mirroring partially failed")
	}
}

func TestSetFilePermissions_DeniedWithoutGrantAuthority(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	_, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: stranger, Grant: true,
		Subject: collaborator, Action: ActionRead, Scope: "read",
	})
	if err == nil {
		t.Fatalf("expected an error: %s has no grant authority over the file object", stranger)
	}
}

// --- SetFileMetadata -------------------------------------------------

func TestSetFileMetadata_UpdatesFields(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))

	newName := "renamed.pdf"
	if _, err := svc.SetFileMetadata(SetFileMetadataRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Name: &newName, Tags: []string{"important", "2026"},
	}); err != nil {
		t.Fatalf("SetFileMetadata: %v", err)
	}

	meta, err := svc.GetFileMetadata(GetFileMetadataRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("GetFileMetadata: %v", err)
	}
	if meta.Name != newName {
		t.Fatalf("name = %q, want %q", meta.Name, newName)
	}
	if len(meta.Tags) != 2 || meta.Tags[0] != "important" {
		t.Fatalf("tags = %v", meta.Tags)
	}
	if meta.MimeType != "application/pdf" {
		t.Fatalf("mime_type unexpectedly changed: %q", meta.MimeType)
	}
}

func TestSetFileMetadata_DeniedWithoutWriteGrant(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	name := "x"
	_, err := svc.SetFileMetadata(SetFileMetadataRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger, Name: &name})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

// --- ExportFile ------------------------------------------------------

func TestExportFile_HappyPath_ContainsAllVersionsAndEvents(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1 content"))
	if _, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2 content")}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}

	resp, err := svc.ExportFile(ExportFileRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("ExportFile: %v", err)
	}
	if resp.FormatVersion == "" {
		t.Fatalf("expected a non-empty format_version")
	}

	var decoded struct {
		Versions []struct {
			Content []byte `json:"content"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(resp.ExportBlob, &decoded); err != nil {
		t.Fatalf("ExportFile's export bundle is not valid JSON: %v", err)
	}
	if len(decoded.Versions) != 2 {
		t.Fatalf("expected 2 versions in the export bundle, got %d", len(decoded.Versions))
	}
	if string(decoded.Versions[0].Content) != "v1 content" {
		t.Fatalf("version 0 content = %q, want %q", decoded.Versions[0].Content, "v1 content")
	}
	if string(decoded.Versions[1].Content) != "v2 content" {
		t.Fatalf("version 1 content = %q, want %q", decoded.Versions[1].Content, "v2 content")
	}

	blob := string(resp.ExportBlob)
	if !strings.Contains(blob, "fileobjects.create_file_object") || !strings.Contains(blob, "fileobjects.create_version") {
		t.Fatalf("expected export bundle to contain the full event history")
	}
}

func TestExportFile_DeniedForStranger(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	_, err := svc.ExportFile(ExportFileRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

// --- DeleteFileObject --------------------------------------------------

func TestDeleteFileObject_DestroysAllVersionContentAndTombstones(t *testing.T) {
	svc, storage, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2")}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	versions := storeVersionsFor(t, svc, fo.FileObjectID)

	if _, err := svc.DeleteFileObject(DeleteFileObjectRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}); err != nil {
		t.Fatalf("DeleteFileObject: %v", err)
	}

	for _, v := range versions {
		if storage.has(v.BlobRef) {
			t.Fatalf("expected version %s's blob to be destroyed after DeleteFileObject", v.VersionRef)
		}
	}

	// Content is gone (GetFileContent fails)...
	if _, err := svc.GetFileContent(GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}); !errors.Is(err, ErrContentUnavailable) {
		t.Fatalf("expected ErrContentUnavailable after deletion, got %v", err)
	}
	// ...but history/metadata remain resolvable for the owner (charter §3:
	// "identity and history entries remain resolvable... but never the
	// content") — the owner's implicit Permissions-owner status survives
	// grant cleanup (Permissions' owner record is separate from any
	// active grant).
	hist, err := svc.GetFileHistory(GetFileHistoryRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("expected GetFileHistory to remain resolvable after deletion for the owner: %v", err)
	}
	found := false
	for _, e := range hist.Events {
		if e.Action == "fileobjects.delete_file_object" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a delete_file_object event in history")
	}
}

func TestDeleteFileObject_RevokesFileObjectAndBlobGrants(t *testing.T) {
	svc, _, perms, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionRead, Scope: "read",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	versions := storeVersionsFor(t, svc, fo.FileObjectID)

	if _, err := svc.DeleteFileObject(DeleteFileObjectRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}); err != nil {
		t.Fatalf("DeleteFileObject: %v", err)
	}

	if perms.hasActiveGrant(collaborator, ActionRead, resourceTypeFileObject, fo.FileObjectID) {
		t.Fatalf("expected collaborator's file-object-level grant to be revoked on delete")
	}
	for _, v := range versions {
		if perms.hasActiveGrant(collaborator, storageRetrieveBlobAction, resourceTypeBlob, v.BlobRef) {
			t.Fatalf("expected collaborator's blob-level grant to be revoked on delete")
		}
	}
}

func TestDeleteFileObject_AlreadyDeleted(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.DeleteFileObject(DeleteFileObjectRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	_, err := svc.DeleteFileObject(DeleteFileObjectRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if !errors.Is(err, ErrFileObjectDeleted) {
		t.Fatalf("expected ErrFileObjectDeleted, got %v", err)
	}
}

func TestDeleteFileObject_PartialContentDeleteFailure_NotMarkedDeleted(t *testing.T) {
	svc, storage, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.CreateVersion(CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2")}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	versions := storeVersionsFor(t, svc, fo.FileObjectID)
	storage.deleteErrFor[versions[1].BlobRef] = errors.New("simulated backend failure")

	_, err := svc.DeleteFileObject(DeleteFileObjectRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err == nil {
		t.Fatalf("expected DeleteFileObject to fail loudly when a version's content can't be destroyed")
	}

	rec, found := svc.store.getFileObject(fo.FileObjectID)
	if !found {
		t.Fatalf("file object record unexpectedly gone")
	}
	if rec.Deleted {
		t.Fatalf("expected the file object NOT to be marked deleted when content destruction only partially succeeded")
	}
	if storage.has(versions[0].BlobRef) {
		t.Fatalf("expected version 0's blob to have been destroyed (its DeleteBlob call was not the one that failed) — the loop must not stop at the first failure")
	}
}

func TestDeleteFileObject_DeniedWithoutWriteGrant(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	_, err := svc.DeleteFileObject(DeleteFileObjectRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

// --- ListFileObjects (charter §3, added 2026-08-18) -------------------

// TestListFileObjects_HappyPath_OwnerGetsExactlyTheirOwnFileObjects proves
// an owner with several file objects gets exactly those back, and that
// another identity's file objects are absent — the core "my files" use case
// this RPC exists for.
func TestListFileObjects_HappyPath_OwnerGetsExactlyTheirOwnFileObjects(t *testing.T) {
	svc, _, _, _ := newTestService(t)

	fo1 := createTestFileObject(t, svc, owner, []byte("one"))
	fo2 := createTestFileObject(t, svc, owner, []byte("two"))
	fo3 := createTestFileObject(t, svc, owner, []byte("three"))
	// Another identity's own file object must never appear in owner's list.
	_ = createTestFileObject(t, svc, stranger, []byte("not-mine"))

	resp, err := svc.ListFileObjects(ListFileObjectsRequest{Owner: owner, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("ListFileObjects: %v", err)
	}
	if len(resp.FileObjects) != 3 {
		t.Fatalf("expected exactly 3 file objects for owner, got %d: %+v", len(resp.FileObjects), resp.FileObjects)
	}
	got := map[string]bool{}
	for _, fo := range resp.FileObjects {
		if fo.Owner != owner {
			t.Fatalf("ListFileObjects(owner=%q) returned a file object owned by %q", owner, fo.Owner)
		}
		got[fo.FileObjectID] = true
	}
	for _, want := range []string{fo1.FileObjectID, fo2.FileObjectID, fo3.FileObjectID} {
		if !got[want] {
			t.Fatalf("expected file_object_id %q in owner's list, got %+v", want, resp.FileObjects)
		}
	}

	// stranger's own list must not include any of owner's file objects.
	strangerResp, err := svc.ListFileObjects(ListFileObjectsRequest{Owner: stranger, RequestingSubject: stranger})
	if err != nil {
		t.Fatalf("ListFileObjects (stranger): %v", err)
	}
	if len(strangerResp.FileObjects) != 1 {
		t.Fatalf("expected exactly 1 file object for stranger, got %d: %+v", len(strangerResp.FileObjects), strangerResp.FileObjects)
	}
}

// TestListFileObjects_ExcludesTombstonedFileObjects documents and proves
// this implementation's choice (service.go's doc comment): a deleted file
// object's content is gone, so ListFileObjects excludes it from the "my
// files" inventory even though the record itself is retained as a
// tombstone.
func TestListFileObjects_ExcludesTombstonedFileObjects(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.DeleteFileObject(DeleteFileObjectRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}); err != nil {
		t.Fatalf("DeleteFileObject: %v", err)
	}

	resp, err := svc.ListFileObjects(ListFileObjectsRequest{Owner: owner, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("ListFileObjects: %v", err)
	}
	if len(resp.FileObjects) != 0 {
		t.Fatalf("expected the tombstoned file object to be excluded, got %+v", resp.FileObjects)
	}
}

// TestListFileObjects_ServiceLevelMismatchRejectedAndAudited is the
// service-level half of charter §3's required two-layer authorization
// discipline: requesting_subject != owner must be rejected, and the
// rejection must be audited (action file.list_denied, actor the caller who
// attempted the mismatched call, resource ("identity", owner) — never a
// file_object_id).
func TestListFileObjects_ServiceLevelMismatchRejectedAndAudited(t *testing.T) {
	svc, _, _, audit := newTestService(t)
	_ = createTestFileObject(t, svc, owner, []byte("v1"))

	resp, err := svc.ListFileObjects(ListFileObjectsRequest{Owner: owner, RequestingSubject: stranger})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for requesting_subject != owner, got %v", err)
	}
	if len(resp.FileObjects) != 0 {
		t.Fatalf("expected no file objects returned on rejection, got %+v", resp.FileObjects)
	}

	call, ok := audit.lastCall()
	if !ok {
		t.Fatalf("expected the service-level rejection to be audited, but no audit call was recorded")
	}
	if call.action != listDeniedAction {
		t.Fatalf("expected audit action %q, got %q", listDeniedAction, call.action)
	}
	if call.actor != stranger {
		t.Fatalf("expected audit actor to be the caller who attempted the mismatched call (%q), got %q", stranger, call.actor)
	}
	if call.resource.ResourceType != "identity" || call.resource.ResourceID != owner {
		t.Fatalf("expected audit resource (\"identity\", %q) naming the targeted owner, got %+v", owner, call.resource)
	}
}

// TestListFileObjects_EmptyFieldsRejected covers the ordinary required-field
// validation, matching this package's other RPCs' precedent.
func TestListFileObjects_EmptyFieldsRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	if _, err := svc.ListFileObjects(ListFileObjectsRequest{Owner: "", RequestingSubject: owner}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty owner, got %v", err)
	}
	if _, err := svc.ListFileObjects(ListFileObjectsRequest{Owner: owner, RequestingSubject: ""}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty requesting_subject, got %v", err)
	}
}

// TestListFileObjects_ResponseNeverContainsBlobRef is charter §3's own
// established paranoia about this specific leak (§6 point 8), applied to
// this new RPC — trivial since FileObject (types.go) structurally has no
// BlobRef field at all, but asserted explicitly rather than only relying on
// "it compiles", matching blob_ref_leak_test.go's own precedent.
func TestListFileObjects_ResponseNeverContainsBlobRef(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	versions := storeVersionsFor(t, svc, fo.FileObjectID)
	if len(versions) != 1 || versions[0].BlobRef == "" {
		t.Fatalf("setup failed: expected exactly one version with a blob_ref, got %+v", versions)
	}
	blobRef := versions[0].BlobRef

	resp, err := svc.ListFileObjects(ListFileObjectsRequest{Owner: owner, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("ListFileObjects: %v", err)
	}
	if len(resp.FileObjects) != 1 {
		t.Fatalf("expected exactly 1 file object, got %d", len(resp.FileObjects))
	}
	// FileObject (types.go) has no BlobRef field — reflect over it to prove
	// that structurally, not just by inspecting the fields this test happens
	// to know about.
	rv := reflect.ValueOf(resp.FileObjects[0])
	for i := 0; i < rv.NumField(); i++ {
		fieldName := rv.Type().Field(i).Name
		if strings.EqualFold(fieldName, "BlobRef") {
			t.Fatalf("FileObject must never have a BlobRef field, found %q", fieldName)
		}
		if s, ok := rv.Field(i).Interface().(string); ok && s == blobRef {
			t.Fatalf("field %q unexpectedly equals a real blob_ref (%q) — leak", fieldName, blobRef)
		}
	}
}

// --- ListFileAccess (charter §3, proposed/frozen 2026-08-18) ------------

// TestListFileAccess_OwnerHappyPath proves the owner-only happy path, and
// — the required, previously-unbacked plumbing (docs/DECISION_LOG.md,
// "File Objects contract amendment: ListFileAccess, round 1/round 2") —
// that GrantedAtUnix actually makes it from Permissions' real Grant type,
// through fileobjects.PermissionGrant, into AccessGrant, rather than being
// silently dropped the way it was before this amendment.
func TestListFileAccess_OwnerHappyPath(t *testing.T) {
	svc, _, perms, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionRead, Scope: "read",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	resp, err := svc.ListFileAccess(ListFileAccessRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("ListFileAccess: %v", err)
	}

	// Owner's own bootstrap read+write grants, plus collaborator's mirrored
	// read grant — exactly 3 rows.
	if len(resp.Grants) != 3 {
		t.Fatalf("expected 3 grants, got %d: %+v", len(resp.Grants), resp.Grants)
	}
	var foundCollaboratorGrant bool
	for _, g := range resp.Grants {
		if g.Subject == collaborator && g.Action == ActionRead {
			foundCollaboratorGrant = true
			if g.Scope != "read" {
				t.Fatalf("expected scope %q, got %q", "read", g.Scope)
			}
			// The real, load-bearing plumbing assertion: GrantedAtUnix must
			// be non-zero and must match what memPermissions actually
			// recorded for this exact grant — proving the value traced
			// through PermissionsClient.ListGrantsForResource into
			// AccessGrant, not merely defaulted to zero.
			if g.GrantedAtUnix == 0 {
				t.Fatalf("expected non-zero GrantedAtUnix, got 0 — the GrantedAtUnix plumbing gap is not closed")
			}
			want, ok := perms.grants[grantKey{collaborator, ActionRead, resourceTypeFileObject, fo.FileObjectID}]
			if !ok {
				t.Fatalf("setup invariant broken: expected an active grant in the fake")
			}
			if g.GrantedAtUnix != want.grantedAtUnix {
				t.Fatalf("GrantedAtUnix = %d, want %d (the fake's own recorded value)", g.GrantedAtUnix, want.grantedAtUnix)
			}
		}
	}
	if !foundCollaboratorGrant {
		t.Fatalf("expected collaborator's mirrored read grant to be present, got %+v", resp.Grants)
	}
}

// TestListFileAccess_NonOwnerCollaboratorRejected proves the owner-only
// design choice explicitly: a subject who genuinely holds fileobjects.write
// (and could therefore edit the file's content) is still denied — seeing
// the full grant list is reasoned in the charter as more sensitive than
// write access itself (Art. 7 least privilege), so it stays owner-only.
func TestListFileAccess_NonOwnerCollaboratorRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	if _, err := svc.SetFilePermissions(SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionWrite, Scope: "write",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	_, err := svc.ListFileAccess(ListFileAccessRequest{FileObjectID: fo.FileObjectID, RequestingSubject: collaborator})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for a non-owner write-collaborator, got %v", err)
	}
}

// TestListFileAccess_EnumerationOracleClosure is the required,
// merge-gate-critical proof (charter §3, Security Steward gate finding) that
// a nonexistent file_object_id and an existing-but-not-owned file_object_id
// are byte-for-byte indistinguishable from the response alone: same error
// (via errors.Is), and identical audit event shape (same action, same
// resource type/ID pattern differing only by the actual file_object_id each
// case names — never a distinguishing detail like "not found" vs "not
// owned").
func TestListFileAccess_EnumerationOracleClosure(t *testing.T) {
	svc, _, _, audit := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	nonexistentID := "file-object-does-not-exist-at-all"

	// Case 1: existing file, but requesting_subject is not its owner.
	respA, errA := svc.ListFileAccess(ListFileAccessRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
	callA, okA := audit.lastCall()

	// Case 2: file_object_id doesn't exist at all.
	respB, errB := svc.ListFileAccess(ListFileAccessRequest{FileObjectID: nonexistentID, RequestingSubject: stranger})
	callB, okB := audit.lastCall()

	if !errors.Is(errA, ErrPermissionDenied) || !errors.Is(errB, ErrPermissionDenied) {
		t.Fatalf("expected both cases to return ErrPermissionDenied, got errA=%v errB=%v", errA, errB)
	}
	// Byte-for-byte identical error text (what an HTTP error body would
	// carry) — asserted directly, not just errors.Is, since errors.Is alone
	// would not catch two DIFFERENT wrapped messages that both happen to
	// wrap the same sentinel.
	if errA.Error() != errB.Error() {
		t.Fatalf("expected identical error text for both cases, got %q vs %q", errA.Error(), errB.Error())
	}
	if len(respA.Grants) != 0 || len(respB.Grants) != 0 {
		t.Fatalf("expected no grants returned in either rejection case, got %+v / %+v", respA.Grants, respB.Grants)
	}

	if !okA || !okB {
		t.Fatalf("expected both rejections to be audited, got okA=%v okB=%v", okA, okB)
	}
	if callA.action != accessListDeniedAction || callB.action != accessListDeniedAction {
		t.Fatalf("expected both audit actions to be %q, got %q / %q", accessListDeniedAction, callA.action, callB.action)
	}
	if callA.resource.ResourceType != resourceTypeFileObject || callB.resource.ResourceType != resourceTypeFileObject {
		t.Fatalf("expected both audit resource types to be %q, got %q / %q", resourceTypeFileObject, callA.resource.ResourceType, callB.resource.ResourceType)
	}
	if callA.ruleReference != callB.ruleReference {
		t.Fatalf("expected identical rule_reference for both cases, got %q vs %q", callA.ruleReference, callB.ruleReference)
	}
	if callA.actor != stranger || callB.actor != stranger {
		t.Fatalf("expected both audit actors to be the verified caller (%q), got %q / %q", stranger, callA.actor, callB.actor)
	}
}

// TestListFileAccess_DeniedOwnerCheckIsAudited proves the Art. 5 obligation
// (§4, named explicitly for ListFileAccess) directly: any rejection of the
// service-level owner-resolution check emits accessListDeniedAction, actor
// the caller who attempted it, resource ("file_object", file_object_id).
func TestListFileAccess_DeniedOwnerCheckIsAudited(t *testing.T) {
	svc, _, _, audit := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))

	_, err := svc.ListFileAccess(ListFileAccessRequest{FileObjectID: fo.FileObjectID, RequestingSubject: stranger})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
	call, ok := audit.lastCall()
	if !ok {
		t.Fatalf("expected the rejection to be audited, but no audit call was recorded")
	}
	if call.action != accessListDeniedAction {
		t.Fatalf("expected audit action %q, got %q", accessListDeniedAction, call.action)
	}
	if call.actor != stranger {
		t.Fatalf("expected audit actor to be the rejected caller (%q), got %q", stranger, call.actor)
	}
	if call.resource.ResourceType != resourceTypeFileObject || call.resource.ResourceID != fo.FileObjectID {
		t.Fatalf("expected audit resource (%q, %q), got %+v", resourceTypeFileObject, fo.FileObjectID, call.resource)
	}
}

// TestListFileAccess_EmptyFieldsRejected covers ordinary required-field
// validation, matching this package's other RPCs' precedent — orthogonal to
// the enumeration-oracle requirement above (empty file_object_id is never a
// legitimate ID to probe).
func TestListFileAccess_EmptyFieldsRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	if _, err := svc.ListFileAccess(ListFileAccessRequest{FileObjectID: "", RequestingSubject: owner}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty file_object_id, got %v", err)
	}
	if _, err := svc.ListFileAccess(ListFileAccessRequest{FileObjectID: "some-id", RequestingSubject: ""}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty requesting_subject, got %v", err)
	}
}

// TestListFileAccess_NoOwnerRequestField is a structural, reflect-based
// proof of the charter's required, permanent property (Security Steward gate
// finding): ListFileAccessRequest must never gain an Owner field. A future
// edit that adds one "for symmetry" with ListFileObjectsRequest would reopen
// the exact self-asserted-owner bypass ListFileObjects was originally vetoed
// for.
func TestListFileAccess_NoOwnerRequestField(t *testing.T) {
	rv := reflect.TypeOf(ListFileAccessRequest{})
	for i := 0; i < rv.NumField(); i++ {
		if strings.EqualFold(rv.Field(i).Name, "Owner") {
			t.Fatalf("ListFileAccessRequest must never have an Owner field — found %q", rv.Field(i).Name)
		}
	}
}

// TestListFileAccess_ResourceTypeAlwaysFileObject proves the resource-type
// invariant (charter §3): ListFileAccess only ever calls
// PermissionsClient.ListGrantsForResource with the literal "file_object"
// resource type, regardless of grants that exist on OTHER resource types
// for the exact same resource ID string (e.g. a same-named "blob" resource)
// — it must never become a back-door way to query Permissions' "blob"
// namespace.
func TestListFileAccess_ResourceTypeAlwaysFileObject(t *testing.T) {
	svc, _, perms, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	versions := storeVersionsFor(t, svc, fo.FileObjectID)
	blobRef := versions[0].BlobRef

	// A real "blob"-namespaced grant exists (established by CreateFileObject
	// itself) for this file's own blob_ref — confirm ListFileAccess's result
	// contains nothing from that namespace.
	if !perms.hasActiveGrant(owner, storageRetrieveBlobAction, resourceTypeBlob, blobRef) {
		t.Fatalf("setup invariant broken: expected owner to hold a blob-level grant")
	}

	resp, err := svc.ListFileAccess(ListFileAccessRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("ListFileAccess: %v", err)
	}
	for _, g := range resp.Grants {
		if g.Action == storageRetrieveBlobAction {
			t.Fatalf("ListFileAccess must never surface a %q-namespaced grant, got %+v", resourceTypeBlob, g)
		}
	}
}

// TestListFileAccess_ResponseNeverContainsBlobRef is charter §6 point 8's
// established paranoia, applied to this new RPC (charter §3 explicitly
// requires this test even though the leak is impossible by construction —
// AccessGrant has no field that could carry a blob_ref, and the call is
// always scoped to resource_type "file_object"). Reflects over AccessGrant
// structurally, matching TestListFileObjects_ResponseNeverContainsBlobRef's
// own precedent exactly.
func TestListFileAccess_ResponseNeverContainsBlobRef(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	versions := storeVersionsFor(t, svc, fo.FileObjectID)
	if len(versions) != 1 || versions[0].BlobRef == "" {
		t.Fatalf("setup failed: expected exactly one version with a blob_ref, got %+v", versions)
	}
	blobRef := versions[0].BlobRef

	resp, err := svc.ListFileAccess(ListFileAccessRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner})
	if err != nil {
		t.Fatalf("ListFileAccess: %v", err)
	}
	if len(resp.Grants) == 0 {
		t.Fatalf("expected at least the owner's own bootstrap grants, got none")
	}
	for _, g := range resp.Grants {
		rv := reflect.ValueOf(g)
		for i := 0; i < rv.NumField(); i++ {
			fieldName := rv.Type().Field(i).Name
			if strings.EqualFold(fieldName, "BlobRef") {
				t.Fatalf("AccessGrant must never have a BlobRef field, found %q", fieldName)
			}
			if s, ok := rv.Field(i).Interface().(string); ok && s == blobRef {
				t.Fatalf("field %q unexpectedly equals a real blob_ref (%q) — leak", fieldName, blobRef)
			}
		}
	}
}
