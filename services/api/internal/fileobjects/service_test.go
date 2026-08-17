package fileobjects

import (
	"encoding/json"
	"errors"
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
