package fileobjects

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// newHTTPTestServer mounts svc's HTTP surface with no external middleware
// (Mount's signature is unchanged — composition-root session-auth
// middleware is applied externally via r.Group, not threaded through
// Mount's parameters, per docs/DECISION_LOG.md "Storage and File Objects
// wiring design"). Tests set callerHeader directly on each request,
// mirroring services/api/internal/audit/http_test.go's approach, so these
// tests exercise exactly this package's own requireCaller/caller-match
// checks (the handler-level defense-in-depth).
func newHTTPTestServer(svc *Service) *httptest.Server {
	r := chi.NewRouter()
	Mount(r, svc)
	return httptest.NewServer(r)
}

func doJSON(t *testing.T, method, url, caller string, body any) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if caller != "" {
		req.Header.Set(callerHeader, caller)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// --- CreateFileObject ---

func TestHTTP_CreateFileObject_RequestingSubjectMismatchRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	// Verified caller is bob, but the body claims alice as
	// requesting_subject.
	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/", collaborator, CreateFileObjectRequest{
		Owner: collaborator, RequestingSubject: owner, InitialContent: []byte("x"), Name: "f", MimeType: "text/plain",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_CreateFileObject_OwnerMismatchRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	// Verified caller is bob and claims to be the requesting_subject
	// truthfully, but names alice as owner — a network caller may only
	// create a file object owned by themselves.
	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/", collaborator, CreateFileObjectRequest{
		Owner: owner, RequestingSubject: collaborator, InitialContent: []byte("x"), Name: "f", MimeType: "text/plain",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for owner/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_CreateFileObject_CallerMatchSucceeds(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/", owner, CreateFileObjectRequest{
		Owner: owner, RequestingSubject: owner, InitialContent: []byte("hello"), Name: "f.txt", MimeType: "text/plain",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 when owner and requesting_subject match caller, got %d", resp.StatusCode)
	}
	var out CreateFileObjectResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.FileObject.Owner != owner || out.FileObject.FileObjectID == "" {
		t.Fatalf("unexpected file object: %+v", out.FileObject)
	}
}

// --- CreateVersion ---

func TestHTTP_CreateVersion_CallerMismatchRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/versions", collaborator, CreateVersionRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_CreateVersion_CallerMatchSucceeds(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/versions", owner, CreateVersionRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
}

// --- GetFileContent ---

func TestHTTP_GetFileContent_CallerMismatchRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("secret"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/content", collaborator, GetFileContentRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_GetFileContent_CallerMatchSucceeds(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("hello world"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/content", owner, GetFileContentRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
	var out GetFileContentResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if string(out.Content) != "hello world" {
		t.Fatalf("content = %q, want %q", out.Content, "hello world")
	}
}

// --- ListVersions ---

func TestHTTP_ListVersions_CallerMismatchRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/versions/list", collaborator, ListVersionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_ListVersions_CallerMatchSucceeds(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/versions/list", owner, ListVersionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
	var out ListVersionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out.Versions) != 1 {
		t.Fatalf("expected 1 version, got %d", len(out.Versions))
	}
}

// --- GetFileHistory ---

func TestHTTP_GetFileHistory_CallerMismatchRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/history", collaborator, GetFileHistoryRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_GetFileHistory_CallerMatchSucceeds(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/history", owner, GetFileHistoryRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
	var out GetFileHistoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(out.Events))
	}
}

// --- SetFilePermissions ---

func TestHTTP_SetFilePermissions_CallerMismatchRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/permissions", collaborator, SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionRead, Scope: "read",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_SetFilePermissions_CallerMatchSucceeds(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/permissions", owner, SetFilePermissionsRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true,
		Subject: collaborator, Action: ActionRead, Scope: "read",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
}

// --- GetFileMetadata ---

func TestHTTP_GetFileMetadata_CallerMismatchRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/metadata/get", collaborator, GetFileMetadataRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_GetFileMetadata_CallerMatchSucceeds(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/metadata/get", owner, GetFileMetadataRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
}

// --- SetFileMetadata ---

func TestHTTP_SetFileMetadata_CallerMismatchRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	newName := "renamed.pdf"
	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/metadata/set", collaborator, SetFileMetadataRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Name: &newName,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_SetFileMetadata_CallerMatchSucceeds(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	newName := "renamed.pdf"
	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/metadata/set", owner, SetFileMetadataRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner, Name: &newName,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
}

// --- ExportFile ---

func TestHTTP_ExportFile_CallerMismatchRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/export", collaborator, ExportFileRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_ExportFile_CallerMatchSucceeds(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/export", owner, ExportFileRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
	var out ExportFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.FormatVersion == "" {
		t.Fatal("expected non-empty format version")
	}
}

// --- DeleteFileObject ---

func TestHTTP_DeleteFileObject_CallerMismatchRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/delete", collaborator, DeleteFileObjectRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}

	// The file object must not actually have been deleted — the rejected
	// request must not have reached Service.DeleteFileObject at all.
	if _, err := svc.GetFileHistory(GetFileHistoryRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}); err != nil {
		t.Fatalf("GetFileHistory after rejected delete attempt: %v", err)
	}
	if _, err := svc.GetFileContent(GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}); err != nil {
		t.Fatalf("expected content still retrievable after rejected delete attempt, got %v", err)
	}
}

func TestHTTP_DeleteFileObject_CallerMatchSucceeds(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/delete", owner, DeleteFileObjectRequest{
		FileObjectID: fo.FileObjectID, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
}

// --- ListFileObjects ---

// TestHTTP_ListFileObjects_CallerMismatchRejectedDespiteServiceFieldsMatching
// is the real, load-bearing proof of the Security Steward veto fix
// (docs/DECISION_LOG.md, 2026-08-18, "ListFileObjects: Security Steward
// veto and fix"): a request whose Owner and RequestingSubject fields agree
// with EACH OTHER (which is all the original, vetoed charter draft would
// have checked) must still be rejected when the verified network caller is
// someone else entirely — proving the HTTP-level check is real and not
// redundant with the service-level one. Uses the real httptest handler, not
// the service layer in isolation, matching this file's own precedent for
// its other ten routes.
func TestHTTP_ListFileObjects_CallerMismatchRejectedDespiteServiceFieldsMatching(t *testing.T) {
	svc, _, _, audit := newTestService(t)
	_ = createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	// Verified caller is mallory (stranger), but the request body claims
	// owner=requesting_subject=alice (owner) — internally self-consistent,
	// exactly what the original vetoed draft would have let through.
	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/list", stranger, ListFileObjectsRequest{
		Owner: owner, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for caller/requesting_subject mismatch even though owner==requesting_subject, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}

	// This rejection must be audited too (charter §3's denial-auditing
	// requirement, broadened to cover the HTTP-level check as well as the
	// service-level one) — actor is the VERIFIED caller (mallory), never the
	// unverified request body's requesting_subject (alice), resource is
	// ("identity", owner), never a file_object_id.
	call, ok := audit.lastCall()
	if !ok {
		t.Fatalf("expected the HTTP-level rejection to be audited, but no audit call was recorded")
	}
	if call.action != listDeniedAction {
		t.Fatalf("expected audit action %q, got %q", listDeniedAction, call.action)
	}
	if call.actor != stranger {
		t.Fatalf("expected audit actor to be the verified caller (%q), got %q", stranger, call.actor)
	}
	if call.resource.ResourceType != "identity" || call.resource.ResourceID != owner {
		t.Fatalf("expected audit resource (\"identity\", %q), got %+v", owner, call.resource)
	}
}

func TestHTTP_ListFileObjects_CallerMatchSucceeds(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo1 := createTestFileObject(t, svc, owner, []byte("one"))
	fo2 := createTestFileObject(t, svc, owner, []byte("two"))
	_ = createTestFileObject(t, svc, stranger, []byte("not-mine"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/list", owner, ListFileObjectsRequest{
		Owner: owner, RequestingSubject: owner,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
	var out ListFileObjectsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out.FileObjects) != 2 {
		t.Fatalf("expected exactly owner's 2 file objects, got %d: %+v", len(out.FileObjects), out.FileObjects)
	}
	got := map[string]bool{}
	for _, fo := range out.FileObjects {
		got[fo.FileObjectID] = true
	}
	if !got[fo1.FileObjectID] || !got[fo2.FileObjectID] {
		t.Fatalf("expected both of owner's file objects present, got %+v", out.FileObjects)
	}
}

// TestHTTP_ListFileObjects_OwnerMismatchStillRejectedByServiceLayer proves
// the service-level check (Service.ListFileObjects) still holds even when
// the HTTP-level check alone would have let a request through: caller and
// requesting_subject agree (so the HTTP-level check passes), but Owner names
// someone else — this must still be rejected, by the service layer's own
// requesting_subject == owner check, and audited.
func TestHTTP_ListFileObjects_OwnerMismatchStillRejectedByServiceLayer(t *testing.T) {
	svc, _, _, audit := newTestService(t)
	_ = createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	// Verified caller is mallory, and the request truthfully names mallory
	// as requesting_subject (passes the HTTP-level check) — but claims
	// owner=alice, attempting to enumerate alice's inventory.
	resp := doJSON(t, http.MethodPost, ts.URL+"/file-objects/list", stranger, ListFileObjectsRequest{
		Owner: owner, RequestingSubject: stranger,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for owner != requesting_subject, got %d", resp.StatusCode)
	}
	call, ok := audit.lastCall()
	if !ok {
		t.Fatalf("expected the service-level rejection to be audited")
	}
	if call.action != listDeniedAction || call.actor != stranger || call.resource.ResourceType != "identity" || call.resource.ResourceID != owner {
		t.Fatalf("unexpected audit call: %+v", call)
	}
}

// --- Missing caller header (401, distinct from a mismatch's 403), across
// all eleven routes ---

func TestHTTP_MissingCallerHeaderRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	fo := createTestFileObject(t, svc, owner, []byte("v1"))
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	newName := "x"
	cases := []struct {
		name string
		path string
		body any
	}{
		{"create_file_object", "/file-objects/", CreateFileObjectRequest{Owner: owner, RequestingSubject: owner, InitialContent: []byte("x"), Name: "f", MimeType: "text/plain"}},
		{"create_version", "/file-objects/versions", CreateVersionRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Content: []byte("v2")}},
		{"get_file_content", "/file-objects/content", GetFileContentRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}},
		{"list_versions", "/file-objects/versions/list", ListVersionsRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}},
		{"get_file_history", "/file-objects/history", GetFileHistoryRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}},
		{"set_file_permissions", "/file-objects/permissions", SetFilePermissionsRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Grant: true, Subject: collaborator, Action: ActionRead, Scope: "read"}},
		{"get_file_metadata", "/file-objects/metadata/get", GetFileMetadataRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}},
		{"set_file_metadata", "/file-objects/metadata/set", SetFileMetadataRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner, Name: &newName}},
		{"export_file", "/file-objects/export", ExportFileRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}},
		{"delete_file_object", "/file-objects/delete", DeleteFileObjectRequest{FileObjectID: fo.FileObjectID, RequestingSubject: owner}},
		{"list_file_objects", "/file-objects/list", ListFileObjectsRequest{Owner: owner, RequestingSubject: owner}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doJSON(t, http.MethodPost, ts.URL+tc.path, "", tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s: expected 401 with no caller header, got %d", tc.name, resp.StatusCode)
			}
		})
	}
}
