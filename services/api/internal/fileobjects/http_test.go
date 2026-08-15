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

// --- Missing caller header (401, distinct from a mismatch's 403), across
// all ten routes ---

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
