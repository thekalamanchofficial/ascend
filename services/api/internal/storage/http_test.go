package storage

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

const (
	alice   = "identity:alice"
	bob     = "identity:bob"
	mallory = "identity:mallory"
)

// doRequest issues method to url with an optional JSON body and an optional
// X-Ascend-Actor header (skipped entirely when caller == ""), mirroring
// services/api/internal/permissions/http_test.go's doJSON helper and
// services/api/internal/audit/http_test.go's convention of setting
// callerHeader directly on the request rather than depending on any real
// session-auth middleware.
func doRequest(t *testing.T, method, url, caller string, body any) *http.Response {
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

// newTestServer builds a real Service (allow-all permission checker, fake
// backend, fake audit) and mounts it, returning the server plus the
// pre-stored blob's ref so handlers under test have something real to
// operate on.
func newTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	backend := newFakeBackend(true, "fake")
	checker := newFakePermissionChecker(true)
	audit := newFakeAuditEmitter()
	svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	stored, err := svc.StoreBlob(StoreBlobRequest{Owner: alice, Data: []byte("hello"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("bootstrap StoreBlob: %v", err)
	}

	r := chi.NewRouter()
	Mount(r, svc)
	server := httptest.NewServer(r)
	return server, stored.BlobRef
}

// TestMount_StoreAndRetrieveBlob is a smoke test proving Mount wires a
// working HTTP surface end to end. Per this capability's spawn brief and
// docs/DECISION_LOG.md, Mount is never actually called from
// services/api/main.go — this test exercises it in isolation, the way
// the Chief Architect will once a Session/Request Authentication
// capability exists to gate real network exposure.
func TestMount_StoreAndRetrieveBlob(t *testing.T) {
	backend := newFakeBackend(true, "fake")
	checker := newFakePermissionChecker(true)
	audit := newFakeAuditEmitter()
	svc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	r := chi.NewRouter()
	Mount(r, svc)
	server := httptest.NewServer(r)
	defer server.Close()

	storeBody, _ := json.Marshal(StoreBlobRequest{Owner: alice, Data: []byte("hello"), PolicyID: "policy-a"})
	req, err := http.NewRequest(http.MethodPost, server.URL+"/storage/blobs", bytes.NewReader(storeBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(callerHeader, alice)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /storage/blobs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var storeResp StoreBlobResponse
	if err := json.NewDecoder(resp.Body).Decode(&storeResp); err != nil {
		t.Fatalf("decoding store response: %v", err)
	}
	if storeResp.BlobRef == "" {
		t.Fatalf("expected a non-empty blob_ref")
	}

	retrieveBody, _ := json.Marshal(RetrieveBlobRequest{BlobRef: storeResp.BlobRef, RequestingSubject: alice})
	req2, err := http.NewRequest(http.MethodPost, server.URL+"/storage/blobs/retrieve", bytes.NewReader(retrieveBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req2.Header.Set(callerHeader, alice)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("POST /storage/blobs/retrieve: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
	var retrieveResp RetrieveBlobResponse
	if err := json.NewDecoder(resp2.Body).Decode(&retrieveResp); err != nil {
		t.Fatalf("decoding retrieve response: %v", err)
	}
	if string(retrieveResp.Data) != "hello" {
		t.Fatalf("expected retrieved data %q, got %q", "hello", retrieveResp.Data)
	}
}

func TestMount_RetrieveBlobPermissionDenied_Returns403(t *testing.T) {
	backend := newFakeBackend(true, "fake")
	audit := newFakeAuditEmitter()
	allowSvc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, newFakePermissionChecker(true), audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	stored, err := allowSvc.StoreBlob(StoreBlobRequest{Owner: alice, Data: []byte("hello"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}

	denySvc, err := NewService(NewInMemoryStore(), []Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, newFakePermissionChecker(false), audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	r := chi.NewRouter()
	Mount(r, denySvc)
	server := httptest.NewServer(r)
	defer server.Close()

	resp := doRequest(t, http.MethodPost, server.URL+"/storage/blobs/retrieve", mallory, RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: mallory})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

// --- StoreBlob ---

func TestHTTP_StoreBlob_CallerMismatchRejected(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	// Verified caller is bob, but the body names alice as owner — must be
	// rejected before Service.StoreBlob even runs, or bob could store
	// blobs attributed to any owner he names.
	resp := doRequest(t, http.MethodPost, server.URL+"/storage/blobs", bob, StoreBlobRequest{Owner: alice, Data: []byte("x"), PolicyID: "policy-a"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for owner/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_StoreBlob_CallerMatchSucceeds(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodPost, server.URL+"/storage/blobs", alice, StoreBlobRequest{Owner: alice, Data: []byte("x"), PolicyID: "policy-a"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 when owner matches caller, got %d", resp.StatusCode)
	}
	var out StoreBlobResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.BlobRef == "" {
		t.Fatalf("expected non-empty blob_ref")
	}
}

// --- RetrieveBlob ---

func TestHTTP_RetrieveBlob_CallerMismatchRejected(t *testing.T) {
	server, blobRef := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodPost, server.URL+"/storage/blobs/retrieve", bob, RetrieveBlobRequest{BlobRef: blobRef, RequestingSubject: alice})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_RetrieveBlob_CallerMatchSucceeds(t *testing.T) {
	server, blobRef := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodPost, server.URL+"/storage/blobs/retrieve", alice, RetrieveBlobRequest{BlobRef: blobRef, RequestingSubject: alice})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
	var out RetrieveBlobResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if string(out.Data) != "hello" {
		t.Fatalf("expected data %q, got %q", "hello", out.Data)
	}
}

// --- MoveBlob ---

func TestHTTP_MoveBlob_CallerMismatchRejected(t *testing.T) {
	server, blobRef := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodPost, server.URL+"/storage/blobs/move", bob, MoveBlobRequest{BlobRef: blobRef, NewPolicyID: "policy-a", RequestingSubject: alice})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_MoveBlob_CallerMatchSucceeds(t *testing.T) {
	server, blobRef := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodPost, server.URL+"/storage/blobs/move", alice, MoveBlobRequest{BlobRef: blobRef, NewPolicyID: "policy-a", RequestingSubject: alice})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
}

// --- DeleteBlob ---

func TestHTTP_DeleteBlob_CallerMismatchRejected(t *testing.T) {
	server, blobRef := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodPost, server.URL+"/storage/blobs/delete", bob, DeleteBlobRequest{BlobRef: blobRef, RequestingSubject: alice})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_DeleteBlob_CallerMatchSucceeds(t *testing.T) {
	server, blobRef := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodPost, server.URL+"/storage/blobs/delete", alice, DeleteBlobRequest{BlobRef: blobRef, RequestingSubject: alice})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
}

// --- GetStorageLocation ---

func TestHTTP_GetStorageLocation_CallerMismatchRejected(t *testing.T) {
	server, blobRef := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodGet, server.URL+"/storage/blobs/location?blob_ref="+blobRef+"&requesting_subject="+alice, bob, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for requesting_subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_GetStorageLocation_CallerMatchSucceeds(t *testing.T) {
	server, blobRef := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodGet, server.URL+"/storage/blobs/location?blob_ref="+blobRef+"&requesting_subject="+alice, alice, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject matches caller, got %d", resp.StatusCode)
	}
	var out GetStorageLocationResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.HumanReadableLocation == "" {
		t.Fatalf("expected non-empty location")
	}
}

// TestHTTP_GetStorageLocation_OmittedSubjectDefaultsToCaller proves the
// deliberate default-to-self behavior (mirroring Audit's ExportAuditTrail
// precedent, per docs/DECISION_LOG.md "Storage and File Objects wiring
// design") for the requesting_subject query param: omitting it entirely
// must succeed as the caller, not 403/400.
func TestHTTP_GetStorageLocation_OmittedSubjectDefaultsToCaller(t *testing.T) {
	server, blobRef := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodGet, server.URL+"/storage/blobs/location?blob_ref="+blobRef, alice, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when requesting_subject is omitted (defaults to caller), got %d", resp.StatusCode)
	}
}

// --- ListStoragePolicies ---

func TestHTTP_ListStoragePolicies_CallerPresentSucceeds(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodGet, server.URL+"/storage/policies", alice, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with a caller header present, got %d", resp.StatusCode)
	}
	var out ListStoragePoliciesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(out.Policies))
	}
}

// --- ExportAllBlobs ---

func TestHTTP_ExportAllBlobs_CallerMismatchRejected(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodGet, server.URL+"/storage/export?owner="+alice+"&requesting_subject="+alice, bob, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for owner/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_ExportAllBlobs_CallerMatchSucceeds(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodGet, server.URL+"/storage/export?owner="+alice+"&requesting_subject="+alice, alice, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when owner matches caller, got %d", resp.StatusCode)
	}
	var out ExportAllBlobsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.FormatVersion == "" {
		t.Fatalf("expected non-empty format version")
	}
}

// TestHTTP_ExportAllBlobs_OmittedOwnerDefaultsToCaller proves the same
// deliberate default-to-self behavior as GetStorageLocation, applied to the
// owner query param instead.
func TestHTTP_ExportAllBlobs_OmittedOwnerDefaultsToCaller(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	resp := doRequest(t, http.MethodGet, server.URL+"/storage/export?requesting_subject="+alice, alice, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when owner is omitted (defaults to caller), got %d", resp.StatusCode)
	}
}

// --- Missing caller header (401, distinct from a mismatch's 403), all 7 routes ---

func TestHTTP_MissingCallerHeaderRejected(t *testing.T) {
	server, blobRef := newTestServer(t)
	defer server.Close()

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"store_blob", http.MethodPost, "/storage/blobs", StoreBlobRequest{Owner: alice, Data: []byte("x"), PolicyID: "policy-a"}},
		{"retrieve_blob", http.MethodPost, "/storage/blobs/retrieve", RetrieveBlobRequest{BlobRef: blobRef, RequestingSubject: alice}},
		{"move_blob", http.MethodPost, "/storage/blobs/move", MoveBlobRequest{BlobRef: blobRef, NewPolicyID: "policy-a", RequestingSubject: alice}},
		{"delete_blob", http.MethodPost, "/storage/blobs/delete", DeleteBlobRequest{BlobRef: blobRef, RequestingSubject: alice}},
		{"get_storage_location", http.MethodGet, "/storage/blobs/location?blob_ref=" + blobRef + "&requesting_subject=" + alice, nil},
		{"list_storage_policies", http.MethodGet, "/storage/policies", nil},
		{"export_all_blobs", http.MethodGet, "/storage/export?owner=" + alice + "&requesting_subject=" + alice, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doRequest(t, tc.method, server.URL+tc.path, "", tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s: expected 401 with no caller header, got %d", tc.name, resp.StatusCode)
			}
		})
	}
}
