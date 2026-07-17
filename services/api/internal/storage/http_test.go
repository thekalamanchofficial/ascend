package storage

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

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
	svc, err := NewService([]Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, checker, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	r := chi.NewRouter()
	Mount(r, svc)
	server := httptest.NewServer(r)
	defer server.Close()

	storeBody, _ := json.Marshal(StoreBlobRequest{Owner: "identity:alice", Data: []byte("hello"), PolicyID: "policy-a"})
	resp, err := http.Post(server.URL+"/storage/blobs", "application/json", bytes.NewReader(storeBody))
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

	retrieveBody, _ := json.Marshal(RetrieveBlobRequest{BlobRef: storeResp.BlobRef, RequestingSubject: "identity:alice"})
	resp2, err := http.Post(server.URL+"/storage/blobs/retrieve", "application/json", bytes.NewReader(retrieveBody))
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
	allowSvc, err := NewService([]Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, newFakePermissionChecker(true), audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	stored, err := allowSvc.StoreBlob(StoreBlobRequest{Owner: "identity:alice", Data: []byte("hello"), PolicyID: "policy-a"})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}

	denySvc, err := NewService([]Policy{{ID: "policy-a", DisplayName: "A", Description: "d", Backend: backend}}, newFakePermissionChecker(false), audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	r := chi.NewRouter()
	Mount(r, denySvc)
	server := httptest.NewServer(r)
	defer server.Close()

	body, _ := json.Marshal(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:mallory"})
	resp, err := http.Post(server.URL+"/storage/blobs/retrieve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /storage/blobs/retrieve: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}
