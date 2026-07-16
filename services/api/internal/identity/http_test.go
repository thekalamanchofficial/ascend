package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// http_test.go is a light smoke test for Mount — the HTTP surface is a
// thin adapter over Service (already covered thoroughly by
// service_test.go), so this only checks the wiring (status codes, JSON
// shapes, URL params) rather than re-testing business logic.
func TestMount_CreateResolveBindHTTP(t *testing.T) {
	svc, _ := newTestService()
	server := httptest.NewServer(Mount(svc))
	defer server.Close()

	identityPub, _ := mustGenerateKey(t)
	devicePub, devicePriv := mustGenerateKey(t)

	createBody, _ := json.Marshal(CreateIdentityRequest{
		DisplayName:          "HTTP Test User",
		PublicKey:            identityPub,
		FirstDevicePublicKey: devicePub,
		FirstDeviceName:      "Primary",
	})
	resp, err := http.Post(server.URL+"/", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST / status = %d, want 200", resp.StatusCode)
	}
	var created CreateIdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	identityRef := created.PublicIdentity.IdentityRef
	if identityRef == "" {
		t.Fatal("expected non-empty identityRef")
	}

	// Resolve.
	resolveResp, err := http.Get(server.URL + "/" + identityRef)
	if err != nil {
		t.Fatalf("GET /{identityRef}: %v", err)
	}
	defer resolveResp.Body.Close()
	if resolveResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /{identityRef} status = %d, want 200", resolveResp.StatusCode)
	}

	// Bind a second device over HTTP.
	secondPub, _ := mustGenerateKey(t)
	message := buildDeviceBindingMessage(identityRef, secondPub, "Second", 0)
	proof := ed25519.Sign(devicePriv, message)
	bindBody, _ := json.Marshal(BindDeviceRequest{
		DevicePublicKey:    secondPub,
		DeviceName:         "Second",
		AuthorizationProof: proof,
	})
	bindResp, err := http.Post(server.URL+"/"+identityRef+"/devices", "application/json", bytes.NewReader(bindBody))
	if err != nil {
		t.Fatalf("POST /{identityRef}/devices: %v", err)
	}
	defer bindResp.Body.Close()
	if bindResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /{identityRef}/devices status = %d, want 200", bindResp.StatusCode)
	}

	// Unknown identity resolves to 404.
	notFoundResp, err := http.Get(server.URL + "/does-not-exist")
	if err != nil {
		t.Fatalf("GET /does-not-exist: %v", err)
	}
	defer notFoundResp.Body.Close()
	if notFoundResp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /does-not-exist status = %d, want 404", notFoundResp.StatusCode)
	}
}
