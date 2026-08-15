package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// passThroughMiddleware calls the wrapped handler unconditionally — it
// exists to prove Mount's wiring is transparent to a caller-supplied
// middleware that does not itself reject anything.
func passThroughMiddleware(next http.Handler) http.Handler {
	return next
}

// alwaysForbiddenMiddleware never calls the wrapped handler at all — it
// exists to prove exactly which of Mount's routes actually invoke the
// caller-supplied requireCallerMatchesIdentity middleware and which do
// not, without needing a real session/identity-matching implementation.
func alwaysForbiddenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
}

// http_test.go is a light smoke test for Mount — the HTTP surface is a
// thin adapter over Service (already covered thoroughly by
// service_test.go), so this only checks the wiring (status codes, JSON
// shapes, URL params) rather than re-testing business logic.
func TestMount_CreateResolveBindHTTP(t *testing.T) {
	svc, _ := newTestService()
	server := httptest.NewServer(Mount(svc, passThroughMiddleware))
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

// TestMount_MiddlewareGatesOnlySensitiveRoutes proves requireCallerMatchesIdentity
// (as passed into Mount) is actually applied to RevokeDevice, ListDevices, and
// ExportIdentity — and only those three — by wiring in a middleware that always
// returns 403 and confirming those three routes never reach the real handler.
func TestMount_MiddlewareGatesOnlySensitiveRoutes(t *testing.T) {
	svc, _ := newTestService()
	server := httptest.NewServer(Mount(svc, alwaysForbiddenMiddleware))
	defer server.Close()

	identityPub, _ := mustGenerateKey(t)
	devicePub, _ := mustGenerateKey(t)
	created, err := svc.CreateIdentity(CreateIdentityRequest{
		DisplayName:          "Gated Routes User",
		PublicKey:            identityPub,
		FirstDevicePublicKey: devicePub,
		FirstDeviceName:      "Primary",
	})
	if err != nil {
		t.Fatalf("CreateIdentity setup: %v", err)
	}
	identityRef := created.PublicIdentity.IdentityRef
	deviceID := created.FirstDevice.DeviceID

	// ListDevices — wrapped, must be blocked by the middleware.
	listResp, err := http.Get(server.URL + "/" + identityRef + "/devices")
	if err != nil {
		t.Fatalf("GET /{identityRef}/devices: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /{identityRef}/devices status = %d, want 403 (middleware should have blocked this)", listResp.StatusCode)
	}

	// ExportIdentity — wrapped, must be blocked by the middleware.
	exportResp, err := http.Get(server.URL + "/" + identityRef + "/export")
	if err != nil {
		t.Fatalf("GET /{identityRef}/export: %v", err)
	}
	defer exportResp.Body.Close()
	if exportResp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /{identityRef}/export status = %d, want 403 (middleware should have blocked this)", exportResp.StatusCode)
	}

	// RevokeDevice — wrapped, must be blocked by the middleware.
	revokeReq, err := http.NewRequest(http.MethodDelete, server.URL+"/"+identityRef+"/devices/"+deviceID, nil)
	if err != nil {
		t.Fatalf("build DELETE request: %v", err)
	}
	revokeResp, err := http.DefaultClient.Do(revokeReq)
	if err != nil {
		t.Fatalf("DELETE /{identityRef}/devices/{deviceId}: %v", err)
	}
	defer revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE /{identityRef}/devices/{deviceId} status = %d, want 403 (middleware should have blocked this)", revokeResp.StatusCode)
	}
}

// TestMount_MiddlewareDoesNotAffectUnwrappedRoutes proves the same
// always-403 middleware passed into Mount does NOT reach CreateIdentity,
// BindDevice, or ResolveIdentity — i.e. requireCallerMatchesIdentity is
// genuinely scoped to three routes via r.With(...), not accidentally
// applied router-wide.
func TestMount_MiddlewareDoesNotAffectUnwrappedRoutes(t *testing.T) {
	svc, _ := newTestService()
	server := httptest.NewServer(Mount(svc, alwaysForbiddenMiddleware))
	defer server.Close()

	identityPub, _ := mustGenerateKey(t)
	devicePub, devicePriv := mustGenerateKey(t)

	// CreateIdentity — unwrapped, must succeed despite the 403-always middleware.
	createBody, _ := json.Marshal(CreateIdentityRequest{
		DisplayName:          "Unwrapped Routes User",
		PublicKey:            identityPub,
		FirstDevicePublicKey: devicePub,
		FirstDeviceName:      "Primary",
	})
	createResp, err := http.Post(server.URL+"/", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("POST / status = %d, want 200 (CreateIdentity must not be gated)", createResp.StatusCode)
	}
	var created CreateIdentityResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	identityRef := created.PublicIdentity.IdentityRef
	if identityRef == "" {
		t.Fatal("expected non-empty identityRef")
	}

	// ResolveIdentity — unwrapped, must succeed despite the 403-always middleware.
	resolveResp, err := http.Get(server.URL + "/" + identityRef)
	if err != nil {
		t.Fatalf("GET /{identityRef}: %v", err)
	}
	defer resolveResp.Body.Close()
	if resolveResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /{identityRef} status = %d, want 200 (ResolveIdentity must not be gated)", resolveResp.StatusCode)
	}

	// BindDevice — unwrapped, must succeed despite the 403-always middleware.
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
		t.Fatalf("POST /{identityRef}/devices status = %d, want 200 (BindDevice must not be gated)", bindResp.StatusCode)
	}
}
