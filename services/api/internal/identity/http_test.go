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
	server := httptest.NewServer(Mount(svc, passThroughMiddleware, passThroughMiddleware, passThroughMiddleware))
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
	// Only requireCallerMatchesIdentity is the always-403 middleware here —
	// the two new prekey middlewares are pass-through, so this test's
	// original scope (proving requireCallerMatchesIdentity gates exactly
	// RevokeDevice/ListDevices/ExportIdentity) is unaffected. See
	// TestMount_PublishPrekeyBundle_GatedByDeviceBindingMiddleware and
	// TestMount_FetchPrekeyBundle_GatedByVerifiedCallerMiddleware below for
	// the two new middlewares' own dedicated gating proofs.
	server := httptest.NewServer(Mount(svc, alwaysForbiddenMiddleware, passThroughMiddleware, passThroughMiddleware))
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
	server := httptest.NewServer(Mount(svc, alwaysForbiddenMiddleware, passThroughMiddleware, passThroughMiddleware))
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

// TestMount_PublishPrekeyBundle_GatedByDeviceBindingMiddleware proves
// PublishPrekeyBundle is gated by the requireCallerMatchesIdentityAndDevice
// parameter specifically — a real requireCallerMatchesIdentity-shaped
// pass-through middleware for the OTHER two Mount parameters would not
// have blocked this route if wiring.go's Mount call ever accidentally
// passed the wrong middleware into the wrong parameter position.
func TestMount_PublishPrekeyBundle_GatedByDeviceBindingMiddleware(t *testing.T) {
	svc, _ := newTestService()
	server := httptest.NewServer(Mount(svc, passThroughMiddleware, alwaysForbiddenMiddleware, passThroughMiddleware))
	defer server.Close()

	identityPub, _ := mustGenerateKey(t)
	devicePub, _ := mustGenerateKey(t)
	created, err := svc.CreateIdentity(CreateIdentityRequest{
		DisplayName:          "Prekey Gate User",
		PublicKey:            identityPub,
		FirstDevicePublicKey: devicePub,
		FirstDeviceName:      "Primary",
	})
	if err != nil {
		t.Fatalf("CreateIdentity setup: %v", err)
	}

	body, _ := json.Marshal(PublishPrekeyBundleRequest{SignedPrekey: testSignedPrekey("spk-1")})
	resp, err := http.Post(
		server.URL+"/"+created.PublicIdentity.IdentityRef+"/devices/"+created.FirstDevice.DeviceID+"/prekeys",
		"application/json", bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST .../prekeys: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST .../prekeys status = %d, want 403 (requireCallerMatchesIdentityAndDevice should have blocked this)", resp.StatusCode)
	}
}

// TestMount_FetchPrekeyBundle_GatedByVerifiedCallerMiddleware proves
// FetchPrekeyBundle is gated by the requireVerifiedCaller parameter
// specifically, and NOT by requireCallerMatchesIdentity (which stays
// pass-through here) — this route must be reachable by ANY authenticated
// caller regardless of whose identity_ref is in the URL, so it is
// deliberately the requireVerifiedCaller-shaped middleware, not the
// identity-matching one, that is exercised here.
func TestMount_FetchPrekeyBundle_GatedByVerifiedCallerMiddleware(t *testing.T) {
	svc, _ := newTestService()
	server := httptest.NewServer(Mount(svc, passThroughMiddleware, passThroughMiddleware, alwaysForbiddenMiddleware))
	defer server.Close()

	identityPub, _ := mustGenerateKey(t)
	devicePub, _ := mustGenerateKey(t)
	created, err := svc.CreateIdentity(CreateIdentityRequest{
		DisplayName:          "Fetch Gate User",
		PublicKey:            identityPub,
		FirstDevicePublicKey: devicePub,
		FirstDeviceName:      "Primary",
	})
	if err != nil {
		t.Fatalf("CreateIdentity setup: %v", err)
	}

	resp, err := http.Get(server.URL + "/" + created.PublicIdentity.IdentityRef + "/prekey-bundle")
	if err != nil {
		t.Fatalf("GET .../prekey-bundle: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET .../prekey-bundle status = %d, want 403 (requireVerifiedCaller should have blocked this)", resp.StatusCode)
	}
}

// TestMount_FetchPrekeyBundle_ReachableForAnyCaller_NotIdentityGated proves
// the converse: with requireCallerMatchesIdentity forced to always-403 (as
// TestMount_MiddlewareGatesOnlySensitiveRoutes already exercises for the
// other three routes) but requireVerifiedCaller pass-through,
// FetchPrekeyBundle must still succeed — it is deliberately NOT gated by
// caller-identity-matching at all (charter §3/§6).
func TestMount_FetchPrekeyBundle_ReachableForAnyCaller_NotIdentityGated(t *testing.T) {
	svc, _ := newTestService()
	server := httptest.NewServer(Mount(svc, alwaysForbiddenMiddleware, passThroughMiddleware, passThroughMiddleware))
	defer server.Close()

	identityPub, _ := mustGenerateKey(t)
	devicePub, _ := mustGenerateKey(t)
	created, err := svc.CreateIdentity(CreateIdentityRequest{
		DisplayName:          "Fetch Openness User",
		PublicKey:            identityPub,
		FirstDevicePublicKey: devicePub,
		FirstDeviceName:      "Primary",
	})
	if err != nil {
		t.Fatalf("CreateIdentity setup: %v", err)
	}

	resp, err := http.Get(server.URL + "/" + created.PublicIdentity.IdentityRef + "/prekey-bundle")
	if err != nil {
		t.Fatalf("GET .../prekey-bundle: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET .../prekey-bundle status = %d, want 200 (must not be gated by requireCallerMatchesIdentity)", resp.StatusCode)
	}
	var parsed FetchPrekeyBundleResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if parsed.Status != PrekeyBundleStatusNotPublished {
		t.Fatalf("expected NOT_PUBLISHED (no bundle published yet), got %v", parsed.Status)
	}
}
