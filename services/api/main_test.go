package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ascend/services/api/internal/fileobjects"
	"github.com/ascend/services/api/internal/storage"
)

// This file is the integration test main.go's own doc comment has always
// claimed exists. It exercises newRouter() — the real, fully-wired
// composition root, with real (non-fake) identity/audit/sessionauth
// instances, exactly as main() constructs them — via httptest, never a
// mock middleware or a fake service. This is deliberately the one place in
// the repo allowed to depend on multiple capabilities' packages at once,
// since it IS the composition root under test.
//
// Every scenario here was first proven by hand against a live `go run .`
// server during the 2026-08-16 Identity wiring pass, then independently
// reproduced by both Security Steward and Constitution Warden during that
// pass's merge gate — this file exists so that verification is never again
// only a one-off manual probe (see docs/DECISION_LOG.md, 2026-08-16,
// "Identity network wiring: merge gate" for the finding this closes).
//
// Extended 2026-08-16 for the follow-on "Permissions and Audit wiring"
// pass (docs/DECISION_LOG.md, same date) — TestAuditRoutes_GatedAndReachable
// and TestPermissionsRoutes_GatedAndReachable replace the earlier
// TestAuditAndPermissions_NotMountedOnNetwork, which is now factually false.
//
// Extended again 2026-08-16 for "Storage and File Objects wiring design" —
// TestStorageRoutes_GatedAndReachable and
// TestFileObjectsRoutes_GatedAndReachable. Unlike Permissions'
// SelfGrant_Bootstraps subtest above (which deliberately documents a
// known, still-open fail-closed gap for an arbitrary unregistered resource
// type), both of these prove a genuinely working happy path end to end,
// including the real bootstrap-ownership fix from "Storage: StoreBlob
// establishes Permissions ownership via GrantPermission" — a blob's true
// owner can actually retrieve/move/delete/export it after storing it
// through the real, live Permissions instance, not a fake.

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(newRouter())
	t.Cleanup(srv.Close)
	return srv
}

// testIdentity creates a real identity with a real Ed25519 keypair against
// the live test server and returns everything needed to drive an
// authenticated flow.
type testIdentity struct {
	identityRef string
	deviceID    string
	pub         ed25519.PublicKey
	priv        ed25519.PrivateKey
}

func createTestIdentity(t *testing.T, baseURL string) testIdentity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	body, _ := json.Marshal(map[string]any{
		"displayName":          "Test User",
		"publicKey":            pubB64,
		"firstDevicePublicKey": pubB64,
		"firstDeviceName":      "Test Device",
	})
	resp, err := http.Post(baseURL+"/v1/identity", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("CreateIdentity request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateIdentity: expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		PublicIdentity struct {
			IdentityRef string `json:"identityRef"`
		} `json:"publicIdentity"`
		FirstDevice struct {
			DeviceID string `json:"deviceId"`
		} `json:"firstDevice"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode CreateIdentity response: %v", err)
	}
	return testIdentity{
		identityRef: out.PublicIdentity.IdentityRef,
		deviceID:    out.FirstDevice.DeviceID,
		pub:         pub,
		priv:        priv,
	}
}

// issueRealSession drives the genuine challenge -> sign -> issue flow
// against the live server, using real Ed25519 signing over the exact
// canonical message sessionauth expects (mirrors internal/sessionauth/sign.go's
// buildIssueSessionMessage, duplicated here deliberately so this test does
// not depend on an unexported function from another package).
func issueRealSession(t *testing.T, baseURL string, id testIdentity) string {
	t.Helper()

	chalBody, _ := json.Marshal(map[string]any{
		"identityRef": id.identityRef,
		"deviceId":    id.deviceID,
	})
	chalResp, err := http.Post(baseURL+"/v1/sessionauth/challenge", "application/json", bytes.NewReader(chalBody))
	if err != nil {
		t.Fatalf("GetSessionChallenge request: %v", err)
	}
	defer chalResp.Body.Close()
	if chalResp.StatusCode != http.StatusOK {
		t.Fatalf("GetSessionChallenge: expected 200, got %d", chalResp.StatusCode)
	}
	var chal struct {
		ChallengeNonce string `json:"challengeNonce"`
	}
	if err := json.NewDecoder(chalResp.Body).Decode(&chal); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}

	var buf bytes.Buffer
	buf.WriteString("ascend.session.v1.IssueSession")
	buf.WriteByte(0)
	buf.WriteString(id.identityRef)
	buf.WriteByte(0)
	buf.WriteString(id.deviceID)
	buf.WriteByte(0)
	buf.WriteString(chal.ChallengeNonce)
	sig := ed25519.Sign(id.priv, buf.Bytes())

	issueBody, _ := json.Marshal(map[string]any{
		"identityRef":    id.identityRef,
		"deviceId":       id.deviceID,
		"challengeNonce": chal.ChallengeNonce,
		"proof":          base64.StdEncoding.EncodeToString(sig),
	})
	issueResp, err := http.Post(baseURL+"/v1/sessionauth/sessions", "application/json", bytes.NewReader(issueBody))
	if err != nil {
		t.Fatalf("IssueSession request: %v", err)
	}
	defer issueResp.Body.Close()
	if issueResp.StatusCode != http.StatusCreated {
		t.Fatalf("IssueSession: expected 201, got %d", issueResp.StatusCode)
	}
	var issued struct {
		SessionToken string `json:"sessionToken"`
	}
	if err := json.NewDecoder(issueResp.Body).Decode(&issued); err != nil {
		t.Fatalf("decode IssueSession response: %v", err)
	}
	if issued.SessionToken == "" {
		t.Fatalf("IssueSession returned an empty session token")
	}
	return issued.SessionToken
}

func getWithAuth(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func deleteWithAuth(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func postWithAuth(t *testing.T, url, token string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func TestGatedRoutes_NoToken_Rejected(t *testing.T) {
	srv := newTestServer(t)
	id := createTestIdentity(t, srv.URL)

	for _, tc := range []struct {
		name string
		do   func() *http.Response
	}{
		{"ListDevices", func() *http.Response { return getWithAuth(t, srv.URL+"/v1/identity/"+id.identityRef+"/devices", "") }},
		{"ExportIdentity", func() *http.Response { return getWithAuth(t, srv.URL+"/v1/identity/"+id.identityRef+"/export", "") }},
		{"RevokeDevice", func() *http.Response {
			return deleteWithAuth(t, srv.URL+"/v1/identity/"+id.identityRef+"/devices/"+id.deviceID, "")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.do()
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s with no token: expected 401, got %d", tc.name, resp.StatusCode)
			}
		})
	}
}

func TestGatedRoutes_GarbageToken_Rejected(t *testing.T) {
	srv := newTestServer(t)
	id := createTestIdentity(t, srv.URL)

	resp := getWithAuth(t, srv.URL+"/v1/identity/"+id.identityRef+"/devices", "not-a-real-token")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("ListDevices with garbage token: expected 401, got %d", resp.StatusCode)
	}
}

func TestGatedRoutes_ValidSession_OwnIdentity_Allowed(t *testing.T) {
	srv := newTestServer(t)
	id := createTestIdentity(t, srv.URL)
	token := issueRealSession(t, srv.URL, id)

	resp := getWithAuth(t, srv.URL+"/v1/identity/"+id.identityRef+"/devices", token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListDevices with a valid session for the caller's own identity: expected 200, got %d", resp.StatusCode)
	}

	exportResp := getWithAuth(t, srv.URL+"/v1/identity/"+id.identityRef+"/export", token)
	defer exportResp.Body.Close()
	if exportResp.StatusCode != http.StatusOK {
		t.Errorf("ExportIdentity with a valid session for the caller's own identity: expected 200, got %d", exportResp.StatusCode)
	}
}

func TestGatedRoutes_ValidSession_OtherIdentity_Forbidden(t *testing.T) {
	srv := newTestServer(t)
	alice := createTestIdentity(t, srv.URL)
	bob := createTestIdentity(t, srv.URL)
	aliceToken := issueRealSession(t, srv.URL, alice)

	// Alice's own, genuinely valid session token, used against Bob's identity.
	resp := getWithAuth(t, srv.URL+"/v1/identity/"+bob.identityRef+"/devices", aliceToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Alice's valid session against Bob's ListDevices: expected 403, got %d", resp.StatusCode)
	}

	revokeResp := deleteWithAuth(t, srv.URL+"/v1/identity/"+bob.identityRef+"/devices/"+bob.deviceID, aliceToken)
	defer revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusForbidden {
		t.Errorf("Alice's valid session against Bob's RevokeDevice: expected 403, got %d", revokeResp.StatusCode)
	}
}

func TestUnwrappedRoutes_ReachableWithNoSession(t *testing.T) {
	srv := newTestServer(t)
	// createTestIdentity itself already proves CreateIdentity needs no
	// session (it calls it with no Authorization header at all); this test
	// additionally proves ResolveIdentity is public.
	id := createTestIdentity(t, srv.URL)

	resp, err := http.Get(srv.URL + "/v1/identity/" + id.identityRef)
	if err != nil {
		t.Fatalf("ResolveIdentity request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ResolveIdentity with no session: expected 200, got %d", resp.StatusCode)
	}

	var out struct {
		PublicIdentity map[string]any `json:"publicIdentity"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode ResolveIdentity response: %v", err)
	}
	if _, hasDevices := out.PublicIdentity["devices"]; hasDevices {
		t.Errorf("ResolveIdentity leaked a devices field — must only return public identity fields")
	}
}

// TestAuditRoutes_GatedAndReachable covers the 2026-08-16 "Permissions and
// Audit wiring" pass: Audit's four routes are now mounted at /v1/audit and
// gated by the same requireVerifiedCaller middleware as Permissions,
// wrapping the X-Ascend-Actor header with a verified session identity
// rather than trusting a caller-supplied one — and handleEmit additionally
// requires the body's `actor` field to equal that verified caller.
func TestAuditRoutes_GatedAndReachable(t *testing.T) {
	srv := newTestServer(t)
	id := createTestIdentity(t, srv.URL)
	token := issueRealSession(t, srv.URL, id)

	t.Run("NoToken_Rejected", func(t *testing.T) {
		for _, path := range []string{"/v1/audit/events", "/v1/audit/export"} {
			resp := getWithAuth(t, srv.URL+path, "")
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("GET %s with no token: expected 401, got %d", path, resp.StatusCode)
			}
		}
	})

	t.Run("EmitActorMismatch_Rejected", func(t *testing.T) {
		resp := postWithAuth(t, srv.URL+"/v1/audit/events", token, map[string]any{
			"actor":  "someone-else",
			"action": "test.action",
			"resource": map[string]string{
				"resource_type": "test_resource",
				"resource_id":   "abc123",
			},
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Emit with actor != verified caller: expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("EmitAsSelf_Succeeds", func(t *testing.T) {
		resp := postWithAuth(t, srv.URL+"/v1/audit/events", token, map[string]any{
			"actor":  id.identityRef,
			"action": "test.action",
			"resource": map[string]string{
				"resource_type": "test_resource",
				"resource_id":   "abc123",
			},
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("Emit with actor == verified caller: expected 201, got %d", resp.StatusCode)
		}

		queryResp := getWithAuth(t, srv.URL+"/v1/audit/events?subject="+id.identityRef, token)
		defer queryResp.Body.Close()
		if queryResp.StatusCode != http.StatusOK {
			t.Errorf("Query as the emitting caller: expected 200, got %d", queryResp.StatusCode)
		}

		exportResp := getWithAuth(t, srv.URL+"/v1/audit/export?identity_ref="+id.identityRef, token)
		defer exportResp.Body.Close()
		if exportResp.StatusCode != http.StatusOK {
			t.Errorf("ExportAuditTrail as the emitting caller: expected 200, got %d", exportResp.StatusCode)
		}
	})

	t.Run("ForgedHeader_Overwritten", func(t *testing.T) {
		// A caller may present their own genuine session token but try to
		// smuggle a different X-Ascend-Actor value — requireVerifiedCaller
		// must delete-then-set the header, so the forged value never
		// survives to the handler; a mismatched body actor is still
		// rejected as if no header had been sent at all.
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/audit/events", bytes.NewReader(mustJSON(t, map[string]any{
			"actor":  "someone-else",
			"action": "test.action",
			"resource": map[string]string{
				"resource_type": "test_resource",
				"resource_id":   "abc123",
			},
		})))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Ascend-Actor", "someone-else") // forged; middleware must overwrite this
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Emit with a forged X-Ascend-Actor header and mismatched body actor: expected 403, got %d", resp.StatusCode)
		}
	})
}

// TestPermissionsRoutes_GatedAndReachable covers the same wiring pass for
// Permissions: five of its seven routes are mounted at /v1/permissions,
// each requiring the caller-supplied grantor/subject/identity_ref field to
// equal the verified caller. DefinePolicy and ListGrantsForResource are
// deliberately excluded from Mount entirely (see internal/permissions/http.go
// and docs/DECISION_LOG.md) and must remain unreachable.
func TestPermissionsRoutes_GatedAndReachable(t *testing.T) {
	srv := newTestServer(t)
	alice := createTestIdentity(t, srv.URL)
	bob := createTestIdentity(t, srv.URL)
	aliceToken := issueRealSession(t, srv.URL, alice)

	resource := map[string]string{"resource_type": "test_resource", "resource_id": "res-1"}

	t.Run("NoToken_Rejected", func(t *testing.T) {
		resp := postWithAuth(t, srv.URL+"/v1/permissions/grants", "", map[string]any{
			"grantor": alice.identityRef, "subject": alice.identityRef, "action": "read", "resource": resource,
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GrantPermission with no token: expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("GrantorMismatch_Rejected", func(t *testing.T) {
		// Alice's genuine session, but the body claims Bob as grantor —
		// must be rejected regardless of what service.go's own
		// authorizeGrant rule would otherwise allow.
		resp := postWithAuth(t, srv.URL+"/v1/permissions/grants", aliceToken, map[string]any{
			"grantor": bob.identityRef, "subject": bob.identityRef, "action": "read", "resource": resource,
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GrantPermission with grantor != verified caller: expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("SelfGrant_Bootstraps_Then_Check_List_Revoke_Export", func(t *testing.T) {
		grantResp := postWithAuth(t, srv.URL+"/v1/permissions/grants", aliceToken, map[string]any{
			"grantor": alice.identityRef, "subject": alice.identityRef, "action": "read", "resource": resource, "scope": "owner",
		})
		defer grantResp.Body.Close()
		if grantResp.StatusCode != http.StatusCreated {
			t.Fatalf("self-grant on a fresh (unowned) resource: expected 201 (bootstrap_owner), got %d", grantResp.StatusCode)
		}

		checkResp := postWithAuth(t, srv.URL+"/v1/permissions/check", aliceToken, map[string]any{
			"subject": alice.identityRef, "action": "read", "resource": resource,
		})
		defer checkResp.Body.Close()
		if checkResp.StatusCode != http.StatusOK {
			t.Errorf("CheckPermission as the subject: expected 200, got %d", checkResp.StatusCode)
		}
		// Deliberately asserting the CURRENT (fail-closed) value, not the
		// intuitively-expected one — see docs/DECISION_LOG.md, 2026-08-16,
		// "Permissions and Audit network wiring", follow-up gap: CheckPermission
		// fails closed for any resource_type with no policy registered via
		// DefinePolicy, and DefinePolicy is not network-exposed this pass, so
		// self-granting "owner" scope above does NOT make this return true yet
		// (flagged by Security Steward's gate on this pass — asserting only the
		// HTTP status here would silently mask that gap instead of tracking it).
		// When DefinePolicy is wired (network-exposed or bootstrap-registered
		// in-process for this resource_type), this assertion must flip to true —
		// that failure is the intended signal to update this test, not a bug.
		var checkBody struct {
			Allowed bool `json:"Allowed"`
		}
		if err := json.NewDecoder(checkResp.Body).Decode(&checkBody); err != nil {
			t.Fatalf("decode CheckPermission response: %v", err)
		}
		if checkBody.Allowed {
			t.Errorf("CheckPermission on a never-policy-registered resource_type: expected Allowed=false (known fail-closed gap, see decision log), got Allowed=true — either the gap was fixed (update this test) or something is unexpectedly allowing access")
		}

		checkOtherResp := postWithAuth(t, srv.URL+"/v1/permissions/check", aliceToken, map[string]any{
			"subject": bob.identityRef, "action": "read", "resource": resource,
		})
		defer checkOtherResp.Body.Close()
		if checkOtherResp.StatusCode != http.StatusForbidden {
			t.Errorf("CheckPermission with subject != verified caller: expected 403, got %d", checkOtherResp.StatusCode)
		}

		listResp := getWithAuth(t, srv.URL+"/v1/permissions/grants/subject?subject="+alice.identityRef, aliceToken)
		defer listResp.Body.Close()
		if listResp.StatusCode != http.StatusOK {
			t.Errorf("ListGrantsForSubject as the subject: expected 200, got %d", listResp.StatusCode)
		}

		exportResp := getWithAuth(t, srv.URL+"/v1/permissions/export?identity_ref="+alice.identityRef, aliceToken)
		defer exportResp.Body.Close()
		if exportResp.StatusCode != http.StatusOK {
			t.Errorf("ExportPermissions as self: expected 200, got %d", exportResp.StatusCode)
		}

		revokeResp := postWithAuth(t, srv.URL+"/v1/permissions/revoke", aliceToken, map[string]any{
			"grantor": alice.identityRef, "subject": alice.identityRef, "action": "read", "resource": resource,
		})
		defer revokeResp.Body.Close()
		if revokeResp.StatusCode != http.StatusOK {
			t.Errorf("RevokePermission (self_revoke): expected 200, got %d", revokeResp.StatusCode)
		}
	})
}

// TestPermissionsExcludedRoutes_NotMounted confirms DefinePolicy and
// ListGrantsForResource remain unreachable on the network — deliberately
// excluded from Mount rather than exposed unauthenticated, since neither
// has a legitimate external caller yet and ListGrantsForResourceRequest's
// frozen contract has no caller-identity field to check at all (tracked as
// a future wire-contract amendment, see docs/DECISION_LOG.md).
func TestPermissionsExcludedRoutes_NotMounted(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Post(srv.URL+"/v1/permissions/policies", "application/json", bytes.NewReader(mustJSON(t, map[string]any{
		"resource_type": "test_resource",
	})))
	if err != nil {
		t.Fatalf("POST /v1/permissions/policies: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("/v1/permissions/policies: expected 404 (excluded this wiring pass), got %d", resp.StatusCode)
	}

	listResp, err := http.Get(srv.URL + "/v1/permissions/grants/resource?resource_type=test_resource&resource_id=res-1")
	if err != nil {
		t.Fatalf("GET /v1/permissions/grants/resource: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusNotFound {
		t.Errorf("/v1/permissions/grants/resource: expected 404 (excluded this wiring pass), got %d", listResp.StatusCode)
	}
}

// TestStorageRoutes_GatedAndReachable covers the "Storage and File Objects
// wiring design" pass: all seven Storage routes are now mounted at
// /storage, gated by requireVerifiedCaller exactly like Audit, with each
// handler additionally requiring the request's own owner/requesting_subject
// field to equal the verified caller (internal/storage/http.go). This is
// also the real, live proof of the separately-found-and-fixed "Storage:
// StoreBlob establishes Permissions ownership via GrantPermission" gap
// (docs/DECISION_LOG.md) — RetrieveBlob/MoveBlob/DeleteBlob/ExportAllBlobs
// by the blob's true owner must actually succeed against the real,
// live Permissions instance, not merely be reachable.
func TestStorageRoutes_GatedAndReachable(t *testing.T) {
	srv := newTestServer(t)
	alice := createTestIdentity(t, srv.URL)
	bob := createTestIdentity(t, srv.URL)
	aliceToken := issueRealSession(t, srv.URL, alice)

	t.Run("NoToken_Rejected", func(t *testing.T) {
		resp := postWithAuth(t, srv.URL+"/storage/blobs", "", storage.StoreBlobRequest{
			Owner: alice.identityRef, Data: []byte("x"), PolicyID: storage.PolicyLocalDefault,
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("StoreBlob with no token: expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("OwnerMismatch_Rejected", func(t *testing.T) {
		resp := postWithAuth(t, srv.URL+"/storage/blobs", aliceToken, storage.StoreBlobRequest{
			Owner: bob.identityRef, Data: []byte("x"), PolicyID: storage.PolicyLocalDefault,
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("StoreBlob with owner != verified caller: expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("FullLifecycle_AsOwner_Succeeds", func(t *testing.T) {
		storeResp := postWithAuth(t, srv.URL+"/storage/blobs", aliceToken, storage.StoreBlobRequest{
			Owner: alice.identityRef, Data: []byte("hello from alice"), PolicyID: storage.PolicyLocalDefault,
		})
		defer storeResp.Body.Close()
		if storeResp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(storeResp.Body)
			t.Fatalf("StoreBlob: expected 201, got %d: %s", storeResp.StatusCode, body)
		}
		var stored storage.StoreBlobResponse
		if err := json.NewDecoder(storeResp.Body).Decode(&stored); err != nil {
			t.Fatalf("decode StoreBlob response: %v", err)
		}
		if stored.BlobRef == "" {
			t.Fatalf("expected a non-empty blob_ref")
		}

		// The real proof: retrieval by the true owner, through the real,
		// live Permissions instance, must succeed — this is exactly the
		// call that would have failed closed before the ownership-bootstrap
		// fix.
		retrieveResp := postWithAuth(t, srv.URL+"/storage/blobs/retrieve", aliceToken, storage.RetrieveBlobRequest{
			BlobRef: stored.BlobRef, RequestingSubject: alice.identityRef,
		})
		defer retrieveResp.Body.Close()
		if retrieveResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(retrieveResp.Body)
			t.Fatalf("RetrieveBlob by the true owner: expected 200, got %d: %s", retrieveResp.StatusCode, body)
		}
		var retrieved storage.RetrieveBlobResponse
		if err := json.NewDecoder(retrieveResp.Body).Decode(&retrieved); err != nil {
			t.Fatalf("decode RetrieveBlob response: %v", err)
		}
		if string(retrieved.Data) != "hello from alice" {
			t.Errorf("RetrieveBlob: got %q, want %q", retrieved.Data, "hello from alice")
		}

		// A stranger, even with a genuinely valid session, is denied — both
		// by the HTTP-layer caller check and, independently, by the real
		// Permissions ownership check.
		strangerResp := postWithAuth(t, srv.URL+"/storage/blobs/retrieve", aliceToken, storage.RetrieveBlobRequest{
			BlobRef: stored.BlobRef, RequestingSubject: bob.identityRef,
		})
		defer strangerResp.Body.Close()
		if strangerResp.StatusCode != http.StatusForbidden {
			t.Errorf("RetrieveBlob with requesting_subject != verified caller: expected 403, got %d", strangerResp.StatusCode)
		}

		locResp := getWithAuth(t, srv.URL+"/storage/blobs/location?blob_ref="+stored.BlobRef, aliceToken)
		defer locResp.Body.Close()
		if locResp.StatusCode != http.StatusOK {
			t.Errorf("GetStorageLocation (requesting_subject omitted, defaults to caller): expected 200, got %d", locResp.StatusCode)
		}

		policiesResp := getWithAuth(t, srv.URL+"/storage/policies", aliceToken)
		defer policiesResp.Body.Close()
		if policiesResp.StatusCode != http.StatusOK {
			t.Errorf("ListStoragePolicies: expected 200, got %d", policiesResp.StatusCode)
		}
		var policies storage.ListStoragePoliciesResponse
		if err := json.NewDecoder(policiesResp.Body).Decode(&policies); err != nil {
			t.Fatalf("decode ListStoragePolicies response: %v", err)
		}
		if len(policies.Policies) == 0 {
			t.Errorf("expected at least one real, working storage policy, got none")
		}

		moveResp := postWithAuth(t, srv.URL+"/storage/blobs/move", aliceToken, storage.MoveBlobRequest{
			BlobRef: stored.BlobRef, NewPolicyID: storage.PolicyLocalSecondary, RequestingSubject: alice.identityRef,
		})
		defer moveResp.Body.Close()
		if moveResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(moveResp.Body)
			t.Errorf("MoveBlob by the true owner: expected 200, got %d: %s", moveResp.StatusCode, body)
		}

		exportResp := getWithAuth(t, srv.URL+"/storage/export?owner="+alice.identityRef+"&requesting_subject="+alice.identityRef, aliceToken)
		defer exportResp.Body.Close()
		if exportResp.StatusCode != http.StatusOK {
			t.Errorf("ExportAllBlobs as owner: expected 200, got %d", exportResp.StatusCode)
		}

		deleteResp := postWithAuth(t, srv.URL+"/storage/blobs/delete", aliceToken, storage.DeleteBlobRequest{
			BlobRef: stored.BlobRef, RequestingSubject: alice.identityRef,
		})
		defer deleteResp.Body.Close()
		if deleteResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(deleteResp.Body)
			t.Errorf("DeleteBlob by the true owner: expected 200, got %d: %s", deleteResp.StatusCode, body)
		}
	})
}

// TestFileObjectsRoutes_GatedAndReachable covers the same wiring pass for
// File Objects: all ten routes are mounted at /file-objects, gated by
// requireVerifiedCaller exactly like Audit/Storage, with each handler
// requiring req.RequestingSubject == caller (and, on CreateFileObject,
// req.Owner == caller too — internal/fileobjects/http.go). This exercises
// the full real composition — File Objects' own real Storage and
// Permissions dependencies, not fakes — including File Objects' own
// bootstrap grants (CreateFileObject) and Storage's separately-fixed
// blob-ownership bootstrap underneath them.
func TestFileObjectsRoutes_GatedAndReachable(t *testing.T) {
	srv := newTestServer(t)
	alice := createTestIdentity(t, srv.URL)
	bob := createTestIdentity(t, srv.URL)
	aliceToken := issueRealSession(t, srv.URL, alice)

	t.Run("NoToken_Rejected", func(t *testing.T) {
		resp := postWithAuth(t, srv.URL+"/file-objects/", "", fileobjects.CreateFileObjectRequest{
			Owner: alice.identityRef, RequestingSubject: alice.identityRef, InitialContent: []byte("x"), Name: "n",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("CreateFileObject with no token: expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("OwnerMismatch_Rejected", func(t *testing.T) {
		resp := postWithAuth(t, srv.URL+"/file-objects/", aliceToken, fileobjects.CreateFileObjectRequest{
			Owner: bob.identityRef, RequestingSubject: alice.identityRef, InitialContent: []byte("x"), Name: "n",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("CreateFileObject with owner != verified caller: expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("FullLifecycle_AsOwner_Succeeds", func(t *testing.T) {
		createResp := postWithAuth(t, srv.URL+"/file-objects/", aliceToken, fileobjects.CreateFileObjectRequest{
			Owner: alice.identityRef, RequestingSubject: alice.identityRef,
			InitialContent: []byte("v1 content"), Name: "notes.txt", MimeType: "text/plain",
		})
		defer createResp.Body.Close()
		if createResp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(createResp.Body)
			t.Fatalf("CreateFileObject: expected 201, got %d: %s", createResp.StatusCode, body)
		}
		var created fileobjects.CreateFileObjectResponse
		if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
			t.Fatalf("decode CreateFileObject response: %v", err)
		}
		fileObjectID := created.FileObject.FileObjectID
		if fileObjectID == "" {
			t.Fatalf("expected a non-empty file_object_id")
		}

		// Real end-to-end proof this rides correctly on Storage's own real
		// ownership-bootstrap fix too: GetFileContent retrieves version 1's
		// blob via the real Storage instance, which itself depends on the
		// real Permissions instance correctly recognizing alice (via File
		// Objects' own bootstrap grant, in this path) as that blob's owner.
		contentResp := postWithAuth(t, srv.URL+"/file-objects/content", aliceToken, fileobjects.GetFileContentRequest{
			FileObjectID: fileObjectID, RequestingSubject: alice.identityRef,
		})
		defer contentResp.Body.Close()
		if contentResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(contentResp.Body)
			t.Fatalf("GetFileContent by the true owner: expected 200, got %d: %s", contentResp.StatusCode, body)
		}
		var content fileobjects.GetFileContentResponse
		if err := json.NewDecoder(contentResp.Body).Decode(&content); err != nil {
			t.Fatalf("decode GetFileContent response: %v", err)
		}
		if string(content.Content) != "v1 content" {
			t.Errorf("GetFileContent: got %q, want %q", content.Content, "v1 content")
		}

		// A stranger, even with a genuinely valid session, is denied — both
		// by the HTTP-layer caller check and, independently, by File
		// Objects' own real fileobjects.read CheckPermission gate.
		strangerResp := postWithAuth(t, srv.URL+"/file-objects/content", aliceToken, fileobjects.GetFileContentRequest{
			FileObjectID: fileObjectID, RequestingSubject: bob.identityRef,
		})
		defer strangerResp.Body.Close()
		if strangerResp.StatusCode != http.StatusForbidden {
			t.Errorf("GetFileContent with requesting_subject != verified caller: expected 403, got %d", strangerResp.StatusCode)
		}

		versionResp := postWithAuth(t, srv.URL+"/file-objects/versions", aliceToken, fileobjects.CreateVersionRequest{
			FileObjectID: fileObjectID, RequestingSubject: alice.identityRef, Content: []byte("v2 content"),
		})
		defer versionResp.Body.Close()
		if versionResp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(versionResp.Body)
			t.Errorf("CreateVersion by the true owner: expected 201, got %d: %s", versionResp.StatusCode, body)
		}

		listResp := postWithAuth(t, srv.URL+"/file-objects/versions/list", aliceToken, fileobjects.ListVersionsRequest{
			FileObjectID: fileObjectID, RequestingSubject: alice.identityRef,
		})
		defer listResp.Body.Close()
		if listResp.StatusCode != http.StatusOK {
			t.Errorf("ListVersions: expected 200, got %d", listResp.StatusCode)
		}

		historyResp := postWithAuth(t, srv.URL+"/file-objects/history", aliceToken, fileobjects.GetFileHistoryRequest{
			FileObjectID: fileObjectID, RequestingSubject: alice.identityRef,
		})
		defer historyResp.Body.Close()
		if historyResp.StatusCode != http.StatusOK {
			t.Errorf("GetFileHistory: expected 200, got %d", historyResp.StatusCode)
		}

		grantResp := postWithAuth(t, srv.URL+"/file-objects/permissions", aliceToken, fileobjects.SetFilePermissionsRequest{
			FileObjectID: fileObjectID, RequestingSubject: alice.identityRef,
			Grant: true, Subject: bob.identityRef, Action: fileobjects.ActionRead, Scope: "full",
		})
		defer grantResp.Body.Close()
		if grantResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(grantResp.Body)
			t.Errorf("SetFilePermissions (grant read to bob): expected 200, got %d: %s", grantResp.StatusCode, body)
		}

		metaGetResp := postWithAuth(t, srv.URL+"/file-objects/metadata/get", aliceToken, fileobjects.GetFileMetadataRequest{
			FileObjectID: fileObjectID, RequestingSubject: alice.identityRef,
		})
		defer metaGetResp.Body.Close()
		if metaGetResp.StatusCode != http.StatusOK {
			t.Errorf("GetFileMetadata: expected 200, got %d", metaGetResp.StatusCode)
		}

		newName := "renamed.txt"
		metaSetResp := postWithAuth(t, srv.URL+"/file-objects/metadata/set", aliceToken, fileobjects.SetFileMetadataRequest{
			FileObjectID: fileObjectID, RequestingSubject: alice.identityRef, Name: &newName,
		})
		defer metaSetResp.Body.Close()
		if metaSetResp.StatusCode != http.StatusOK {
			t.Errorf("SetFileMetadata: expected 200, got %d", metaSetResp.StatusCode)
		}

		exportResp := postWithAuth(t, srv.URL+"/file-objects/export", aliceToken, fileobjects.ExportFileRequest{
			FileObjectID: fileObjectID, RequestingSubject: alice.identityRef,
		})
		defer exportResp.Body.Close()
		if exportResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(exportResp.Body)
			t.Errorf("ExportFile as owner: expected 200, got %d: %s", exportResp.StatusCode, body)
		}

		deleteResp := postWithAuth(t, srv.URL+"/file-objects/delete", aliceToken, fileobjects.DeleteFileObjectRequest{
			FileObjectID: fileObjectID, RequestingSubject: alice.identityRef,
		})
		defer deleteResp.Body.Close()
		if deleteResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(deleteResp.Body)
			t.Errorf("DeleteFileObject as owner: expected 200, got %d: %s", deleteResp.StatusCode, body)
		}
	})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestBindDevice_ForgedSignature_Rejected(t *testing.T) {
	srv := newTestServer(t)
	id := createTestIdentity(t, srv.URL)

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"identityRef":        id.identityRef,
		"devicePublicKey":    base64.StdEncoding.EncodeToString(otherPub),
		"deviceName":         "Forged Device",
		"authorizationProof": base64.StdEncoding.EncodeToString([]byte("not-a-real-signature")),
	})
	resp, err := http.Post(srv.URL+"/v1/identity/"+id.identityRef+"/devices", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("BindDevice request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("BindDevice with a forged authorization_proof: expected rejection, got 200")
	}
}

// TestHealthz is a trivial smoke test that the composition root itself
// starts up without panicking during construction — every other test in
// this file already implies this, but it's worth one direct assertion.
func TestHealthz(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz: expected 200, got %d", resp.StatusCode)
	}
}

