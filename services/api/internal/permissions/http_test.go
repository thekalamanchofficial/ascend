package permissions

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// noopVerifiedCaller stands in for the composition-root session-auth
// middleware in tests: it does not modify the request at all, so these
// tests exercise exactly this package's own requireCaller/caller-match
// checks (the handler-level defense-in-depth), independent of whatever
// real middleware main.go/wiring.go eventually wires in. Tests set
// callerHeader directly, mirroring how
// services/api/internal/audit/http_test.go's tests set their own
// callerHeader.
func noopVerifiedCaller(h http.Handler) http.Handler { return h }

func newHTTPTestServer(svc *Service) *httptest.Server {
	r := chi.NewRouter()
	Mount(r, svc, noopVerifiedCaller)
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

// --- GrantPermission ---

func TestHTTP_GrantPermission_CallerMismatchRejected(t *testing.T) {
	svc, _ := newTestService()
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	// Verified caller is bob, but the body names alice as grantor — must
	// be rejected before Service.authorizeGrant's own logic even runs, or
	// bob could grant himself access to any resource by simply claiming
	// to be alice in the request body.
	resp := doJSON(t, http.MethodPost, ts.URL+"/v1/permissions/grants", bob, GrantPermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: fileResource("f1"), Scope: "owner",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for grantor/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_GrantPermission_CallerMatchSucceeds(t *testing.T) {
	svc, _ := newTestService()
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/v1/permissions/grants", alice, GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: fileResource("f1"), Scope: "owner",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 when grantor matches caller, got %d", resp.StatusCode)
	}
	var out GrantPermissionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Grant.Grantor != alice {
		t.Fatalf("unexpected grant: %+v", out.Grant)
	}
}

// --- RevokePermission ---

func TestHTTP_RevokePermission_CallerMismatchRejected(t *testing.T) {
	svc, _ := newTestService()
	if _, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "file_object", DefaultRules: "owner_only"}); err != nil {
		t.Fatalf("DefinePolicy: %v", err)
	}
	resource := fileResource("f1")
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("bootstrap grant: %v", err)
	}
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource, Scope: "read",
	}); err != nil {
		t.Fatalf("grant to bob: %v", err)
	}
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	// Verified caller is carol, but the body names alice as grantor.
	resp := doJSON(t, http.MethodPost, ts.URL+"/v1/permissions/revoke", carol, RevokePermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for grantor/caller mismatch, got %d", resp.StatusCode)
	}

	// The grant must still be active — the rejected request must not have
	// reached Service.RevokePermission at all.
	checkResp, err := svc.CheckPermission(CheckPermissionRequest{Subject: bob, Action: "read", Resource: resource})
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if !checkResp.Allowed {
		t.Fatal("expected bob's grant to remain active after rejected revoke attempt")
	}
}

func TestHTTP_RevokePermission_CallerMatchSucceeds(t *testing.T) {
	svc, _ := newTestService()
	if _, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "file_object", DefaultRules: "owner_only"}); err != nil {
		t.Fatalf("DefinePolicy: %v", err)
	}
	resource := fileResource("f1")
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("bootstrap grant: %v", err)
	}
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource, Scope: "read",
	}); err != nil {
		t.Fatalf("grant to bob: %v", err)
	}
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/v1/permissions/revoke", alice, RevokePermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when grantor matches caller, got %d", resp.StatusCode)
	}

	checkResp, err := svc.CheckPermission(CheckPermissionRequest{Subject: bob, Action: "read", Resource: resource})
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if checkResp.Allowed {
		t.Fatal("expected bob's grant to be revoked")
	}
}

// --- CheckPermission ---

func TestHTTP_CheckPermission_CallerMismatchRejected(t *testing.T) {
	svc, _ := newTestService()
	resource := fileResource("f1")
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("bootstrap grant: %v", err)
	}
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	// Verified caller is bob, but the body asks "can alice read f1" —
	// a caller may only check their own permissions.
	resp := doJSON(t, http.MethodPost, ts.URL+"/v1/permissions/check", bob, CheckPermissionRequest{
		Subject: alice, Action: "read", Resource: resource,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_CheckPermission_CallerMatchSucceeds(t *testing.T) {
	svc, _ := newTestService()
	if _, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "file_object", DefaultRules: "owner_only"}); err != nil {
		t.Fatalf("DefinePolicy: %v", err)
	}
	resource := fileResource("f1")
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("bootstrap grant: %v", err)
	}
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/v1/permissions/check", alice, CheckPermissionRequest{
		Subject: alice, Action: "read", Resource: resource,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when subject matches caller, got %d", resp.StatusCode)
	}
	var out CheckPermissionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !out.Allowed {
		t.Fatal("expected alice to be allowed (resource owner)")
	}
}

// --- ListGrantsForSubject ---

func TestHTTP_ListGrantsForSubject_CallerMismatchRejected(t *testing.T) {
	svc, _ := newTestService()
	resource := fileResource("f1")
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("bootstrap grant: %v", err)
	}
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodGet, ts.URL+"/v1/permissions/grants/subject?subject="+alice, bob, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for subject/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_ListGrantsForSubject_CallerMatchSucceeds(t *testing.T) {
	svc, _ := newTestService()
	resource := fileResource("f1")
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("bootstrap grant: %v", err)
	}
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodGet, ts.URL+"/v1/permissions/grants/subject?subject="+alice, alice, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when subject matches caller, got %d", resp.StatusCode)
	}
	var out ListGrantsForSubjectResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out.Grants) != 1 {
		t.Fatalf("expected 1 grant for alice, got %d", len(out.Grants))
	}
}

// --- ExportPermissions ---

func TestHTTP_ExportPermissions_CallerMismatchRejected(t *testing.T) {
	svc, _ := newTestService()
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodGet, ts.URL+"/v1/permissions/export?identity_ref="+alice, bob, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for identity_ref/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_ExportPermissions_CallerMatchSucceeds(t *testing.T) {
	svc, _ := newTestService()
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodGet, ts.URL+"/v1/permissions/export?identity_ref="+alice, alice, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when identity_ref matches caller, got %d", resp.StatusCode)
	}
	var out ExportPermissionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.FormatVersion == "" {
		t.Fatal("expected non-empty format version")
	}
}

// --- Missing caller header (401, distinct from a mismatch's 403) ---

func TestHTTP_MissingCallerHeaderRejected(t *testing.T) {
	svc, _ := newTestService()
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"grant", http.MethodPost, "/v1/permissions/grants", GrantPermissionRequest{Grantor: alice, Subject: alice, Action: "read", Resource: fileResource("f1"), Scope: "owner"}},
		{"revoke", http.MethodPost, "/v1/permissions/revoke", RevokePermissionRequest{Grantor: alice, Subject: alice, Action: "read", Resource: fileResource("f1")}},
		{"check", http.MethodPost, "/v1/permissions/check", CheckPermissionRequest{Subject: alice, Action: "read", Resource: fileResource("f1")}},
		{"list_grants_for_subject", http.MethodGet, "/v1/permissions/grants/subject?subject=" + alice, nil},
		{"export", http.MethodGet, "/v1/permissions/export?identity_ref=" + alice, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doJSON(t, tc.method, ts.URL+tc.path, "", tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s: expected 401 with no caller header, got %d", tc.name, resp.StatusCode)
			}
		})
	}
}
