package permissions

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// fakeAudit is a test double for AuditEmitter. It records every call so
// tests can assert that Grant/Revoke/DefinePolicy actually emit audit
// events (Art. 5), without depending on the real services/api/internal/audit
// package (which this capability does not import — see types.go).
type fakeAudit struct {
	mu     sync.Mutex
	events []auditCall
	nextID int

	// failWith, when non-nil, makes every subsequent Emit call return this
	// error instead of succeeding — used to prove that a failed audit
	// emit surfaces as a loud caller-visible error rather than a silent
	// success (docs/DECISION_LOG.md, "Fix: check and handle
	// AuditEmitter.Emit's error at every call site").
	failWith error
}

type auditCall struct {
	Actor         string
	Action        string
	Resource      ResourceRef
	RuleReference string
	Metadata      map[string]string
}

func (f *fakeAudit) Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		// A real Emit that rejects the call (e.g. oversized metadata)
		// does not produce a persisted audit record — mirror that here
		// by not appending to events, so tests can also assert no
		// spurious event was recorded on a failure path.
		return "", f.failWith
	}
	f.nextID++
	f.events = append(f.events, auditCall{actor, action, resource, ruleReference, metadata})
	return fmt.Sprintf("evt-%d", f.nextID), nil
}

func (f *fakeAudit) count(action string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		if e.Action == action {
			n++
		}
	}
	return n
}

func newTestService() (*Service, *fakeAudit) {
	audit := &fakeAudit{}
	svc := NewService(NewStore(), audit)
	return svc, audit
}

const (
	alice = "identity:alice"
	bob   = "identity:bob"
	carol = "identity:carol"
)

func fileResource(id string) ResourceRef {
	return ResourceRef{ResourceType: "file_object", ResourceID: id}
}

// --- Core lifecycle: grant -> check (allowed) -> revoke -> check (denied) ---

func TestGrantCheckRevokeCheck(t *testing.T) {
	svc, audit := newTestService()

	if _, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "file_object", DefaultRules: "owner_only"}); err != nil {
		t.Fatalf("DefinePolicy failed: %v", err)
	}

	resource := fileResource("f1")

	// alice is the resource's implicit owner (first grantor), granting
	// bob read access.
	grantResp, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	})
	if err != nil {
		t.Fatalf("bootstrap GrantPermission (owner) failed: %v", err)
	}
	if grantResp.Grant.Grantor != alice {
		t.Fatalf("unexpected grant: %+v", grantResp.Grant)
	}

	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource, Scope: "read",
	}); err != nil {
		t.Fatalf("owner GrantPermission to bob failed: %v", err)
	}

	checkResp, err := svc.CheckPermission(CheckPermissionRequest{Subject: bob, Action: "read", Resource: resource})
	if err != nil {
		t.Fatalf("CheckPermission returned error: %v", err)
	}
	if !checkResp.Allowed {
		t.Fatalf("expected bob to be allowed read access after grant, got denied")
	}

	if _, err := svc.RevokePermission(RevokePermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource,
	}); err != nil {
		t.Fatalf("RevokePermission failed: %v", err)
	}

	checkResp2, err := svc.CheckPermission(CheckPermissionRequest{Subject: bob, Action: "read", Resource: resource})
	if err != nil {
		t.Fatalf("CheckPermission returned error: %v", err)
	}
	if checkResp2.Allowed {
		t.Fatalf("expected bob to be denied read access after revoke, got allowed")
	}

	if got := audit.count("permissions.grant"); got != 2 {
		t.Errorf("expected 2 permissions.grant audit events, got %d", got)
	}
	if got := audit.count("permissions.revoke"); got != 1 {
		t.Errorf("expected 1 permissions.revoke audit event, got %d", got)
	}
}

// --- Default-policy gap: unregistered resource type fails closed ---

func TestCheckPermissionFailsClosedForUnregisteredResourceType(t *testing.T) {
	svc, _ := newTestService()
	// No DefinePolicy call for "unknown_type" at all.

	resp, err := svc.CheckPermission(CheckPermissionRequest{
		Subject: alice, Action: "read", Resource: ResourceRef{ResourceType: "unknown_type", ResourceID: "x"},
	})
	if err != nil {
		t.Fatalf("expected a clean deny, not an error, got err=%v", err)
	}
	if resp.Allowed {
		t.Fatalf("expected deny for unregistered resource type (fail closed), got allowed")
	}
}

// Even an owner-established resource must fail closed if the resource
// type itself was never registered via DefinePolicy — ownership alone
// does not substitute for a registered default policy.
func TestCheckPermissionFailsClosedEvenForResourceOwnerIfTypeUnregistered(t *testing.T) {
	svc, _ := newTestService()
	resource := ResourceRef{ResourceType: "unregistered_type", ResourceID: "r1"}

	// GrantPermission itself does not require a registered policy — policy
	// registration and grant authorization are independent concerns per
	// the charter (DefinePolicy gates CheckPermission specifically).
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("GrantPermission failed: %v", err)
	}

	resp, err := svc.CheckPermission(CheckPermissionRequest{Subject: alice, Action: "read", Resource: resource})
	if err != nil {
		t.Fatalf("expected clean deny, got error: %v", err)
	}
	if resp.Allowed {
		t.Fatalf("expected deny: resource type was never registered via DefinePolicy")
	}
}

// --- Privilege escalation via grant chains is rejected ---

func TestGrantChainEscalationRejected(t *testing.T) {
	svc, audit := newTestService()
	if _, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "file_object", DefaultRules: "owner_only"}); err != nil {
		t.Fatalf("DefinePolicy failed: %v", err)
	}
	resource := fileResource("f2")

	// alice becomes owner.
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "edit", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("bootstrap grant failed: %v", err)
	}

	// alice grants bob only "read" scope on "edit".
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: bob, Action: "edit", Resource: resource, Scope: "read",
	}); err != nil {
		t.Fatalf("alice->bob grant failed: %v", err)
	}

	// bob (holding only "read" scope) attempts to grant carol "write"
	// scope on the same action/resource — a privilege escalation via
	// grant chain. Must be rejected.
	_, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: bob, Subject: carol, Action: "edit", Resource: resource, Scope: "write",
	})
	if err == nil {
		t.Fatalf("expected escalation attempt (bob granting a higher scope than he holds) to be rejected")
	}

	// carol must not have been granted anything.
	checkResp, _ := svc.CheckPermission(CheckPermissionRequest{Subject: carol, Action: "edit", Resource: resource})
	if checkResp.Allowed {
		t.Fatalf("carol should not have been granted access via bob's escalation attempt")
	}

	if got := audit.count("permissions.grant_denied"); got != 1 {
		t.Errorf("expected 1 permissions.grant_denied audit event, got %d", got)
	}

	// bob CAN re-share his own exact scope (read), that's not escalation.
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: bob, Subject: carol, Action: "edit", Resource: resource, Scope: "read",
	}); err != nil {
		t.Fatalf("expected bob to be able to delegate his own held scope, got error: %v", err)
	}

	// A grantor attempting to grant an action they hold no grant for at
	// all (not just a lower scope of the same action) is also rejected.
	_, err = svc.GrantPermission(GrantPermissionRequest{
		Grantor: bob, Subject: carol, Action: "delete", Resource: resource, Scope: "read",
	})
	if err == nil {
		t.Fatalf("expected bob to be rejected granting an action (delete) he holds no grant for at all")
	}
}

// --- ListGrants, both directions ---

func TestListGrantsBothDirections(t *testing.T) {
	svc, _ := newTestService()
	if _, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "file_object", DefaultRules: "owner_only"}); err != nil {
		t.Fatalf("DefinePolicy failed: %v", err)
	}
	resource := fileResource("f3")

	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("bootstrap grant failed: %v", err)
	}
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource, Scope: "read",
	}); err != nil {
		t.Fatalf("alice->bob grant failed: %v", err)
	}
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: carol, Action: "read", Resource: resource, Scope: "read",
	}); err != nil {
		t.Fatalf("alice->carol grant failed: %v", err)
	}

	byResource, err := svc.ListGrantsForResource(ListGrantsForResourceRequest{Resource: resource})
	if err != nil {
		t.Fatalf("ListGrantsForResource failed: %v", err)
	}
	if len(byResource.Grants) != 3 {
		t.Fatalf("expected 3 grants on resource (owner+bob+carol), got %d: %+v", len(byResource.Grants), byResource.Grants)
	}

	bySubject, err := svc.ListGrantsForSubject(ListGrantsForSubjectRequest{Subject: bob})
	if err != nil {
		t.Fatalf("ListGrantsForSubject failed: %v", err)
	}
	if len(bySubject.Grants) != 1 || bySubject.Grants[0].Subject != bob {
		t.Fatalf("expected exactly 1 grant for bob, got %+v", bySubject.Grants)
	}
}

// --- ExportPermissions ---

func TestExportPermissions(t *testing.T) {
	svc, audit := newTestService()
	if _, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "file_object", DefaultRules: "owner_only"}); err != nil {
		t.Fatalf("DefinePolicy failed: %v", err)
	}
	resource := fileResource("f4")

	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("bootstrap grant failed: %v", err)
	}
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource, Scope: "read",
	}); err != nil {
		t.Fatalf("alice->bob grant failed: %v", err)
	}
	if _, err := svc.RevokePermission(RevokePermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource,
	}); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	exportResp, err := svc.ExportPermissions(ExportPermissionsRequest{IdentityRef: bob})
	if err != nil {
		t.Fatalf("ExportPermissions failed: %v", err)
	}
	if exportResp.FormatVersion != exportDocumentFormatVersion {
		t.Fatalf("unexpected format_version: %s", exportResp.FormatVersion)
	}
	if len(exportResp.ExportBlob) == 0 {
		t.Fatalf("expected non-empty export blob")
	}
	if got := audit.count("permissions.export"); got != 1 {
		t.Errorf("expected 1 permissions.export audit event, got %d", got)
	}
}

// --- DefinePolicy emits an audit event ---

func TestDefinePolicyEmitsAudit(t *testing.T) {
	svc, audit := newTestService()
	if _, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "conversation", DefaultRules: "owner_only"}); err != nil {
		t.Fatalf("DefinePolicy failed: %v", err)
	}
	if got := audit.count("permissions.define_policy"); got != 1 {
		t.Errorf("expected 1 permissions.define_policy audit event, got %d", got)
	}
}

// --- Confused deputy: CheckPermission requires an explicit subject ---

func TestCheckPermissionRequiresExplicitSubject(t *testing.T) {
	svc, _ := newTestService()
	if _, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "file_object", DefaultRules: "owner_only"}); err != nil {
		t.Fatalf("DefinePolicy failed: %v", err)
	}
	_, err := svc.CheckPermission(CheckPermissionRequest{Subject: "", Action: "read", Resource: fileResource("f5")})
	if err == nil {
		t.Fatalf("expected an error when subject is not explicitly provided")
	}
}

// --- Audit-emit failures must surface as loud errors, never a silent
// success (Constitution Warden finding, docs/DECISION_LOG.md "Fix: check
// and handle AuditEmitter.Emit's error at every call site"). ---

var errAuditRejected = fmt.Errorf("audit metadata value exceeds 2048 chars")

func TestGrantPermissionSurfacesAuditEmitFailure(t *testing.T) {
	svc, audit := newTestService()
	if _, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "file_object", DefaultRules: "owner_only"}); err != nil {
		t.Fatalf("DefinePolicy failed: %v", err)
	}
	resource := fileResource("f6")

	// Bootstrap ownership first, while audit still succeeds, so the
	// failure being tested is isolated to the grant under test.
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("bootstrap grant failed: %v", err)
	}

	audit.failWith = errAuditRejected
	_, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource, Scope: "read",
	})
	if err == nil {
		t.Fatalf("expected GrantPermission to return an error when the audit emit fails, got a silent success")
	}
	if !errors.Is(err, errAuditRejected) {
		t.Fatalf("expected the returned error to wrap the audit emit error, got: %v", err)
	}
}

func TestRevokePermissionSurfacesAuditEmitFailure(t *testing.T) {
	svc, audit := newTestService()
	if _, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "file_object", DefaultRules: "owner_only"}); err != nil {
		t.Fatalf("DefinePolicy failed: %v", err)
	}
	resource := fileResource("f7")

	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: alice, Action: "read", Resource: resource, Scope: "owner",
	}); err != nil {
		t.Fatalf("bootstrap grant failed: %v", err)
	}
	if _, err := svc.GrantPermission(GrantPermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource, Scope: "read",
	}); err != nil {
		t.Fatalf("alice->bob grant failed: %v", err)
	}

	audit.failWith = errAuditRejected
	_, err := svc.RevokePermission(RevokePermissionRequest{
		Grantor: alice, Subject: bob, Action: "read", Resource: resource,
	})
	if err == nil {
		t.Fatalf("expected RevokePermission to return an error when the audit emit fails, got a silent success")
	}
	if !errors.Is(err, errAuditRejected) {
		t.Fatalf("expected the returned error to wrap the audit emit error, got: %v", err)
	}
}

// TestDefinePolicySurfacesAuditEmitFailure is the concrete regression test
// for the Constitution Warden finding: DefinePolicy embeds default_rules
// verbatim into audit metadata with no length guard of its own, and
// Audit's real Emit rejects any metadata value over 2048 chars. Before the
// fix, DefinePolicy reported success to the caller while producing zero
// audit record for an oversized policy string; fakeAudit.Emit always
// returning nil meant nothing in this suite caught it. This test proves
// the failure is now surfaced, using the fake's failWith hook rather than
// depending on the real audit package (which this capability does not
// import) to simulate the same rejection.
func TestDefinePolicySurfacesAuditEmitFailure(t *testing.T) {
	svc, audit := newTestService()
	audit.failWith = errAuditRejected

	oversizedRules := make([]byte, 3000)
	for i := range oversizedRules {
		oversizedRules[i] = 'a'
	}

	_, err := svc.DefinePolicy(DefinePolicyRequest{ResourceType: "file_object", DefaultRules: string(oversizedRules)})
	if err == nil {
		t.Fatalf("expected DefinePolicy to return an error when the audit emit fails, got a silent success")
	}
	if !errors.Is(err, errAuditRejected) {
		t.Fatalf("expected the returned error to wrap the audit emit error, got: %v", err)
	}
}

func TestExportPermissionsSurfacesAuditEmitFailure(t *testing.T) {
	svc, audit := newTestService()
	audit.failWith = errAuditRejected

	_, err := svc.ExportPermissions(ExportPermissionsRequest{IdentityRef: bob})
	if err == nil {
		t.Fatalf("expected ExportPermissions to return an error when the audit emit fails, got a silent success")
	}
	if !errors.Is(err, errAuditRejected) {
		t.Fatalf("expected the returned error to wrap the audit emit error, got: %v", err)
	}
}
