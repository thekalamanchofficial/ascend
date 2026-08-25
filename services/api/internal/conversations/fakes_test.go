package conversations

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// memPermissions is a from-scratch, package-local reimplementation of
// Permissions' real CheckPermission/GrantPermission/DefinePolicy decision
// logic (fail closed on an unregistered resource type; first grantor on a
// resource becomes its permanent implicit owner; a grantor may grant only
// if they are the owner, the resource has no owner yet, or they hold an
// equal-or-greater active grant for the same action/resource).
//
// This deliberately does NOT import services/api/internal/permissions:
// scripts/constitution/check-modularity.sh's Art. 10 check has no test-file
// exemption for non-shared capability packages (confirmed precedent:
// internal/fileobjects/fakes_test.go's memPermissions takes the identical
// approach, for the identical reason). Using a from-scratch
// reimplementation rather than a simple unconditional-allow/deny fake is
// what makes this package's enumeration-oracle tests (service_test.go,
// http_test.go) a faithful proof of the real invariant — "no grant exists"
// for a genuinely nonexistent conversation_id must behave identically to
// "no grant exists" for one that exists but subject never joined, which
// only a real deny-by-default/no-implicit-anything engine can actually
// exercise.
type memPermissions struct {
	mu       sync.Mutex
	policies map[string]bool
	owners   map[string]string // resourceType\x1fresourceID -> owner subject
	grants   map[grantKey]grantValue

	definePolicyErr error
	grantFailFor    map[string]error // callKey(...) -> forced error
	checkErrAll     error

	grantCalls        []grantKey
	definePolicyCalls []string
}

type grantKey struct {
	subject, action, resourceType, resourceID string
}

type grantValue struct {
	scope   string
	grantor string
}

func newMemPermissions() *memPermissions {
	return &memPermissions{
		policies:     make(map[string]bool),
		owners:       make(map[string]string),
		grants:       make(map[grantKey]grantValue),
		grantFailFor: make(map[string]error),
	}
}

func resourceKey(resourceType, resourceID string) string {
	return resourceType + "\x1f" + resourceID
}

func callKey(subject, action, resourceType, resourceID string) string {
	return subject + "\x1f" + action + "\x1f" + resourceType + "\x1f" + resourceID
}

func (m *memPermissions) CheckPermission(subject, action, resourceType, resourceID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.checkErrAll != nil {
		return false, m.checkErrAll
	}
	if !m.policies[resourceType] {
		return false, nil
	}
	if owner, ok := m.owners[resourceKey(resourceType, resourceID)]; ok && owner == subject {
		return true, nil
	}
	if _, ok := m.grants[grantKey{subject, action, resourceType, resourceID}]; ok {
		return true, nil
	}
	return false, nil
}

func (m *memPermissions) GrantPermission(grantor, subject, action, resourceType, resourceID, scope string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grantCalls = append(m.grantCalls, grantKey{subject, action, resourceType, resourceID})

	if err, ok := m.grantFailFor[callKey(subject, action, resourceType, resourceID)]; ok {
		return err
	}

	rk := resourceKey(resourceType, resourceID)
	owner, hasOwner := m.owners[rk]

	allowed := false
	switch {
	case !hasOwner:
		allowed = true // bootstrap_owner
	case owner == grantor:
		allowed = true // resource_owner
	default:
		if _, ok := m.grants[grantKey{grantor, action, resourceType, resourceID}]; ok {
			allowed = true // delegated_from_existing_grant
		}
	}
	if !allowed {
		return errors.New("mem permissions: permission denied: grantor does not hold sufficient privilege to grant this action/scope")
	}

	if !hasOwner {
		m.owners[rk] = grantor
	}
	m.grants[grantKey{subject, action, resourceType, resourceID}] = grantValue{scope: scope, grantor: grantor}
	return nil
}

func (m *memPermissions) DefinePolicy(resourceType, defaultRules string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.definePolicyCalls = append(m.definePolicyCalls, resourceType)
	if m.definePolicyErr != nil {
		return m.definePolicyErr
	}
	m.policies[resourceType] = true
	return nil
}

// hasActiveGrant is a test-only inspection helper (not part of
// PermissionsClient).
func (m *memPermissions) hasActiveGrant(subject, action, resourceType, resourceID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.grants[grantKey{subject, action, resourceType, resourceID}]
	return ok
}

// ownerOf is a test-only inspection helper.
func (m *memPermissions) ownerOf(resourceType, resourceID string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.owners[resourceKey(resourceType, resourceID)]
	return o, ok
}

// --- fakeAuditEmitter: a controllable AuditEmitter fake that records every
// call and can be told to fail, mirroring fileobjects.fakeAuditEmitter
// exactly. ---

type auditCall struct {
	actor, action, ruleReference string
	resource                     ResourceRef
	metadata                     map[string]string
}

type fakeAuditEmitter struct {
	mu       sync.Mutex
	calls    []auditCall
	nextID   int
	failNext bool
	failAll  bool
}

func newFakeAuditEmitter() *fakeAuditEmitter {
	return &fakeAuditEmitter{}
}

func (f *fakeAuditEmitter) Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, auditCall{actor: actor, action: action, resource: resource, ruleReference: ruleReference, metadata: metadata})
	if f.failAll || f.failNext {
		f.failNext = false
		return "", errors.New("fake audit emit failure")
	}
	f.nextID++
	return fmt.Sprintf("evt-%d", f.nextID), nil
}

func (f *fakeAuditEmitter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeAuditEmitter) lastCall() (auditCall, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return auditCall{}, false
	}
	return f.calls[len(f.calls)-1], true
}

func (f *fakeAuditEmitter) allCalls() []auditCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]auditCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// newTestService constructs a Service against fresh, real-semantics fakes —
// the standard test fixture used across this package's test suite. Mirrors
// fileobjects.newTestService's identical shape.
func newTestService(t *testing.T) (*Service, *memPermissions, *fakeAuditEmitter) {
	t.Helper()
	perms := newMemPermissions()
	audit := newFakeAuditEmitter()
	svc, err := NewService(newInMemoryStore(), perms, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, perms, audit
}

// Test-only identity constants used throughout this package's tests.
const (
	alice    = "identity:alice"
	bob      = "identity:bob"
	carol    = "identity:carol"
	stranger = "identity:stranger"
)
