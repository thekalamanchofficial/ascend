package fileobjects

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// --- fakeStorageClient: a controllable StorageClient fake. ---

type storedBlob struct {
	owner   string
	data    []byte
	deleted bool
}

type retrieveCall struct {
	blobRef, requestingSubject string
}

type fakeStorageClient struct {
	mu     sync.Mutex
	blobs  map[string]storedBlob
	nextID int

	storeErr       error
	retrieveErrFor map[string]error
	retrieveErrAll error
	deleteErrFor   map[string]error
	deleteErrAll   error

	retrieveCalls []retrieveCall
}

func newFakeStorageClient() *fakeStorageClient {
	return &fakeStorageClient{
		blobs:          make(map[string]storedBlob),
		retrieveErrFor: make(map[string]error),
		deleteErrFor:   make(map[string]error),
	}
}

func (f *fakeStorageClient) StoreBlob(owner string, data []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.storeErr != nil {
		return "", f.storeErr
	}
	f.nextID++
	ref := fmt.Sprintf("blob-%d", f.nextID)
	cp := append([]byte(nil), data...)
	f.blobs[ref] = storedBlob{owner: owner, data: cp}
	return ref, nil
}

func (f *fakeStorageClient) RetrieveBlob(blobRef, requestingSubject string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retrieveCalls = append(f.retrieveCalls, retrieveCall{blobRef, requestingSubject})
	if err, ok := f.retrieveErrFor[blobRef]; ok {
		return nil, err
	}
	if f.retrieveErrAll != nil {
		return nil, f.retrieveErrAll
	}
	b, ok := f.blobs[blobRef]
	if !ok || b.deleted {
		return nil, fmt.Errorf("fake storage: blob %s not found", blobRef)
	}
	return append([]byte(nil), b.data...), nil
}

func (f *fakeStorageClient) DeleteBlob(blobRef, requestingSubject string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.deleteErrFor[blobRef]; ok {
		return err
	}
	if f.deleteErrAll != nil {
		return f.deleteErrAll
	}
	b, ok := f.blobs[blobRef]
	if !ok {
		return fmt.Errorf("fake storage: blob %s not found", blobRef)
	}
	b.deleted = true
	f.blobs[blobRef] = b
	return nil
}

func (f *fakeStorageClient) has(blobRef string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.blobs[blobRef]
	return ok && !b.deleted
}

// --- memPermissions: a from-scratch, package-local reimplementation of
// Permissions' real CheckPermission/GrantPermission/RevokePermission
// decision logic (fail closed on unregistered resource type; first
// grantor on a resource becomes its permanent implicit owner; a grantor
// may grant only if they are the owner, the resource has no owner yet, or
// they hold an equal-or-greater active grant for the same action/resource;
// a grantor may revoke if they are the owner, the original grantor of that
// grant, or self-revoking).
//
// This deliberately does NOT import services/api/internal/permissions:
// scripts/constitution/check-modularity.sh's Art. 10 check has no
// test-file exemption for non-shared capability packages (confirmed
// precedent: services/api/internal/storage/permissions_integration_test.go's
// realisticPermissionChecker takes the identical approach, for the
// identical reason). Using a from-scratch reimplementation rather than a
// simple unconditional-allow/deny fake is what makes this package's most
// safety-critical test — proving CreateVersion's mirroring never lets a
// non-owner collaborator become a new blob's permanent Permissions-owner —
// a faithful proof of the real invariant, not a fake that could never have
// caught the bug it's proving fixed.
type memPermissions struct {
	mu       sync.Mutex
	policies map[string]bool
	owners   map[string]string // resourceType\x1fresourceID -> owner subject

	grants map[grantKey]grantValue

	grantFailFor    map[string]error // "subject\x1faction\x1fresourceType\x1fresourceID" -> forced error
	revokeFailFor   map[string]error
	listGrantsErr   map[string]error // "resourceType\x1fresourceID" -> forced error
	definePolicyErr error
	checkErrAll     error

	grantCalls        []grantKey
	revokeCalls       []grantKey
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
		policies:      make(map[string]bool),
		owners:        make(map[string]string),
		grants:        make(map[grantKey]grantValue),
		grantFailFor:  make(map[string]error),
		revokeFailFor: make(map[string]error),
		listGrantsErr: make(map[string]error),
	}
}

func resourceKey(resourceType, resourceID string) string {
	return resourceType + "\x1f" + resourceID
}

func callKey(subject, action, resourceType, resourceID string) string {
	return subject + "\x1f" + action + "\x1f" + resourceType + "\x1f" + resourceID
}

// scopeRankLocal/scopeAtLeastLocal mirror permissions/scope.go's ranking
// exactly (from scratch, not imported — see the type doc comment above).
var scopeRankLocal = map[string]int{"read": 1, "write": 2, "full": 3, "owner": 4}

func scopeAtLeastLocal(held, requested string) bool {
	normalize := func(s string) string {
		if s == "" {
			return "full"
		}
		return strings.ToLower(s)
	}
	h, hOK := scopeRankLocal[normalize(held)]
	r, rOK := scopeRankLocal[normalize(requested)]
	if hOK && rOK {
		return h >= r
	}
	return normalize(held) == normalize(requested)
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
	if g, ok := m.grants[grantKey{subject, action, resourceType, resourceID}]; ok {
		_ = g
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
	if !hasOwner {
		allowed = true // bootstrap_owner
	} else if owner == grantor {
		allowed = true // resource_owner
	} else if held, ok := m.grants[grantKey{grantor, action, resourceType, resourceID}]; ok && scopeAtLeastLocal(held.scope, scope) {
		allowed = true // delegated_from_existing_grant
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

func (m *memPermissions) RevokePermission(grantor, subject, action, resourceType, resourceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeCalls = append(m.revokeCalls, grantKey{subject, action, resourceType, resourceID})

	if err, ok := m.revokeFailFor[callKey(subject, action, resourceType, resourceID)]; ok {
		return err
	}

	key := grantKey{subject, action, resourceType, resourceID}
	existing, found := m.grants[key]
	if !found {
		return errors.New("mem permissions: no active grant found to revoke")
	}

	rk := resourceKey(resourceType, resourceID)
	owner := m.owners[rk]

	allowed := owner == grantor || existing.grantor == grantor || grantor == subject
	if !allowed {
		return errors.New("mem permissions: permission denied: grantor does not hold sufficient privilege to revoke this grant")
	}

	delete(m.grants, key)
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

func (m *memPermissions) ListGrantsForResource(resourceType, resourceID string) ([]PermissionGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.listGrantsErr[resourceKey(resourceType, resourceID)]; ok {
		return nil, err
	}
	var out []PermissionGrant
	for k := range m.grants {
		if k.resourceType == resourceType && k.resourceID == resourceID {
			out = append(out, PermissionGrant{Subject: k.subject, Action: k.action, Scope: m.grants[k].scope})
		}
	}
	return out, nil
}

// ownerOf is a test-only inspection helper (not part of the
// PermissionsClient interface) — used specifically to prove the
// CreateVersion ownership-bootstrap invariant.
func (m *memPermissions) ownerOf(resourceType, resourceID string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.owners[resourceKey(resourceType, resourceID)]
	return o, ok
}

// hasActiveGrant is a test-only inspection helper.
func (m *memPermissions) hasActiveGrant(subject, action, resourceType, resourceID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.grants[grantKey{subject, action, resourceType, resourceID}]
	return ok
}

// --- fakeAuditEmitter: a controllable AuditEmitter fake that records
// every call and can be told to fail, mirroring Storage's/Permissions'
// identical test fixture. ---

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

// newTestService constructs a Service against fresh, real-semantics fakes
// — the standard test fixture used across this package's test suite.
func newTestService(t *testing.T) (*Service, *fakeStorageClient, *memPermissions, *fakeAuditEmitter) {
	t.Helper()
	storage := newFakeStorageClient()
	perms := newMemPermissions()
	audit := newFakeAuditEmitter()
	svc, err := NewService(storage, perms, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, storage, perms, audit
}
