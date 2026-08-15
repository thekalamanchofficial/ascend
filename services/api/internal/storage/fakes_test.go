package storage

import (
	"errors"
	"sync"
)

// --- fakePermissionChecker: a controllable PermissionChecker fake. ---

type fakePermissionChecker struct {
	mu               sync.Mutex
	allow            bool
	err              error
	calls            []permCall
	definePolicyErr  error
	definePolicyCall []policyCall
	grantErr         error
	grantCalls       []grantCall
	revokeErr        error
	revokeCalls      []revokeCall
}

type permCall struct {
	subject, action, resourceType, resourceID string
}

type policyCall struct {
	resourceType, defaultRules string
}

type grantCall struct {
	grantor, subject, action, resourceType, resourceID, scope string
}

type revokeCall struct {
	grantor, subject, action, resourceType, resourceID string
}

func newFakePermissionChecker(allow bool) *fakePermissionChecker {
	return &fakePermissionChecker{allow: allow}
}

func (f *fakePermissionChecker) CheckPermission(subject, action, resourceType, resourceID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, permCall{subject, action, resourceType, resourceID})
	if f.err != nil {
		return false, f.err
	}
	return f.allow, nil
}

// DefinePolicy records the call (so tests can assert NewService registers
// resourceTypeBlob's policy at construction) and, unless definePolicyErr
// is set, always succeeds — mirroring the real Permissions.DefinePolicy's
// plain-map-write, no-error-on-redefinition semantics (store.go's
// setPolicy).
func (f *fakePermissionChecker) DefinePolicy(resourceType, defaultRules string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.definePolicyCall = append(f.definePolicyCall, policyCall{resourceType, defaultRules})
	return f.definePolicyErr
}

// GrantPermission records the call (so tests can assert StoreBlob
// establishes the owner grant, and with what shape) and, unless grantErr is
// set, always succeeds. This fake does not model Permissions' real
// bootstrap-owner/CheckPermission interaction at all — it is deliberately
// as simplistic as this fake's existing allow/deny CheckPermission (see the
// package-level doc comment on realisticPermissionChecker in
// permissions_integration_test.go for why a from-scratch, real-rule
// reimplementation lives there instead, not here).
func (f *fakePermissionChecker) GrantPermission(grantor, subject, action, resourceType, resourceID, scope string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grantCalls = append(f.grantCalls, grantCall{grantor, subject, action, resourceType, resourceID, scope})
	return f.grantErr
}

// RevokePermission records the call (so tests can assert StoreBlob's
// audit-failure rollback path revokes the grant it just made) and, unless
// revokeErr is set, always succeeds.
func (f *fakePermissionChecker) RevokePermission(grantor, subject, action, resourceType, resourceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeCalls = append(f.revokeCalls, revokeCall{grantor, subject, action, resourceType, resourceID})
	return f.revokeErr
}

// --- fakeAuditEmitter: a controllable AuditEmitter fake that records
// every call and can be told to fail (to test the "audit failure surfaces
// loudly" paths this package's spawn brief specifically requires). ---

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
	return "evt", nil
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

// --- fakeBackend: an in-memory Backend whose physical-delete support and
// failure behavior are fully controllable, used to exercise the
// crypto-shred deletion path and MoveBlob's rollback path without
// depending on filesystem-specific failure injection. ---

type fakeBackend struct {
	mu             sync.Mutex
	data           map[string][]byte
	physicalDelete bool
	failStore      bool
	failRetrieve   bool
	failDelete     bool
	locationPrefix string
	// deleteCalls/storeCalls count real Backend.Delete/Store invocations —
	// used by the DeleteBlob/MoveBlob concurrency-hardening tests
	// (service_concurrency_test.go) to prove the underlying backend
	// mechanism only ever runs once per genuine relocation/deletion, even
	// under concurrent duplicate requests, rather than merely inferring
	// that from the final map state (which, for this in-memory fake,
	// would stay correct even under a double-call race a real backend
	// might not tolerate as gracefully).
	deleteCalls int
	storeCalls  int
}

func newFakeBackend(physicalDelete bool, locationPrefix string) *fakeBackend {
	return &fakeBackend{data: make(map[string][]byte), physicalDelete: physicalDelete, locationPrefix: locationPrefix}
}

func (b *fakeBackend) Store(key string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.storeCalls++
	if b.failStore {
		return errors.New("fake backend: store failed")
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	b.data[key] = cp
	return nil
}

func (b *fakeBackend) Retrieve(key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failRetrieve {
		return nil, errors.New("fake backend: retrieve failed")
	}
	d, ok := b.data[key]
	if !ok {
		return nil, ErrBackendKeyNotFound
	}
	cp := make([]byte, len(d))
	copy(cp, d)
	return cp, nil
}

func (b *fakeBackend) Delete(key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deleteCalls++
	if b.failDelete {
		return errors.New("fake backend: delete failed")
	}
	if !b.physicalDelete {
		// Models a backend that cannot guarantee true byte-level erasure
		// (e.g. some replicated object-storage backends, per the
		// charter's own "some object-storage replication models" example):
		// the call reports success, but the underlying bytes are not
		// actually guaranteed to be gone — this is exactly the situation
		// DeleteBlob's crypto-shred fallback exists for, and exactly why
		// SupportsPhysicalDelete() must be checked BEFORE trusting a
		// Delete() call's success to mean the bytes are truly erased.
		return nil
	}
	delete(b.data, key)
	return nil
}

func (b *fakeBackend) SupportsPhysicalDelete() bool { return b.physicalDelete }

func (b *fakeBackend) Location(key string) string {
	return b.locationPrefix + ":" + key
}

// has reports whether key is still physically present in this fake
// backend's store — used by tests to prove crypto-shredded bytes remain
// present-but-unrecoverable (as opposed to also physically removed, which
// a real non-physical-delete backend couldn't guarantee anyway).
func (b *fakeBackend) has(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.data[key]
	return ok
}

// deleteCallCount/storeCallCount are locked accessors for the counters
// above — safe to call from a test goroutine concurrently with the
// backend still being exercised by other goroutines.
func (b *fakeBackend) deleteCallCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.deleteCalls
}

func (b *fakeBackend) storeCallCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.storeCalls
}

func (b *fakeBackend) rawBytes(key string) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.data[key]
	return d, ok
}
