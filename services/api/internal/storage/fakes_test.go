package storage

import (
	"errors"
	"sync"
)

// --- fakePermissionChecker: a controllable PermissionChecker fake. ---

type fakePermissionChecker struct {
	mu    sync.Mutex
	allow bool
	err   error
	calls []permCall
}

type permCall struct {
	subject, action, resourceType, resourceID string
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
}

func newFakeBackend(physicalDelete bool, locationPrefix string) *fakeBackend {
	return &fakeBackend{data: make(map[string][]byte), physicalDelete: physicalDelete, locationPrefix: locationPrefix}
}

func (b *fakeBackend) Store(key string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
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

func (b *fakeBackend) rawBytes(key string) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.data[key]
	return d, ok
}
