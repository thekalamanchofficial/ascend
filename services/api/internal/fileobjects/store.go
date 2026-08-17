package fileobjects

import "sync"

// Store is the persistence boundary this package's Service depends on. It
// is intentionally narrow and storage-agnostic — InMemoryStore below is a
// mutex-guarded, process-lifetime implementation; PostgresStore
// (postgres_store.go) is a real Postgres-backed implementation of the exact
// same interface, so Service (service.go) is written against Store and does
// not know or care which implementation actually backs it. This mirrors
// Audit's own Store interface pattern (internal/audit/store.go) and
// Permissions' own recent interface introduction
// (internal/permissions/store.go) exactly: the interface's method set
// matches InMemoryStore's existing unexported methods verbatim (kept
// unexported — everything here stays in-package). See
// docs/DECISION_LOG.md, "File Objects: Store interface introduced,
// PostgresStore added".
type Store interface {
	putFileObject(r FileObjectRecord)
	getFileObject(id string) (FileObjectRecord, bool)
	deleteFileObjectRecord(id string)
	addVersion(fileObjectID string, v VersionRecord)
	listVersions(fileObjectID string) []VersionRecord
	getVersion(fileObjectID, versionRef string) (VersionRecord, bool)
	addEvent(fileObjectID string, e FileEvent)
	eventsForFileObject(fileObjectID string) []FileEvent
}

// InMemoryStore is the first-pass Store implementation: a mutex-guarded,
// process-lifetime store (same precedent as Storage's/Permissions' own
// first-wave in-memory store — narrow method set, easy to swap for a real
// database later without touching Service's public API). See
// docs/DECISION_LOG.md, "File Objects: in-memory store", and its own
// interface-introduction entry above.
type InMemoryStore struct {
	mu sync.RWMutex

	fileObjects map[string]FileObjectRecord
	// versions holds every version of a file object, in creation order
	// (oldest first) — never reordered or pruned except by
	// DeleteFileObject's atomic teardown (charter §7's version-storage
	// open question: no intermediate/delta blob exists independently of
	// this slice, so nothing here can be orphaned outside that teardown).
	versions map[string][]VersionRecord
	// events holds this package's own emitted FileEvents per file object,
	// in emission order — the exclusive backing store for
	// GetFileHistory/ExportFile (charter §6 point 8a).
	events map[string][]FileEvent
}

func newInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		fileObjects: make(map[string]FileObjectRecord),
		versions:    make(map[string][]VersionRecord),
		events:      make(map[string][]FileEvent),
	}
}

func (s *InMemoryStore) putFileObject(r FileObjectRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fileObjects[r.FileObjectID] = r
}

func (s *InMemoryStore) getFileObject(id string) (FileObjectRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.fileObjects[id]
	return r, ok
}

func (s *InMemoryStore) deleteFileObjectRecord(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.fileObjects, id)
	delete(s.versions, id)
	delete(s.events, id)
}

func (s *InMemoryStore) addVersion(fileObjectID string, v VersionRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions[fileObjectID] = append(s.versions[fileObjectID], v)
}

// listVersions returns a defensive copy of fileObjectID's versions, in
// creation order.
func (s *InMemoryStore) listVersions(fileObjectID string) []VersionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.versions[fileObjectID]
	out := make([]VersionRecord, len(src))
	copy(out, src)
	return out
}

func (s *InMemoryStore) getVersion(fileObjectID, versionRef string) (VersionRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.versions[fileObjectID] {
		if v.VersionRef == versionRef {
			return v, true
		}
	}
	return VersionRecord{}, false
}

func (s *InMemoryStore) addEvent(fileObjectID string, e FileEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[fileObjectID] = append(s.events[fileObjectID], e)
}

// eventsForFileObject returns a defensive copy of fileObjectID's own
// File-Objects-emitted event log, in emission order.
func (s *InMemoryStore) eventsForFileObject(fileObjectID string) []FileEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.events[fileObjectID]
	out := make([]FileEvent, len(src))
	copy(out, src)
	return out
}
