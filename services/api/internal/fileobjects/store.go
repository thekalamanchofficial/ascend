package fileobjects

import "sync"

// Store is the in-memory persistence layer for this first implementation
// wave — same precedent as Storage's/Permissions' own Store (narrow method
// set, easy to swap for a real database later without touching Service's
// public API). See docs/DECISION_LOG.md, "File Objects: in-memory store".
type Store struct {
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

func newStore() *Store {
	return &Store{
		fileObjects: make(map[string]FileObjectRecord),
		versions:    make(map[string][]VersionRecord),
		events:      make(map[string][]FileEvent),
	}
}

func (s *Store) putFileObject(r FileObjectRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fileObjects[r.FileObjectID] = r
}

func (s *Store) getFileObject(id string) (FileObjectRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.fileObjects[id]
	return r, ok
}

func (s *Store) deleteFileObjectRecord(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.fileObjects, id)
	delete(s.versions, id)
	delete(s.events, id)
}

func (s *Store) addVersion(fileObjectID string, v VersionRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions[fileObjectID] = append(s.versions[fileObjectID], v)
}

// listVersions returns a defensive copy of fileObjectID's versions, in
// creation order.
func (s *Store) listVersions(fileObjectID string) []VersionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.versions[fileObjectID]
	out := make([]VersionRecord, len(src))
	copy(out, src)
	return out
}

func (s *Store) getVersion(fileObjectID, versionRef string) (VersionRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.versions[fileObjectID] {
		if v.VersionRef == versionRef {
			return v, true
		}
	}
	return VersionRecord{}, false
}

func (s *Store) addEvent(fileObjectID string, e FileEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[fileObjectID] = append(s.events[fileObjectID], e)
}

// eventsForFileObject returns a defensive copy of fileObjectID's own
// File-Objects-emitted event log, in emission order.
func (s *Store) eventsForFileObject(fileObjectID string) []FileEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.events[fileObjectID]
	out := make([]FileEvent, len(src))
	copy(out, src)
	return out
}
