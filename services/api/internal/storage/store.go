package storage

import "sync"

// Store is the in-memory persistence layer for this first pass. See
// docs/DECISION_LOG.md ("Storage storage: in-memory metadata store behind
// a narrow interface, filesystem for bytes") for why: it follows the same
// precedent Permissions established (services/api/internal/permissions/
// store.go) for a first implementation wave with no established
// services/api Postgres convention yet — narrow method set, easy to swap
// for a real database later without touching Service's public API.
//
// Store holds two logically distinct things, kept in separate maps
// deliberately: BlobRecord metadata (persisted, exported, Art. 8/9
// governed — see DATA_MANIFEST.md) and wrapping keys (operational secret
// material, NEVER exported, NEVER part of any persisted/exported type —
// see wrap.go). Conflating them into one struct would risk a future
// change accidentally leaking a wrapping key through an export path.
type Store struct {
	mu sync.RWMutex

	records      map[string]BlobRecord
	wrappingKeys map[string][]byte
}

func NewStore() *Store {
	return &Store{
		records:      make(map[string]BlobRecord),
		wrappingKeys: make(map[string][]byte),
	}
}

func (s *Store) put(record BlobRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.BlobRef] = record
}

func (s *Store) get(blobRef string) (BlobRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[blobRef]
	return r, ok
}

func (s *Store) delete(blobRef string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, blobRef)
}

// recordsForOwner returns every BlobRecord (including tombstones) owned by
// owner, backing ExportAllBlobs.
func (s *Store) recordsForOwner(owner string) []BlobRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []BlobRecord
	for _, r := range s.records {
		if r.Owner == owner {
			out = append(out, r)
		}
	}
	return out
}

func (s *Store) putWrappingKey(blobRef string, key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrappingKeys[blobRef] = key
}

func (s *Store) wrappingKey(blobRef string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.wrappingKeys[blobRef]
	return k, ok
}

// destroyWrappingKey zeroes and removes blobRef's wrapping key, if
// present. Returns false if no key was present to destroy (already
// destroyed, or never existed) — DeleteBlob's crypto-shred path uses this
// to fail loudly rather than silently no-op on a double-shred attempt.
func (s *Store) destroyWrappingKey(blobRef string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.wrappingKeys[blobRef]
	if !ok {
		return false
	}
	zeroBytes(key)
	delete(s.wrappingKeys, blobRef)
	return true
}

// hasWrappingKey is a test/inspection helper: it never returns the key
// itself, only whether one is currently held. Exported (lowercase, so
// package-internal-only) for use by tests proving the crypto-shred
// deletion path actually removes the key rather than merely claiming to.
func (s *Store) hasWrappingKey(blobRef string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.wrappingKeys[blobRef]
	return ok
}
