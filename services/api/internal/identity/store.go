package identity

import "sync"

// Store is the persistence seam this capability builds against. Only an
// in-memory implementation (InMemoryStore, below) exists in this pass —
// see docs/DECISION_LOG.md for the "storage approach for this pass"
// decision. A future Postgres-backed implementation (once Storage's own
// charter/contract lands) only needs to satisfy this interface; Service
// (service.go) never depends on the concrete type.
type Store interface {
	// Create inserts a brand-new record. Returns ErrInvalidArgument-wrapped
	// error if the identity_ref already exists (should not happen given
	// newID()'s collision odds, but callers must not silently overwrite).
	Create(record IdentityRecord) error

	// Get returns the record for identityRef, or ErrIdentityNotFound.
	Get(identityRef string) (IdentityRecord, error)

	// Replace overwrites the stored record for record.IdentityRef in place
	// (used after appending/removing a device). Returns ErrIdentityNotFound
	// if no record exists yet for that ref.
	Replace(record IdentityRecord) error
}

// InMemoryStore is a goroutine-safe, process-local Store. It deliberately
// holds no durability guarantee across restarts — that is an explicit,
// documented limitation of this pass, not a hidden one (Art. 15).
type InMemoryStore struct {
	mu      sync.RWMutex
	records map[string]IdentityRecord
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{records: make(map[string]IdentityRecord)}
}

func (s *InMemoryStore) Create(record IdentityRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.IdentityRef]; exists {
		return ErrInvalidArgument
	}
	s.records[record.IdentityRef] = cloneRecord(record)
	return nil
}

func (s *InMemoryStore) Get(identityRef string) (IdentityRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[identityRef]
	if !ok {
		return IdentityRecord{}, ErrIdentityNotFound
	}
	return cloneRecord(rec), nil
}

func (s *InMemoryStore) Replace(record IdentityRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[record.IdentityRef]; !ok {
		return ErrIdentityNotFound
	}
	s.records[record.IdentityRef] = cloneRecord(record)
	return nil
}

// cloneRecord returns a deep-enough copy that callers holding a returned
// IdentityRecord can't mutate the store's internal state through shared
// slice/byte-slice backing arrays.
func cloneRecord(rec IdentityRecord) IdentityRecord {
	out := rec
	out.PublicKey = append([]byte(nil), rec.PublicKey...)
	out.Devices = make([]Device, len(rec.Devices))
	for i, d := range rec.Devices {
		out.Devices[i] = Device{
			DeviceID:     d.DeviceID,
			Name:         d.Name,
			PublicKey:    append([]byte(nil), d.PublicKey...),
			AddedAtUnix:  d.AddedAtUnix,
			LastSeenUnix: d.LastSeenUnix,
		}
	}
	return out
}
