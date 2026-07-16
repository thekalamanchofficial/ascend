package audit

import (
	"errors"
	"sort"
	"strconv"
	"sync"
)

// ErrChainTampered is returned by VerifyIntegrity when a stored event's
// content or ordering no longer matches its recorded hash chain.
var ErrChainTampered = errors.New("audit: event chain integrity check failed")

// Store is the persistence boundary this package's Service depends on. It is
// intentionally small and storage-agnostic — the first-pass implementation
// (InMemoryStore below) is an in-memory, process-lifetime store; a future
// Postgres-backed implementation (append-only table, DB-level REVOKE of
// UPDATE/DELETE grants) can satisfy the same interface without any change to
// Service. See the 2026-07-16 "Audit storage: in-memory Store first pass"
// decision log entry for why this pass doesn't wire a real database.
type Store interface {
	// Append assigns the event its position in the global hash chain
	// (computing PrevHash and EventID) and persists it. Append-only: no
	// Update or Delete method exists on this interface by design — see
	// charter §6 ("must not be silently editable or deletable, including
	// by platform operators").
	Append(e AuditEvent) (AuditEvent, error)
	// Get looks up a single event by its EventID.
	Get(eventID string) (AuditEvent, bool)
	// Query returns events matching filter, most-recent-first.
	Query(filter QueryFilter) ([]AuditEvent, error)
	// All returns every event in append order (oldest first). Used by
	// VerifyIntegrity and ExportAuditTrail.
	All() []AuditEvent
}

// InMemoryStore is the first-pass Store implementation: a mutex-guarded,
// append-only, process-lifetime event log.
type InMemoryStore struct {
	mu       sync.RWMutex
	events   []AuditEvent
	byID     map[string]AuditEvent
	lastHash string
}

// NewInMemoryStore constructs an empty store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{byID: make(map[string]AuditEvent)}
}

func (s *InMemoryStore) Append(e AuditEvent) (AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e.PrevHash = s.lastHash
	e.EventID = computeEventHash(e)

	s.events = append(s.events, e)
	s.byID[e.EventID] = e
	s.lastHash = e.EventID
	return e, nil
}

func (s *InMemoryStore) Get(eventID string) (AuditEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byID[eventID]
	return e, ok
}

func (s *InMemoryStore) Query(filter QueryFilter) ([]AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]AuditEvent, 0)
	for _, e := range s.events {
		if filter.Subject != "" && e.Actor != filter.Subject {
			continue
		}
		if filter.ResourceTypeFilter != "" && e.Resource.ResourceType != filter.ResourceTypeFilter {
			continue
		}
		if filter.ResourceIDFilter != "" && e.Resource.ResourceID != filter.ResourceIDFilter {
			continue
		}
		if filter.ActionFilter != "" && e.Action != filter.ActionFilter {
			continue
		}
		if filter.SinceUnix != 0 && e.OccurredAtUnix < filter.SinceUnix {
			continue
		}
		if filter.UntilUnix != 0 && e.OccurredAtUnix > filter.UntilUnix {
			continue
		}
		out = append(out, e)
	}

	// Most-recent-first: the natural reading order for "why did this
	// happen" investigations, which usually start from the latest event.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].OccurredAtUnix > out[j].OccurredAtUnix
	})
	return out, nil
}

func (s *InMemoryStore) All() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEvent, len(s.events))
	copy(out, s.events)
	return out
}

// VerifyIntegrity recomputes the hash chain over events (assumed to be in
// append order, oldest first — as returned by Store.All) and returns
// ErrChainTampered (wrapped with detail) at the first event whose recorded
// EventID no longer matches its recomputed content hash, or whose PrevHash
// does not match the previous event's EventID. This is the mechanical proof
// behind the charter's tamper-evidence requirement: any edit, deletion, or
// reordering of a historical event is detectable, not just discouraged by
// convention.
func VerifyIntegrity(events []AuditEvent) error {
	prev := ""
	for i, e := range events {
		if e.PrevHash != prev {
			return errChainAt(i, e.EventID, "prev_hash does not match preceding event's event_id")
		}
		want := computeEventHash(e)
		if want != e.EventID {
			return errChainAt(i, e.EventID, "recomputed hash does not match stored event_id")
		}
		prev = e.EventID
	}
	return nil
}

func errChainAt(index int, eventID, reason string) error {
	return &chainError{index: index, eventID: eventID, reason: reason}
}

type chainError struct {
	index   int
	eventID string
	reason  string
}

func (e *chainError) Error() string {
	return "audit: chain integrity check failed at index " + strconv.Itoa(e.index) + " (event_id=" + e.eventID + "): " + e.reason
}

func (e *chainError) Unwrap() error { return ErrChainTampered }
