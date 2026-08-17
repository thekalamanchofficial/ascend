package permissions

import "sync"

// Store is the persistence boundary this package's Service depends on. It
// is intentionally narrow and storage-agnostic — InMemoryStore below is a
// mutex-guarded, process-lifetime implementation; PostgresStore
// (postgres_store.go) is a real Postgres-backed implementation of the exact
// same interface, so Service (service.go) is written against Store and does
// not know or care which implementation actually backs it. This mirrors
// Audit's own Store interface pattern (internal/audit/store.go) exactly,
// except this interface's method set matches InMemoryStore's existing
// unexported methods verbatim (kept unexported — everything here stays
// in-package) rather than Audit's exported ones. See docs/DECISION_LOG.md,
// "Permissions: Store interface introduced, PostgresStore added".
type Store interface {
	activeGrant(subject, action string, resource ResourceRef) (Grant, bool)
	ownerOf(resource ResourceRef) (string, bool)
	putGrant(g Grant)
	removeGrant(subject, action string, resource ResourceRef)
	appendHistory(h HistoryEntry)
	setPolicy(p Policy)
	hasPolicy(resourceType string) bool
	grantsForResource(resource ResourceRef) []Grant
	grantsForSubject(subject string) []Grant
	historyForIdentity(identityRef string) []HistoryEntry
	activeGrantsForIdentity(identityRef string) []Grant
}

// InMemoryStore is the first-pass Store implementation: a mutex-guarded,
// process-lifetime store. See docs/DECISION_LOG.md ("Permissions storage:
// in-memory store behind a narrow interface") for why an in-memory store,
// rather than Postgres directly, was chosen for the first implementation
// wave, and how it upgrades later (PostgresStore, postgres_store.go)
// without touching Service's public API.
type InMemoryStore struct {
	mu sync.RWMutex

	// active holds the single currently-effective Grant for each
	// (subject, action, resource) tuple. Re-granting the same tuple
	// overwrites the previous entry (the latest grant is authoritative);
	// revoking removes the entry.
	active map[string]Grant

	// owners maps a resource key (ResourceRef.key()) to the subject who
	// was the first-ever grantor for that resource — the implicit owner,
	// per the charter §6 privilege-escalation rule.
	owners map[string]string

	// policies maps resource_type to its registered default policy.
	// A resource_type with no entry here fails CheckPermission closed.
	policies map[string]Policy

	// history is the append-only grant/revoke event log backing
	// ExportPermissions and Art. 5/9 explainability + export obligations.
	history []HistoryEntry
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		active:   make(map[string]Grant),
		owners:   make(map[string]string),
		policies: make(map[string]Policy),
	}
}

func activeGrantKey(subject, action string, resource ResourceRef) string {
	return subject + "\x1f" + action + "\x1f" + resource.key()
}

func (s *InMemoryStore) activeGrant(subject, action string, resource ResourceRef) (Grant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.active[activeGrantKey(subject, action, resource)]
	return g, ok
}

func (s *InMemoryStore) ownerOf(resource ResourceRef) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	owner, ok := s.owners[resource.key()]
	return owner, ok
}

// putGrant records g as the active grant for its (subject, action,
// resource) tuple. If no owner is yet recorded for the resource, g's
// grantor becomes the resource's implicit owner (charter §6: "the first
// grantor for a given resource is implicitly its owner").
func (s *InMemoryStore) putGrant(g Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active[activeGrantKey(g.Subject, g.Action, g.Resource)] = g
	if _, hasOwner := s.owners[g.Resource.key()]; !hasOwner {
		s.owners[g.Resource.key()] = g.Grantor
	}
}

func (s *InMemoryStore) removeGrant(subject, action string, resource ResourceRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, activeGrantKey(subject, action, resource))
}

func (s *InMemoryStore) appendHistory(h HistoryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.history = append(s.history, h)
}

func (s *InMemoryStore) setPolicy(p Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ResourceType] = p
}

func (s *InMemoryStore) hasPolicy(resourceType string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.policies[resourceType]
	return ok
}

func (s *InMemoryStore) grantsForResource(resource ResourceRef) []Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Grant
	for _, g := range s.active {
		if g.Resource == resource {
			out = append(out, g)
		}
	}
	return out
}

func (s *InMemoryStore) grantsForSubject(subject string) []Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Grant
	for _, g := range s.active {
		if g.Subject == subject {
			out = append(out, g)
		}
	}
	return out
}

func (s *InMemoryStore) historyForIdentity(identityRef string) []HistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []HistoryEntry
	for _, h := range s.history {
		if h.Subject == identityRef || h.Grantor == identityRef {
			out = append(out, h)
		}
	}
	return out
}

func (s *InMemoryStore) activeGrantsForIdentity(identityRef string) []Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Grant
	for _, g := range s.active {
		if g.Subject == identityRef || g.Grantor == identityRef {
			out = append(out, g)
		}
	}
	return out
}
