package audit

import (
	"testing"
)

func TestInMemoryStore_AppendChainsHashes(t *testing.T) {
	s := NewInMemoryStore()

	e1, err := s.Append(AuditEvent{Actor: "identity:alice", Action: "file.viewed", OccurredAtUnix: 100})
	if err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if e1.PrevHash != "" {
		t.Fatalf("expected genesis event to have empty PrevHash, got %q", e1.PrevHash)
	}
	if e1.EventID == "" {
		t.Fatal("expected non-empty EventID")
	}

	e2, err := s.Append(AuditEvent{Actor: "identity:alice", Action: "file.shared", OccurredAtUnix: 200})
	if err != nil {
		t.Fatalf("append 2: %v", err)
	}
	if e2.PrevHash != e1.EventID {
		t.Fatalf("expected e2.PrevHash == e1.EventID (%q), got %q", e1.EventID, e2.PrevHash)
	}
	if e2.EventID == e1.EventID {
		t.Fatal("expected distinct event IDs for distinct events")
	}
}

func TestVerifyIntegrity_DetectsTamperedField(t *testing.T) {
	s := NewInMemoryStore()
	if _, err := s.Append(AuditEvent{Actor: "identity:alice", Action: "file.viewed", OccurredAtUnix: 100}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := s.Append(AuditEvent{Actor: "identity:alice", Action: "file.shared", OccurredAtUnix: 200}); err != nil {
		t.Fatalf("append: %v", err)
	}

	events := s.All()
	if err := VerifyIntegrity(events); err != nil {
		t.Fatalf("expected untampered chain to verify clean, got %v", err)
	}

	// Simulate an operator directly mutating a stored record's Action
	// field (bypassing the Store's Append-only API entirely, since All()
	// returns a copy — this models what "editing the database row
	// directly" would look like).
	tampered := make([]AuditEvent, len(events))
	copy(tampered, events)
	tampered[0].Action = "file.deleted" // silently rewritten history

	err := VerifyIntegrity(tampered)
	if err == nil {
		t.Fatal("expected VerifyIntegrity to detect the tampered event, got nil error")
	}
}

func TestVerifyIntegrity_DetectsBrokenLinkage(t *testing.T) {
	s := NewInMemoryStore()
	if _, err := s.Append(AuditEvent{Actor: "identity:alice", Action: "file.viewed", OccurredAtUnix: 100}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := s.Append(AuditEvent{Actor: "identity:alice", Action: "file.shared", OccurredAtUnix: 200}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := s.Append(AuditEvent{Actor: "identity:alice", Action: "file.renamed", OccurredAtUnix: 300}); err != nil {
		t.Fatalf("append: %v", err)
	}

	events := s.All()
	// Simulate deleting the middle event (an operator "silently deleting"
	// an inconvenient event) by removing it from the slice — the
	// remaining first/third events' hash linkage no longer connects.
	withDeletion := []AuditEvent{events[0], events[2]}

	err := VerifyIntegrity(withDeletion)
	if err == nil {
		t.Fatal("expected VerifyIntegrity to detect the broken chain linkage from a deleted event, got nil error")
	}
}

func TestInMemoryStore_QueryFilters(t *testing.T) {
	s := NewInMemoryStore()
	mustAppend := func(actor, action, resourceType, resourceID string, occurred int64) {
		if _, err := s.Append(AuditEvent{
			Actor:          actor,
			Action:         action,
			Resource:       ResourceRef{ResourceType: resourceType, ResourceID: resourceID},
			OccurredAtUnix: occurred,
		}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	mustAppend("identity:alice", "file.viewed", "file", "f1", 100)
	mustAppend("identity:alice", "file.shared", "file", "f2", 200)
	mustAppend("identity:bob", "file.viewed", "file", "f1", 300)

	got, err := s.Query(QueryFilter{Subject: "identity:alice"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 events for alice, got %d", len(got))
	}
	// most-recent-first
	if got[0].Action != "file.shared" {
		t.Fatalf("expected most-recent-first ordering, got first=%s", got[0].Action)
	}

	got, err = s.Query(QueryFilter{ResourceIDFilter: "f1"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 events for resource f1, got %d", len(got))
	}

	got, err = s.Query(QueryFilter{Subject: "identity:alice", SinceUnix: 150})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 || got[0].Action != "file.shared" {
		t.Fatalf("expected only the since-filtered event, got %+v", got)
	}
}
