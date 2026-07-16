package audit

import (
	"encoding/json"
	"testing"
)

// TestExportAuditEvent_ProducesParseableVersionedRecord exercises the
// mechanically-required Export<TypeName> function for the persisted-record
// AuditEvent type (see the marker comment above its declaration in
// types.go and scripts/constitution/check-export-paths.sh). It proves the
// output is genuinely parseable (round-trips through encoding/json) and
// carries the hash-chain fields needed for independent verification, not
// just that the function exists and returns bytes.
func TestExportAuditEvent_ProducesParseableVersionedRecord(t *testing.T) {
	s := NewInMemoryStore()
	stored, err := s.Append(AuditEvent{
		Actor:          "identity:alice",
		Action:         "file.viewed",
		Resource:       ResourceRef{ResourceType: "file", ResourceID: "f1"},
		RuleReference:  "permissions.owner_access",
		Metadata:       map[string]string{"note": "first view"},
		OccurredAtUnix: 100,
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	blob, err := ExportAuditEvent(stored)
	if err != nil {
		t.Fatalf("ExportAuditEvent: %v", err)
	}

	var rec ExportedEvent
	if err := json.Unmarshal(blob, &rec); err != nil {
		t.Fatalf("exported blob did not parse as JSON: %v", err)
	}

	if rec.EventID != stored.EventID {
		t.Fatalf("expected event_id %q, got %q", stored.EventID, rec.EventID)
	}
	if rec.PrevHash != stored.PrevHash {
		t.Fatalf("expected prev_hash %q, got %q", stored.PrevHash, rec.PrevHash)
	}
	if rec.Actor != "identity:alice" || rec.Action != "file.viewed" {
		t.Fatalf("unexpected actor/action in exported record: %+v", rec)
	}
	if rec.Resource.ResourceID != "f1" {
		t.Fatalf("expected resource_id f1, got %q", rec.Resource.ResourceID)
	}

	// The exported record must itself be independently verifiable: it
	// carries enough fields to recompute the same content hash.
	recomputed := computeEventHash(AuditEvent{
		Actor:          rec.Actor,
		Action:         rec.Action,
		Resource:       rec.Resource,
		RuleReference:  rec.RuleReference,
		Metadata:       rec.Metadata,
		OccurredAtUnix: rec.OccurredAtUnix,
		PrevHash:       rec.PrevHash,
	})
	if recomputed != rec.EventID {
		t.Fatalf("exported record does not recompute to its own event_id: got %q, want %q", recomputed, rec.EventID)
	}
}
