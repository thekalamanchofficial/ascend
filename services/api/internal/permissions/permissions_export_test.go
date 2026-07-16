package permissions

import (
	"encoding/json"
	"testing"
)

// TestExportGrant proves Grant (ascend:persisted) has a working, parseable
// export path, per Art. 9 / scripts/constitution/check-export-paths.sh.
func TestExportGrant(t *testing.T) {
	g := Grant{
		Grantor:       "identity:alice",
		Subject:       "identity:bob",
		Action:        "read",
		Resource:      ResourceRef{ResourceType: "file_object", ResourceID: "file-1"},
		Scope:         "read",
		GrantedAtUnix: 1700000000,
	}

	blob, err := ExportGrant(g)
	if err != nil {
		t.Fatalf("ExportGrant returned error: %v", err)
	}

	var roundTripped Grant
	if err := json.Unmarshal(blob, &roundTripped); err != nil {
		t.Fatalf("exported Grant blob did not parse back as JSON: %v", err)
	}
	if roundTripped != g {
		t.Fatalf("round-tripped Grant does not match original: got %+v, want %+v", roundTripped, g)
	}
}

// TestExportHistoryEntry proves HistoryEntry (ascend:persisted) has a
// working, parseable export path, per Art. 9.
func TestExportHistoryEntry(t *testing.T) {
	h := HistoryEntry{
		EventType: "grant",
		Grantor:   "identity:alice",
		Subject:   "identity:bob",
		Action:    "read",
		Resource:  ResourceRef{ResourceType: "file_object", ResourceID: "file-1"},
		Scope:     "read",
		AtUnix:    1700000000,
		Outcome:   "allowed",
	}

	blob, err := ExportHistoryEntry(h)
	if err != nil {
		t.Fatalf("ExportHistoryEntry returned error: %v", err)
	}

	var roundTripped HistoryEntry
	if err := json.Unmarshal(blob, &roundTripped); err != nil {
		t.Fatalf("exported HistoryEntry blob did not parse back as JSON: %v", err)
	}
	if roundTripped != h {
		t.Fatalf("round-tripped HistoryEntry does not match original: got %+v, want %+v", roundTripped, h)
	}
}
