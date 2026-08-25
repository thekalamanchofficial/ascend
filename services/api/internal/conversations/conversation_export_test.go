package conversations

import (
	"encoding/json"
	"testing"
)

// TestExportConversation satisfies Art. 9's mechanical requirement
// (scripts/constitution/check-export-paths.sh) for Conversation, the
// // ascend:persisted-marked struct in types.go: a matching
// ExportConversation function must exist and be referenced by a
// *_export_test.go file in this package. See export.go's doc comment for
// why this package-level function is a distinct Go symbol from
// Service.ExportConversation (the RPC).
func TestExportConversation(t *testing.T) {
	c := Conversation{
		ConversationID: "conv_abc123",
		ParticipantLo:  alice,
		ParticipantHi:  bob,
		CreatedAtUnix:  1735689600,
	}

	blob, err := ExportConversation(c)
	if err != nil {
		t.Fatalf("ExportConversation: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("ExportConversation did not produce valid JSON: %v", err)
	}
	if decoded["conversationId"] != c.ConversationID {
		t.Fatalf("conversationId = %v, want %v", decoded["conversationId"], c.ConversationID)
	}
	if decoded["participantLo"] != c.ParticipantLo || decoded["participantHi"] != c.ParticipantHi {
		t.Fatalf("participants = %v/%v, want %v/%v", decoded["participantLo"], decoded["participantHi"], c.ParticipantLo, c.ParticipantHi)
	}
	if decoded["createdAtUnix"] != float64(c.CreatedAtUnix) {
		t.Fatalf("createdAtUnix = %v, want %v", decoded["createdAtUnix"], c.CreatedAtUnix)
	}
}
