package conversations

import (
	"encoding/json"
	"testing"
)

// TestExportMessage satisfies Art. 9's mechanical requirement
// (scripts/constitution/check-export-paths.sh) for Message, the
// // ascend:persisted-marked struct in types.go: a matching ExportMessage
// function must exist and be referenced by a *_export_test.go file in this
// package. It also proves the function honors Message's own doc comment:
// Seq (the internal ordering key) must never appear in the rendered
// output, even though it's a genuine field of the persisted Message this
// function exports.
func TestExportMessage(t *testing.T) {
	m := Message{
		MessageID:                   "msg_abc123",
		ConversationID:              "conv_def456",
		Sender:                      alice,
		Ciphertext:                  []byte("opaque-ciphertext-bytes"),
		SessionEstablishmentPayload: []byte("opaque-payload-bytes"),
		SentAtUnix:                  1735689600,
		Seq:                         987654321,
	}

	blob, err := ExportMessage(m)
	if err != nil {
		t.Fatalf("ExportMessage: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("ExportMessage did not produce valid JSON: %v", err)
	}
	if decoded["messageId"] != m.MessageID {
		t.Fatalf("messageId = %v, want %v", decoded["messageId"], m.MessageID)
	}
	if decoded["sender"] != m.Sender {
		t.Fatalf("sender = %v, want %v", decoded["sender"], m.Sender)
	}
	if _, present := decoded["seq"]; present {
		t.Fatal("ExportMessage must never include seq — it is this package's own internal ordering key, never exposed on the wire (types.go)")
	}
	if _, present := decoded["Seq"]; present {
		t.Fatal("ExportMessage must never include Seq — it is this package's own internal ordering key, never exposed on the wire (types.go)")
	}
}

// TestExportMessage_OmitsSessionEstablishmentPayloadWhenAbsent confirms the
// optional field round-trips correctly when absent (nil) — omitted from
// the JSON entirely (omitempty), not rendered as null/empty-string.
func TestExportMessage_OmitsSessionEstablishmentPayloadWhenAbsent(t *testing.T) {
	m := Message{
		MessageID:      "msg_abc123",
		ConversationID: "conv_def456",
		Sender:         alice,
		Ciphertext:     []byte("opaque-ciphertext-bytes"),
		SentAtUnix:     1735689600,
	}

	blob, err := ExportMessage(m)
	if err != nil {
		t.Fatalf("ExportMessage: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("ExportMessage did not produce valid JSON: %v", err)
	}
	if _, present := decoded["sessionEstablishmentPayload"]; present {
		t.Fatal("expected sessionEstablishmentPayload to be omitted when absent")
	}
}
