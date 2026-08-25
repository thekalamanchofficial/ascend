package conversations

import "encoding/json"

// exportFormatVersion is the format_version returned on every
// ExportConversationResponse (the RPC, service.go). Bumped whenever
// buildExportDocument's shape changes in a way a consumer parsing the JSON
// would need to know about.
const exportFormatVersion = "ascend-conversations-export-v1"

// --- Art. 9 mechanical per-persisted-type export path ---
//
// Every type marked // ascend:persisted in types.go (Conversation, Message)
// needs its own Export<TypeName> function plus a *_export_test.go
// referencing it, per scripts/constitution/check-export-paths.sh — charter
// §4 Art. 9 names this exact function-pair requirement explicitly:
// "a genuine ExportConversation/ExportMessage Go function pair in
// internal/conversations, each with its own *_export_test.go".
//
// NAMING NOTE: ExportConversation (the package-level function below) is a
// DIFFERENT Go symbol from Service.ExportConversation (service.go), the
// ExportConversation RPC — one is a method (has a receiver), the other is a
// package-level function; Go has no naming collision between them, and this
// naming is what the charter itself specifies (§4 Art. 9), not an
// implementation accident. The RPC returns a full conversation+messages
// bundle (buildExportDocument, below); this function is the narrower,
// single-record proof the mechanical check requires — mirroring
// fileobjects.ExportVersionRecord's identical relationship to the
// ExportFile RPC (internal/fileobjects/export.go).

// exportedConversation is Conversation's export-safe projection. Every
// field of Conversation is safe to export as-is — unlike fileobjects'
// VersionRecord, Conversation carries no internal-only field (no
// blob_ref-equivalent) that must be scrubbed before leaving this package.
type exportedConversation struct {
	ConversationID string `json:"conversationId"`
	ParticipantLo  string `json:"participantLo"`
	ParticipantHi  string `json:"participantHi"`
	CreatedAtUnix  int64  `json:"createdAtUnix"`
}

func toExportedConversation(c Conversation) exportedConversation {
	return exportedConversation{
		ConversationID: c.ConversationID,
		ParticipantLo:  c.ParticipantLo,
		ParticipantHi:  c.ParticipantHi,
		CreatedAtUnix:  c.CreatedAtUnix,
	}
}

// ExportConversation renders a single Conversation record as self-describing
// JSON, satisfying Art. 9's per-persisted-type export path requirement for
// Conversation (types.go, marked ascend:persisted). See the package doc
// comment above for how this differs from Service.ExportConversation (the
// RPC).
func ExportConversation(c Conversation) ([]byte, error) {
	return json.MarshalIndent(toExportedConversation(c), "", "  ")
}

// exportedMessage is Message's export-safe projection — EVERY field of
// Message except Seq (types.go: "NEVER exposed on the wire" — this
// package's own internal ordering key, not a field any caller has ever
// been told exists).
type exportedMessage struct {
	MessageID                   string `json:"messageId"`
	ConversationID              string `json:"conversationId"`
	Sender                      string `json:"sender"`
	Ciphertext                  []byte `json:"ciphertext"`
	SessionEstablishmentPayload []byte `json:"sessionEstablishmentPayload,omitempty"`
	SentAtUnix                  int64  `json:"sentAtUnix"`
}

func toExportedMessage(m Message) exportedMessage {
	return exportedMessage{
		MessageID:                   m.MessageID,
		ConversationID:              m.ConversationID,
		Sender:                      m.Sender,
		Ciphertext:                  m.Ciphertext,
		SessionEstablishmentPayload: m.SessionEstablishmentPayload,
		SentAtUnix:                  m.SentAtUnix,
	}
}

// ExportMessage renders a single Message record as self-describing JSON,
// satisfying Art. 9's per-persisted-type export path requirement for
// Message (types.go, marked ascend:persisted). Ciphertext/
// SessionEstablishmentPayload are rendered as opaque bytes (base64 via
// Go's encoding/json []byte marshaling) — never parsed, never interpreted
// (charter §6).
func ExportMessage(m Message) ([]byte, error) {
	return json.MarshalIndent(toExportedMessage(m), "", "  ")
}

// --- ExportConversation RPC's full bundle (service.go's Service.ExportConversation) ---

// exportDocument is the ExportConversation RPC's full portable bundle:
// conversation metadata plus EVERY message ever sent in it (charter §3's
// "complete artifact" bar — never just the current page a paginated
// ListMessages call would return). Reuses toExportedMessage directly rather
// than round-tripping through ExportMessage's own JSON encoding — see
// message_export_test.go for the proof that ExportMessage itself renders
// the identical, Seq-free shape (mirrors fileobjects.ExportFile's identical
// "reused directly, but see version_record_export_test.go" pattern).
type exportDocument struct {
	FormatVersion   string            `json:"formatVersion"`
	ConversationID  string            `json:"conversationId"`
	Participants    []string          `json:"participants"`
	CreatedAtUnix   int64             `json:"createdAtUnix"`
	GeneratedAtUnix int64             `json:"generatedAtUnix"`
	Messages        []exportedMessage `json:"messages"`
}

func buildExportDocument(c Conversation, messages []Message, generatedAtUnix int64) ([]byte, error) {
	exportedMessages := make([]exportedMessage, 0, len(messages))
	for _, m := range messages {
		exportedMessages = append(exportedMessages, toExportedMessage(m))
	}

	doc := exportDocument{
		FormatVersion:   exportFormatVersion,
		ConversationID:  c.ConversationID,
		Participants:    []string{c.ParticipantLo, c.ParticipantHi},
		CreatedAtUnix:   c.CreatedAtUnix,
		GeneratedAtUnix: generatedAtUnix,
		Messages:        exportedMessages,
	}
	return json.MarshalIndent(doc, "", "  ")
}
