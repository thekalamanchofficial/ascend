package audit

import (
	"encoding/json"
	"sort"
)

// ExportFormatVersion identifies the shape of the bundle produced by
// ExportAuditTrail / ExportAuditEvent. Bump this (and keep the old version
// parseable, or document the break) if the shape ever changes — same
// versioned-export discipline Cryptography & Keys' ExportKeyMaterial uses.
const ExportFormatVersion = "ascend-audit-export-v1"

// ExportedEvent is the export-bundle record shape for one AuditEvent. It is
// deliberately richer than the RPC-facing AuditEvent message (it also
// carries prev_hash), because an export bundle's job is to be genuinely
// usable and independently verifiable OUTSIDE this module — a reader with
// no access to this Go package's code should be able to recompute
// event_id = sha256(canonical(actor, action, resource, rule_reference,
// metadata, occurred_at_unix, prev_hash)) for every record and confirm (a)
// each record's own hash is correct and (b) each record's prev_hash equals
// the previous record's event_id, proving the trail has not been edited,
// reordered, or had entries removed since it was exported.
type ExportedEvent struct {
	EventID        string            `json:"event_id"`
	PrevHash       string            `json:"prev_hash"`
	Actor          string            `json:"actor"`
	Action         string            `json:"action"`
	Resource       ResourceRef       `json:"resource"`
	RuleReference  string            `json:"rule_reference"`
	Metadata       map[string]string `json:"metadata"`
	OccurredAtUnix int64             `json:"occurred_at_unix"`
}

// ExportBundle is the top-level, self-describing export document returned
// (JSON-encoded) as ExportAuditTrailResponse.export_blob.
type ExportBundle struct {
	FormatVersion  string `json:"format_version"`
	IdentityRef    string `json:"identity_ref"`
	ExportedAtUnix int64  `json:"exported_at_unix"`
	// VerificationNote documents, in the bundle itself, exactly how a
	// reader with no access to this module's source can independently
	// verify integrity — so the bundle is self-describing, not merely
	// well-formed.
	VerificationNote string          `json:"verification_note"`
	Events           []ExportedEvent `json:"events"`
}

const verificationNote = "Each event's event_id is a SHA-256 hash (hex-encoded) of the JSON object " +
	"{actor, action, resource_type, resource_id, rule_reference, metadata, occurred_at_unix, prev_hash} " +
	"for that event, with metadata's keys in sorted order (RFC 8785-style deterministic JSON). To verify " +
	"this trail has not been edited, reordered, or had entries removed: recompute this hash for each " +
	"event in array order and confirm it equals that event's event_id, and confirm each event's " +
	"prev_hash equals the previous event's event_id (the first event's prev_hash is \"\")."

func toExportedEvent(e AuditEvent) ExportedEvent {
	return ExportedEvent{
		EventID:        e.EventID,
		PrevHash:       e.PrevHash,
		Actor:          e.Actor,
		Action:         e.Action,
		Resource:       e.Resource,
		RuleReference:  e.RuleReference,
		Metadata:       e.Metadata,
		OccurredAtUnix: e.OccurredAtUnix,
	}
}

func buildExportBundle(identityRef string, eventsAscending []AuditEvent) ExportBundle {
	records := make([]ExportedEvent, 0, len(eventsAscending))
	for _, e := range eventsAscending {
		records = append(records, toExportedEvent(e))
	}
	return ExportBundle{
		FormatVersion:    ExportFormatVersion,
		IdentityRef:      identityRef,
		ExportedAtUnix:   nowFunc().Unix(),
		VerificationNote: verificationNote,
		Events:           records,
	}
}

func sortByOccurredAscending(events []AuditEvent) {
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].OccurredAtUnix < events[j].OccurredAtUnix
	})
}

// ExportAuditEvent serializes a single AuditEvent into the same
// self-describing JSON record format used inside ExportAuditTrail's bundle.
// This is the mechanically-required Export<TypeName> function for the
// persisted-record AuditEvent type (see the marker comment above its
// declaration in types.go and scripts/constitution/check-export-paths.sh)
// — a caller who only has one event (e.g. from Query) can still get a
// portable, documented representation of it without calling the bulk
// ExportAuditTrail RPC.
func ExportAuditEvent(e AuditEvent) ([]byte, error) {
	return json.Marshal(toExportedEvent(e))
}

// MarshalBundle serializes an ExportBundle to the bytes returned as
// ExportAuditTrailResponse.export_blob.
func MarshalBundle(b ExportBundle) ([]byte, error) {
	return json.Marshal(b)
}
