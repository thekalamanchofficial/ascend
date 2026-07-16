package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// canonicalForm is the deterministic serialization of an AuditEvent used to
// compute its content hash. Go's encoding/json marshals map[string]string
// keys in sorted order, so this gives a stable byte sequence for any given
// set of field values regardless of map iteration order — no hand-rolled
// canonicalization needed. EventID itself is deliberately excluded (it is
// the *output* of this hash, not an input to it).
type canonicalForm struct {
	Actor          string            `json:"actor"`
	Action         string            `json:"action"`
	ResourceType   string            `json:"resource_type"`
	ResourceID     string            `json:"resource_id"`
	RuleReference  string            `json:"rule_reference"`
	Metadata       map[string]string `json:"metadata"`
	OccurredAtUnix int64             `json:"occurred_at_unix"`
	PrevHash       string            `json:"prev_hash"`
}

// computeEventHash derives the content-addressed EventID for e: a SHA-256
// hash over e's own fields plus e.PrevHash (the previous event's EventID in
// append order). Because each event's identity is a function of both its
// own content and the identity of the event before it, the events form a
// hash chain: modifying any field of any historical event, or reordering /
// removing an event, changes that event's recomputed hash and breaks the
// PrevHash linkage of every event after it. See VerifyIntegrity in store.go.
func computeEventHash(e AuditEvent) string {
	cf := canonicalForm{
		Actor:          e.Actor,
		Action:         e.Action,
		ResourceType:   e.Resource.ResourceType,
		ResourceID:     e.Resource.ResourceID,
		RuleReference:  e.RuleReference,
		Metadata:       e.Metadata,
		OccurredAtUnix: e.OccurredAtUnix,
		PrevHash:       e.PrevHash,
	}
	b, err := json.Marshal(cf)
	if err != nil {
		// canonicalForm contains only marshalable primitive/map[string]string
		// fields; a marshal error here would indicate a programming error,
		// not a runtime condition callers can recover from.
		panic("audit: canonicalForm marshal failed: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
