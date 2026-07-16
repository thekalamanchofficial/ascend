// Package audit implements the Audit / Explainability capability
// (docs/capabilities/audit-explainability.charter.md), the shared "why/when/
// by-what-rule" event substrate every state-changing action in Ascend emits
// into (Art. 5).
//
// This package is a shared, directly-importable substrate, like a logging
// library — scripts/constitution/check-modularity.sh exempts it by name
// (alongside internal/platform) from the normal "no capability may import
// another capability's internal package" rule. Every other backend
// capability calls audit.Emit(...) directly, in-process.
//
// The Go types below are a hand-written mirror of
// packages/contracts/proto/ascend/audit/v1/audit.proto. Per the 2026-07-16
// "Identity, Permissions, Audit / Explainability interfaces frozen" decision
// log entry, buf generate codegen is not wired up yet, so this mirror is a
// documented temporary stand-in — field names/shapes must stay in lockstep
// with the .proto file until real codegen exists.
package audit

// ResourceRef identifies the resource an audit event is about. Shape matches
// Permissions' ResourceRef by convention (same two fields) — this package
// does not import internal/permissions to get it; see charter §3.
type ResourceRef struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

// AuditEvent is the durable, append-only record of one explainable action.
//
// ascend:persisted
type AuditEvent struct {
	EventID        string            `json:"event_id"`
	Actor          string            `json:"actor"`
	Action         string            `json:"action"`
	Resource       ResourceRef       `json:"resource"`
	RuleReference  string            `json:"rule_reference"`
	Metadata       map[string]string `json:"metadata"`
	OccurredAtUnix int64             `json:"occurred_at_unix"`

	// PrevHash is the EventID of the immediately preceding event in the
	// global append-order chain ("" for the very first event ever
	// emitted). It is the tamper-evidence linkage (see hash.go) and is
	// deliberately NOT part of the frozen AuditEvent proto message — it
	// is an internal storage detail, not part of the RPC-facing wire
	// shape, so it is excluded from JSON here (see toExportedEvent for
	// where it IS surfaced, in the richer, independently-verifiable
	// export bundle format — see the 2026-07-16 "Export bundle carries
	// hash-chain fields" decision log entry).
	PrevHash string `json:"-"`
}

// QueryFilter is the Go-level mirror of QueryRequest, minus the `subject`
// field's dual role — see service.go's Query method doc for why callerActor
// is a separate, explicit parameter rather than folded into this struct.
type QueryFilter struct {
	Subject            string
	ResourceTypeFilter string
	ResourceIDFilter   string
	ActionFilter       string
	SinceUnix          int64
	UntilUnix          int64
}
