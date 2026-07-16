package identity

import "github.com/ascend/services/api/internal/audit"

// ResourceRef mirrors ascend.audit.v1.ResourceRef (packages/contracts/proto/
// ascend/audit/v1/audit.proto). This capability was originally built
// before internal/audit existed, with a locally-defined struct kept
// shape-identical to audit.ResourceRef for that reason (per this
// capability's brief). internal/audit has since landed (built and tested
// concurrently by the Audit capability-engineer), so this is now a type
// alias to audit.ResourceRef rather than a separate look-alike type — that
// change is a real, logged decision (docs/DECISION_LOG.md, this
// capability's "AuditEmitter wiring" entry): it means *audit.Service's
// real Emit method (identical signature, same ResourceRef type) satisfies
// AuditEmitter below with zero adapter code at composition time, while
// still keeping the audit-logging call a dependency-injected interface
// call rather than a hardcoded package-level call. Importing only
// audit.ResourceRef (a plain data type, not calling audit.Emit directly)
// is well within the exemption scripts/constitution/check-modularity.sh
// already grants this package for internal/audit.
type ResourceRef = audit.ResourceRef

// AuditEmitter is the seam this capability depends on for its Art. 5
// obligation ("BindDevice, RevokeDevice, and any change to the public
// identity record emit audit events") without importing
// services/api/internal/audit directly. Its method shape mirrors
// ascend.audit.v1.AuditService.Emit's request fields one-for-one
// (actor, action, resource, rule_reference, metadata) plus the event_id
// the real Emit RPC returns.
//
// The Chief Architect wires the real internal/audit.Emit implementation
// into NewService's constructor once both packages exist (see
// docs/DECISION_LOG.md for the injection decision) — direct import of
// internal/audit is allowed by scripts/constitution/check-modularity.sh's
// exemption but not required by this package, per the brief this
// capability was built against.
//
// Known mechanical-check limitation (flagged, not silently skipped): this
// package's Service struct injects an AuditEmitter via a field literally
// named `audit` (see service.go), and every state-mutating method marked
// with this package's audit-obligation comment marker calls
// `s.audit.Emit(...)`. scripts/constitution/check-audit-events.sh does a
// substring match for `audit.Emit(`, which `s.audit.Emit(` satisfies
// textually — this was a deliberate naming choice, not an accident, so the
// mechanical check has real signal here rather than needing a waiver. If a
// future refactor renames that field, the mechanical check will (correctly)
// start failing and must be re-satisfied, not silenced.
type AuditEmitter interface {
	Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (eventID string, err error)
}

// NoopAuditEmitter is a safe-by-default fallback: it never panics if a
// caller constructs a Service without wiring a real emitter (e.g. an
// oversight during composition), but it makes that gap loud rather than
// silent by returning an error, since Art. 5 requires every mutation to be
// genuinely explainable — silently swallowing an audit failure would
// itself be a constitutional violation. Production wiring must always
// supply a real emitter; this type exists for tests and to fail safe, not
// as a way to skip the obligation.
type NoopAuditEmitter struct{}

func (NoopAuditEmitter) Emit(_ string, _ string, _ ResourceRef, _ string, _ map[string]string) (string, error) {
	return "", errAuditNotConfigured
}
