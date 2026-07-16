package audit

import (
	"sync"
	"time"
)

// ActionQueryOther is the permission action name checked when a caller asks
// to see another subject's audit trail (Query, Explain, or
// ExportAuditTrail where the target subject differs from the caller). It is
// deliberately a single, documented action shared across all three
// operations rather than one bespoke action per operation — see the
// 2026-07-16 "Cross-subject visibility: one documented permission action"
// decision log entry.
const ActionQueryOther = "audit:query_other"

// Maximum metadata size accepted by Emit — see validateMetadata. This is a
// lightweight structural guard against accidental over-collection (Art. 8),
// not a substitute for caller discipline: metadata must only ever describe
// THAT an action happened, never carry sensitive content itself (e.g.
// "file decrypted, by whom" — never the plaintext). See DATA_MANIFEST.md.
const (
	maxMetadataKeys      = 32
	maxMetadataKeyLength = 128
	maxMetadataValLength = 2048
)

// PermissionChecker is the local interface Service depends on to decide
// whether a caller may see another subject's audit trail. Audit does not
// import internal/permissions directly (Art. 10 — see charter §3's
// opaque-reference/lazy-resolution design); a real implementation is
// injected at server construction time by whoever wires Permissions and
// Audit together in main.go.
type PermissionChecker interface {
	// CheckPermission reports whether subject is authorized to perform
	// action against resource, per Permissions' own grant model.
	CheckPermission(subject, action string, resource ResourceRef) (bool, error)
}

// denyAllChecker is the fail-closed default PermissionChecker: every
// cross-subject check is denied. Matches Permissions' own stated
// fail-closed threat-model default (see charter §6 "Visibility leakage" and
// the task brief's explicit first-pass instruction) — used whenever no real
// checker has been wired in yet (e.g. NewService(store, nil), or the
// package-level default Service before SetDefault is called).
type denyAllChecker struct{}

func (denyAllChecker) CheckPermission(subject, action string, resource ResourceRef) (bool, error) {
	return false, nil
}

// Service implements the four AuditService RPCs (Emit, Query, Explain,
// ExportAuditTrail) against an injected Store and PermissionChecker.
type Service struct {
	store   Store
	checker PermissionChecker
}

// NewService constructs a Service. A nil checker defaults to
// denyAllChecker{} (fail closed), never to "allow all".
func NewService(store Store, checker PermissionChecker) *Service {
	if checker == nil {
		checker = denyAllChecker{}
	}
	return &Service{store: store, checker: checker}
}

// nowFunc is overridable in tests for deterministic timestamps.
var nowFunc = time.Now

// Emit records a new, immutable audit event and returns its content-addressed
// event_id. This is the call every other capability's marked
// mutating-operation function must make (mechanically enforced by
// scripts/constitution/check-audit-events.sh). actor/action are required;
// resource, rule_reference, and metadata may be zero-valued when not
// applicable to a given action.
func (s *Service) Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (string, error) {
	if actor == "" || action == "" {
		return "", ErrInvalidEvent
	}
	if err := validateMetadata(metadata); err != nil {
		return "", err
	}
	e := AuditEvent{
		Actor:          actor,
		Action:         action,
		Resource:       resource,
		RuleReference:  ruleReference,
		Metadata:       metadata,
		OccurredAtUnix: nowFunc().Unix(),
	}
	stored, err := s.store.Append(e)
	if err != nil {
		return "", err
	}
	return stored.EventID, nil
}

// Query returns events matching filter. callerActor is the identity_ref of
// whoever is asking (see the doc block above QueryRequest's Go mirror in
// http.go for why this is a parameter distinct from filter.Subject — the
// frozen QueryRequest message has no separate "caller" field, since it
// predates any session/auth wiring in this codebase; callerActor is
// supplied by the in-process Go caller directly, or read from a
// placeholder auth header by the HTTP layer — see http.go).
//
// If filter.Subject is empty, it defaults to callerActor (query my own
// trail). If filter.Subject == callerActor, the query is always allowed —
// Art. 1: a user's own trail is unconditionally theirs to see. Otherwise
// (a cross-subject query), the caller must be authorized via
// PermissionChecker.CheckPermission(callerActor, ActionQueryOther, ...) or
// the query is denied (ErrPermissionDenied) — fail closed.
func (s *Service) Query(callerActor string, filter QueryFilter) ([]AuditEvent, error) {
	if callerActor == "" {
		return nil, ErrMissingCaller
	}
	if filter.Subject == "" {
		filter.Subject = callerActor
	}
	if filter.Subject != callerActor {
		allowed, err := s.checker.CheckPermission(callerActor, ActionQueryOther, ResourceRef{
			ResourceType: "audit_subject",
			ResourceID:   filter.Subject,
		})
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, ErrPermissionDenied
		}
	}
	return s.store.Query(filter)
}

// Explain looks up eventID and returns a plain-language rationale
// synthesized from the event's own fields (see explain.go for the exact
// template). Subject to the same self-or-permitted visibility rule as
// Query, evaluated against the event's actor.
func (s *Service) Explain(callerActor, eventID string) (string, error) {
	if callerActor == "" {
		return "", ErrMissingCaller
	}
	e, ok := s.store.Get(eventID)
	if !ok {
		return "", ErrNotFound
	}
	if e.Actor != callerActor {
		allowed, err := s.checker.CheckPermission(callerActor, ActionQueryOther, e.Resource)
		if err != nil {
			return "", err
		}
		if !allowed {
			return "", ErrPermissionDenied
		}
	}
	return renderExplanation(e), nil
}

// ExportAuditTrail returns a full, versioned, self-describing export bundle
// of identityRef's audit trail (Art. 9). Subject to the same self-or-
// permitted visibility rule as Query.
func (s *Service) ExportAuditTrail(callerActor, identityRef string) (ExportBundle, error) {
	if callerActor == "" {
		return ExportBundle{}, ErrMissingCaller
	}
	if identityRef != callerActor {
		allowed, err := s.checker.CheckPermission(callerActor, ActionQueryOther, ResourceRef{
			ResourceType: "audit_subject",
			ResourceID:   identityRef,
		})
		if err != nil {
			return ExportBundle{}, err
		}
		if !allowed {
			return ExportBundle{}, ErrPermissionDenied
		}
	}

	events, err := s.store.Query(QueryFilter{Subject: identityRef})
	if err != nil {
		return ExportBundle{}, err
	}
	// Export in append (chronological) order, not Query's most-recent-
	// first order, so a reader/verifier can walk the hash chain forward
	// exactly as it was built.
	sortByOccurredAscending(events)

	return buildExportBundle(identityRef, events), nil
}

func validateMetadata(metadata map[string]string) error {
	if len(metadata) > maxMetadataKeys {
		return ErrMetadataTooLarge
	}
	for k, v := range metadata {
		if len(k) > maxMetadataKeyLength || len(v) > maxMetadataValLength {
			return ErrMetadataTooLarge
		}
	}
	return nil
}

// --- package-level default Service -----------------------------------
//
// Other backend capabilities call audit.Emit(...) as a plain package
// function (this is the literal text scripts/constitution/check-audit-
// events.sh greps for), the same way they'd call a logging library — they
// do not construct or inject a *Service themselves. defaultService backs
// that call. SetDefault lets main.go (owned by the Chief Architect) install
// a real Store/PermissionChecker at startup; until that happens,
// defaultService is a working in-memory, fail-closed Service rather than
// nil, so package-level Emit/Query/Explain/ExportAuditTrail are always safe
// to call (e.g. from tests, or another capability's own test suite) without
// requiring server wiring to exist first.
var (
	defaultMu      sync.RWMutex
	defaultService = NewService(NewInMemoryStore(), denyAllChecker{})
)

// SetDefault installs svc as the Service backing the package-level Emit,
// Query, Explain, and ExportAuditTrail functions. Intended to be called
// exactly once, at server startup, by main.go.
func SetDefault(svc *Service) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultService = svc
}

// Default returns the currently-installed default Service.
func Default() *Service {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultService
}

// Emit is the package-level entry point every other backend capability's
// marked mutating-operation function calls, in-process, as
// `audit.Emit(...)`. It delegates to the currently-installed default
// Service (see SetDefault).
func Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (string, error) {
	return Default().Emit(actor, action, resource, ruleReference, metadata)
}
