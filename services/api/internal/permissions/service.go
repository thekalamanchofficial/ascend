package permissions

import (
	"errors"
	"fmt"
	"time"
)

// Service implements the seven PermissionsService RPCs against an
// in-memory Store and an injected AuditEmitter.
//
// The `audit` field is deliberately named `audit` (not e.g. `auditClient`
// or `emitter`) so every call site reads as `s.audit.Emit(...)` — this is
// a textual-match requirement, not just a style preference:
// scripts/constitution/check-audit-events.sh greps function bodies for the
// literal substring `audit.Emit(`, and this package does not import
// services/api/internal/audit directly (see AuditEmitter in types.go).
// Documented in docs/DECISION_LOG.md.
type Service struct {
	store *Store
	audit AuditEmitter
	now   func() time.Time
}

func NewService(store *Store, audit AuditEmitter) *Service {
	return &Service{store: store, audit: audit, now: time.Now}
}

const (
	outcomeAllowed = "allowed"
	outcomeDenied  = "denied"
)

func validateResource(r ResourceRef) error {
	if r.ResourceType == "" || r.ResourceID == "" {
		return errors.New("resource_type and resource_id are required")
	}
	return nil
}

// CheckPermission is the single call every other capability uses to
// decide who may do what to which resource. It is read-only — not marked
// ascend:mutates, no audit event is emitted per call (see
// docs/DECISION_LOG.md for why CheckPermission's volume makes per-call
// auditing impractical, unlike Grant/Revoke/DefinePolicy).
//
// Confused-deputy note (charter §6): `Subject` is a required, explicit
// field on CheckPermissionRequest. There is no ambient "caller identity"
// this method could fall back to — a caller MUST pass the true acting
// subject.
func (s *Service) CheckPermission(req CheckPermissionRequest) (CheckPermissionResponse, error) {
	if req.Subject == "" || req.Action == "" {
		return CheckPermissionResponse{Allowed: false}, errors.New("subject and action are required")
	}
	if err := validateResource(req.Resource); err != nil {
		return CheckPermissionResponse{Allowed: false}, err
	}

	// Fail closed: an unregistered resource type is always denied, never
	// an ambiguous error and never an implicit allow (charter §6).
	if !s.store.hasPolicy(req.Resource.ResourceType) {
		return CheckPermissionResponse{Allowed: false}, nil
	}

	if owner, ok := s.store.ownerOf(req.Resource); ok && owner == req.Subject {
		return CheckPermissionResponse{Allowed: true}, nil
	}

	if _, ok := s.store.activeGrant(req.Subject, req.Action, req.Resource); ok {
		return CheckPermissionResponse{Allowed: true}, nil
	}

	return CheckPermissionResponse{Allowed: false}, nil
}

// authorizeGrant implements the charter §6 privilege-escalation rule: a
// grantor may grant an action/resource/scope only if (a) the resource has
// no owner yet (this call is the resource's first-ever grant, and the
// grantor becomes its implicit owner), (b) the grantor IS the resource's
// owner, or (c) the grantor already holds an active grant for that exact
// (action, resource) with a scope that is equal-or-greater than the scope
// being granted (see scope.go).
func (s *Service) authorizeGrant(req GrantPermissionRequest) (bool, string) {
	if _, hasOwner := s.store.ownerOf(req.Resource); !hasOwner {
		return true, "bootstrap_owner"
	}
	if owner, _ := s.store.ownerOf(req.Resource); owner == req.Grantor {
		return true, "resource_owner"
	}
	if held, ok := s.store.activeGrant(req.Grantor, req.Action, req.Resource); ok {
		if scopeAtLeast(held.Scope, req.Scope) {
			return true, "delegated_from_existing_grant"
		}
	}
	return false, "insufficient_privilege"
}

// ascend:mutates
func (s *Service) GrantPermission(req GrantPermissionRequest) (GrantPermissionResponse, error) {
	if req.Grantor == "" || req.Subject == "" || req.Action == "" {
		return GrantPermissionResponse{}, errors.New("grantor, subject, and action are required")
	}
	if err := validateResource(req.Resource); err != nil {
		return GrantPermissionResponse{}, err
	}

	now := s.now().Unix()
	allowed, reason := s.authorizeGrant(req)

	metadata := map[string]string{
		"resource_type": req.Resource.ResourceType,
		"resource_id":   req.Resource.ResourceID,
		"action":        req.Action,
		"scope":         req.Scope,
		"subject":       req.Subject,
		"reason":        reason,
	}

	if !allowed {
		// Rejection path: no state change occurred, and this function is
		// already returning a specific, more informative domain error
		// ("permission denied: ...") below. Per Identity's established
		// pattern (services/api/internal/identity/service.go's
		// BindDevice rejection paths), the audit-emit error is
		// deliberately discarded here rather than shadowing that more
		// useful denial reason — there is no "the mutation silently
		// succeeded" hazard to guard against on a path where nothing
		// mutated.
		_, _ = s.audit.Emit(req.Grantor, "permissions.grant_denied", req.Resource, reason, metadata)
		s.store.appendHistory(HistoryEntry{
			EventType: "grant", Grantor: req.Grantor, Subject: req.Subject, Action: req.Action,
			Resource: req.Resource, Scope: req.Scope, AtUnix: now,
			Outcome: outcomeDenied, DenialReason: reason,
		})
		return GrantPermissionResponse{}, errors.New("permission denied: grantor does not hold sufficient privilege to grant this action/scope")
	}

	grant := Grant{
		Grantor:       req.Grantor,
		Subject:       req.Subject,
		Action:        req.Action,
		Resource:      req.Resource,
		Scope:         req.Scope,
		GrantedAtUnix: now,
	}
	s.store.putGrant(grant)
	s.store.appendHistory(HistoryEntry{
		EventType: "grant", Grantor: req.Grantor, Subject: req.Subject, Action: req.Action,
		Resource: req.Resource, Scope: req.Scope, AtUnix: now, Outcome: outcomeAllowed,
	})

	// The grant has already taken effect in the store above — if the
	// audit emit fails here, that is exactly the silent-success hazard
	// Art. 5 forbids (a state change with no discoverable audit record).
	// Fail loudly rather than report success, matching Identity's
	// CreateIdentity/BindDevice/RevokeDevice/ExportIdentity pattern.
	if _, err := s.audit.Emit(req.Grantor, "permissions.grant", req.Resource, reason, metadata); err != nil {
		return GrantPermissionResponse{}, fmt.Errorf("grant recorded but audit emit failed: %w", err)
	}

	return GrantPermissionResponse{Grant: grant}, nil
}

// authorizeRevoke: the resource's owner may revoke any grant on it; the
// original grantor of a specific grant may revoke that same grant; and a
// subject may always revoke their own access (self-revocation only ever
// reduces access, never escalates it). Documented in
// docs/DECISION_LOG.md alongside the grant-escalation rule.
func (s *Service) authorizeRevoke(req RevokePermissionRequest, existing Grant) (bool, string) {
	if owner, ok := s.store.ownerOf(req.Resource); ok && owner == req.Grantor {
		return true, "resource_owner"
	}
	if existing.Grantor == req.Grantor {
		return true, "original_grantor"
	}
	if req.Grantor == req.Subject {
		return true, "self_revoke"
	}
	return false, "insufficient_privilege"
}

// ascend:mutates
func (s *Service) RevokePermission(req RevokePermissionRequest) (RevokePermissionResponse, error) {
	if req.Grantor == "" || req.Subject == "" || req.Action == "" {
		return RevokePermissionResponse{}, errors.New("grantor, subject, and action are required")
	}
	if err := validateResource(req.Resource); err != nil {
		return RevokePermissionResponse{}, err
	}

	now := s.now().Unix()
	metadata := map[string]string{
		"resource_type": req.Resource.ResourceType,
		"resource_id":   req.Resource.ResourceID,
		"action":        req.Action,
		"subject":       req.Subject,
	}

	existing, found := s.store.activeGrant(req.Subject, req.Action, req.Resource)
	if !found {
		// Rejection path (nothing to revoke) — see the equivalent comment
		// in GrantPermission's denial branch for why the audit-emit error
		// is discarded here rather than masking the domain error below.
		metadata["reason"] = "not_found"
		_, _ = s.audit.Emit(req.Grantor, "permissions.revoke_failed", req.Resource, "not_found", metadata)
		s.store.appendHistory(HistoryEntry{
			EventType: "revoke", Grantor: req.Grantor, Subject: req.Subject, Action: req.Action,
			Resource: req.Resource, AtUnix: now, Outcome: outcomeDenied, DenialReason: "not_found",
		})
		return RevokePermissionResponse{}, errors.New("no active grant found to revoke")
	}

	allowed, reason := s.authorizeRevoke(req, existing)
	metadata["reason"] = reason
	if !allowed {
		_, _ = s.audit.Emit(req.Grantor, "permissions.revoke_denied", req.Resource, reason, metadata)
		s.store.appendHistory(HistoryEntry{
			EventType: "revoke", Grantor: req.Grantor, Subject: req.Subject, Action: req.Action,
			Resource: req.Resource, AtUnix: now, Outcome: outcomeDenied, DenialReason: reason,
		})
		return RevokePermissionResponse{}, errors.New("permission denied: grantor does not hold sufficient privilege to revoke this grant")
	}

	s.store.removeGrant(req.Subject, req.Action, req.Resource)
	s.store.appendHistory(HistoryEntry{
		EventType: "revoke", Grantor: req.Grantor, Subject: req.Subject, Action: req.Action,
		Resource: req.Resource, AtUnix: now, Outcome: outcomeAllowed,
	})

	// The revoke has already taken effect in the store above — same
	// silent-success hazard as GrantPermission's success path: fail
	// loudly rather than report success if the audit record didn't land.
	if _, err := s.audit.Emit(req.Grantor, "permissions.revoke", req.Resource, reason, metadata); err != nil {
		return RevokePermissionResponse{}, fmt.Errorf("revoke recorded but audit emit failed: %w", err)
	}

	return RevokePermissionResponse{}, nil
}

// DefinePolicy registers resource_type's default (least-privilege) policy
// shape. Registering a resource_type here is also what makes
// CheckPermission stop failing closed for that type (charter §6:
// "Default-policy gaps: fail closed, always"). See docs/DECISION_LOG.md
// for the default_rules representation and the known actor-attribution
// gap in this RPC's contract.
//
// ascend:mutates
func (s *Service) DefinePolicy(req DefinePolicyRequest) (DefinePolicyResponse, error) {
	if req.ResourceType == "" {
		return DefinePolicyResponse{}, errors.New("resource_type is required")
	}

	now := s.now().Unix()
	s.store.setPolicy(Policy{
		ResourceType:  req.ResourceType,
		DefaultRules:  req.DefaultRules,
		DefinedAtUnix: now,
	})

	// DefinePolicyRequest carries no actor/caller field in the frozen
	// contract (unlike Grant/RevokePermissionRequest's grantor) — see
	// docs/DECISION_LOG.md for why "capability:<resource_type>" is used
	// as the best-effort audit actor here rather than inventing an
	// unrequested field or silently skipping the audit obligation.
	actor := "capability:" + req.ResourceType
	resource := ResourceRef{ResourceType: req.ResourceType, ResourceID: "*"}

	// The policy has already taken effect in the store above (and, in
	// particular, resource_type is now "known", changing CheckPermission's
	// fail-closed behavior for it) — silently reporting success if the
	// audit emit failed would be the exact hazard Art. 5 forbids. This is
	// not hypothetical here: default_rules is embedded verbatim in
	// metadata with no length guard of its own, and Audit's Emit rejects
	// any metadata value over 2048 chars, so an oversized policy string
	// must surface as a loud failure, not a silent one.
	if _, err := s.audit.Emit(actor, "permissions.define_policy", resource, "policy_registration", map[string]string{
		"resource_type": req.ResourceType,
		"default_rules": req.DefaultRules,
	}); err != nil {
		return DefinePolicyResponse{}, fmt.Errorf("policy defined but audit emit failed: %w", err)
	}

	return DefinePolicyResponse{}, nil
}

// ListGrantsForResource answers "who can see this" — every active grant
// on the given resource. Read-only, not audited per call (see
// CheckPermission's comment above for the same rationale).
func (s *Service) ListGrantsForResource(req ListGrantsForResourceRequest) (ListGrantsForResourceResponse, error) {
	if err := validateResource(req.Resource); err != nil {
		return ListGrantsForResourceResponse{}, err
	}
	return ListGrantsForResourceResponse{Grants: s.store.grantsForResource(req.Resource)}, nil
}

// ListGrantsForSubject answers "what can I access" — every active grant
// held by the given subject.
func (s *Service) ListGrantsForSubject(req ListGrantsForSubjectRequest) (ListGrantsForSubjectResponse, error) {
	if req.Subject == "" {
		return ListGrantsForSubjectResponse{}, errors.New("subject is required")
	}
	return ListGrantsForSubjectResponse{Grants: s.store.grantsForSubject(req.Subject)}, nil
}
