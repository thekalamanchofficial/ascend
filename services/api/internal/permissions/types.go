// Package permissions implements the Permissions capability: the
// fine-grained, least-privilege access-control primitive every other
// capability calls to decide who may do what to which resource.
//
// Frozen from docs/capabilities/permissions.charter.md §3 and
// packages/contracts/proto/ascend/permissions/v1/permissions.proto.
//
// TEMPORARY MIRROR: no protoc-gen-go toolchain is wired up yet
// (docs/DECISION_LOG.md, 2026-07-16, "Identity, Permissions, Audit /
// Explainability interfaces frozen..."). The types in this file are a
// hand-written mirror of the frozen .proto messages, field-for-field, and
// must be kept in sync with the .proto until real codegen replaces them.
//
// MODULARITY (Art. 10): this package never imports
// services/api/internal/identity or services/api/internal/audit directly.
// `subject`/`grantor` are opaque identity-reference strings (matching
// Identity's identity_ref format by convention) — never resolved or
// validated against Identity here. Audit access is via the small
// AuditEmitter interface below, satisfied by dependency injection at
// server-startup time (see docs/DECISION_LOG.md, this capability's
// "AuditEmitter dependency injection" entry).
package permissions

// ResourceRef mirrors permissions.proto's ResourceRef message.
// resource_type is a free-form namespace each owning capability defines
// (e.g. "file_object"); resource_id identifies a specific instance within
// that namespace.
type ResourceRef struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

func (r ResourceRef) key() string {
	return r.ResourceType + "\x1f" + r.ResourceID
}

// Grant mirrors permissions.proto's Grant message exactly. It is the
// currently-effective access record for one (subject, action, resource)
// tuple. See DATA_MANIFEST.md for the documented purpose of every field.
//
// ascend:persisted
type Grant struct {
	Grantor       string      `json:"grantor"`
	Subject       string      `json:"subject"`
	Action        string      `json:"action"`
	Resource      ResourceRef `json:"resource"`
	Scope         string      `json:"scope"`
	GrantedAtUnix int64       `json:"granted_at_unix"`
}

// HistoryEntry is the append-only grant/revoke history record this
// capability retains to answer ExportPermissions and to support Art. 5
// explainability ("who granted/revoked what, and when"). It is not part of
// the frozen wire contract (no proto message corresponds to it 1:1) but it
// is persisted data derived entirely from Grant/RevokePermission calls, so
// it gets its own export path per Art. 9.
//
// ascend:persisted
type HistoryEntry struct {
	EventType    string      `json:"event_type"` // "grant" or "revoke"
	Grantor      string      `json:"grantor"`
	Subject      string      `json:"subject"`
	Action       string      `json:"action"`
	Resource     ResourceRef `json:"resource"`
	Scope        string      `json:"scope"` // empty for "revoke" events
	AtUnix       int64       `json:"at_unix"`
	Outcome      string      `json:"outcome"` // "allowed" or "denied"
	DenialReason string      `json:"denial_reason,omitempty"`
}

// Policy is a resource type's registered default policy shape
// (DefinePolicy). It is platform configuration, not personal user data —
// no export path is required by Art. 9, and it is intentionally excluded
// from DATA_MANIFEST.md's "## Fields" (which documents fields of user
// grant records, per the charter's data manifest, not capability
// configuration). See docs/DECISION_LOG.md for the rule-language decision.
type Policy struct {
	ResourceType  string
	DefaultRules  string
	DefinedAtUnix int64
}

// AuditEmitter is the local interface this package depends on instead of
// importing services/api/internal/audit directly. Signature matches
// Audit's Emit shape per this capability's spawn brief. Satisfied via
// constructor injection (see NewService); a real implementation is wired
// in by the Chief Architect once all three foundation capabilities land.
type AuditEmitter interface {
	Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (eventID string, err error)
}

// --- Request/response types, mirroring permissions.proto messages. ---

type CheckPermissionRequest struct {
	Subject  string
	Action   string
	Resource ResourceRef
}

type CheckPermissionResponse struct {
	Allowed bool
}

type GrantPermissionRequest struct {
	Grantor  string
	Subject  string
	Action   string
	Resource ResourceRef
	Scope    string
}

type GrantPermissionResponse struct {
	Grant Grant
}

type RevokePermissionRequest struct {
	Grantor  string
	Subject  string
	Action   string
	Resource ResourceRef
}

type RevokePermissionResponse struct{}

type DefinePolicyRequest struct {
	ResourceType string
	DefaultRules string
}

type DefinePolicyResponse struct{}

type ListGrantsForResourceRequest struct {
	Resource ResourceRef
}

type ListGrantsForResourceResponse struct {
	Grants []Grant
}

type ListGrantsForSubjectRequest struct {
	Subject string
}

type ListGrantsForSubjectResponse struct {
	Grants []Grant
}

type ExportPermissionsRequest struct {
	IdentityRef string
}

type ExportPermissionsResponse struct {
	ExportBlob    []byte
	FormatVersion string
}
