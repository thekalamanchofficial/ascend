// Package sessionauth implements the Session / Request Authentication
// capability (docs/capabilities/session-authentication.charter.md) against
// the frozen contract at
// packages/contracts/proto/ascend/sessionauth/v1/sessionauth.proto.
//
// No protoc-gen-go toolchain output exists for this contract yet (checked
// at implementation time: services/api/gen/go/ascend/sessionauth is absent
// even though gen/go/ascend/{identity,audit,permissions,crypto} exist) —
// the types below are a hand-written mirror of the frozen .proto messages,
// following the same precedent Identity/Permissions/Audit used
// (docs/DECISION_LOG.md, 2026-07-16, "Identity, Permissions, Audit /
// Explainability interfaces frozen..."). Field names use camelCase JSON
// tags to match protojson's default output, so this package's HTTP surface
// will not need to change shape once real codegen replaces this mirror.
// See docs/DECISION_LOG.md, this capability's "hand-mirrored types, not
// generated" entry.
//
// MODULARITY (Art. 10): this package never imports
// services/api/internal/identity, services/api/internal/permissions,
// services/api/internal/audit, or services/api/internal/storage directly —
// stricter than the check-modularity.sh exemption for internal/audit,
// per this capability's spawn brief. It depends on Identity's device
// validity via the small DeviceResolver interface below and on Audit's
// Emit via the small AuditEmitter interface below, both satisfied by
// dependency injection at server-composition time (owned by the Chief
// Architect, not this package).
package sessionauth

// ResourceRef mirrors ascend.audit.v1.ResourceRef's shape. Defined locally
// (not imported from internal/audit) per this capability's brief — see the
// package doc comment above.
type ResourceRef struct {
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId"`
}

// DeviceResolver is the seam this capability depends on for Identity's
// device-validity data, without importing services/api/internal/identity.
// A revoked/unbound device must resolve as found=false — that is what
// closes the "revoked device's key can still be used" gap for IssueSession
// (charter §6, mirroring the exact class of fix already applied to
// Identity's own BindDevice replay finding). The Chief Architect wires a
// real adapter over identity.Service (ListDevices/ResolveIdentity) in once
// this capability is composed into the running binary.
type DeviceResolver interface {
	ResolveDevicePublicKey(identityRef, deviceID string) (publicKey []byte, found bool, err error)
}

// AuditEmitter is the seam this capability depends on for its Art. 5
// obligation without importing services/api/internal/audit directly. Its
// method shape mirrors ascend.audit.v1.AuditService.Emit's request fields
// one-for-one (actor, action, resource, rule_reference, metadata) plus the
// event_id the real Emit RPC returns — matching the exact interface shape
// every other capability in this wave (Identity, Permissions) used.
//
// Service (service.go) injects this via a field literally named `audit`,
// so every audited call site reads `s.audit.Emit(...)` — the substring
// scripts/constitution/check-audit-events.sh greps for on every
// `// ascend:mutates`-marked function.
type AuditEmitter interface {
	Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (eventID string, err error)
}

// NoopAuditEmitter is a safe-by-default fallback for a Service constructed
// without a real emitter wired in: it never panics, but it makes the gap
// loud (returns an error) rather than silently dropping an audit event,
// since Art. 5 requires every audited action to be genuinely explainable.
// Mirrors Identity's/Permissions' identical precedent.
type NoopAuditEmitter struct{}

func (NoopAuditEmitter) Emit(_ string, _ string, _ ResourceRef, _ string, _ map[string]string) (string, error) {
	return "", errAuditNotConfigured
}

// --- Persisted record ---

// Session is this capability's persisted aggregate for one issued session.
// See DATA_MANIFEST.md for the documented purpose of every field.
// session_token is the opaque bearer credential itself — see export.go and
// DATA_MANIFEST.md for why it is deliberately excluded from ExportSessions'
// output despite being part of this persisted record.
//
// ascend:persisted
type Session struct {
	SessionToken   string `json:"sessionToken"`
	IdentityRef    string `json:"identityRef"`
	DeviceID       string `json:"deviceId"`
	IssuedAtUnix   int64  `json:"issuedAtUnix"`
	ExpiresAtUnix  int64  `json:"expiresAtUnix"`
	LastUsedAtUnix int64  `json:"lastUsedAtUnix"`
}

// SessionSummary mirrors the `SessionSummary` proto message — the
// transparency-view projection ListActiveSessions returns. Deliberately
// omits session_token and identity_ref (the caller already knows their own
// identity_ref; the field isn't in the frozen SessionSummary message).
type SessionSummary struct {
	DeviceID       string `json:"deviceId"`
	IssuedAtUnix   int64  `json:"issuedAtUnix"`
	ExpiresAtUnix  int64  `json:"expiresAtUnix"`
	LastUsedAtUnix int64  `json:"lastUsedAtUnix"`
}

// --- Request/response DTOs, one per RPC in sessionauth.proto ---

type GetSessionChallengeRequest struct {
	IdentityRef string `json:"identityRef"`
	DeviceID    string `json:"deviceId"`
}

type GetSessionChallengeResponse struct {
	ChallengeNonce         string `json:"challengeNonce"`
	ChallengeExpiresAtUnix int64  `json:"challengeExpiresAtUnix"`
}

type IssueSessionRequest struct {
	IdentityRef    string `json:"identityRef"`
	DeviceID       string `json:"deviceId"`
	ChallengeNonce string `json:"challengeNonce"`
	Proof          []byte `json:"proof"`
}

type IssueSessionResponse struct {
	SessionToken  string `json:"sessionToken"`
	ExpiresAtUnix int64  `json:"expiresAtUnix"`
}

type ValidateSessionRequest struct {
	SessionToken string `json:"sessionToken"`
}

type ValidateSessionResponse struct {
	IdentityRef string `json:"identityRef"`
	DeviceID    string `json:"deviceId"`
	Valid       bool   `json:"valid"`
}

type RevokeSessionRequest struct {
	SessionToken string `json:"sessionToken"`
}

type RevokeSessionResponse struct{}

type RevokeAllSessionsRequest struct {
	CallerSessionToken string `json:"callerSessionToken"`
}

type RevokeAllSessionsResponse struct {
	SessionsRevoked int32 `json:"sessionsRevoked"`
}

// RevokeSessionsForDeviceRequest/Response mirror the `RevokeSessionsForDevice`
// RPC added to sessionauth.proto by the 2026-08-17 charter amendment (see
// docs/capabilities/session-authentication.charter.md §3 and
// docs/DECISION_LOG.md, "Session/Request Authentication contract amendment:
// RevokeSessionsForDevice"). Same authorization shape as
// RevokeAllSessionsRequest — CallerSessionToken, never a bare IdentityRef —
// scoped additionally to one DeviceID. SessionsRevoked is a completion
// guarantee, not a point-in-time snapshot count (charter's atomicity
// requirement; see service.go's RevokeSessionsForDevice and store.go's
// SessionStore.revokeAllForDevice).
type RevokeSessionsForDeviceRequest struct {
	CallerSessionToken string `json:"callerSessionToken"`
	DeviceID           string `json:"deviceId"`
}

type RevokeSessionsForDeviceResponse struct {
	SessionsRevoked int32 `json:"sessionsRevoked"`
}

type ListActiveSessionsRequest struct {
	CallerSessionToken string `json:"callerSessionToken"`
}

type ListActiveSessionsResponse struct {
	Sessions []SessionSummary `json:"sessions"`
}

type ExportSessionsRequest struct {
	CallerSessionToken string `json:"callerSessionToken"`
}

type ExportSessionsResponse struct {
	ExportBlob    []byte `json:"exportBlob"`
	FormatVersion string `json:"formatVersion"`
}
