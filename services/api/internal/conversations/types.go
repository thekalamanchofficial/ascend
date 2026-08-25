// Package conversations implements the Conversations capability: the
// durable, participant-scoped message-relay and history primitive for
// direct (exactly two-participant) communication between two identities.
// The platform's first actual *messaging* surface.
//
// Frozen from docs/capabilities/conversations.charter.md and
// packages/contracts/proto/ascend/conversations/v1/conversations.proto.
// Read the charter's §6 (threat model) in full before changing anything in
// this package — its central claim is load-bearing and mechanically
// enforced by ciphertext_leak_test.go, not just asserted in prose.
//
// TEMPORARY MIRROR: no protoc-gen-go toolchain output exists for this
// contract yet, same as every other hand-mirrored capability in this build
// (docs/DECISION_LOG.md, 2026-07-16). The types below are a hand-written
// mirror of the frozen .proto messages, field-for-field.
//
// STRUCTURAL INCAPABILITY (charter §6, THE central design constraint of
// this whole package): this package must have ZERO import, direct or
// transitive, of any cryptography/key-material capability. `Ciphertext`
// and `SessionEstablishmentPayload` are opaque []byte end to end — stored,
// relayed, exported, NEVER parsed, NEVER logged, NEVER included in any
// error string or audit metadata value. See ciphertext_leak_test.go for
// the mechanical proof this holds, not merely a promise in this comment.
//
// MODULARITY (Art. 10): this package never imports
// services/api/internal/{identity,permissions,audit,storage,fileobjects,
// sessionauth} directly — it depends on Permissions and Audit exclusively
// through the small, capability-owned DI interfaces below (PermissionsClient,
// AuditEmitter), satisfied by dependency injection at server-composition
// time (owned by the Chief Architect), mirroring File Objects' identical
// discipline (internal/fileobjects/types.go).
//
// IDENTITY: like every other capability in this build, this package treats
// `creator`/`participant`/`sender`/`requesting_subject` as opaque
// identity-reference strings (Identity's format, by convention) and never
// resolves or validates them against Identity at runtime — including
// `participant` on CreateConversation, deliberately never checked for
// existence (charter §4 Art. 8: validating it would create a direct
// platform-wide identity-enumeration oracle with no offsetting benefit).
package conversations

// ResourceRef mirrors Permissions'/Audit's ResourceRef shape by convention
// (same two fields) — this package does not import either directly to get
// it. See internal/fileobjects/types.go's identical ResourceRef for the
// precedent this follows.
type ResourceRef struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

// --- Local, capability-owned dependency-injection interfaces ---
//
// This package never imports services/api/internal/{permissions,identity,
// audit} directly (Art. 10). The Chief Architect wires real adapters over
// permissions.Service/audit.Service into these two interfaces once this
// package is composed into the running binary (see services/api/wiring.go).

// PermissionsClient is the local interface this package depends on for
// every access-control decision instead of importing internal/permissions
// directly. Conversations never decides allow/deny itself anywhere in this
// service (charter §3's Consumes correction) — every allow/deny comes from
// CheckPermission; GrantPermission calls here are CreateConversation's own
// bootstrap bookkeeping, never a second access-control decision.
//
// Deliberately narrower than fileobjects.PermissionsClient: no
// RevokePermission (this capability's v1 RPC surface exposes no
// revoke-equivalent action — charter §7's own flagged, non-blocking
// creator/participant grant asymmetry observation) and no
// ListGrantsForResource (no RPC in this freeze needs to enumerate a
// conversation's grants back out — unlike File Objects' ListFileAccess,
// this charter defines no analogous "who has access to this conversation"
// RPC). See docs/DECISION_LOG.md, "Conversations: narrower PermissionsClient
// than File Objects".
type PermissionsClient interface {
	CheckPermission(subject, action, resourceType, resourceID string) (bool, error)
	GrantPermission(grantor, subject, action, resourceType, resourceID, scope string) error
	// DefinePolicy registers resourceType's default policy at this
	// package's own construction, mirroring File Objects'/Storage's
	// DefinePolicy-at-construction discipline exactly. Conversations
	// registers its own resource type, "conversation"; it never registers
	// any other capability's resource type on their behalf.
	DefinePolicy(resourceType, defaultRules string) error
}

// AuditEmitter is the local interface this package depends on for its
// Art. 5 obligation instead of importing internal/audit directly. Field is
// named `audit` at every call site (see service.go) so `s.audit.Emit(`
// satisfies scripts/constitution/check-audit-events.sh's textual match on
// every // ascend:mutates-marked function, matching every prior
// capability's convention in this build.
type AuditEmitter interface {
	Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (eventID string, err error)
}

// --- Permission action / resource-type vocabulary (charter §3's Consumes
// correction) ---

const (
	// ActionAccess is the SINGLE Permissions action this capability
	// registers, deliberately not split into a read/write pair the way
	// File Objects' fileobjects.read/fileobjects.write is (charter §3):
	// v1's fixed two-party model has no read-only-vs-write-only
	// distinction to express — a participant either belongs to the
	// conversation or doesn't.
	ActionAccess = "conversations.access"

	// resourceTypeConversation is this capability's single Permissions
	// resource type, keyed by conversation_id.
	resourceTypeConversation = "conversation"

	// conversationDefaultRules is the free-form default_rules string this
	// capability registers for resourceTypeConversation via
	// PermissionsClient.DefinePolicy at construction — mirrors File
	// Objects' fileObjectDefaultRules convention exactly: a human-readable
	// statement of intent (deny by default; a conversation's two
	// participants, established once via CreateConversation's bootstrap
	// grants, always have access; no other grant path exists in this
	// freeze), not a string Permissions parses/evaluates in this
	// implementation wave.
	conversationDefaultRules = "deny_by_default_bootstrap_participants_only"

	// scopeFull is the scope used for every bootstrap grant this package
	// establishes on a new conversation (charter §3) — neither
	// participant's own access is ever scope-limited by this capability's
	// own bookkeeping.
	scopeFull = "full"
)

// --- Persisted records ---
//
// Conversation is this capability's primary persisted aggregate — one row
// per direct conversation, keyed by ConversationID, with the two
// participants stored in canonical (lexicographically sorted) order as
// ParticipantLo/ParticipantHi so a single unique index over
// (ParticipantLo, ParticipantHi) enforces "at most one conversation per
// unordered pair" regardless of which caller is creator vs participant on
// any given CreateConversation call (charter §3's idempotent-by-pair
// requirement). See store.go's canonicalPair helper and
// Store.findOrCreateConversation for the atomic mechanism this backs.
//
// Every field here is safe to export verbatim (see export.go's
// ExportConversation) — unlike fileobjects.VersionRecord's BlobRef, this
// record has no internal-only field that must be scrubbed before leaving
// this package.
//
// ascend:persisted
type Conversation struct {
	ConversationID string
	ParticipantLo  string
	ParticipantHi  string
	CreatedAtUnix  int64
}

// Message is this capability's per-message persisted record. Ciphertext and
// SessionEstablishmentPayload are opaque bytes end to end (charter §6) —
// this package never parses, interprets, or logs their contents.
//
// Seq is this capability's own internal, monotonic ordering key (a
// BIGSERIAL-backed sequence number in PostgresStore, an equivalent
// in-process counter in InMemoryStore) — required because MessageID is an
// opaque random ref (crypto/rand-generated, idgen.go), not itself
// sortable, and ListMessages' cursor pagination (before_message_id,
// charter §3) needs a monotonic key to page by. Seq is NEVER exposed on
// the wire: it appears on no RPC response DTO (ConversationMessage,
// types.go) and no export.go projection — see export.go's exportedMessage,
// which deliberately excludes it, the same discipline
// fileobjects/export.go's exportedVersionSummary applies to BlobRef.
//
// ascend:persisted
type Message struct {
	MessageID                   string
	ConversationID              string
	Sender                      string
	Ciphertext                  []byte
	SessionEstablishmentPayload []byte // nil if absent (optional per contract)
	SentAtUnix                  int64
	Seq                         int64
}

// --- Request/response DTOs, one per RPC in conversations.proto ---

// ConversationMessage is ListMessages'/ExportConversation's per-message wire
// shape — Message's export-safe projection (never Seq).
type ConversationMessage struct {
	MessageID                   string
	Sender                      string
	Ciphertext                  []byte
	SessionEstablishmentPayload []byte // nil if absent
	SentAtUnix                  int64
}

// ConversationSummary is ListConversations' per-conversation wire shape.
// LastMessageAtUnix is ALWAYS derived at query time as MAX(sent_at) over
// the conversation's stored messages (charter §3/§4 Art. 8) — never a
// separately persisted/denormalized field; see store.go's
// conversationSummariesForSubject, the sole place this value is computed.
type ConversationSummary struct {
	ConversationID    string
	OtherParticipant  string
	CreatedAtUnix     int64
	LastMessageAtUnix int64
}

type CreateConversationRequest struct {
	Creator     string
	Participant string
}

type CreateConversationResponse struct {
	ConversationID string
	CreatedAtUnix  int64
}

type SendMessageRequest struct {
	ConversationID              string
	Sender                      string
	Ciphertext                  []byte
	SessionEstablishmentPayload []byte // optional; nil if absent
}

type SendMessageResponse struct {
	MessageID  string
	SentAtUnix int64
}

// ListMessagesRequest.BeforeMessageID is a pointer so "omitted" (nil,
// start from the most recent page) is distinguishable from "explicitly the
// empty string" — matching fileobjects.SetFileMetadataRequest's *string
// convention for an optional field, applied here to a request field
// instead of a response one.
type ListMessagesRequest struct {
	ConversationID    string
	RequestingSubject string
	BeforeMessageID   *string
	Limit             int32
}

type ListMessagesResponse struct {
	Messages []ConversationMessage
	HasMore  bool
}

type ListConversationsRequest struct {
	RequestingSubject string
}

type ListConversationsResponse struct {
	Conversations []ConversationSummary
}

type GetConversationRequest struct {
	ConversationID    string
	RequestingSubject string
}

type GetConversationResponse struct {
	ConversationID string
	Participants   []string
	CreatedAtUnix  int64
}

type ExportConversationRequest struct {
	ConversationID    string
	RequestingSubject string
}

// ExportConversationResponse's ExportBlob is this capability's own stored
// bytes, byte-for-byte, as held — NOT a promise the bundle is decryptable
// (charter §3, proto file-level comment). See export.go.
type ExportConversationResponse struct {
	ExportBlob    []byte
	FormatVersion string
}
