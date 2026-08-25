package conversations

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// defaultListMessagesLimit/maxListMessagesLimit bound ListMessages' page
// size. The charter/proto specify cursor-paginated-from-day-one but no
// concrete default/max — this package's own narrow, defensive choice
// (Art. 7 defense-in-depth against an unbounded-response resource-
// exhaustion surface, the same spirit as main.go's maxRequestBodyBytes),
// logged in docs/DECISION_LOG.md as "Conversations: ListMessages page-size
// bounds".
const (
	defaultListMessagesLimit = 50
	maxListMessagesLimit     = 200
)

// Service implements the six ConversationsService RPCs against an injected
// Store and two DI seams: PermissionsClient and AuditEmitter (types.go).
// The `audit` field is deliberately named `audit` (not e.g. `auditClient`)
// so every call site reads as `s.audit.Emit(...)` — the literal substring
// scripts/constitution/check-audit-events.sh greps for on every
// // ascend:mutates-marked function, matching fileobjects.Service's
// identical convention.
type Service struct {
	store Store
	perms PermissionsClient
	audit AuditEmitter

	now       func() time.Time
	genConvID func() (string, error)
	genMsgID  func() (string, error)
}

// NewService constructs a Service and registers "conversation"'s own
// default Permissions policy at construction (charter §3's Consumes
// correction, mirroring File Objects'/Storage's DefinePolicy-at-
// construction discipline exactly).
func NewService(store Store, perms PermissionsClient, audit AuditEmitter) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("conversations: a Store is required")
	}
	if perms == nil {
		return nil, fmt.Errorf("conversations: a PermissionsClient is required")
	}
	if audit == nil {
		return nil, fmt.Errorf("conversations: an AuditEmitter is required")
	}
	if err := perms.DefinePolicy(resourceTypeConversation, conversationDefaultRules); err != nil {
		return nil, fmt.Errorf("conversations: registering default policy for resource type %q: %w", resourceTypeConversation, err)
	}

	return &Service{
		store:     store,
		perms:     perms,
		audit:     audit,
		now:       time.Now,
		genConvID: generateConversationID,
		genMsgID:  generateMessageID,
	}, nil
}

func (s *Service) nowUnix() int64 { return s.now().Unix() }

// canonicalPair returns a, b in canonical (lexicographically sorted) order
// — the mechanism backing "at most one conversation per unordered pair"
// (charter §3), regardless of which caller is creator vs participant on
// any given CreateConversation call.
func canonicalPair(a, b string) (lo, hi string) {
	if a <= b {
		return a, b
	}
	return b, a
}

// accessDeniedAction is the audit action emitted on every
// GetConversation/ListMessages/ExportConversation/SendMessage rejection for
// a non-participant (charter §4 Art. 5's required denial-audit obligation).
const accessDeniedAction = "conversations.access_denied"

// auditAccessDenied is the SINGLE shared denial-audit call site for the
// four participant-gated RPCs — deliberately callable from both this file
// (checkAccess's own service-level denial) and http.go (the HTTP-level
// caller/requesting_subject-or-sender mismatch), so every rejection reason
// funnels through identical audit vocabulary, mirroring
// fileobjects.auditAccessListDenied's identical "one shared call site"
// discipline.
//
// Naming conversationID here is safe, reasoned through explicitly (charter
// §4 Art. 5, not merely asserted by analogy to File Objects'
// file_object_id naming): correlating a bare conversation_id to its real
// two participants requires a SEPARATE, independently-gated GetConversation
// call, which a non-participant cannot make successfully (it funnels
// through this exact same checkAccess denial). Audit's own Query is
// actor-scoped self-only by default, so a would-be attacker's own audit
// trail records only their own denied attempts, never any other party's.
// Naming conversation_id in a denial event therefore adds no correlation
// capability beyond what a successful GetConversation call would already
// gate.
func (s *Service) auditAccessDenied(actor, conversationID, rpcName string) {
	_, _ = s.audit.Emit(actor, accessDeniedAction,
		ResourceRef{ResourceType: resourceTypeConversation, ResourceID: conversationID},
		"not_a_participant_or_conversation_does_not_exist",
		map[string]string{"rpc": rpcName})
}

// checkAccess is the SINGLE shared authorization call site for
// GetConversation, ListMessages, ExportConversation, and SendMessage
// (charter §3: "every other RPC's participant check delegates to
// Permissions.CheckPermission rather than this capability inventing its
// own parallel decision").
//
// ENUMERATION-ORACLE-SAFE BY CONSTRUCTION (charter §3/§6): this method
// deliberately never looks up the conversation record to decide allow/deny
// — CheckPermission alone is the decision. CreateConversation (below) is
// the ONLY place a grant on a conversation_id is ever created, and it does
// so atomically alongside the conversation row itself (both succeed or the
// whole call rolls back — see CreateConversation). That means "no grant
// exists for (subject, conversationID)" is already EXACTLY as true for a
// conversation_id that was never created as it is for one that exists but
// subject never joined — there is no second code path that could
// distinguish the two cases even if it wanted to, so the
// nonexistent-vs-not-a-participant indistinguishability this charter
// requires is automatic, not a separately-maintained invariant that could
// silently drift.
func (s *Service) checkAccess(subject, conversationID, rpcName string) error {
	if subject == "" || conversationID == "" {
		return fmt.Errorf("%w: conversation_id and the acting subject are required", ErrInvalidArgument)
	}
	allowed, err := s.perms.CheckPermission(subject, ActionAccess, resourceTypeConversation, conversationID)
	if err != nil {
		return fmt.Errorf("conversations: permission check failed: %w", err)
	}
	if !allowed {
		s.auditAccessDenied(subject, conversationID, rpcName)
		return ErrPermissionDenied
	}
	return nil
}

// CreateConversation establishes a direct conversation between exactly two
// identity_refs, idempotent by unordered pair (charter §3) — see
// canonicalPair/Store.findOrCreateConversation for the atomic mechanism.
// Bootstraps both participants' Permissions access: creator's own grant
// first (establishing implicit ownership per Permissions' first-grantor
// rule), then the named participant's grant, grantor always creator —
// mirroring fileobjects.CreateFileObject's two-grant bootstrap exactly
// (charter §3's Consumes correction).
//
// HTTP-level creator == caller binding (http.go) is what closes the
// enumeration risk this RPC's idempotent-by-pair behavior would otherwise
// open (charter §3: "without it, an unrelated caller could probe arbitrary
// (creator, participant) pairs..."); this method itself does not re-check
// that binding, trusting http.go to have already enforced it before this
// method is ever called, exactly like every other RPC in this package.
//
// IDEMPOTENT-HIT BEHAVIOR, CORRECTED after Security Steward's implementation
// merge-gate veto (docs/DECISION_LOG.md, "Conversations implementation
// merge gate: Constitution Warden passes; Security Steward vetoes a real
// crash-window access-control gap in CreateConversation's bootstrap", and
// the fix entry that follows it): when the pair already has a conversation,
// this method does NOT unconditionally skip grant bootstrap — it calls
// repairMissingBootstrapGrants, which checks (via CheckPermission) whether
// creator and participant actually hold their access grant and re-issues
// whichever is missing. This closes a real gap the original design missed:
// findOrCreateConversation's atomicity covers only the conversations row
// insert, not the GrantPermission calls that follow — a process crash
// between the row committing and grant bootstrap completing would
// otherwise leave a row permanently in existence (idempotent-by-pair means
// it can never be re-created for that pair) with zero grants, ever, and
// every retry would report false success while every subsequent
// participant-gated RPC silently denied both parties forever. In the
// overwhelmingly common case (no crash ever happened, both grants already
// present), this costs exactly two CheckPermission calls and emits no
// audit event — see repairMissingBootstrapGrants for why "no audit noise on
// a normal idempotent replay" is still preserved.
//
// PARTIAL-FAILURE ROLLBACK: if either bootstrap grant or the audit emit
// fails after a genuinely new row was inserted, the row is deleted
// (deleteConversationRecord) before returning an error — the same "don't
// leave an unreachable, ungoverned resource behind" reasoning
// fileobjects.CreateFileObject's own rollback follows. Any already-
// succeeded GrantPermission call in that same failed attempt is NOT
// separately revoked: this package's PermissionsClient interface
// deliberately excludes RevokePermission (types.go's own doc comment) —
// per its spawn brief, this capability's v1 RPC surface exposes no
// revoke-equivalent action at all, so a stray grant left behind by a
// partial failure references a conversation_id that was just deleted and
// will never be generated again (crypto/rand) and was never returned to
// any caller — genuinely unreachable, not merely hidden, so no RPC path can
// ever exercise it. Logged as its own decision in docs/DECISION_LOG.md,
// "Conversations: no grant-revoke on CreateConversation rollback".
//
// ascend:mutates
func (s *Service) CreateConversation(req CreateConversationRequest) (CreateConversationResponse, error) {
	if req.Creator == "" || req.Participant == "" {
		return CreateConversationResponse{}, fmt.Errorf("%w: creator and participant are required", ErrInvalidArgument)
	}
	if req.Creator == req.Participant {
		return CreateConversationResponse{}, fmt.Errorf("%w: a conversation requires two distinct participants", ErrInvalidArgument)
	}

	lo, hi := canonicalPair(req.Creator, req.Participant)
	candidateID, err := s.genConvID()
	if err != nil {
		return CreateConversationResponse{}, fmt.Errorf("conversations: generating conversation_id: %w", err)
	}
	now := s.nowUnix()
	candidate := Conversation{ConversationID: candidateID, ParticipantLo: lo, ParticipantHi: hi, CreatedAtUnix: now}

	rec, created := s.store.findOrCreateConversation(candidate)
	if !created {
		if err := s.repairMissingBootstrapGrants(req.Creator, req.Participant, rec.ConversationID); err != nil {
			return CreateConversationResponse{}, err
		}
		return CreateConversationResponse{ConversationID: rec.ConversationID, CreatedAtUnix: rec.CreatedAtUnix}, nil
	}

	rollback := func() { s.store.deleteConversationRecord(rec.ConversationID) }

	// Bootstrap grants (charter §3): creator's own grant first — the
	// resource's first-ever grant, establishing implicit ownership per
	// Permissions' own bootstrap rule — then the named participant's
	// grant, grantor always creator.
	if err := s.perms.GrantPermission(req.Creator, req.Creator, ActionAccess, resourceTypeConversation, rec.ConversationID, scopeFull); err != nil {
		rollback()
		return CreateConversationResponse{}, fmt.Errorf("conversations: bootstrapping creator access grant failed: %w", err)
	}
	if err := s.perms.GrantPermission(req.Creator, req.Participant, ActionAccess, resourceTypeConversation, rec.ConversationID, scopeFull); err != nil {
		rollback()
		return CreateConversationResponse{}, fmt.Errorf("conversations: bootstrapping participant access grant failed: %w", err)
	}

	// Content-free per charter §4 Art. 5/8 — participant is safe to name
	// here: it's the creator's own request field, not new information the
	// creator didn't already have.
	metadata := map[string]string{"participant": req.Participant}
	if _, err := s.audit.Emit(req.Creator, "conversations.create_conversation",
		ResourceRef{ResourceType: resourceTypeConversation, ResourceID: rec.ConversationID},
		"creator_established_pair", metadata); err != nil {
		rollback()
		return CreateConversationResponse{}, fmt.Errorf("conversations: create rolled back, audit emit failed: %w", err)
	}

	return CreateConversationResponse{ConversationID: rec.ConversationID, CreatedAtUnix: rec.CreatedAtUnix}, nil
}

// repairMissingBootstrapGrants closes the crash-window access-control gap
// Security Steward's implementation merge gate found and vetoed
// (docs/DECISION_LOG.md, "Conversations implementation merge gate:
// Constitution Warden passes; Security Steward vetoes a real crash-window
// access-control gap in CreateConversation's bootstrap", and the
// corresponding fix entry): findOrCreateConversation's atomicity (the
// canonical-pair unique-index upsert) covers only the conversations row
// insert — the two GrantPermission bootstrap calls that follow it in
// CreateConversation's own body are separate, unprotected calls, not part
// of the same transaction. A process crash (OOM kill, pod eviction,
// deploy-mid-request) between the row committing and grant bootstrap
// completing would otherwise leave a conversations row permanently in
// existence — idempotent-by-pair means it can never be re-created for that
// participant pair — with ZERO access grants, ever; every retry would then
// hit the idempotent-hit path and report false success while every
// subsequent participant-gated RPC denied both parties forever,
// indistinguishably from "conversation doesn't exist," with no repair path.
//
// Called on EVERY idempotent-hit (!created) path in CreateConversation,
// this checks (via CheckPermission — never assumes) whether creator and
// participant actually hold their access grant on conversationID, and
// re-issues GrantPermission for whichever is missing, grantor always
// creator (mirroring the original bootstrap's grantor discipline exactly,
// regardless of which specific grant is being repaired or why). Uses only
// methods already on PermissionsClient (CheckPermission/GrantPermission) —
// no RevokePermission, no new interface method, no schema change, per
// Security Steward's own fix specification.
//
// AUDIT NOISE, deliberately preserved (charter §3's original design intent,
// docs/DECISION_LOG.md, "Conversations: CreateConversation audits and
// re-grants only a genuine first creation"): a repair-specific audit event
// is emitted ONLY when a repair actually happened. The overwhelmingly
// common case — no crash ever occurred, both grants already present — costs
// exactly two CheckPermission calls and produces zero audit events, exactly
// like every ordinary idempotent replay before this fix.
func (s *Service) repairMissingBootstrapGrants(creator, participant, conversationID string) error {
	creatorOK, err := s.perms.CheckPermission(creator, ActionAccess, resourceTypeConversation, conversationID)
	if err != nil {
		return fmt.Errorf("conversations: checking creator's bootstrap grant: %w", err)
	}
	participantOK, err := s.perms.CheckPermission(participant, ActionAccess, resourceTypeConversation, conversationID)
	if err != nil {
		return fmt.Errorf("conversations: checking participant's bootstrap grant: %w", err)
	}
	if creatorOK && participantOK {
		return nil // the overwhelmingly common case: nothing to repair, nothing to audit
	}

	var repaired []string
	if !creatorOK {
		// Creator's own grant, grantor == subject == creator — establishes
		// implicit ownership per Permissions' first-grantor rule if this is
		// genuinely the resource's first-ever grant (the worst-case crash:
		// the row committed but NO grant was ever issued before the
		// crash), or is simply accepted as an already-owned resource's
		// grant otherwise (owner == grantor branch) — correct either way.
		if err := s.perms.GrantPermission(creator, creator, ActionAccess, resourceTypeConversation, conversationID, scopeFull); err != nil {
			return fmt.Errorf("conversations: repairing creator's missing bootstrap grant failed: %w", err)
		}
		repaired = append(repaired, "creator")
	}
	if !participantOK {
		// Grantor is always creator, exactly matching CreateConversation's
		// own original bootstrap order/grantor discipline above — never
		// participant, and never conditioned on whether creator's own
		// grant was itself just repaired immediately above.
		if err := s.perms.GrantPermission(creator, participant, ActionAccess, resourceTypeConversation, conversationID, scopeFull); err != nil {
			return fmt.Errorf("conversations: repairing participant's missing bootstrap grant failed: %w", err)
		}
		repaired = append(repaired, "participant")
	}

	// Content-free per charter §4 Art. 5/8 — "creator"/"participant" are
	// role labels, not new identity information: conversation_id already
	// correlates these two identities via ResourceRef, and this is the
	// same actor/resource pair CreateConversation's own successful-create
	// audit event already names.
	if _, err := s.audit.Emit(creator, "conversations.bootstrap_grants_repaired",
		ResourceRef{ResourceType: resourceTypeConversation, ResourceID: conversationID},
		"crash_window_missing_grant_detected_on_idempotent_retry",
		map[string]string{"repaired": strings.Join(repaired, ",")}); err != nil {
		return fmt.Errorf("conversations: bootstrap grant(s) repaired but audit emit failed: %w", err)
	}
	return nil
}

// SendMessage relays ciphertext opaquely — this backend never decrypts,
// never attempts to, and structurally cannot (charter §6; see
// ciphertext_leak_test.go). Authorization is exactly checkAccess above:
// HTTP-level sender == caller (http.go) plus this method's own
// Permissions.CheckPermission gate.
//
// Not rolled back on audit failure (unlike CreateConversation) — message_id
// is already the durable handle the caller needs once persisted, and
// SendMessage is an incremental mutation on an already-existing,
// already-governed resource, not the sole creation of a new one. Mirrors
// fileobjects.CreateVersion's identical "version created but audit emit
// failed" precedent (service.go there), not
// fileobjects.CreateFileObject's rollback-everything precedent.
//
// ascend:mutates
func (s *Service) SendMessage(req SendMessageRequest) (SendMessageResponse, error) {
	if req.ConversationID == "" || req.Sender == "" {
		return SendMessageResponse{}, fmt.Errorf("%w: conversation_id and sender are required", ErrInvalidArgument)
	}
	if len(req.Ciphertext) == 0 {
		return SendMessageResponse{}, fmt.Errorf("%w: ciphertext must not be empty", ErrInvalidArgument)
	}

	if err := s.checkAccess(req.Sender, req.ConversationID, "SendMessage"); err != nil {
		return SendMessageResponse{}, err
	}

	messageID, err := s.genMsgID()
	if err != nil {
		return SendMessageResponse{}, fmt.Errorf("conversations: generating message_id: %w", err)
	}
	now := s.nowUnix()

	s.store.addMessage(Message{
		MessageID:                   messageID,
		ConversationID:              req.ConversationID,
		Sender:                      req.Sender,
		Ciphertext:                  req.Ciphertext,
		SessionEstablishmentPayload: req.SessionEstablishmentPayload,
		SentAtUnix:                  now,
	})

	// Audit metadata is content-free by construction: only message_id is
	// ever included, never ciphertext or session_establishment_payload
	// (charter §4 Art. 5/§6 threat model) — see ciphertext_leak_test.go
	// for the mechanical proof.
	if _, err := s.audit.Emit(req.Sender, "conversations.send_message",
		ResourceRef{ResourceType: resourceTypeConversation, ResourceID: req.ConversationID},
		"sender_is_participant", map[string]string{"message_id": messageID}); err != nil {
		return SendMessageResponse{MessageID: messageID, SentAtUnix: now}, fmt.Errorf("conversations: message sent but audit emit failed: %w", err)
	}

	return SendMessageResponse{MessageID: messageID, SentAtUnix: now}, nil
}

func toConversationMessage(m Message) ConversationMessage {
	return ConversationMessage{
		MessageID:                   m.MessageID,
		Sender:                      m.Sender,
		Ciphertext:                  m.Ciphertext,
		SessionEstablishmentPayload: m.SessionEstablishmentPayload,
		SentAtUnix:                  m.SentAtUnix,
	}
}

// ListMessages is cursor-paginated from day one, ascending chronological
// order (charter §3 — deliberately not the "unbounded, accepted for now"
// precedent other List RPCs in this codebase share). Gated to conversation
// participants only via checkAccess, identical enumeration-oracle-safe
// discipline as GetConversation.
func (s *Service) ListMessages(req ListMessagesRequest) (ListMessagesResponse, error) {
	if err := s.checkAccess(req.RequestingSubject, req.ConversationID, "ListMessages"); err != nil {
		return ListMessagesResponse{}, err
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = defaultListMessagesLimit
	}
	if limit > maxListMessagesLimit {
		limit = maxListMessagesLimit
	}

	var beforeSeq *int64
	if req.BeforeMessageID != nil && *req.BeforeMessageID != "" {
		seq, found := s.store.messageSeq(req.ConversationID, *req.BeforeMessageID)
		if !found {
			// Post-authorization: the caller already proved participant
			// status via checkAccess above, so revealing "that
			// message_id isn't part of this conversation" leaks nothing
			// beyond what they're already authorized to know.
			return ListMessagesResponse{}, fmt.Errorf("%w: before_message_id does not identify a message in this conversation", ErrInvalidArgument)
		}
		beforeSeq = &seq
	}

	msgs, hasMore := s.store.listMessages(req.ConversationID, beforeSeq, limit)
	out := make([]ConversationMessage, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, toConversationMessage(m))
	}
	return ListMessagesResponse{Messages: out, HasMore: hasMore}, nil
}

// listConversationsDeniedAction is emitted only from http.go, when the
// HTTP-level requesting_subject != verified caller check fails — mirroring
// fileobjects.listDeniedAction's identical treatment of ListFileObjects'
// analogous self-scoped-inventory RPC (charter §3 explicitly names
// ListFileObjects as this RPC's own established-pattern precedent). Logged
// as its own decision in docs/DECISION_LOG.md, "Conversations:
// ListConversations denial audit", since the charter's own enumerated
// Art. 5 denial-audit list (GetConversation/ListMessages/
// ExportConversation/SendMessage) does not name ListConversations
// explicitly — this extends that established pattern by the narrowest
// reasonable reading, not a charter-mandated requirement.
const listConversationsDeniedAction = "conversations.list_denied"

func (s *Service) auditListConversationsDenied(actor, requestingSubject string) {
	_, _ = s.audit.Emit(actor, listConversationsDeniedAction,
		ResourceRef{ResourceType: "identity", ResourceID: requestingSubject},
		"requesting_subject_mismatch", nil)
}

// ListConversations is self-only (charter §3: "mirroring
// ListFileObjects/ListGrantsForSubject's established self-scoped-inventory
// pattern") — deliberately NOT CheckPermission-gated, the same precedent
// fileobjects.ListFileObjects follows: this is a right-to-see-your-own-
// stuff inventory listing, not a shareable read. A conversation with zero
// messages is omitted entirely by Store.conversationSummariesForSubject
// (charter §3/§5's partial-failure-gap requirement) — sorted most-recent-
// first for inbox display (design decision, logged in
// docs/DECISION_LOG.md, "Conversations: ListConversations ordering" — the
// contract names last_message_at "for inbox ordering" but does not mandate
// a specific sort direction).
func (s *Service) ListConversations(req ListConversationsRequest) (ListConversationsResponse, error) {
	if req.RequestingSubject == "" {
		return ListConversationsResponse{}, fmt.Errorf("%w: requesting_subject is required", ErrInvalidArgument)
	}
	summaries := s.store.conversationSummariesForSubject(req.RequestingSubject)
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].LastMessageAtUnix > summaries[j].LastMessageAtUnix })
	return ListConversationsResponse{Conversations: summaries}, nil
}

// GetConversation is participant-only gated (checkAccess), same
// nonexistent-vs-not-a-participant indistinguishability as every other
// checkAccess-gated RPC.
func (s *Service) GetConversation(req GetConversationRequest) (GetConversationResponse, error) {
	if err := s.checkAccess(req.RequestingSubject, req.ConversationID, "GetConversation"); err != nil {
		return GetConversationResponse{}, err
	}
	conv, found := s.store.getConversation(req.ConversationID)
	if !found {
		// Should never happen — checkAccess above already proved an
		// active grant exists for this conversation_id, and grants are
		// only ever created atomically alongside the conversation row
		// itself (CreateConversation). This is an internal invariant
		// violation, not a legitimate "not found" response — the
		// enumeration-oracle discipline governs checkAccess's own denial
		// path above, already handled; it has nothing to say about this
		// should-never-happen branch, so no dedicated sentinel is used
		// here.
		return GetConversationResponse{}, fmt.Errorf("conversations: internal: conversation record missing for %s despite an active access grant", req.ConversationID)
	}
	return GetConversationResponse{
		ConversationID: conv.ConversationID,
		Participants:   []string{conv.ParticipantLo, conv.ParticipantHi},
		CreatedAtUnix:  conv.CreatedAtUnix,
	}, nil
}

// ExportConversation returns this capability's own stored bytes verbatim —
// every message's ciphertext/session_establishment_payload/sender/sent_at
// plus conversation metadata — NOT a promise the bundle is decryptable
// (charter §3; see the proto's own file-level comment and export.go).
// Same participant-gated, enumeration-oracle-safe discipline as
// ListMessages. Not audited on success, matching every other read RPC in
// this package (charter §4 Art. 5).
func (s *Service) ExportConversation(req ExportConversationRequest) (ExportConversationResponse, error) {
	if err := s.checkAccess(req.RequestingSubject, req.ConversationID, "ExportConversation"); err != nil {
		return ExportConversationResponse{}, err
	}
	conv, found := s.store.getConversation(req.ConversationID)
	if !found {
		return ExportConversationResponse{}, fmt.Errorf("conversations: internal: conversation record missing for %s despite an active access grant", req.ConversationID)
	}

	messages := s.store.allMessagesForConversation(req.ConversationID)
	blob, err := buildExportDocument(conv, messages, s.nowUnix())
	if err != nil {
		return ExportConversationResponse{}, fmt.Errorf("conversations: building export document: %w", err)
	}
	return ExportConversationResponse{ExportBlob: blob, FormatVersion: exportFormatVersion}, nil
}
