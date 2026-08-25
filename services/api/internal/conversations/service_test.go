package conversations

import (
	"errors"
	"testing"
	"time"
)

func TestNewService_RegistersDefaultPolicyAtConstruction(t *testing.T) {
	perms := newMemPermissions()
	audit := newFakeAuditEmitter()
	if _, err := NewService(newInMemoryStore(), perms, audit); err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if len(perms.definePolicyCalls) != 1 || perms.definePolicyCalls[0] != resourceTypeConversation {
		t.Fatalf("expected exactly one DefinePolicy(%q) call at construction, got %v", resourceTypeConversation, perms.definePolicyCalls)
	}
}

func TestNewService_RequiresAllDependencies(t *testing.T) {
	perms := newMemPermissions()
	audit := newFakeAuditEmitter()
	store := newInMemoryStore()

	if _, err := NewService(nil, perms, audit); err == nil {
		t.Fatal("expected error for nil store")
	}
	if _, err := NewService(store, nil, audit); err == nil {
		t.Fatal("expected error for nil perms")
	}
	if _, err := NewService(store, perms, nil); err == nil {
		t.Fatal("expected error for nil audit")
	}
}

// --- CreateConversation ---

func TestCreateConversation_BootstrapsGrantsInOrderCreatorThenParticipant(t *testing.T) {
	svc, perms, audit := newTestService(t)

	resp, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	if resp.ConversationID == "" {
		t.Fatal("expected a non-empty conversation_id")
	}

	if !perms.hasActiveGrant(alice, ActionAccess, resourceTypeConversation, resp.ConversationID) {
		t.Fatal("expected creator to hold an active access grant")
	}
	if !perms.hasActiveGrant(bob, ActionAccess, resourceTypeConversation, resp.ConversationID) {
		t.Fatal("expected participant to hold an active access grant")
	}
	// Creator's own grant must be first (establishing implicit ownership
	// per Permissions' first-grantor rule) — charter §3.
	owner, ok := perms.ownerOf(resourceTypeConversation, resp.ConversationID)
	if !ok || owner != alice {
		t.Fatalf("expected creator (%s) to be the resource's implicit owner, got %q (found=%v)", alice, owner, ok)
	}
	if len(perms.grantCalls) != 2 || perms.grantCalls[0].subject != alice || perms.grantCalls[1].subject != bob {
		t.Fatalf("expected grant order [creator, participant], got %+v", perms.grantCalls)
	}

	call, ok := audit.lastCall()
	if !ok {
		t.Fatal("expected an audit call")
	}
	if call.actor != alice || call.action != "conversations.create_conversation" {
		t.Fatalf("unexpected audit call: %+v", call)
	}
	if call.resource.ResourceType != resourceTypeConversation || call.resource.ResourceID != resp.ConversationID {
		t.Fatalf("unexpected audit resource: %+v", call.resource)
	}
}

func TestCreateConversation_IdempotentByPairRegardlessOfCreatorParticipantOrder(t *testing.T) {
	svc, _, audit := newTestService(t)

	respA, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation (A): %v", err)
	}
	countAfterFirst := audit.callCount()

	// Reversed creator/participant — must resolve to the SAME conversation.
	respB, err := svc.CreateConversation(CreateConversationRequest{Creator: bob, Participant: alice})
	if err != nil {
		t.Fatalf("CreateConversation (B): %v", err)
	}

	if respA.ConversationID != respB.ConversationID {
		t.Fatalf("expected idempotent-by-pair: got %q then %q", respA.ConversationID, respB.ConversationID)
	}
	if respA.CreatedAtUnix != respB.CreatedAtUnix {
		t.Fatalf("expected identical created_at on an idempotent hit, got %d vs %d", respA.CreatedAtUnix, respB.CreatedAtUnix)
	}
	// No re-grant/re-audit on an idempotent hit (design decision, logged).
	if audit.callCount() != countAfterFirst {
		t.Fatalf("expected no additional audit event on an idempotent hit, count went from %d to %d", countAfterFirst, audit.callCount())
	}
}

func TestCreateConversation_RejectsEmptyOrSelfPair(t *testing.T) {
	svc, _, _ := newTestService(t)

	if _, err := svc.CreateConversation(CreateConversationRequest{Creator: "", Participant: bob}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty creator, got %v", err)
	}
	if _, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: ""}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty participant, got %v", err)
	}
	if _, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: alice}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for creator == participant, got %v", err)
	}
}

// TestCreateConversation_RollsBackOnGrantFailure proves the row-deletion
// rollback (service.go's CreateConversation) actually fires when the
// participant's bootstrap grant fails after the creator's own grant already
// succeeded — a retry for the SAME pair afterward must start clean (not be
// permanently blocked by a half-bootstrapped row occupying that pair's
// unique-index slot).
func TestCreateConversation_RollsBackOnGrantFailure(t *testing.T) {
	svc, perms, audit := newTestServiceFailingParticipantGrant(t)

	_, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err == nil {
		t.Fatal("expected an error when the participant grant fails")
	}
	if audit.callCount() != 0 {
		t.Fatalf("expected no audit event when bootstrap failed before reaching the audit step, got %d", audit.callCount())
	}

	// A retry for the SAME pair must succeed cleanly and be treated as a
	// genuinely fresh creation — proves the broken row was actually rolled
	// back, not left occupying the pair's unique-index slot forever.
	perms.failSubject = "" // stop forcing the failure for this retry
	resp, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("retry for the same pair after rollback: %v", err)
	}
	if resp.ConversationID == "" {
		t.Fatal("expected a valid conversation_id on the retry")
	}
	if !perms.hasActiveGrant(bob, ActionAccess, resourceTypeConversation, resp.ConversationID) {
		t.Fatal("expected the retry to have bootstrapped fresh grants")
	}
}

// testPermsFailingParticipantGrant wraps memPermissions, deterministically
// failing GrantPermission calls where subject == bob (the participant in
// this test's CreateConversation call, never the creator), regardless of
// the freshly-generated resourceID.
type testPermsFailingParticipantGrant struct {
	*memPermissions
	failSubject string
}

func (p *testPermsFailingParticipantGrant) GrantPermission(grantor, subject, action, resourceType, resourceID, scope string) error {
	if subject == p.failSubject {
		return errors.New("forced participant grant failure")
	}
	return p.memPermissions.GrantPermission(grantor, subject, action, resourceType, resourceID, scope)
}

func newTestServiceFailingParticipantGrant(t *testing.T) (*Service, *testPermsFailingParticipantGrant, *fakeAuditEmitter) {
	t.Helper()
	perms := &testPermsFailingParticipantGrant{memPermissions: newMemPermissions(), failSubject: bob}
	audit := newFakeAuditEmitter()
	svc, err := NewService(newInMemoryStore(), perms, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, perms, audit
}

func TestCreateConversation_RollsBackOnAuditFailure(t *testing.T) {
	svc, perms, audit := newTestService(t)
	audit.failNext = true

	_, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err == nil {
		t.Fatal("expected an error when the audit emit fails")
	}

	// A retry for the same pair, now that audit no longer fails, must
	// succeed and be treated as a genuinely fresh creation (proves the
	// broken row was actually rolled back).
	resp, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
	if !perms.hasActiveGrant(alice, ActionAccess, resourceTypeConversation, resp.ConversationID) {
		t.Fatal("expected the retry to have bootstrapped fresh grants")
	}
}

// --- CreateConversation crash-window bootstrap repair ---
//
// These tests cover the gap Security Steward's implementation merge-gate
// veto found (docs/DECISION_LOG.md, "Conversations implementation merge
// gate: Constitution Warden passes; Security Steward vetoes a real
// crash-window access-control gap in CreateConversation's bootstrap"):
// findOrCreateConversation's atomicity covers only the conversations row
// insert, not the GrantPermission calls that follow it — a process crash
// in between would otherwise leave a permanently-existing, permanently-
// ungranted row with no repair path. Unlike
// TestCreateConversation_RollsBackOnGrantFailure/_OnAuditFailure above
// (which cover a Go-error DURING the original bootstrap attempt, closed by
// deleting the row), these simulate the row already having committed with
// zero grants ever issued — the row-deletion rollback path never runs at
// all in this scenario, since findOrCreateConversation reports created=true
// exactly once, for the call that sets up the scenario, not for the
// CreateConversation retry that must detect and repair it.

// TestCreateConversation_RepairsMissingBootstrapGrantsAfterCrashWindow
// simulates the worst case: a row committed via a direct store call, with
// NO GrantPermission call ever issued (the exact state a real process
// crash between the row commit and the FIRST bootstrap grant would leave
// behind). A CreateConversation retry for the same pair must detect and
// repair both missing grants, not report false success while leaving both
// participants permanently denied.
func TestCreateConversation_RepairsMissingBootstrapGrantsAfterCrashWindow(t *testing.T) {
	svc, perms, audit := newTestService(t)

	// Simulate the crash: insert the row directly via the store (bypassing
	// Service.CreateConversation entirely, so NO GrantPermission call ever
	// happens).
	lo, hi := canonicalPair(alice, bob)
	crashedID, err := generateConversationID()
	if err != nil {
		t.Fatalf("generateConversationID: %v", err)
	}
	rec, created := svc.store.findOrCreateConversation(Conversation{ConversationID: crashedID, ParticipantLo: lo, ParticipantHi: hi, CreatedAtUnix: 1000})
	if !created {
		t.Fatal("expected a fresh insert to set up the crash scenario")
	}
	if perms.hasActiveGrant(alice, ActionAccess, resourceTypeConversation, rec.ConversationID) || perms.hasActiveGrant(bob, ActionAccess, resourceTypeConversation, rec.ConversationID) {
		t.Fatal("test setup invariant violated: expected zero grants before the repair-triggering retry")
	}

	// The retry: same pair, must detect the missing grants and repair them.
	resp, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation (repair retry): %v", err)
	}
	if resp.ConversationID != rec.ConversationID {
		t.Fatalf("expected the retry to resolve to the crashed row's own conversation_id (%q), got %q", rec.ConversationID, resp.ConversationID)
	}

	if !perms.hasActiveGrant(alice, ActionAccess, resourceTypeConversation, resp.ConversationID) {
		t.Fatal("expected creator's grant to be repaired")
	}
	if !perms.hasActiveGrant(bob, ActionAccess, resourceTypeConversation, resp.ConversationID) {
		t.Fatal("expected participant's grant to be repaired")
	}
	owner, ok := perms.ownerOf(resourceTypeConversation, resp.ConversationID)
	if !ok || owner != alice {
		t.Fatalf("expected creator to become the resource's implicit owner via the repair, got %q (found=%v)", owner, ok)
	}

	// The repair itself must be audited — this is a real, previously-silent
	// gap being closed, not a normal idempotent replay.
	call, ok := audit.lastCall()
	if !ok || call.action != "conversations.bootstrap_grants_repaired" {
		t.Fatalf("expected a bootstrap-repair audit event, got %+v (ok=%v)", call, ok)
	}
	if call.resource.ResourceType != resourceTypeConversation || call.resource.ResourceID != resp.ConversationID {
		t.Fatalf("unexpected audit resource: %+v", call.resource)
	}

	// A SUBSEQUENT idempotent hit, now that both grants are present, must
	// NOT re-repair or re-audit — preserving "no audit noise on a normal
	// idempotent replay" for the steady state after a one-time repair.
	countAfterRepair := audit.callCount()
	if _, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob}); err != nil {
		t.Fatalf("CreateConversation (post-repair replay): %v", err)
	}
	if audit.callCount() != countAfterRepair {
		t.Fatalf("expected no additional audit event once both grants are present, count went from %d to %d", countAfterRepair, audit.callCount())
	}
}

// TestCreateConversation_RepairsPartiallyMissingBootstrapGrant covers the
// more realistic partial-crash case: creator's own grant succeeded before
// the crash (matching CreateConversation's real bootstrap order — creator
// first), only participant's grant is missing. The repair must issue
// exactly the one missing grant, name only "participant" in its audit
// metadata, and leave creator's pre-existing grant/ownership untouched.
func TestCreateConversation_RepairsPartiallyMissingBootstrapGrant(t *testing.T) {
	svc, perms, audit := newTestService(t)

	lo, hi := canonicalPair(alice, bob)
	crashedID, err := generateConversationID()
	if err != nil {
		t.Fatalf("generateConversationID: %v", err)
	}
	rec, created := svc.store.findOrCreateConversation(Conversation{ConversationID: crashedID, ParticipantLo: lo, ParticipantHi: hi, CreatedAtUnix: 1000})
	if !created {
		t.Fatal("expected a fresh insert to set up the crash scenario")
	}
	// Simulate a crash AFTER creator's own grant succeeded but BEFORE
	// participant's — the exact ordering CreateConversation's real
	// bootstrap uses.
	if err := perms.GrantPermission(alice, alice, ActionAccess, resourceTypeConversation, rec.ConversationID, scopeFull); err != nil {
		t.Fatalf("simulating creator's pre-crash grant: %v", err)
	}

	resp, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation (repair retry): %v", err)
	}
	if !perms.hasActiveGrant(bob, ActionAccess, resourceTypeConversation, resp.ConversationID) {
		t.Fatal("expected participant's grant to be repaired")
	}
	if len(perms.grantCalls) != 2 { // 1 simulated pre-crash grant + 1 repair grant
		t.Fatalf("expected exactly one repair grant call beyond the simulated pre-crash grant, got %d calls: %+v", len(perms.grantCalls), perms.grantCalls)
	}

	call, ok := audit.lastCall()
	if !ok || call.action != "conversations.bootstrap_grants_repaired" || call.metadata["repaired"] != "participant" {
		t.Fatalf("expected a repair audit event naming only participant, got %+v (ok=%v)", call, ok)
	}
}

// TestCreateConversation_RepairFailurePropagatesError proves a failed
// repair attempt returns an error — never a false success — and leaves the
// missing grant genuinely missing, so a later retry can try again rather
// than the caller being told (incorrectly) that access now works.
func TestCreateConversation_RepairFailurePropagatesError(t *testing.T) {
	perms := &testPermsFailingParticipantGrant{memPermissions: newMemPermissions(), failSubject: bob}
	audit := newFakeAuditEmitter()
	svc, err := NewService(newInMemoryStore(), perms, audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	lo, hi := canonicalPair(alice, bob)
	crashedID, err := generateConversationID()
	if err != nil {
		t.Fatalf("generateConversationID: %v", err)
	}
	rec, created := svc.store.findOrCreateConversation(Conversation{ConversationID: crashedID, ParticipantLo: lo, ParticipantHi: hi, CreatedAtUnix: 1000})
	if !created {
		t.Fatal("expected a fresh insert to set up the crash scenario")
	}

	if _, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob}); err == nil {
		t.Fatal("expected an error when the repair grant fails, not a false success")
	}
	if perms.hasActiveGrant(bob, ActionAccess, resourceTypeConversation, rec.ConversationID) {
		t.Fatal("expected participant's grant to remain missing after a failed repair attempt")
	}
	if audit.callCount() != 0 {
		t.Fatalf("expected no repair audit event when the repair itself failed, got %d", audit.callCount())
	}
}

// --- SendMessage ---

func TestSendMessage_ParticipantSucceeds(t *testing.T) {
	svc, _, audit := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	resp, err := svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: alice, Ciphertext: []byte("ct")})
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if resp.MessageID == "" {
		t.Fatal("expected a non-empty message_id")
	}

	call, ok := audit.lastCall()
	if !ok || call.action != "conversations.send_message" || call.actor != alice {
		t.Fatalf("unexpected audit trail: %+v (ok=%v)", call, ok)
	}
	if call.metadata["message_id"] != resp.MessageID {
		t.Fatalf("expected audit metadata to name message_id, got %+v", call.metadata)
	}
}

func TestSendMessage_NonParticipantDenied(t *testing.T) {
	svc, _, audit := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	before := audit.callCount()
	_, err = svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: stranger, Ciphertext: []byte("ct")})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
	if audit.callCount() != before+1 {
		t.Fatalf("expected exactly one denial audit event, count went from %d to %d", before, audit.callCount())
	}
}

func TestSendMessage_RejectsEmptyCiphertext(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	if _, err := svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: alice, Ciphertext: nil}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty ciphertext, got %v", err)
	}
}

func TestSendMessage_CarriesOptionalSessionEstablishmentPayload(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	payload := []byte("ephemeral-pubkey-bytes")
	if _, err := svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: alice, Ciphertext: []byte("ct"), SessionEstablishmentPayload: payload}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	lm, err := svc.ListMessages(ListMessagesRequest{ConversationID: conv.ConversationID, RequestingSubject: bob, Limit: 10})
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(lm.Messages) != 1 || string(lm.Messages[0].SessionEstablishmentPayload) != string(payload) {
		t.Fatalf("expected session_establishment_payload to round-trip, got %+v", lm.Messages)
	}
}

// --- ListMessages ---

func sendN(t *testing.T, svc *Service, conversationID, sender string, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		resp, err := svc.SendMessage(SendMessageRequest{ConversationID: conversationID, Sender: sender, Ciphertext: []byte("ct")})
		if err != nil {
			t.Fatalf("SendMessage #%d: %v", i, err)
		}
		ids = append(ids, resp.MessageID)
	}
	return ids
}

func TestListMessages_AscendingOrderAndDefaultMostRecentPage(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	ids := sendN(t, svc, conv.ConversationID, alice, 5)

	resp, err := svc.ListMessages(ListMessagesRequest{ConversationID: conv.ConversationID, RequestingSubject: bob, Limit: 3})
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(resp.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(resp.Messages))
	}
	if !resp.HasMore {
		t.Fatal("expected has_more=true when 2 older messages remain")
	}
	// Most recent page = the LAST 3 sent, still ascending.
	want := ids[2:5]
	for i, m := range resp.Messages {
		if m.MessageID != want[i] {
			t.Fatalf("message %d: expected %q, got %q (full: %v vs %v)", i, want[i], m.MessageID, want, resp.Messages)
		}
	}
}

func TestListMessages_CursorPaginationWalksBackwardThroughFullHistory(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	ids := sendN(t, svc, conv.ConversationID, alice, 7)

	var collected []string
	var cursor *string
	for i := 0; i < 10; i++ { // bounded loop, avoid an infinite loop on a bug
		resp, err := svc.ListMessages(ListMessagesRequest{ConversationID: conv.ConversationID, RequestingSubject: bob, BeforeMessageID: cursor, Limit: 3})
		if err != nil {
			t.Fatalf("ListMessages (page %d): %v", i, err)
		}
		pageIDs := make([]string, len(resp.Messages))
		for j, m := range resp.Messages {
			pageIDs[j] = m.MessageID
		}
		collected = append(pageIDs, collected...) // pages walk backward; prepend to keep ascending overall order
		if !resp.HasMore {
			break
		}
		cursor = &pageIDs[0]
	}

	if len(collected) != len(ids) {
		t.Fatalf("expected to walk the full history (%d messages), collected %d: %v", len(ids), len(collected), collected)
	}
	for i, id := range ids {
		if collected[i] != id {
			t.Fatalf("message %d: expected %q, got %q — full history must reassemble in original ascending order", i, id, collected[i])
		}
	}
}

func TestListMessages_InvalidBeforeMessageID(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	sendN(t, svc, conv.ConversationID, alice, 1)

	bogus := "msg_does_not_exist"
	if _, err := svc.ListMessages(ListMessagesRequest{ConversationID: conv.ConversationID, RequestingSubject: bob, BeforeMessageID: &bogus, Limit: 10}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestListMessages_LimitClampedToMax(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	sendN(t, svc, conv.ConversationID, alice, 3)

	resp, err := svc.ListMessages(ListMessagesRequest{ConversationID: conv.ConversationID, RequestingSubject: bob, Limit: 999999})
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(resp.Messages) != 3 {
		t.Fatalf("expected all 3 messages within the clamped max, got %d", len(resp.Messages))
	}
}

// --- ListConversations ---

func TestListConversations_OmitsZeroMessageConversationsEntirely(t *testing.T) {
	svc, _, _ := newTestService(t)
	// CreateConversation-succeeded/SendMessage-never-called gap (charter
	// §3/§5): this conversation must be invisible to ListConversations.
	if _, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob}); err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	resp, err := svc.ListConversations(ListConversationsRequest{RequestingSubject: alice})
	if err != nil {
		t.Fatalf("ListConversations: %v", err)
	}
	if len(resp.Conversations) != 0 {
		t.Fatalf("expected a zero-message conversation to be omitted entirely, got %+v", resp.Conversations)
	}
}

func TestListConversations_AppearsOnceAtLeastOneMessageExists(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	if _, err := svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: alice, Ciphertext: []byte("ct")}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	resp, err := svc.ListConversations(ListConversationsRequest{RequestingSubject: bob})
	if err != nil {
		t.Fatalf("ListConversations: %v", err)
	}
	if len(resp.Conversations) != 1 {
		t.Fatalf("expected exactly 1 conversation, got %d", len(resp.Conversations))
	}
	got := resp.Conversations[0]
	if got.ConversationID != conv.ConversationID {
		t.Fatalf("unexpected conversation_id: %q", got.ConversationID)
	}
	if got.OtherParticipant != alice {
		t.Fatalf("expected other_participant=%q (from bob's perspective), got %q", alice, got.OtherParticipant)
	}
}

func TestListConversations_LastMessageAtIsDerivedNotStale(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	svc.now = fixedClock(1000)
	if _, err := svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: alice, Ciphertext: []byte("ct1")}); err != nil {
		t.Fatalf("SendMessage 1: %v", err)
	}
	svc.now = fixedClock(2000)
	if _, err := svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: bob, Ciphertext: []byte("ct2")}); err != nil {
		t.Fatalf("SendMessage 2: %v", err)
	}

	resp, err := svc.ListConversations(ListConversationsRequest{RequestingSubject: alice})
	if err != nil {
		t.Fatalf("ListConversations: %v", err)
	}
	if len(resp.Conversations) != 1 || resp.Conversations[0].LastMessageAtUnix != 2000 {
		t.Fatalf("expected last_message_at=2000 (the most recent message), got %+v", resp.Conversations)
	}
}

// --- GetConversation ---

func TestGetConversation_ParticipantSucceeds(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	resp, err := svc.GetConversation(GetConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: bob})
	if err != nil {
		t.Fatalf("GetConversation: %v", err)
	}
	if resp.ConversationID != conv.ConversationID {
		t.Fatalf("unexpected conversation_id: %q", resp.ConversationID)
	}
	if len(resp.Participants) != 2 {
		t.Fatalf("expected exactly 2 participants, got %v", resp.Participants)
	}
	found := map[string]bool{}
	for _, p := range resp.Participants {
		found[p] = true
	}
	if !found[alice] || !found[bob] {
		t.Fatalf("expected both alice and bob in participants, got %v", resp.Participants)
	}
}

// --- Enumeration-oracle-safe denial: THE merge-gate-critical test ---
//
// charter §3/§6: a nonexistent conversation_id and an existing-but-not-a-
// participant conversation_id must produce byte-for-byte identical
// response and identical audit event shape, for GetConversation,
// ListMessages, ExportConversation, and SendMessage.

func TestEnumerationOracleClosure_GetConversation(t *testing.T) {
	svc, _, audit := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	_, errA := svc.GetConversation(GetConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: stranger})
	callA, okA := audit.lastCall()

	_, errB := svc.GetConversation(GetConversationRequest{ConversationID: "conv_does_not_exist_at_all", RequestingSubject: stranger})
	callB, okB := audit.lastCall()

	if !errors.Is(errA, ErrPermissionDenied) || !errors.Is(errB, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for both cases, got %v / %v", errA, errB)
	}
	if errA.Error() != errB.Error() {
		t.Fatalf("expected byte-for-byte identical error text, got %q vs %q", errA.Error(), errB.Error())
	}
	if !okA || !okB {
		t.Fatalf("expected both cases to be audited, got okA=%v okB=%v", okA, okB)
	}
	if callA.action != callB.action || callA.ruleReference != callB.ruleReference {
		t.Fatalf("expected identical audit event SHAPE (action/rule_reference) for both cases, got %+v vs %+v", callA, callB)
	}
}

func TestEnumerationOracleClosure_ListMessages(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	_, errA := svc.ListMessages(ListMessagesRequest{ConversationID: conv.ConversationID, RequestingSubject: stranger, Limit: 10})
	_, errB := svc.ListMessages(ListMessagesRequest{ConversationID: "conv_does_not_exist_at_all", RequestingSubject: stranger, Limit: 10})

	if !errors.Is(errA, ErrPermissionDenied) || !errors.Is(errB, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for both cases, got %v / %v", errA, errB)
	}
	if errA.Error() != errB.Error() {
		t.Fatalf("expected byte-for-byte identical error text, got %q vs %q", errA.Error(), errB.Error())
	}
}

func TestEnumerationOracleClosure_ExportConversation(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	_, errA := svc.ExportConversation(ExportConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: stranger})
	_, errB := svc.ExportConversation(ExportConversationRequest{ConversationID: "conv_does_not_exist_at_all", RequestingSubject: stranger})

	if !errors.Is(errA, ErrPermissionDenied) || !errors.Is(errB, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for both cases, got %v / %v", errA, errB)
	}
	if errA.Error() != errB.Error() {
		t.Fatalf("expected byte-for-byte identical error text, got %q vs %q", errA.Error(), errB.Error())
	}
}

func TestEnumerationOracleClosure_SendMessage(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	_, errA := svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: stranger, Ciphertext: []byte("ct")})
	_, errB := svc.SendMessage(SendMessageRequest{ConversationID: "conv_does_not_exist_at_all", Sender: stranger, Ciphertext: []byte("ct")})

	if !errors.Is(errA, ErrPermissionDenied) || !errors.Is(errB, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for both cases, got %v / %v", errA, errB)
	}
	if errA.Error() != errB.Error() {
		t.Fatalf("expected byte-for-byte identical error text, got %q vs %q", errA.Error(), errB.Error())
	}
}

// --- ExportConversation content ---

func TestExportConversation_ContainsFullHistoryAndFormatVersion(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	ids := sendN(t, svc, conv.ConversationID, alice, 4)

	resp, err := svc.ExportConversation(ExportConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: bob})
	if err != nil {
		t.Fatalf("ExportConversation: %v", err)
	}
	if resp.FormatVersion == "" {
		t.Fatal("expected a non-empty format_version")
	}
	for _, id := range ids {
		if !containsString(string(resp.ExportBlob), id) {
			t.Fatalf("expected export bundle to contain message_id %q", id)
		}
	}
}

func containsString(haystack, needle string) bool {
	return len(needle) > 0 && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// fixedClock returns a now func (Service.now's real type, func() time.Time)
// fixed at unixSeconds.
func fixedClock(unixSeconds int64) func() time.Time {
	return func() time.Time { return time.Unix(unixSeconds, 0) }
}
